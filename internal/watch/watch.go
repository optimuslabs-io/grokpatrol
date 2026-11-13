// Package watch turns repeated, light apps-only runs into alerts. It remembers
// which grok.me apps were seen and what each check showed, and raises an alert only
// when an app newly opens without sign-in, or newly serves a server secret.
//
// It cannot warn before a publish. Grok Build publishes from grok.com, in the
// browser, where no tool on this host can intercept it. The earliest a local tool can
// know is when the address reaches this machine (browser history, a Grok session,
// shell history) or a certificate log. Watch shortens the time from publish to alert
// from "whenever someone next runs a scan" to minutes.
//
// The package reads and writes no file itself. grokpatrol-online --watch reads the
// previous record through hostfs and prints the next one on stdout; the plugin's
// watch-apps.sh saves it. grokpatrol stays read-only.
package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/detect/apps"
	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/exposure"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/pdns"
)

// Schema names the watch record; a record with any other schema is not loaded.
const Schema = "grokpatrol-watch/1"

// MaxStateBytes bounds the previous record read back in.
const MaxStateBytes = 8 << 20

// maxApps bounds the record, so a run of public-source names cannot grow it forever.
const maxApps = 5000

// How often a known app is checked again, by how long it has been watched. A new
// app is checked on the run that first sees it. The first day matters most: that is
// when an app someone is building gets published.
const (
	everyRunFor = 24 * time.Hour
	hourlyFor   = 7 * 24 * time.Hour
)

// Limitation is the standing caveat of every watch record.
const Limitation = "Watch cannot warn before a publish: Grok Build publishes from grok.com, where no tool on " +
	"this machine can intercept it. It alerts once an app's address reaches this machine (browser history, a " +
	"Grok session, shell history) or, with org keywords, a public name list, and the app opens without sign-in. " +
	"Apps first seen in the last day are checked on every run, in the last week hourly, and older ones daily."

// ScanLimitation is the caveat of a watch run with --scan-public.
const ScanLimitation = "The secret scan runs when an app first opens without sign-in and then daily. It reads " +
	"only what a stranger is served first: the home page and up to 8 of its same-host scripts. No match is not " +
	"proof of no secrets."

// Entry is what the record remembers about one app. It carries no file paths: only
// the address, how it was found, and what the checks showed.
type Entry struct {
	Host   string `json:"host"`
	Source string `json:"source"`
	// OnThisMachine: the address was found in a file on this host in some run.
	OnThisMachine bool   `json:"on_this_machine"`
	MatchedBy     string `json:"matched_by,omitempty"`
	PointsTo      string `json:"points_to,omitempty"`
	// WatchingSince is when this record first listed the app.
	WatchingSince time.Time `json:"watching_since"`

	Exposure     model.Exposure `json:"exposure,omitempty"`
	ExposureNote string         `json:"exposure_note,omitempty"`
	// CheckedAt is the last check that gave a definite answer. A failed request
	// (unknown) leaves it, and Exposure, as they were.
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// PublicSince is set when a check first finds the app public, and cleared only by
	// a definite non-public answer. An alert is raised when it goes from unset to set.
	PublicSince *time.Time `json:"public_since,omitempty"`

	Secrets    []model.AppSecret `json:"secrets,omitempty"`
	SecretScan string            `json:"secret_scan,omitempty"`
	// SecretsCheckedAt is the last run that attempted the secret scan (--scan-public).
	SecretsCheckedAt *time.Time `json:"secrets_checked_at,omitempty"`
}

// Alert is one notification. Title and Message are tool-authored: the only values in
// them are hosts and rule ids, both validated to a fixed character set.
type Alert struct {
	Kind    string `json:"kind"` // AlertPublic, AlertSecret or AlertSummary
	Host    string `json:"host,omitempty"`
	Title   string `json:"title"`
	Message string `json:"message"`
}

const (
	AlertPublic  = "public"
	AlertSecret  = "secret"
	AlertSummary = "summary"
)

// Record is what grokpatrol-online --watch prints, and what the next run reads back.
type Record struct {
	Schema      string            `json:"schema"`
	Tool        model.ToolInfo    `json:"tool"`
	CheckedAt   time.Time         `json:"checked_at"`
	FirstRun    bool              `json:"first_run,omitempty"`
	Alerts      []Alert           `json:"alerts"`
	Apps        []Entry           `json:"apps"`
	Errors      []model.ScanError `json:"errors"`
	Limitations []string          `json:"limitations"`
}

var ruleID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ErrSchema means the file is not a watch record this version understands.
var ErrSchema = errors.New("not a " + Schema + " record")

// Load parses a previous record into entries by host. The file is the user's own,
// but it is still a file: an entry that fails validation is dropped and counted,
// so nothing in it can become a network destination or alert text unchecked.
func Load(b []byte) (prev map[string]Entry, dropped int, err error) {
	var r struct {
		Schema string  `json:"schema"`
		Apps   []Entry `json:"apps"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, 0, errors.New("previous watch record does not parse")
	}
	if r.Schema != Schema {
		return nil, 0, ErrSchema
	}
	prev = map[string]Entry{}
	for _, e := range r.Apps {
		if !e.valid() {
			dropped++
			continue
		}
		e.clean()
		prev[e.Host] = e
	}
	return prev, dropped, nil
}

// grokHost reports whether s is exactly one label under grok.me.
func grokHost(s string) bool {
	h := apps.Hosts([]byte(s))
	return len(h) == 1 && h[0] == s
}

func (e *Entry) valid() bool {
	hostOK := grokHost(e.Host) || (pdns.ValidDomain(e.Host) && grokHost(e.PointsTo))
	if !hostOK || e.WatchingSince.IsZero() {
		return false
	}
	switch e.Source {
	case model.AppSourceLocal, model.AppSourcePassiveDNS, model.AppSourceWebSearch:
	default:
		return false
	}
	switch e.Exposure {
	case "", model.ExposurePublic, model.ExposureAppSignIn, model.ExposureRestricted,
		model.ExposureNotFound, model.ExposureUnknown:
		return true
	}
	return false
}

// clean drops whatever a hand-edited record could smuggle into later output: notes
// that are not short plain text, and secrets with an unknown rule, kind or path.
func (e *Entry) clean() {
	e.MatchedBy = plain(e.MatchedBy)
	e.ExposureNote = plain(e.ExposureNote)
	e.SecretScan = plain(e.SecretScan)
	if e.PointsTo != "" && !grokHost(e.PointsTo) {
		e.PointsTo = ""
	}
	e.Secrets = slices.DeleteFunc(e.Secrets, func(s model.AppSecret) bool {
		kindOK := s.Kind == model.SecretServer || s.Kind == model.SecretBrowser
		return !kindOK || !ruleID.MatchString(s.Rule) || (s.Asset != "/" && !exposure.SafePath(s.Asset))
	})
}

// plain keeps s only if it is at most 300 bytes of printable ASCII.
func plain(s string) string {
	if len(s) > 300 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return ""
		}
	}
	return s
}

// Carry appends the apps the previous record knew and this run did not find, so an
// app found once (by a public source, or in history since cleared) stays watched
// and its state does not reset. An app last seen on this machine gets a placeholder
// sighting, which keeps it eligible for the secret scan as it was before.
func Carry(rep *model.Report, prev map[string]Entry) {
	found := map[string]bool{}
	for i := range rep.Apps {
		a := &rep.Apps[i]
		if e, ok := prev[a.Host]; ok && e.OnThisMachine && len(a.Seen) == 0 {
			a.Seen = []model.Evidence{{Note: "seen on this machine in an earlier watch run"}}
		}
		found[a.Host] = true
	}
	hosts := make([]string, 0, len(prev))
	for h := range prev {
		if !found[h] {
			hosts = append(hosts, h)
		}
	}
	sort.Strings(hosts)
	for _, h := range hosts {
		e := prev[h]
		a := model.PublishedApp{Host: h, Source: e.Source, MatchedBy: e.MatchedBy, PointsTo: e.PointsTo}
		if e.OnThisMachine {
			a.Seen = []model.Evidence{{Note: "seen on this machine in an earlier watch run"}}
		}
		rep.Apps = append(rep.Apps, a)
	}
}

// Due reports whether host should be checked on this run.
func Due(host string, prev map[string]Entry, now time.Time) bool {
	e, ok := prev[host]
	if !ok || e.CheckedAt == nil {
		return true
	}
	watched, since := now.Sub(e.WatchingSince), now.Sub(*e.CheckedAt)
	switch {
	case watched < everyRunFor:
		return true
	case watched < hourlyFor:
		return since >= time.Hour
	default:
		return since >= 24*time.Hour
	}
}

// Prioritize puts apps that have never had a successful check first, then the
// least-recently checked apps, so per-run exposure limits do not starve the tail.
func Prioritize(found []model.PublishedApp, prev map[string]Entry) {
	sort.SliceStable(found, func(i, j int) bool {
		a, aok := prev[found[i].Host]
		b, bok := prev[found[j].Host]
		if (aok && a.CheckedAt != nil) != (bok && b.CheckedAt != nil) {
			return !(aok && a.CheckedAt != nil)
		}
		if aok && bok && a.CheckedAt != nil && b.CheckedAt != nil && !a.CheckedAt.Equal(*b.CheckedAt) {
			return a.CheckedAt.Before(*b.CheckedAt)
		}
		return found[i].Host < found[j].Host
	})
}

// ScanDue reports whether a due app should also get the secret scan on this run:
// when it is not yet known to be public (so the run that finds it public scans it),
// and otherwise once a day. A public app's scripts are up to 9 requests, too many to
// repeat every few minutes.
func ScanDue(host string, prev map[string]Entry, now time.Time) bool {
	e, ok := prev[host]
	return !ok || e.PublicSince == nil || e.SecretsCheckedAt == nil || now.Sub(*e.SecretsCheckedAt) >= 24*time.Hour
}

// Build folds this run's apps into the previous record and returns the next one.
// checked names the apps whose exposure was requested on this run; the others keep
// what the previous record said. On the first run there is one summary alert
// instead of one per app, so installing the watch does not flood the screen.
func Build(now time.Time, found []model.PublishedApp, checked map[string]bool, prev map[string]Entry, first bool) ([]Entry, []Alert) {
	var entries []Entry
	var secretAlerts, publicAlerts []Alert
	for _, a := range found {
		e, known := prev[a.Host]
		if !known {
			e = Entry{Host: a.Host, WatchingSince: now}
		}
		if a.Source != "" {
			e.Source = a.Source
		}
		if a.MatchedBy != "" {
			e.MatchedBy = a.MatchedBy
		}
		if a.PointsTo != "" {
			e.PointsTo = a.PointsTo
		}
		e.OnThisMachine = e.OnThisMachine || len(a.Seen) > 0

		if checked[a.Host] {
			switch a.Exposure {
			case model.ExposurePublic:
				at := now
				e.Exposure, e.ExposureNote, e.CheckedAt = a.Exposure, a.ExposureNote, &at
				if e.PublicSince == nil {
					e.PublicSince = &at
					if !first {
						publicAlerts = append(publicAlerts, publicAlert(e))
					}
				}
			case model.ExposureRestricted, model.ExposureNotFound, model.ExposureAppSignIn:
				at := now
				e.Exposure, e.ExposureNote, e.CheckedAt, e.PublicSince = a.Exposure, a.ExposureNote, &at, nil
			default:
				// A failed request says nothing about the app. Keep the last definite
				// answer, so a flaky network neither hides nor repeats an alert.
				if e.Exposure == "" {
					e.Exposure = model.ExposureUnknown
				}
				e.ExposureNote = "latest check failed: " + a.ExposureNote
			}
			if len(a.SecretScanAssets) > 0 {
				secrets := mergeScannedSecrets(e.Secrets, a.Secrets, a.SecretScanAssets)
				fresh := newServerRules(e.Secrets, secrets)
				at := now
				e.Secrets, e.SecretScan, e.SecretsCheckedAt = secrets, a.SecretScan, &at
				if len(fresh) > 0 && !first {
					secretAlerts = append(secretAlerts, Alert{
						Kind: AlertSecret, Host: e.Host, Title: "Public grok.me app serves a secret",
						Message: fmt.Sprintf("%s serves a server secret to anyone (%s). Revoke and rotate it, then restrict the app.",
							e.Host, strings.Join(fresh, ", ")),
					})
				}
			}
		}
		entries = append(entries, e)
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Host < entries[j].Host })
	alerts := append(secretAlerts, publicAlerts...)
	if first {
		alerts = []Alert{summary(entries)}
	}
	return entries, alerts
}

// Cap trims entries to maxApps, keeping apps seen on this machine first and then the
// most recently watched, and reports whether it dropped any.
func Cap(entries []Entry) ([]Entry, bool) {
	if len(entries) <= maxApps {
		return entries, false
	}
	kept := slices.Clone(entries)
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].OnThisMachine != kept[j].OnThisMachine {
			return kept[i].OnThisMachine
		}
		return kept[i].WatchingSince.After(kept[j].WatchingSince)
	})
	kept = kept[:maxApps]
	sort.Slice(kept, func(i, j int) bool { return kept[i].Host < kept[j].Host })
	return kept, true
}

func publicAlert(e Entry) Alert {
	msg := e.Host + " opens without sign-in. If it is yours, set access to Only you or Invited users in Grok Build."
	if !e.OnThisMachine {
		msg += " It was matched to your org by name, so it may be someone else's."
	}
	return Alert{Kind: AlertPublic, Host: e.Host, Title: "Public grok.me app", Message: msg}
}

// newServerRules returns the server-kind rules in now that were not in before.
func newServerRules(before, now []model.AppSecret) []string {
	had := map[string]bool{}
	for _, s := range before {
		if s.Kind == model.SecretServer {
			had[s.Rule] = true
		}
	}
	var out []string
	for _, s := range now {
		if s.Kind == model.SecretServer && !had[s.Rule] && !slices.Contains(out, s.Rule) {
			out = append(out, s.Rule)
		}
	}
	return out
}

func mergeScannedSecrets(before, now []model.AppSecret, scanned []string) []model.AppSecret {
	covered := make(map[string]bool, len(scanned))
	for _, asset := range scanned {
		covered[asset] = true
	}
	seen := make(map[model.AppSecret]bool, len(before)+len(now))
	var out []model.AppSecret
	for _, s := range before {
		if !covered[s.Asset] && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range now {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func summary(entries []Entry) Alert {
	a := Alert{Kind: AlertSummary, Title: "grokpatrol is watching grok.me apps"}
	if len(entries) == 0 {
		a.Message = "No grok.me app found yet. You will get an alert when one appears and opens without sign-in."
		return a
	}
	var public, secrets []string
	unknown := 0
	for _, e := range entries {
		if e.PublicSince != nil {
			public = append(public, e.Host)
		} else if e.Exposure == "" || e.Exposure == model.ExposureUnknown {
			unknown++
		}
		rules := newServerRules(nil, e.Secrets)
		if len(rules) > 0 {
			secrets = append(secrets, e.Host+" ("+strings.Join(rules, ", ")+")")
		}
	}
	a.Message = "Watching " + engine.Plural(len(entries), "app") + ". "
	if len(public) == 0 {
		if unknown > 0 {
			a.Message += fmt.Sprintf("No app was confirmed open without sign-in; %d %s could not be checked successfully.",
				unknown, engine.Plural(unknown, "app"))
		} else {
			a.Message += "None opens without sign-in."
		}
	} else {
		shown := public
		if len(shown) > 3 {
			shown = shown[:3]
		}
		verb := "open"
		if len(public) == 1 {
			verb = "opens"
		}
		a.Message += fmt.Sprintf("%d %s without sign-in: %s", len(public), verb, strings.Join(shown, ", "))
		if more := len(public) - len(shown); more > 0 {
			a.Message += fmt.Sprintf(" and %d more", more)
		}
		a.Message += "."
	}
	if len(secrets) > 0 {
		shown := secrets
		if len(shown) > 3 {
			shown = shown[:3]
		}
		a.Message += " Server secrets found: " + strings.Join(shown, "; ")
		if more := len(secrets) - len(shown); more > 0 {
			a.Message += fmt.Sprintf("; and %d more", more)
		}
		a.Message += ". Revoke and rotate these secrets, then restrict the apps."
	}
	return a
}
