//go:build online

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/buildinfo"
	"github.com/optimuslabs-io/grokpatrol/internal/detect/apps"
	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/exposure"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/pdns"
	"github.com/optimuslabs-io/grokpatrol/internal/report"
	"github.com/optimuslabs-io/grokpatrol/internal/watch"
)

// onlineOpts are the flags that exist only in the grokpatrol-online build
// (-tags online); the standard binary has none of them and no network code.
type onlineOpts struct {
	checkExposure      bool
	scanPublic         bool
	scanKeywordMatches bool
	discover           bool
	grokSearch         bool
	grokModel          string
	appHosts           string
	watch              string
	orgKeywords        repeatable
	orgDomains         repeatable
}

var online onlineOpts

// maxAppHostsBytes bounds --app-hosts: it is a list of URLs, not a dataset.
const maxAppHostsBytes = 4 << 20

func registerOnlineFlags() {
	flag.BoolVar(&online.checkExposure, "check-exposure", false,
		"after the scan, make one unauthenticated request to each grok.me app found, to see whether it opens without sign-in (network)")
	flag.BoolVar(&online.scanPublic, "scan-public", false,
		"for each app that opens without sign-in, also fetch up to 8 of its same-host scripts and scan them and the home page in memory for secrets; implies --check-exposure (network)")
	flag.BoolVar(&online.scanKeywordMatches, "scan-keyword-matches", false,
		"with --scan-public, also scan apps tied to the org only by a keyword or a search result, not just apps seen on this machine or under --org-domain")
	flag.BoolVar(&online.discover, "discover", false,
		"list grok.me names from free public sources: crt.sh, urlscan.io ($URLSCAN_API_KEY optional) and AlienVault OTX ($OTX_API_KEY, free) (network)")
	flag.BoolVar(&online.grokSearch, "grok-search", false,
		"ask the xAI API's web and X search for grok.me apps matching the org keywords; needs $XAI_API_KEY and bills its API credits (network)")
	flag.StringVar(&online.grokModel, "grok-model", "grok-4.7", "with --grok-search, the xAI model to use")
	flag.StringVar(&online.appHosts, "app-hosts", "", "file of grok.me URLs or hosts from a web search, one per line (the Claude plugin writes it)")
	flag.StringVar(&online.watch, "watch", "",
		"light watch run: look only for grok.me apps (no repository scan), compare with the watch record in this file, "+
			"and print the next record as JSON with alerts for apps that newly open without sign-in; the file is only read "+
			"(the plugin's watch-apps.sh saves the output); implies --check-exposure (network)")
	flag.Var(&online.orgKeywords, "org-keyword", "report grok.me apps whose name contains this word (repeatable)")
	flag.Var(&online.orgDomains, "org-domain", "your org's domain: its name becomes a keyword, and custom domains under it that point at grok.me are reported (repeatable)")
}

// configureOnline validates the online flags and records them on env. A non-nil
// error is a usage error (exit 1), never a finding.
func configureOnline(env *engine.Env) error {
	if online.scanKeywordMatches && !online.scanPublic {
		return fmt.Errorf("--scan-keyword-matches needs --scan-public")
	}
	if online.watch != "" && (online.grokSearch || online.appHosts != "") {
		return fmt.Errorf("--watch runs on a schedule, so it takes neither --grok-search (it would bill every run) nor --app-hosts")
	}
	env.CheckExposure = online.checkExposure || online.scanPublic || online.watch != ""
	env.ScanPublic, env.ScanKeywordMatches = online.scanPublic, online.scanKeywordMatches
	if online.grokSearch && os.Getenv("XAI_API_KEY") == "" {
		return fmt.Errorf("--grok-search needs an xAI API key in $XAI_API_KEY (grokpatrol never reads ~/.grok/auth.json)")
	}
	var domains []string
	for _, d := range online.orgDomains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if !pdns.ValidDomain(d) {
			return fmt.Errorf("--org-domain %q is not a domain name", d)
		}
		domains = append(domains, d)
	}
	keywords, dropped := pdns.Keywords(domains, pdns.GitEmails(env.Home), online.orgKeywords)
	if len(dropped) > 0 {
		fmt.Fprintf(os.Stderr, "grokpatrol: ignoring keywords shorter than 4 characters or not a-z0-9-: %s\n", strings.Join(dropped, ", "))
	}
	if online.grokSearch && len(keywords) == 0 {
		return fmt.Errorf("--grok-search needs an org keyword: pass --org-keyword or --org-domain")
	}
	env.Discover, env.GrokSearch, env.AppHosts = online.discover, online.grokSearch, online.appHosts != ""
	env.OrgKeywords, env.OrgDomains = keywords, domains
	return nil
}

// runOnline does the opt-in network work after the offline scan: the public sources
// first (they can add apps), then the exposure check over everything found.
func runOnline(ctx context.Context, env *engine.Env, rep *model.Report, prog engine.Progress) {
	if env.AppHosts {
		addAppHosts(rep, env.OrgDomains, prog)
	}
	if env.Discover || env.GrokSearch {
		discoverApps(ctx, env, rep, prog)
	}
	if env.CheckExposure && len(rep.Apps) > 0 {
		if prog != nil {
			prog.Checking("exposure", fmt.Sprintf("requesting the home page of %s without signing in (network)",
				engine.Plural(len(rep.Apps), "app")))
		}
		start := time.Now()
		exposure.Check(ctx, rep.Apps, exposureConfig(env))
		if prog != nil {
			open, leaking := 0, 0
			for _, a := range rep.Apps {
				if a.Exposure == model.ExposurePublic {
					open++
				}
				if len(a.Secrets) > 0 {
					leaking++
				}
			}
			summary := fmt.Sprintf("%d of %d open without sign-in", open, len(rep.Apps))
			if env.ScanPublic {
				summary += fmt.Sprintf("; %d serve a key or secret", leaking)
			}
			prog.Checked("exposure", summary, time.Since(start))
		}
	}
}

func exposureConfig(env *engine.Env) exposure.Config {
	return exposure.Config{
		UserAgent:   "grokpatrol/" + buildinfo.Version + " (exposure check; +https://github.com/optimuslabs-io/grokpatrol)",
		OrgDomains:  env.OrgDomains,
		ScanSecrets: env.ScanPublic, ScanKeywordMatches: env.ScanKeywordMatches,
	}
}

// discoverApps asks the public sources (--discover, --grok-search) for grok.me names
// and applies the org rules to rep.Apps.
func discoverApps(ctx context.Context, env *engine.Env, rep *model.Report, prog engine.Progress) {
	var sources []pdns.Source
	var cnames pdns.CNAMESource
	var used []string
	if env.Discover {
		sources = append(sources, pdns.NewCrtSh(), pdns.NewURLScan(os.Getenv("URLSCAN_API_KEY")))
		used = append(used, "crt.sh", "urlscan")
		if k := os.Getenv("OTX_API_KEY"); k != "" {
			otx := pdns.NewOTX(k)
			sources, cnames = append(sources, otx), otx
			used = append(used, "OTX")
		} else {
			rep.AddAppLimitations("AlienVault OTX was skipped: set $OTX_API_KEY (free) for its passive " +
				"DNS names and to find custom domains under --org-domain.")
		}
	}
	if env.GrokSearch {
		sources = append(sources, pdns.NewGrokSearch(os.Getenv("XAI_API_KEY"), online.grokModel))
		used = append(used, "Grok search")
	}
	if prog != nil {
		prog.Checking("discover", fmt.Sprintf("asking %s for grok.me names; matching %s and custom domains under %s (network)",
			strings.Join(used, ", "), orList(env.OrgKeywords, "no keywords"), orList(env.OrgDomains, "no org domain")))
	}
	start := time.Now()
	res := pdns.Enrich(ctx, sources, cnames, rep, env.OrgKeywords, env.OrgDomains)
	rep.Errors = append(rep.Errors, res.Errors...)
	rep.AddAppLimitations(res.Limitations...)
	if prog != nil {
		summary := engine.Plural(res.Added, "app") + " added from public sources"
		if len(res.Errors) > 0 {
			summary += fmt.Sprintf(" (%d sources failed; see the report)", len(res.Errors))
		}
		prog.Checked("discover", summary, time.Since(start))
	}
}

// addAppHosts reads --app-hosts. Its lines are untrusted (search results), so only
// counts are printed, never the lines themselves.
func addAppHosts(rep *model.Report, orgDomains []string, prog engine.Progress) {
	b, err := hostfs.ReadFileCapped(online.appHosts, maxAppHostsBytes)
	if err != nil {
		rep.Errors = append(rep.Errors, model.ScanError{Detector: "app-hosts", Kind: "io", Path: online.appHosts, Message: apps.ErrText(err)})
		return
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	added, rejected := pdns.AddHosts(rep, lines, orgDomains)
	if prog != nil {
		prog.Checking("app-hosts", "reading grok.me URLs from "+online.appHosts)
		prog.Checked("app-hosts", fmt.Sprintf("%s added, %d lines rejected (not a grok.me app or a domain under --org-domain)",
			engine.Plural(added, "app"), rejected), 0)
	}
}

// watchMode reports whether this run is a --watch run.
func watchMode() bool { return online.watch != "" }

// runWatch is one light watch run: the apps detector only (no filesystem walk, no
// repository triage), the public sources if asked, then an exposure check of the
// apps that are due. It prints the next watch record on stdout and one line per
// alert on stderr ("alert<TAB>title<TAB>message"); the plugin's watch-apps.sh saves
// the record and shows the alerts. The record file is only ever read here.
func runWatch(ctx context.Context, env *engine.Env, detectorTimeout time.Duration) int {
	now := time.Now().UTC()
	var prev map[string]watch.Entry
	var loadErrs []model.ScanError
	b, err := hostfs.ReadFileCapped(online.watch, watch.MaxStateBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		fmt.Fprintf(os.Stderr, "grokpatrol: cannot read the watch record %s: %v\n", online.watch, apps.ErrText(err))
		return model.ExitToolError
	default:
		var dropped int
		prev, dropped, err = watch.Load(b)
		if err != nil {
			loadErrs = append(loadErrs, model.ScanError{Detector: "watch", Kind: "parse", Path: online.watch,
				Message: err.Error() + "; started a new record"})
			prev = nil
		} else if dropped > 0 {
			loadErrs = append(loadErrs, model.ScanError{Detector: "watch", Kind: "parse", Path: online.watch,
				Message: engine.Plural(dropped, "entry") + " in the watch record failed validation and were dropped"})
		}
	}
	first := prev == nil

	// The engine's standing caveats describe a full scan (what it can say about
	// uploaded archives, a request to every app). Run it with the network options off
	// so they stay out; the watch states its own below.
	offline := *env
	offline.CheckExposure, offline.Discover, offline.ScanPublic, offline.ScanKeywordMatches = false, false, false, false
	eng := &engine.Engine{Readers: []engine.Detector{apps.New()}, DetectorTimeout: detectorTimeout}
	rep := eng.Run(ctx, &offline)
	if env.Discover {
		discoverApps(ctx, env, rep, nil)
	}
	watch.Carry(rep, prev)

	// Two batches, so the secret scan (up to 9 requests per public app) runs only for
	// the apps that are due for it, not on every run.
	var due, scan, plain []model.PublishedApp
	for _, a := range rep.Apps {
		switch {
		case !watch.Due(a.Host, prev, now):
		case env.ScanPublic && watch.ScanDue(a.Host, prev, now):
			scan = append(scan, a)
		default:
			plain = append(plain, a)
		}
	}
	cfg := exposureConfig(env)
	exposure.Check(ctx, scan, cfg)
	cfg.ScanSecrets = false
	exposure.Check(ctx, plain, cfg)
	due = append(scan, plain...)
	checked := map[string]bool{}
	results := map[string]model.PublishedApp{}
	for _, a := range due {
		checked[a.Host], results[a.Host] = true, a
	}
	for i, a := range rep.Apps {
		if r, ok := results[a.Host]; ok {
			rep.Apps[i] = r
		}
	}

	report.Display(rep, env.Home)
	entries, alerts := watch.Build(now, rep.Apps, checked, prev, first)
	limitations := append([]string{watch.Limitation}, rep.AppLimitations...)
	if env.ScanPublic {
		limitations = append(limitations, watch.ScanLimitation)
	}
	entries, capped := watch.Cap(entries)
	if capped {
		limitations = append(limitations, "The watch record keeps at most 5000 apps; the oldest apps found only by public sources were dropped.")
	}
	rec := watch.Record{
		Schema: watch.Schema, Tool: rep.Tool, CheckedAt: now, FirstRun: first,
		Alerts: alerts, Apps: entries, Errors: loadErrs, Limitations: limitations,
	}
	if rec.Alerts == nil {
		rec.Alerts = []watch.Alert{}
	}
	if rec.Apps == nil {
		rec.Apps = []watch.Entry{}
	}
	if rec.Errors == nil {
		rec.Errors = []model.ScanError{}
	}
	for _, e := range rep.Errors {
		if e.Detector == "apps" || e.Detector == "discover" {
			rec.Errors = append(rec.Errors, e)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		fmt.Fprintf(os.Stderr, "grokpatrol: %v\n", err)
		return model.ExitToolError
	}
	for _, a := range rec.Alerts {
		fmt.Fprintf(os.Stderr, "alert\t%s\t%s\n", a.Title, a.Message)
	}
	fmt.Fprintf(os.Stderr, "watch: %s, %d checked, %s, %s\n", engine.Plural(len(rec.Apps), "app"), len(due),
		engine.Plural(len(rec.Alerts), "alert"), engine.Plural(len(rec.Errors), "error"))
	return 0
}

func orList(v []string, none string) string {
	if len(v) == 0 {
		return none
	}
	return strings.Join(v, ", ")
}
