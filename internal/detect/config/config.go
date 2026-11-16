// Package config checks whether the upload mitigations are actually set.
//
// There are THREE of them, not one, and which are required depends on the Grok
// generation on the host:
//
//	[telemetry]
//	trace_upload = false                # every generation
//
//	[harness]
//	disable_workspace_teleport = true   # 1.x: the documented kill switch
//	disable_codebase_upload = true      # 0.2.x: the original kill switch
//
// Grok 1.x documents only disable_workspace_teleport ("Kill switch for per-turn
// workspace snapshots"); disable_codebase_upload is gone from its docs. But the
// 1.0.77 binary still carries the old name, next to a .tar.gz upload path, so on a
// 1.x host, and on a host whose version is unknown, BOTH kill switches are required.
// Only a host whose every known version is in the 0.2.x range this tool analysed
// gets away with the old switch alone. Setting the switch a build does not know
// costs nothing; trusting the wrong one is a false MITIGATED.
//
// A host with only some of the required settings is EXPOSED: "partially mitigated"
// is never rounded up. Checking only the flag the headlines mentioned would tell
// such a host it was safe.
//
// Grok reads more than config.toml. Lowest to highest: /etc/grok/managed_config.toml,
// $GROK_HOME/managed_config.toml, $GROK_HOME/config.toml, then $GROK_HOME/
// requirements.toml and /etc/grok/requirements.toml, whose values are pins that beat
// every other file and the environment. The GROK_CONFIG overlay is confined to an
// allowlist (models, features, toolset, shell_environment_policy) that cannot reach
// any required setting, so it is reported but not read. Environment variables beat
// every file but a pin, and grokpatrol can only see its OWN environment, so one that
// can switch an upload back on makes the mitigation unverifiable.
//
// The parser is a hand-rolled TOML line scanner rather than a library: pulling a
// five-thousand-line third-party parser into a tool whose entire trust story is
// "zero dependencies, read the source" -- to read a handful of keys -- is a bad trade.
//
// It FAILS CLOSED. A naive scanner's failure mode is a false MITIGATED: it sees
// `true` in a comment or inside a multi-line string and declares the host safe.
// That is the one output this tool must never produce, so a key counts only when
// it is positively parsed, in the right table, with the exact expected literal.
package config

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/optimuslabs-io/grokpatrol/internal/detect/version"
	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/grokver"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// Mitigation is one config setting that must hold for uploads to be blocked.
type Mitigation struct {
	Table string
	Key   string
	Want  string // the exact literal required: "true" or "false"
	What  string // what it stops, in plain language
	// Modern marks the 1.x kill switch. It is not required on a host whose every
	// known Grok version is in the analysed 0.2.x range, which does not know it.
	Modern bool
}

// The kill-switch names are sourced from scan rather than written as literals here:
// grokpatrol searches binaries for these strings, so a plain copy would sit in
// grokpatrol's own .rodata and the tool would detect itself as a Grok install. See
// internal/scan/markers.go -- this is not hypothetical, it happened.
var (
	// MitigationKey is the 0.2.x kill switch.
	MitigationKey = scan.MarkerFlag
	// TeleportKey is the 1.x kill switch.
	TeleportKey = scan.MarkerTeleport
)

const (
	MitigationTable = "harness"
	TraceTable      = "telemetry"
	TraceKey        = "trace_upload"
	maxConfigBytes  = 1 << 20
)

// Mitigations returns every required setting, in the order the report prints them.
// This is the full set, required on a 1.x host or one whose version is unknown; see
// requiredFor for the 0.2.x exception.
func Mitigations() []Mitigation {
	return []Mitigation{
		{Table: TraceTable, Key: TraceKey, Want: "false", What: "session trace upload"},
		{Table: MitigationTable, Key: TeleportKey, Want: "true", Modern: true,
			What: "per-turn workspace snapshot upload (the Grok 1.x kill switch)"},
		{Table: MitigationTable, Key: MitigationKey, Want: "true",
			What: "whole-repository archive upload (the Grok 0.2.x kill switch, still present in 1.x builds)"},
	}
}

// Recommended returns settings that reduce what Grok sends but do not gate the
// repository or trace uploads. They are advised, never required: their absence does
// not make a host EXPOSED.
func Recommended() []Mitigation {
	return []Mitigation{
		{Table: "features", Key: "telemetry", Want: "false", What: "product telemetry"},
		{Table: "diagnostics", Key: "error_reporting", Want: "false", What: "crash reports"},
	}
}

// requiredFor drops the 1.x kill switch on a host known to run only 0.2.x builds.
func requiredFor(legacyOnly bool) []Mitigation {
	var out []Mitigation
	for _, m := range Mitigations() {
		if m.Modern && legacyOnly {
			continue
		}
		out = append(out, m)
	}
	return out
}

// legacyOnly reports whether every non-low-confidence Grok version on the host is in
// the 0.2.x range this tool analysed. No evidence at all is NOT legacy: an unknown
// version gets the full set, because guessing the old generation and dropping the
// new switch is the reassuring direction.
func legacyOnly(vs []model.VersionEvidence) bool {
	n := 0
	for _, v := range vs {
		if v.Confidence == "low" {
			continue
		}
		n++
		if grokver.Class(v.Version) == model.VersionUnknown {
			return false
		}
	}
	return n > 0
}

// systemDir is where root-owned fleet files live. A variable so tests can point it
// at a fixture instead of the real /etc.
var systemDir = filepath.Join(string(filepath.Separator), "etc", "grok")

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "config" }

// Describe names EVERY mitigation, on purpose. Public reporting fixated on one flag,
// and a host with only that one set is still uploading session traces. The progress
// line is where a reader learns there is more than one thing to check -- which is the
// whole point of the detector.
func (*Detector) Describe() string {
	keys := make([]string, 0, 3)
	for _, m := range Mitigations() {
		keys = append(keys, m.Table+"."+m.Key)
	}
	return "checking config.toml, managed_config.toml and requirements.toml for the upload mitigations: " +
		strings.Join(keys, ", ")
}

// summarize reports mitigation state. "Partially mitigated" is named as such and
// never rounded up to mitigated.
func summarize(homes []homeState) string {
	for _, h := range homes {
		switch {
		case h.missing:
			return "no config.toml: no upload mitigation is set"
		case h.uncertain:
			return "a config file could not be confirmed -- treated as unmitigated"
		}
		set := 0
		for _, m := range h.required {
			if h.satisfied(m) {
				set++
			}
		}
		switch {
		case set == len(h.required):
			return fmt.Sprintf("all %d required mitigations set", len(h.required))
		case set == 0:
			return "NO required mitigation set: uploads are not blocked"
		default:
			return fmt.Sprintf("only %d of %d required mitigations set -- partially mitigated is NOT mitigated", set, len(h.required))
		}
	}
	return "no config.toml found"
}

func (d *Detector) Run(_ context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result

	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}

	// Only a real install counts. A text file that merely mentions the bucket name --
	// notes, an IoC list, another scanner -- must not make a clean host report EXPOSED.
	grokPresent := len(env.Discovered.Installs()) > 0 || len(env.Discovered.UploadQueues) > 0
	for _, h := range homes {
		if _, err := os.Stat(h); err == nil {
			grokPresent = true
		}
	}

	legacy := legacyOnly(version.Passive(env))
	required := requiredFor(legacy)

	var states []homeState
	for _, h := range homes {
		hs := loadHome(h, &res)
		hs.required = required
		states = append(states, hs)
	}

	// auth.json: existence is noted, and the file is never opened. There is no code
	// path in grokpatrol that reads it.
	for _, h := range homes {
		auth := filepath.Join(h, "auth.json")
		if fi, err := os.Lstat(auth); err == nil {
			res.Findings = append(res.Findings, model.Finding{
				ID:       "config.auth_present",
				Detector: "config",
				Severity: model.SevInfo,
				Tags:     []string{model.TagConfig},
				Title:    "A cached xAI credential is present",
				Detail:   "grokpatrol did not read this file. It only checked that it exists.",
				Remediation: "If you are decommissioning Grok, revoke this token in the xAI console -- deleting the " +
					"file locally does not revoke it.",
				Evidence: []model.Evidence{{Path: auth, SizeBytes: fi.Size(), Note: "not read"}},
			})
		}
	}

	if !grokPresent {
		res.Summary = "no grok install, so no config to check"
		return res, nil // no grok on this host: the absence of its config is not a finding
	}

	res.Findings = append(res.Findings, configFindings(states, env.LookupEnv)...)
	res.Findings = append(res.Findings, envFindings(env.LookupEnv)...)
	res.Findings = append(res.Findings, envDestinationFindings(env)...)
	res.Summary = summarize(states)
	res.Limitations = append(res.Limitations,
		"Environment variables override config files, and grokpatrol can only see the environment it was run "+
			"from, not the one Grok was launched with. A shell profile, launcher or IDE that sets "+
			"GROK_TELEMETRY_TRACE_UPLOAD for Grok alone would not show up here.",
		"Signed requirements.toml pins are counted as applied; grokpatrol cannot verify the signature, and Grok "+
			"ignores the pins when it does not verify. macOS device-management policy (ai.x.grok), remote campaigns "+
			"and experiments are not read.")
	if !legacy {
		res.Limitations = append(res.Limitations,
			"No Grok version in the analysed 0.2.x range was found, so both kill switches are required: Grok 1.x "+
				"documents only "+TeleportKey+", but its binary still carries "+MitigationKey+".")
	}
	return res, nil
}

// layer is one config file Grok merges.
type layer struct {
	path string
	pin  bool // a requirements file: its values beat every other file and the environment
	st   state
}

// homeState is the merged view of one grok home's config layers.
type homeState struct {
	userPath  string // $GROK_HOME/config.toml: the row the report shows, and where advice points
	layers    []layer
	required  []Mitigation
	missing   bool   // no config layer exists at all
	uncertain bool   // some present layer used a construct this scanner does not model
	badPath   string // the layer that was uncertain
}

// layerFiles lists a home's layers lowest-precedence first.
func layerFiles(home string) []layer {
	return []layer{
		{path: filepath.Join(systemDir, "managed_config.toml")},
		{path: filepath.Join(home, "managed_config.toml")},
		{path: filepath.Join(home, "config.toml")},
		{path: filepath.Join(home, "requirements.toml"), pin: true},
		{path: filepath.Join(systemDir, "requirements.toml"), pin: true},
	}
}

func loadHome(home string, res *engine.Result) homeState {
	hs := homeState{userPath: filepath.Join(home, "config.toml"), missing: true}
	for _, l := range layerFiles(home) {
		b, err := hostfs.ReadFileCapped(l.path, maxConfigBytes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if res != nil {
				res.Errors = append(res.Errors, model.ScanError{
					Detector: "config", Kind: "permission", Path: l.path, Message: err.Error(), Material: true,
				})
			}
			hs.missing = false
			if !hs.uncertain {
				hs.uncertain, hs.badPath = true, l.path
			}
			continue
		}
		hs.missing = false
		l.st = parse(string(b))
		l.st.path = l.path
		if l.st.uncertain && !hs.uncertain {
			hs.uncertain, hs.badPath = true, l.path
		}
		hs.layers = append(hs.layers, l)
	}
	return hs
}

// resolve returns the effective literal for table.key and the layer it came from.
// Files merge lowest first; a requirements value is a pin and wins outright.
func (h homeState) resolve(full string) (val string, src layer, ok bool) {
	for _, l := range h.layers {
		if l.pin {
			continue
		}
		if v, set := l.st.values[full]; set {
			val, src, ok = v, l, true
		}
	}
	for _, l := range h.layers {
		if !l.pin {
			continue
		}
		if v, set := l.st.values[full]; set {
			val, src, ok = v, l, true
		}
	}
	return val, src, ok
}

// resolveString is resolve for string-valued keys (the upload endpoints).
func (h homeState) resolveString(full string) (val string, src layer, ok bool) {
	for _, pinPass := range []bool{false, true} {
		for _, l := range h.layers {
			if l.pin != pinPass {
				continue
			}
			if v, set := l.st.strs[full]; set {
				val, src, ok = v, l, true
			}
		}
	}
	return val, src, ok
}

func (h homeState) satisfied(m Mitigation) bool {
	v, _, ok := h.resolve(m.Table + "." + m.Key)
	return ok && v == m.Want
}

func (h homeState) pinned(full string) bool {
	_, src, ok := h.resolve(full)
	return ok && src.pin
}

// envOverrides are the environment variables that can switch a REQUIRED mitigation
// back on over the config files. Only a requirements pin beats them.
var envOverrides = map[string][]string{
	TraceTable + "." + TraceKey: {"GROK_TELEMETRY_TRACE_UPLOAD", "GROK_TELEMETRY_ENABLED"},
}

// envNoted are variables reported for context. They either only turn things off
// (DISABLE_*), touch recommended settings rather than required ones, or are the
// GROK_CONFIG overlay, whose allowlist cannot reach a required setting.
var envNoted = []string{
	"DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "GROK_ERROR_REPORTING", "GROK_CONFIG", "GROK_CONFIG_PATH",
}

// Destination is a configured place Grok sends session traces to.
type Destination struct {
	Name   string // "endpoints.trace_upload_bucket", or "env:GROK_TELEMETRY_GCS_BUCKET"
	Path   string // the file it was read from; empty for the environment
	Target string // the destination, credentials and query stripped
	Bucket string // "gs://name/" or "s3://name/" when the destination is a bucket
}

// destinationKeys are the [endpoints] keys that redirect trace uploads.
var destinationKeys = []string{"trace_upload_bucket", "trace_upload_url", "trace_upload_endpoint_url"}

// destinationEnv maps each environment variable to whether it names a bucket.
var destinationEnv = []struct {
	name   string
	bucket bool
}{
	{"GROK_TRACE_UPLOAD_BUCKET", true},
	{"GROK_TELEMETRY_GCS_BUCKET", true},
	{"GROK_TRACE_UPLOAD_URL", false},
	{"GROK_TRACE_UPLOAD_ENDPOINT_URL", false},
}

// Destinations returns every configured trace-upload destination across the grok
// homes' config layers and the environment. The logs and queue detectors use the
// buckets as extra markers: a redirected upload never names xAI's bucket.
func Destinations(env *engine.Env) []Destination {
	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}
	var out []Destination
	seen := map[string]bool{}
	add := func(d Destination) {
		k := d.Name + "|" + d.Path + "|" + d.Target
		if d.Target == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, d)
	}
	for _, h := range homes {
		hs := loadHome(h, nil)
		for _, k := range destinationKeys {
			full := "endpoints." + k
			if v, src, ok := hs.resolveString(full); ok {
				d := Destination{Name: full, Path: src.path, Target: sanitizeTarget(v)}
				if k == "trace_upload_bucket" {
					d.Bucket = bucketMarker(v)
				}
				add(d)
			}
		}
	}
	for _, e := range destinationEnv {
		v := strings.TrimSpace(env.LookupEnv(e.name))
		if v == "" {
			continue
		}
		d := Destination{Name: "env:" + e.name, Target: sanitizeTarget(v)}
		if e.bucket {
			if !strings.Contains(v, "://") {
				v = "gs://" + v // GROK_TELEMETRY_GCS_BUCKET replaces a gs:// bucket
			}
			d.Bucket = bucketMarker(v)
		}
		add(d)
	}
	return out
}

// UploadBuckets returns the configured buckets as markers ("gs://name/"), minus
// xAI's own, which every detector already searches for.
func UploadBuckets(env *engine.Env) []string {
	var out []string
	seen := map[string]bool{scan.BucketURL(): true}
	for _, d := range Destinations(env) {
		if d.Bucket != "" && !seen[d.Bucket] {
			seen[d.Bucket] = true
			out = append(out, d.Bucket)
		}
	}
	sort.Strings(out)
	return out
}

// bucketMarker reduces "gs://bucket/prefix" to "gs://bucket/". The trailing slash is
// deliberate: it is how an object path names the bucket, and it stops a short bucket
// name from matching as the prefix of an unrelated one.
func bucketMarker(v string) string {
	v = strings.TrimSpace(v)
	for _, scheme := range []string{"gs://", "s3://"} {
		if !strings.HasPrefix(strings.ToLower(v), scheme) {
			continue
		}
		name := strings.Trim(v[len(scheme):], "/ ")
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[:i]
		}
		if name == "" {
			return ""
		}
		return scheme + name + "/"
	}
	return ""
}

// sanitizeTarget keeps a destination's location and drops anything that could carry
// a credential: userinfo, query string and fragment. A URL is a location; a token in
// one is not, and grokpatrol never prints a credential value.
func sanitizeTarget(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexAny(v, "?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "://"); i >= 0 {
		rest := v[i+3:]
		host := rest
		if j := strings.IndexByte(rest, '/'); j >= 0 {
			host = rest[:j]
		}
		if at := strings.LastIndexByte(host, '@'); at >= 0 {
			v = v[:i+3] + rest[at+1:]
		}
	}
	return v
}
