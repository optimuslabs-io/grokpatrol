package model

import "time"

// Verdict is the headline, carried in the report body and --json. It does NOT drive
// the process exit code: the exit code answers only "did grokpatrol run", never "what
// did it find" -- see ExitToolError. A caller that needs the verdict reads the report.
type Verdict string

const (
	VerdictClean         Verdict = "CLEAN"         // no grok artifacts, and the scan was not degraded
	VerdictIndeterminate Verdict = "INDETERMINATE" // no findings, but we could not see everything
	VerdictExposed       Verdict = "EXPOSED"       // grok present/unmitigated and/or repos collected or queued, no evidence of upload
	VerdictCompromised   Verdict = "COMPROMISED"   // evidence of upload: a delivery confirmed, or an unclassifiable upload event
)

// ExitToolError is the only non-zero process exit code grokpatrol produces: bad flags
// or an internal failure. A completed scan -- whatever its verdict -- exits 0; the exit
// code cannot tell a caller what was found, only whether the tool ran. See main.run().
const ExitToolError = 1

const SchemaVersion = "grokpatrol/v1"

type ToolInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuiltAt   string `json:"built_at"`
	GoVersion string `json:"go_version"`
}

type HostInfo struct {
	GOOS         string   `json:"goos"`
	GOARCH       string   `json:"goarch"`
	Home         string   `json:"home"`
	GrokHome     string   `json:"grok_home"`
	ScannedRoots []string `json:"scanned_roots"`
}

// Options records the effective flags so a report is reproducible from itself.
//
// There is no DeepScan option any more: the filesystem walk is not optional. A scan
// that skips it cannot see a grok binary, a staged archive, or a second .grok home,
// and it used to report CLEAN with exactly the same confidence as one that looked.
type Options struct {
	HistoryScope string `json:"history_scope"`
	UseGit       bool   `json:"use_git"`
	Concurrency  int    `json:"concurrency"`
	MaxFileSize  int64  `json:"max_file_size"`
	// FullSecretsSearch records whether file CONTENTS were scanned for secrets
	// (--full-secrets-search). The report layer keys its honesty on this: the
	// "contents were never read" claim is true only when it is false.
	FullSecretsSearch bool  `json:"full_secrets_search"`
	MaxBlobScanBytes  int64 `json:"max_blob_scan_bytes,omitempty"`
	// CheckExposure records whether this run made network requests to the grok.me
	// apps it found (--check-exposure, grokpatrol-online build only). False in every
	// standard build, which cannot make a network call at all.
	CheckExposure bool `json:"check_exposure"`
	// Discover, GrokSearch and AppHosts record which public sources this run used
	// for grok.me names (grokpatrol-online build only), and with which org
	// identifiers. API keys are never recorded.
	Discover   bool `json:"discover"`
	GrokSearch bool `json:"grok_search"`
	AppHosts   bool `json:"app_hosts"`
	// ScanPublic records whether public apps' pages and same-host scripts were
	// fetched and scanned in memory for secrets (--scan-public), and
	// ScanKeywordMatches whether that included apps tied to the org only by a
	// keyword or a search result.
	ScanPublic         bool     `json:"scan_public"`
	ScanKeywordMatches bool     `json:"scan_keyword_matches"`
	OrgKeywords        []string `json:"org_keywords,omitempty"`
	OrgDomains         []string `json:"org_domains,omitempty"`
}

type Report struct {
	Schema    string    `json:"schema"`
	Tool      ToolInfo  `json:"tool"`
	Host      HostInfo  `json:"host"`
	Options   Options   `json:"options"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`

	Verdict Verdict `json:"verdict"`
	// GrokPresent records whether any Grok Build artifact was actually found on this
	// host -- an install, an upload queue, a staged archive, a version, a config, or an
	// implicated repository. It is deliberately independent of the verdict: an
	// INDETERMINATE (or CLEAN) result is usually "no grok, but the disk could not be
	// fully read", yet grok can be PRESENT-but-mitigated too, and the report must never
	// tell a host that has grok on it that none was found.
	GrokPresent bool              `json:"grok_present"`
	Counts      map[string]int    `json:"counts"` // by severity name
	Findings    []Finding         `json:"findings"`
	Repos       []RepoStatus      `json:"repos"`
	Versions    []VersionEvidence `json:"versions"`
	// Apps are Grok Build app addresses (*.grok.me) seen on this host. They do not
	// feed the verdict: the verdict answers "were my repositories taken", and an app
	// address in browser history may belong to somebody else.
	Apps []PublishedApp `json:"published_apps"`

	Errors   []ScanError `json:"errors"`
	Degraded bool        `json:"degraded"`
	// Limitations is populated on EVERY run, including a clean one. Nobody should
	// read "CLEAN" without also reading what this tool structurally cannot see.
	Limitations []string `json:"limitations"`

	// AppLimitations are the caveats about grok.me apps and the public sources used
	// to find them, also present in Limitations. They are kept apart by ORIGIN, not
	// picked out by matching text, because --apps-only (what an agent reads) must
	// carry them and nothing else: a secrets limitation begins with a repository
	// path, and a path can contain any word a text filter would look for.
	AppLimitations []string `json:"-"`
}

// AddAppLimitations records caveats about apps or public sources in both lists.
func (r *Report) AddAppLimitations(ls ...string) {
	r.Limitations = append(r.Limitations, ls...)
	r.AppLimitations = append(r.AppLimitations, ls...)
}
