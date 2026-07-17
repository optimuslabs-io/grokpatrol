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

	Errors   []ScanError `json:"errors"`
	Degraded bool        `json:"degraded"`
	// Limitations is populated on EVERY run, including a clean one. Nobody should
	// read "CLEAN" without also reading what this tool structurally cannot see.
	Limitations []string `json:"limitations"`
}
