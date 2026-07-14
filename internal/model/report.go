package model

import "time"

// Verdict is the headline. Exit codes are derived from it.
type Verdict string

const (
	VerdictClean         Verdict = "CLEAN"         // no grok artifacts, and the scan was not degraded
	VerdictIndeterminate Verdict = "INDETERMINATE" // no findings, but we could not see everything
	VerdictExposed       Verdict = "EXPOSED"       // grok present and unmitigated, no evidence of upload
	VerdictCompromised   Verdict = "COMPROMISED"   // evidence of collection or upload
)

// ExitCode is the scripting contract. Note that findings never produce exit 1;
// that code is reserved for a failure of the tool itself, so a caller can always
// distinguish "grokpatrol broke" from "grokpatrol found something".
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictClean:
		return 0
	case VerdictIndeterminate:
		return 2
	case VerdictExposed:
		return 3
	case VerdictCompromised:
		return 4
	}
	return 1
}

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
}

type Report struct {
	Schema    string    `json:"schema"`
	Tool      ToolInfo  `json:"tool"`
	Host      HostInfo  `json:"host"`
	Options   Options   `json:"options"`
	StartedAt time.Time `json:"started_at"`
	Duration  string    `json:"duration"`

	Verdict  Verdict           `json:"verdict"`
	Counts   map[string]int    `json:"counts"` // by severity name
	Findings []Finding         `json:"findings"`
	Repos    []RepoStatus      `json:"repos"`
	Versions []VersionEvidence `json:"versions"`

	Errors   []ScanError `json:"errors"`
	Degraded bool        `json:"degraded"`
	// Limitations is populated on EVERY run, including a clean one. Nobody should
	// read "CLEAN" without also reading what this tool structurally cannot see.
	Limitations []string `json:"limitations"`
}

// MaxSeverity returns the highest severity among findings, and whether any exist.
func (r *Report) MaxSeverity() (Severity, bool) {
	max, any := SevInfo, false
	for _, f := range r.Findings {
		if !any || f.Severity > max {
			max, any = f.Severity, true
		}
	}
	return max, any
}
