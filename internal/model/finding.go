package model

import "encoding/json"

type Severity int

const (
	SevInfo     Severity = iota // context, not a problem
	SevLow                      // hygiene / weak signal
	SevMedium                   // grok present and unmitigated: exposed, no proof of upload
	SevHigh                     // strong IoC: populated upload_queue, marker in binary, collection events
	SevCritical                 // proof of exfiltration: an archive was enqueued for a real repo
)

var sevNames = map[Severity]string{
	SevInfo:     "info",
	SevLow:      "low",
	SevMedium:   "medium",
	SevHigh:     "high",
	SevCritical: "critical",
}

func (s Severity) String() string {
	if n, ok := sevNames[s]; ok {
		return n
	}
	return "unknown"
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity maps a name to a Severity. Reports ok=false on an unknown name
// so --fail-on can reject a typo rather than silently defaulting to a threshold
// the user did not intend.
func ParseSeverity(name string) (Severity, bool) {
	for s, n := range sevNames {
		if n == name {
			return s, true
		}
	}
	return SevInfo, false
}

// Evidence points at what was found. It has no field capable of carrying file
// contents, and that is the point: this type is the structural guarantee that
// grokpatrol cannot print a secret. Adding an Excerpt/Content/Match field would
// break invariant 4 — locations are reported, values never are.
//
// Every field below is a LOCATION, a HASH, or tool-authored prose. That is the
// test a new field has to pass. "The log line said X" fails it; "the log line was
// at unified.jsonl:27" passes.
type Evidence struct {
	Path      string `json:"path"`                 // display-processed (home-relative)
	Locator   string `json:"locator,omitempty"`    // "line:412", "offset:0x1a4f", "blob:4f2a1c9", a gs:// path
	Note      string `json:"note,omitempty"`       // tool-authored prose, never file-derived
	SHA256    string `json:"sha256,omitempty"`     // only for matched binaries and archives
	SizeBytes int64  `json:"size_bytes,omitempty"` // metadata only; contents are never read

	// Source and SourceLine cite the artifact this evidence was READ FROM: the log
	// file and line number that carried the event. They answer "how do you know?",
	// which is the whole reason a reader believes a verdict they cannot reproduce.
	//
	// The line NUMBER is evidence. The line's TEXT is not, and must never be put
	// here -- that is exactly the excerpt field this type refuses to have.
	Source     string `json:"source,omitempty"` // display-processed, like Path
	SourceLine int    `json:"source_line,omitempty"`
}

type Finding struct {
	ID          string     `json:"id"` // stable slug, e.g. "logs.archive_enqueued"
	Detector    string     `json:"detector"`
	Severity    Severity   `json:"severity"`
	Title       string     `json:"title"`
	Detail      string     `json:"detail"`
	Remediation string     `json:"remediation,omitempty"`
	Tags        []string   `json:"tags,omitempty"` // "exfil", "config", "staging"
	Evidence    []Evidence `json:"evidence,omitempty"`
}

// IsExfil reports whether this finding is evidence that collection or upload
// actually happened, as opposed to mere exposure. It drives the COMPROMISED
// verdict, so it is deliberately tag-based rather than severity-based: a High
// config finding is not proof of exfiltration.
func (f Finding) IsExfil() bool {
	for _, t := range f.Tags {
		if t == TagExfil {
			return true
		}
	}
	return false
}

const (
	TagExfil   = "exfil"
	TagStaging = "staging"
	TagConfig  = "config"
	TagInstall = "install"
	TagSecret  = "secret"
	TagSchema  = "schema-drift"
)

// ScanError is a non-fatal failure.
//
// A MATERIAL error is one that could have hidden an indicator: a directory we
// could not enter, a log we could not parse, a repository whose history we could
// not read. Material errors set Report.Degraded, which forbids a CLEAN verdict --
// a scanner that was blocked from half the disk must never tell you it found nothing.
//
// An immaterial error provably could not have hidden anything -- macOS TCC denying
// a read on a .plist, say. Those are still reported, but they do not degrade the
// verdict. If they did, every Mac would return INDETERMINATE forever, and a CLEAN
// result that nobody can ever reach is a result nobody will believe.
type ScanError struct {
	Detector string `json:"detector"`
	Kind     string `json:"kind"` // "permission", "parse", "timeout", "panic", "io"
	Path     string `json:"path,omitempty"`
	Message  string `json:"message"`
	Material bool   `json:"material"`
}
