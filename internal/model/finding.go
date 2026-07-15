package model

import "encoding/json"

type Severity int

const (
	SevInfo     Severity = iota // context, not a problem
	SevLow                      // hygiene / weak signal
	SevMedium                   // grok present and unmitigated: exposed, no proof of upload
	SevHigh                     // strong IoC: populated upload_queue, marker in binary, an archive collected/enqueued/staged
	SevCritical                 // proof of upload: a delivery to xAI was confirmed, or an upload event we cannot classify
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

	// PathEntry is set only on the ONE discovered install the grok command resolves to
	// on this host's $PATH -- the file that runs when the user types `grok`. It holds
	// that $PATH location (e.g. /usr/local/bin/grok), which differs from Path when the
	// entry is a symlink into a bundle. Empty on every other binary. Like Path it is a
	// LOCATION, display-processed home-relative, and carries no file contents.
	PathEntry string `json:"path_entry,omitempty"`
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

// IsExfil reports whether this finding is evidence that collection, staging, or
// upload of a repository happened, as opposed to mere exposure. It is tag-based
// rather than severity-based, and it is what separates EXPOSED from a merely
// present-but-idle grok. It does NOT by itself drive COMPROMISED -- see IsUpload:
// a queued archive is collection, not proof the bytes left the machine.
func (f Finding) IsExfil() bool {
	for _, t := range f.Tags {
		if t == TagExfil {
			return true
		}
	}
	return false
}

// IsUpload reports whether this finding is evidence that a repository was actually
// UPLOADED -- bytes confirmed delivered to xAI, or an upload event the tool cannot
// classify (read as a delivery, failing safe). It drives the COMPROMISED verdict,
// so it is deliberately tag-based and strictly narrower than IsExfil: collection
// and queueing are exposure; only a proven (or unclassifiable) delivery is
// COMPROMISED. Grok emits no upload-completion event today, so on the current
// schema this is reachable only via the schema-drift findings -- which is the
// point: COMPROMISED asserts the code left the machine, and nothing weaker does.
func (f Finding) IsUpload() bool {
	for _, t := range f.Tags {
		if t == TagUpload {
			return true
		}
	}
	return false
}

const (
	TagExfil   = "exfil"  // collection/queueing/staging happened -> EXPOSED
	TagUpload  = "upload" // a delivery was confirmed or is the safe reading -> COMPROMISED
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
