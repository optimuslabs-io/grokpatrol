package engine

import (
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Env is the immutable input handed to every detector.
type Env struct {
	Home     string
	GrokHome string

	// The filesystem walk is not optional. It used to be (--quick skipped it), but a
	// scan that does not look at the disk cannot see a grok binary, a staged archive,
	// or a second .grok home outside the configured one -- and it reported CLEAN just
	// as confidently as a scan that did. A fast answer to "were my repositories
	// uploaded" that is allowed to miss the evidence is not worth having.
	ScanRoots []string
	// ConfineWalk restricts the filesystem walk to exactly ScanRoots (plus the grok
	// home), skipping the default home and system-bin roots. Production never sets
	// it: a real scan MUST cover /usr/local/bin and the home tree, because that is
	// where an install actually lands, and --scan-root is documented as an
	// *additional* root, not a replacement. It exists for tests, whose fixtures are
	// self-contained: without it every engine test also walks the host's system dirs
	// (8 GB of /opt/hostedtoolcache on a CI runner), adding minutes under -race for
	// coverage the fixture does not need.
	ConfineWalk     bool
	FollowSymlinks  bool
	CrossFilesystem bool
	Concurrency     int
	MaxFileSize     int64

	UseGit        bool
	HistoryScope  string // "head" | "all" | "none"
	MaxGitObjects int
	GitTimeout    time.Duration

	ExtraRepos []string // --repo, forced into triage even if the logs never mention them
	// SeedRepos are the repositories the log ledger implicated. The engine fills
	// this between phases, which is why secrets runs last.
	SeedRepos []string

	// Discovered is filled by the deepscan phase and read by every later phase.
	// It is the reason the phases are ordered rather than fully parallel: a stray
	// .grok found under ~/work has logs and a config of its own, and those must be
	// parsed too. Assuming ~/.grok is the only grok home is a false negative.
	Discovered Discovered
}

// BinaryHit is a file containing at least one marker string.
//
// Kind matters: a file with real executable magic that names the bucket is the
// collector. A text file that names the bucket might be a researcher's notes, an
// IoC list, or another detection tool -- reporting those as a Grok install is a
// false positive that trains people to ignore the tool. See deepscan's findings.
type BinaryHit struct {
	Path       string
	SizeBytes  int64
	SHA256     string
	Kind       string // "elf" | "mach-o" | "pe" | "script"
	Executable bool   // true when the file has genuine executable magic
	Markers    []MarkerHit
}

type MarkerHit struct {
	Marker string
	Offset int64
}

type ArchiveFile struct {
	Path      string
	SizeBytes int64
	SHA256    string
}

// BundleMinBytes is the size above which a marker-carrying script counts as a
// packed program rather than a text file that merely mentions the indicators.
// Grok may ship as a Bun/Node bundle with no executable magic, so scripts cannot
// be ignored outright -- but a real packed CLI is tens of megabytes, while notes,
// an IoC list, or a detection tool's own source are kilobytes.
const BundleMinBytes = 512 << 10

// IsInstall reports whether this hit is plausibly the Grok program itself.
func (b BinaryHit) IsInstall() bool { return b.Executable || b.SizeBytes >= BundleMinBytes }

type Discovered struct {
	GrokHomes     []string // the configured grok home, plus every stray .grok found on disk
	UploadQueues  []string
	MetadataFiles []string
	Archives      []ArchiveFile
	Binaries      []BinaryHit
	// RepoHints are repo paths recovered from staged metadata.json files. A repo can
	// be sitting in the upload queue while its log lines have already rotated away.
	RepoHints []string
}

// Installs returns only the marker-carrying files that are plausibly the Grok
// program, filtering out text files that merely mention the indicator strings.
// Treating a researcher's notes as an install is a false positive that teaches
// people to ignore the tool.
func (d Discovered) Installs() []BinaryHit {
	var out []BinaryHit
	for _, b := range d.Binaries {
		if b.IsInstall() {
			out = append(out, b)
		}
	}
	return out
}

// Result is what a detector returns. Errors are non-fatal by construction: a
// detector reports what it could not do and the engine degrades the verdict,
// rather than failing the run.
type Result struct {
	Findings    []model.Finding
	Repos       []model.RepoStatus
	Versions    []model.VersionEvidence
	Errors      []model.ScanError
	Limitations []string

	// Summary is the one line the progress display prints when this detector
	// finishes: what it found, in the detector's own words. It is for the human
	// watching the scan and never reaches the report -- say "nothing" out loud
	// rather than leaving it blank, because a detector that prints nothing is
	// indistinguishable from one that silently died.
	Summary string

	Discovered *Discovered // deepscan only
	RepoHints  []string    // queue only
}
