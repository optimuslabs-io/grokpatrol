package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// binReport builds a report whose deepscan.binary_marker finding carries several
// installs, one of which is the grok on $PATH (PathEntry set). The bucket marker string
// must appear in each evidence Note, since that is how the renderer selects install rows.
func binReport(ev ...model.Evidence) *model.Report {
	return &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{{
			ID:       "deepscan.binary_marker",
			Detector: "deepscan",
			Severity: model.SevHigh,
			Title:    "executables contain the bucket name",
			Evidence: ev,
		}},
	}
}

func markerEv(path, entry string) model.Evidence {
	return model.Evidence{
		Path:      path,
		PathEntry: entry,
		SizeBytes: 40 << 20,
		Locator:   "offset:0x1a4f",
		Note:      "contains marker " + scan.MarkerBucket,
	}
}

// When several grok binaries are on disk, the one that actually runs -- the install on
// $PATH -- must be surfaced first and clearly marked. A user staring at three "grok
// binary" rows cannot otherwise tell which one executes.
func TestInstallationHighlightsPathBinaryFirst(t *testing.T) {
	rep := binReport(
		markerEv("/home/u/copies/grok-old", ""),
		markerEv("/home/u/.grok/dist/cli.js", "/usr/local/bin/grok"), // the active one
		markerEv("/home/u/backup/grok", ""),
	)
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	active := strings.Index(out, "/home/u/.grok/dist/cli.js")
	other := strings.Index(out, "/home/u/copies/grok-old")
	if active < 0 || other < 0 {
		t.Fatalf("both binaries should render; got:\n%s", out)
	}
	if active > other {
		t.Errorf("the $PATH binary must render before the others; got:\n%s", out)
	}
	if !strings.Contains(out, "runs when you type") {
		t.Errorf("the active binary must be labelled as the one that runs; got:\n%s", out)
	}
	// A symlinked $PATH entry (cli.js bundle) must show the command location too, not just
	// the resolved file.
	if !strings.Contains(out, "/usr/local/bin/grok") {
		t.Errorf("the $PATH entry location must be shown; got:\n%s", out)
	}
}

// The evidence is emitted once per marker OFFSET; a single binary carrying the bucket
// name at several offsets must still render as ONE row, or the count of installs reads
// as inflated.
func TestInstallationDedupesPerBinary(t *testing.T) {
	one := markerEv("/home/u/.grok/grok", "/home/u/.grok/grok")
	two := one
	two.Locator = "offset:0x2b00" // same file, second marker offset
	rep := binReport(one, two)

	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if n := strings.Count(out, "/home/u/.grok/grok ("); n != 1 {
		t.Errorf("binary should render once, rendered %d times; got:\n%s", n, out)
	}
}

// An install can be flagged on a marker OTHER than the bucket name (deepscan builds a
// hit on any DefaultMarkers match). It must still render in INSTALLATION -- and if it is
// the one on $PATH, the highlight must survive -- rather than being filtered out because
// its Note does not mention the bucket. This is the drop the bucket-only filter caused.
func TestInstallationRendersNonBucketMarkerInstall(t *testing.T) {
	e := markerEv("/usr/local/bin/grok", "/usr/local/bin/grok")
	e.Note = "contains marker " + scan.MarkerFlag // a real marker, but not the bucket
	rep := binReport(e)

	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if !strings.Contains(out, "/usr/local/bin/grok") {
		t.Errorf("a non-bucket-marker install must still render; got:\n%s", out)
	}
	if !strings.Contains(out, "runs when you type") {
		t.Errorf("the $PATH highlight must survive a non-bucket marker; got:\n%s", out)
	}
	if !strings.Contains(out, scan.MarkerFlag) {
		t.Errorf("the row must report the marker actually found, not a hardcoded bucket; got:\n%s", out)
	}
}

// A real binary directly on $PATH (not a symlink) is the active one, and its row says so
// without inventing a phantom symlink target.
func TestInstallationRealPathBinary(t *testing.T) {
	rep := binReport(markerEv("/usr/local/bin/grok", "/usr/local/bin/grok"))
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if !strings.Contains(out, "on your $PATH") {
		t.Errorf("active binary must note it is on $PATH; got:\n%s", out)
	}
	if strings.Contains(out, "symlink to the file above") {
		t.Errorf("a non-symlinked $PATH binary must not claim to be a symlink; got:\n%s", out)
	}
}
