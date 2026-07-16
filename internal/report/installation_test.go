package report

import (
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// installed is an EXPOSED-shaped host: the grok binary on disk with a hash, an
// affected version read from a named log, config that does not mitigate, auth.json
// present, and other upload-related keys set. It carries exactly the INSTALLATION
// detail the default report is meant to summarize rather than dump.
func installed() *model.Report {
	return &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{
			{
				ID:       "deepscan.binary_marker",
				Detector: "deepscan",
				Severity: model.SevHigh,
				Evidence: []model.Evidence{{
					Path:      "~/.grok/bin/grok",
					SizeBytes: 91 << 20,
					Locator:   "offset:0x1a2b3c",
					SHA256:    "aaaa1111bbbb2222cccc3333dddd4444eeee5555ffff6666aaaa7777bbbb8888",
					Note:      "executable contains " + scan.MarkerBucket,
				}},
			},
			{ID: "config.not_mitigated", Detector: "config", Severity: model.SevHigh, Title: "config.toml does not disable codebase upload"},
			{ID: "config.auth_present", Detector: "config", Severity: model.SevInfo, Title: "auth.json is present"},
			{ID: "config.other_keys", Detector: "config", Severity: model.SevInfo, Title: "Other upload-related options are set: harness.experimental_flag"},
		},
		Versions: []model.VersionEvidence{{
			Version:    "0.2.51",
			Class:      model.VersionReportedAffected,
			Confidence: "high",
			Path:       "~/.grok/logs/unified.jsonl",
			Source:     "logs",
		}},
	}
}

// The default INSTALLATION is a summary. What locates the install (the binary path)
// and what drives the verdict (the config state) stay; the sha256, the per-version
// file, auth.json and the other-keys list are the receipt -- present under --verbose,
// withheld (but pointed at) by default.
func TestInstallationSummarizesByDefault(t *testing.T) {
	def := renderStyle(installed(), Style{})
	verb := renderStyle(installed(), Style{Verbose: true})

	if !strings.Contains(def, "~/.grok/bin/grok") {
		t.Error("the default report dropped the grok binary path -- the reader can no longer find the install")
	}
	if !strings.Contains(def, "EXPOSED") {
		t.Error("the default report dropped the config mitigation state, which on this host IS the verdict")
	}
	if !strings.Contains(def, "--verbose") {
		t.Error("the default INSTALLATION withholds detail without telling the reader how to see it")
	}

	// The receipt: withheld by default, present under --verbose.
	for _, receipt := range []string{"aaaa1111bbbb", "auth.json", "experimental_flag"} {
		if strings.Contains(def, receipt) {
			t.Errorf("the default report leaked receipt detail %q that belongs behind --verbose", receipt)
		}
		if !strings.Contains(verb, receipt) {
			t.Errorf("--verbose is missing %q, which the default report promised it would show", receipt)
		}
	}
}

// markerEv builds one deepscan.binary_marker evidence row: a binary at path, optionally
// the $PATH entry that resolves to it (empty when this binary is not the one on $PATH).
func markerEv(path, entry string) model.Evidence {
	return model.Evidence{
		Path:      path,
		PathEntry: entry,
		SizeBytes: 40 << 20,
		Locator:   "offset:0x1a4f",
		Note:      "contains marker " + scan.MarkerBucket,
	}
}

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

// When several grok binaries are on disk, the one that actually runs -- the install on
// $PATH -- must be surfaced first and clearly marked. The default report keeps only that
// row (extra copies collapse to "also on disk"); --verbose lists every path.
func TestInstallationHighlightsPathBinaryFirst(t *testing.T) {
	rep := binReport(
		markerEv("/home/u/copies/grok-old", ""),
		markerEv("/home/u/.grok/dist/cli.js", "/usr/local/bin/grok"), // the active one
		markerEv("/home/u/backup/grok", ""),
	)

	def := renderStyle(rep, Style{})
	if !strings.Contains(def, "/home/u/.grok/dist/cli.js") {
		t.Errorf("default must show the $PATH binary; got:\n%s", def)
	}
	if strings.Contains(def, "/home/u/copies/grok-old") || strings.Contains(def, "/home/u/backup/grok") {
		t.Errorf("default must not list secondary binaries in full; got:\n%s", def)
	}
	if !strings.Contains(def, "runs when you type") {
		t.Errorf("default: the active binary must be labelled as the one that runs; got:\n%s", def)
	}
	if !strings.Contains(def, "also on disk") || !strings.Contains(def, "2 other grok binaries") {
		t.Errorf("default must point at the other binaries via --verbose; got:\n%s", def)
	}

	verb := renderStyle(rep, Style{Verbose: true})
	active := strings.Index(verb, "/home/u/.grok/dist/cli.js")
	other := strings.Index(verb, "/home/u/copies/grok-old")
	if active < 0 || other < 0 {
		t.Fatalf("--verbose: both binaries should render; got:\n%s", verb)
	}
	if active > other {
		t.Errorf("--verbose: the $PATH binary must render before the others; got:\n%s", verb)
	}
	if !strings.Contains(verb, "runs when you type") {
		t.Errorf("--verbose: the active binary must be labelled as the one that runs; got:\n%s", verb)
	}
	if !strings.Contains(verb, "/usr/local/bin/grok") {
		t.Errorf("--verbose must show the $PATH entry location; got:\n%s", verb)
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

	for _, s := range []Style{{}, {Verbose: true}} {
		out := renderStyle(rep, s)
		if n := strings.Count(out, "/home/u/.grok/grok ("); n != 1 {
			t.Errorf("verbose=%v: binary should render once, rendered %d times; got:\n%s", s.Verbose, n, out)
		}
	}
}

// An install can be flagged on a marker OTHER than the bucket name (deepscan builds a
// hit on any DefaultMarkers match). It must still render -- and if it is the one on
// $PATH, the highlight must survive -- rather than being filtered out because its Note
// does not mention the bucket.
func TestInstallationRendersNonBucketMarkerInstall(t *testing.T) {
	e := markerEv("/usr/local/bin/grok", "/usr/local/bin/grok")
	e.Note = "contains marker " + scan.MarkerFlag // a real marker, but not the bucket
	rep := binReport(e)

	def := renderStyle(rep, Style{})
	if !strings.Contains(def, "/usr/local/bin/grok") {
		t.Errorf("a non-bucket-marker install must still render; got:\n%s", def)
	}
	if !strings.Contains(def, "runs when you type") {
		t.Errorf("the $PATH highlight must survive a non-bucket marker; got:\n%s", def)
	}

	verb := renderStyle(rep, Style{Verbose: true})
	if !strings.Contains(verb, scan.MarkerFlag) {
		t.Errorf("--verbose must report the marker actually found, not a hardcoded bucket; got:\n%s", verb)
	}
}

// A real binary directly on $PATH (not a symlink) is the active one, and --verbose says
// so without inventing a phantom symlink target.
func TestInstallationRealPathBinary(t *testing.T) {
	rep := binReport(markerEv("/usr/local/bin/grok", "/usr/local/bin/grok"))
	verb := renderStyle(rep, Style{Verbose: true})

	if !strings.Contains(verb, "on your $PATH") {
		t.Errorf("active binary must note it is on $PATH; got:\n%s", verb)
	}
	if strings.Contains(verb, "symlink to the file above") {
		t.Errorf("a non-symlinked $PATH binary must not claim to be a symlink; got:\n%s", verb)
	}
}
