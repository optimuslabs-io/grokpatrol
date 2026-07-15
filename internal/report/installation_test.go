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

// The config detector evaluates each of the two upload mitigations independently, so a
// host with NEITHER set legitimately emits two config.not_mitigated findings -- one per
// missing key, each with its own Title for --json and remediation. Both render to the
// identical INSTALLATION row, and the renderer must print that state ONCE. A second copy
// carries no information (the row already says "not both set") and reads like the tool
// double-counting -- which is exactly what showed up on the demo host.
func TestNeitherMitigationSetPrintsOneConfigRow(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{
			{
				ID: "config.not_mitigated", Detector: "config", Severity: model.SevMedium,
				Title: "disable_codebase_upload = true is not set under [harness]",
			},
			{
				ID: "config.not_mitigated", Detector: "config", Severity: model.SevMedium,
				Title: "trace_upload = false is not set under [telemetry]",
			},
		},
	}

	out := renderStyle(rep, Style{})
	if n := strings.Count(out, "the upload mitigations are not both set"); n != 1 {
		t.Fatalf("config.toml EXPOSED row printed %d times, want exactly 1:\n%s", n, out)
	}
}

// Deduping is on the RENDERED row, not the finding ID: two grok homes in genuinely
// different config states must both appear, because each row tells the reader something
// the other does not. Collapsing distinct states would hide a home that needs attention.
func TestDistinctConfigStatesBothPrint(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{
			{ID: "config.absent", Detector: "config", Severity: model.SevMedium, Title: "No Grok config.toml under ~/.grok"},
			{ID: "config.unparseable", Detector: "config", Severity: model.SevMedium, Title: "config.toml uses constructs this scanner does not model"},
		},
	}

	out := renderStyle(rep, Style{})
	if !strings.Contains(out, configState("config.absent")) {
		t.Errorf("the absent-config state row is missing:\n%s", out)
	}
	if !strings.Contains(out, configState("config.unparseable")) {
		t.Errorf("the unparseable-config state row is missing:\n%s", out)
	}
}
