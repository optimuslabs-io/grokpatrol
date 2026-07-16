package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func cfgFinding(id, key, path string) model.Finding {
	return model.Finding{
		ID: id, Detector: "config", Severity: model.SevMedium,
		Evidence: []model.Evidence{{Path: path, Locator: key}},
	}
}

// countConfigRows counts INSTALLATION config.toml status rows (not ACTION prose that
// also mentions config.toml).
func countConfigRows(out string) int {
	n := 0
	for _, line := range strings.Split(out, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "config.toml") && (strings.Contains(line, "EXPOSED") || strings.Contains(line, "MITIGATED")) {
			n++
		}
	}
	return n
}

// The config detector emits one finding PER mitigation, so a config with neither set
// produced two identical "the upload mitigations are not both set" rows. There must now
// be ONE config.toml row, and it must name the specific mitigations rather than repeat a
// vague phrase.
func TestConfigRowDedupesAndNamesMitigations(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{
			cfgFinding("config.not_mitigated", "harness.disable_codebase_upload", "~/.grok/config.toml"),
			cfgFinding("config.not_mitigated", "telemetry.trace_upload", "~/.grok/config.toml"),
		},
	}
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if n := countConfigRows(out); n != 1 {
		t.Errorf("want exactly one config.toml row, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "~/.grok/config.toml") {
		t.Errorf("config.toml row must show the path; got:\n%s", out)
	}
	if !strings.Contains(out, "EXPOSED") {
		t.Errorf("want EXPOSED config state; got:\n%s", out)
	}
	if strings.Contains(out, "not both set") {
		t.Errorf("the vague phrase must give way to named mitigations; got:\n%s", out)
	}
	for _, want := range []string{"harness.disable_codebase_upload", "telemetry.trace_upload"} {
		if !strings.Contains(out, want) {
			t.Errorf("row must name mitigation %q; got:\n%s", want, out)
		}
	}
}

// A wrong value and a missing key are different faults and must both be named, in one row.
func TestConfigRowDistinguishesWrongFromMissing(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{
			cfgFinding("config.explicitly_disabled", "telemetry.trace_upload", "~/.grok/config.toml"),
			cfgFinding("config.not_mitigated", "harness.disable_codebase_upload", "~/.grok/config.toml"),
		},
	}
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if !strings.Contains(out, "telemetry.trace_upload set to the wrong value") {
		t.Errorf("wrong-value mitigation must be called out; got:\n%s", out)
	}
	if !strings.Contains(out, "harness.disable_codebase_upload not set") {
		t.Errorf("missing mitigation must be called out; got:\n%s", out)
	}
}

// Two genuinely distinct config.toml files (two grok homes): the default report shows
// the active home only (with its path) plus an "also checked" pointer; --verbose lists
// both. Leaving both as unlabeled config.toml rows made the difference imperceptible.
func TestConfigRowKeepsDistinctFiles(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Host:    model.HostInfo{GrokHome: "~/.grok"},
		Findings: []model.Finding{
			cfgFinding("config.not_mitigated", "telemetry.trace_upload", "~/.grok/config.toml"),
			cfgFinding("config.not_mitigated", "telemetry.trace_upload", "~/work/.grok/config.toml"),
		},
	}
	def := renderStyle(rep, Style{})
	if n := countConfigRows(def); n != 1 {
		t.Errorf("default: want one config.toml row (active home), got %d:\n%s", n, def)
	}
	if !strings.Contains(def, "~/.grok/config.toml") {
		t.Errorf("default: active config path must be visible; got:\n%s", def)
	}
	if strings.Contains(def, "~/work/.grok/config.toml") {
		t.Errorf("default: secondary home must not get a full config.toml row; got:\n%s", def)
	}
	if !strings.Contains(def, "also checked") || !strings.Contains(def, "--verbose") {
		t.Errorf("default: must point at the other home via --verbose; got:\n%s", def)
	}

	verb := renderStyle(rep, Style{Verbose: true})
	if n := countConfigRows(verb); n != 2 {
		t.Errorf("--verbose: both config files should get a row, got %d:\n%s", n, verb)
	}
	for _, want := range []string{"~/.grok/config.toml", "~/work/.grok/config.toml"} {
		if !strings.Contains(verb, want) {
			t.Errorf("--verbose missing %q; got:\n%s", want, verb)
		}
	}
}

// The default config.toml row includes the path so two homes never look identical, and
// prefers the .grok home of the $PATH binary when one is known.
func TestConfigRowPrefersPathBinaryHome(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{
			{
				ID: "deepscan.binary_marker", Detector: "deepscan", Severity: model.SevHigh,
				Evidence: []model.Evidence{{
					Path: "~/.grok/downloads/grok", PathEntry: "~/.grok/bin/grok",
				}},
			},
			cfgFinding("config.absent", "", "~/.grok/config.toml"),
			cfgFinding("config.unparseable", "", "~/work/.grok/config.toml"),
		},
	}
	out := renderStyle(rep, Style{})
	if !strings.Contains(out, "~/.grok/config.toml") {
		t.Errorf("PATH binary's home config must be the default row; got:\n%s", out)
	}
	if strings.Contains(out, "UNCONFIRMED") {
		t.Errorf("secondary unparseable home must not dominate the default row; got:\n%s", out)
	}
}

// Every config.toml row states matter in terms of "mitigation(s)" without saying what
// they are; each one must point at the MITIGATIONS lookup table with "(see below)", and
// that table must actually appear below it, short and naming both settings.
func TestConfigRowPointsAtMitigationsSection(t *testing.T) {
	cases := []struct {
		name     string
		findings []model.Finding
	}{
		{"not mitigated", []model.Finding{cfgFinding("config.not_mitigated", "harness.disable_codebase_upload", "~/.grok/config.toml")}},
		{"mitigated", []model.Finding{cfgFinding("config.mitigated", "", "~/.grok/config.toml")}},
		{"absent", []model.Finding{cfgFinding("config.absent", "", "~/.grok/config.toml")}},
		{"unparseable", []model.Finding{cfgFinding("config.unparseable", "", "~/.grok/config.toml")}},
		{"explicitly disabled", []model.Finding{cfgFinding("config.explicitly_disabled", "telemetry.trace_upload", "~/.grok/config.toml")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := &model.Report{Verdict: model.VerdictExposed, Findings: tc.findings}
			var buf bytes.Buffer
			Human(&buf, rep, Style{})
			out := buf.String()

			if !strings.Contains(out, "(see below)") {
				t.Errorf("config.toml row must say (see below); got:\n%s", out)
			}
			if !strings.Contains(out, "MITIGATIONS") {
				t.Errorf("MITIGATIONS section must be printed; got:\n%s", out)
			}
			// LastIndex, not Index: an unmitigated host also prints an ACTION banner
			// above INSTALLATION that names "MITIGATIONS" by name in its own short
			// pointer ("... both required; see MITIGATIONS)"). That earlier mention is
			// not the section itself -- the section header is always the LAST occurrence.
			seeBelowAt := strings.Index(out, "(see below)")
			sectionAt := strings.LastIndex(out, "MITIGATIONS")
			if sectionAt < seeBelowAt {
				t.Errorf("MITIGATIONS section must render AFTER the row pointing at it; got:\n%s", out)
			}
		})
	}
}

// The section is a two-line lookup, not remediation prose: both settings, named exactly.
func TestMitigationsSectionIsShortAndNamesBothSettings(t *testing.T) {
	rep := &model.Report{
		Verdict:  model.VerdictExposed,
		Findings: []model.Finding{cfgFinding("config.not_mitigated", "harness.disable_codebase_upload", "~/.grok/config.toml")},
	}
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	// LastIndex: an unmitigated host's ACTION banner names "MITIGATIONS" by name
	// before the section itself ever prints; the section header is the LAST occurrence.
	start := strings.LastIndex(out, "MITIGATIONS")
	if start < 0 {
		t.Fatalf("MITIGATIONS section missing; got:\n%s", out)
	}
	section := out[start:]
	if end := strings.Index(section, "\n\n"); end > 0 {
		section = section[:end]
	}
	if n := strings.Count(section, "\n"); n > 3 {
		t.Errorf("MITIGATIONS section should be very short (header + 2 lines), got %d lines:\n%s", n, section)
	}
	for _, want := range []string{"harness", "disable_codebase_upload", "true", "telemetry", "trace_upload", "false"} {
		if !strings.Contains(section, want) {
			t.Errorf("MITIGATIONS section must contain %q; got:\n%s", want, section)
		}
	}
}

// A host with no config finding at all (no grok, or grok present but never reached the
// config detector) must not print an orphaned MITIGATIONS section that nothing pointed at.
func TestMitigationsSectionAbsentWithoutConfigFinding(t *testing.T) {
	rep := &model.Report{Verdict: model.VerdictClean}
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	if strings.Contains(buf.String(), "MITIGATIONS") {
		t.Errorf("MITIGATIONS section must not print when nothing referenced it; got:\n%s", buf.String())
	}
}
