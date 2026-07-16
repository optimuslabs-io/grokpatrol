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

	if n := strings.Count(out, "config.toml  EXPOSED"); n != 1 {
		t.Errorf("want exactly one config.toml row, got %d:\n%s", n, out)
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

// Two genuinely distinct config.toml files (two grok homes) still get a row each -- the
// dedupe is per file, not a blanket collapse.
func TestConfigRowKeepsDistinctFiles(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Findings: []model.Finding{
			cfgFinding("config.not_mitigated", "telemetry.trace_upload", "~/.grok/config.toml"),
			cfgFinding("config.not_mitigated", "telemetry.trace_upload", "~/work/.grok/config.toml"),
		},
	}
	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	if n := strings.Count(buf.String(), "config.toml  EXPOSED"); n != 2 {
		t.Errorf("two distinct config files should give two rows, got %d:\n%s", n, buf.String())
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
