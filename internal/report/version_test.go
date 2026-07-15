package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func render(t *testing.T, rep *model.Report) string {
	t.Helper()
	var b bytes.Buffer
	Human(&b, rep, Style{})
	return b.String()
}

func reportWith(verdict model.Verdict, vs ...model.VersionEvidence) *model.Report {
	return &model.Report{
		Verdict:  verdict,
		Versions: vs,
		Counts:   map[string]int{},
		Findings: []model.Finding{{
			ID: "config.absent", Detector: "config", Severity: model.SevMedium,
			Tags: []string{model.TagConfig}, Title: "No Grok config.toml",
		}},
	}
}

// The affected build must sit ABOVE the tables, not inside one. It used to render as
// a single row in INSTALLATION, in the same weight as the config.toml row beside it --
// and 0.2.93 is the build that was publicly reproduced uploading whole repositories,
// which is not a detail of the installation. A reader who skims the tables must not be
// able to skim past it.
func TestConfirmedAffectedIsHoistedAboveInstallation(t *testing.T) {
	out := render(t, reportWith(model.VerdictCompromised,
		model.VersionEvidence{Version: "0.2.93", Source: "logs", Confidence: "high",
			Class: model.VersionConfirmedAffected}))

	banner := strings.Index(out, "CONFIRMED AFFECTED")
	install := strings.Index(out, "INSTALLATION")
	if banner < 0 {
		t.Fatalf("the confirmed-affected build is not called out at all:\n%s", out)
	}
	if install >= 0 && banner > install {
		t.Errorf("CONFIRMED AFFECTED renders below INSTALLATION -- it is still buried in a table")
	}
	if !strings.Contains(out, "0.2.93") {
		t.Error("the banner does not name the version")
	}
}

// Printed on EXPOSED too, and that is the point. A host running the confirmed-affected
// build with no upload evidence YET is the one state where the user can still act;
// gating the warning on COMPROMISED would hide it from exactly the reader it could
// still help.
func TestAffectedBannerPrintsOnEveryVerdict(t *testing.T) {
	for _, v := range []model.Verdict{
		model.VerdictExposed, model.VerdictCompromised,
		model.VerdictIndeterminate, model.VerdictClean,
	} {
		out := render(t, reportWith(v,
			model.VersionEvidence{Version: "0.2.93", Source: "logs", Confidence: "high",
				Class: model.VersionConfirmedAffected}))
		if !strings.Contains(out, "CONFIRMED AFFECTED") {
			t.Errorf("verdict %s: the affected build was not called out", v)
		}
	}
}

// A packed CLI carries dozens of unrelated dependency semvers in its string table, so
// a version scraped out of a binary is low-confidence by construction. Shouting the
// loudest claim in the report on the strength of a coincidence would be the tool
// inventing evidence.
func TestLowConfidenceVersionNeverShouts(t *testing.T) {
	out := render(t, reportWith(model.VerdictExposed,
		model.VersionEvidence{Version: "0.2.93", Source: "binary-strings", Confidence: "low",
			Class: model.VersionConfirmedAffected}))
	if strings.Contains(out, "CONFIRMED AFFECTED") {
		t.Error("a semver scraped from a binary's string table was promoted to the banner")
	}
}

// REPORTED is not CONFIRMED, and the report must not blur them: one was reproduced,
// the other was only reported and this tool has not verified it.
func TestReportedAffectedIsNotClaimedAsConfirmed(t *testing.T) {
	out := render(t, reportWith(model.VerdictExposed,
		model.VersionEvidence{Version: "0.2.97", Source: "logs", Confidence: "high",
			Class: model.VersionReportedAffected}))
	if strings.Contains(out, "CONFIRMED AFFECTED") {
		t.Error("a merely REPORTED-affected build was announced as CONFIRMED")
	}
	if !strings.Contains(out, "REPORTED AFFECTED") {
		t.Errorf("the reported-affected build was not called out at all:\n%s", out)
	}
}

// No affected build, no banner. The loudest line in the report has to stay rare, or it
// stops being read.
func TestNoAffectedVersionNoBanner(t *testing.T) {
	out := render(t, reportWith(model.VerdictClean,
		model.VersionEvidence{Version: "9.9.9", Source: "logs", Confidence: "high",
			Class: model.VersionUnknown}))
	if strings.Contains(out, "AFFECTED") {
		t.Errorf("a version outside the known-bad range was announced as affected:\n%s", out)
	}
}
