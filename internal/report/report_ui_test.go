package report

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Change A: the default secrets section names a few example files by name + risk
// class, deleted-first and diversified by class, and points at --verbose for the
// rest -- without printing a value or a blob id.
func TestSecretsShowExamplesInDefault(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Repos: []model.RepoStatus{{
			RepoPath:       "~/work/api",
			Status:         model.StatusQueued,
			SecretsScanned: true,
			SecretFiles: []model.SecretHit{
				{Path: ".env.production", Class: "dotenv", Blob: "aaaa1111bbbb2222", InHistory: true, DeletedFromCheckout: true},
				{Path: "id_rsa", Class: "private-key", Blob: "cccc3333dddd4444", InHistory: true, DeletedFromCheckout: true},
				{Path: "terraform.tfstate", Class: "iac-secret", Blob: "eeee5555ffff6666", InHistory: true},
				{Path: ".npmrc", Class: "package-registry", Blob: "9999888877776666", InHistory: true},
			},
		}},
	}

	def := renderStyle(rep, Style{})

	if !strings.Contains(def, "PATH") || !strings.Contains(def, "CLASS") || !strings.Contains(def, "RISK") {
		t.Fatal("the default credential examples table is missing column headers")
	}
	if !strings.Contains(def, ".env.production") || !strings.Contains(def, "[dotenv]") {
		t.Error("the default report does not name an example secret with its risk class")
	}
	// Diversified: the second and third examples are different classes, not more dotenvs.
	if !strings.Contains(def, "[private-key]") || !strings.Contains(def, "[iac-secret]") {
		t.Error("the examples are not diversified by risk class")
	}
	// Four secrets, three shown -> a pointer to the withheld one.
	if !strings.Contains(def, "... and 1 more (--verbose)") {
		t.Error("the examples block does not point at the withheld rows")
	}
	// A blob id never appears in the default examples -- it is a --verbose receipt.
	if strings.Contains(def, "aaaa1111bbbb") {
		t.Error("a blob id leaked into the default examples")
	}
	// The example RISK phrase names the priority class; DELETED is a count column.
	if !strings.Contains(def, "deleted from checkout, still in history") {
		t.Error("the deleted example is not flagged as the priority class")
	}
}

// Deleted-from-checkout hits must sort first across ALL repos, not just within each.
// A repo of in-HEAD-only secrets listed before a repo with deleted ones must not crowd
// the deleted ones out of the sample -- they are the whole reason the examples exist.
func TestSecretExamplesPrioritizeDeletedAcrossRepos(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictExposed,
		Repos: []model.RepoStatus{
			{
				RepoPath: "~/work/clean-ish", // listed FIRST, all in-HEAD
				Status:   model.StatusCollectedOnly,
				SecretFiles: []model.SecretHit{
					{Path: "config/app.env", Class: "dotenv", InHistory: true},
					{Path: "deploy/service-account.json", Class: "cloud-credential", InHistory: true},
					{Path: "infra/terraform.tfvars", Class: "iac-secret", InHistory: true},
				},
			},
			{
				RepoPath: "~/work/payments", // listed SECOND, has the deleted ones
				Status:   model.StatusQueued,
				SecretFiles: []model.SecretHit{
					{Path: ".env.production", Class: "dotenv", Blob: "dead", InHistory: true, DeletedFromCheckout: true},
					{Path: "id_rsa", Class: "private-key", Blob: "beef", InHistory: true, DeletedFromCheckout: true},
				},
			},
		},
	}

	def := renderStyle(rep, Style{})
	if !strings.Contains(def, ".env.production") || !strings.Contains(def, "id_rsa") {
		t.Error("deleted-from-checkout secrets were crowded out of the examples by an earlier in-HEAD repo")
	}
	if !strings.Contains(def, "deleted from checkout, still in history") {
		t.Error("the priority (deleted) class is not surfaced in the examples")
	}
}

// Change D: the default report leads with a concrete noun tally under VERDICT.
func TestFoundTallyLeadsWithNouns(t *testing.T) {
	rep := compromised()
	rep.Verdict = model.VerdictExposed // queued (not confirmed exfil) → telegraph facts
	def := renderStyle(rep, Style{})
	if !strings.Contains(def, "Repos") || !strings.Contains(def, "touched") {
		t.Error("the default report does not lead with a concrete Repos tally")
	}
	for _, phrase := range []string{"repo touched", "archive", "credential path"} {
		if !strings.Contains(def, phrase) {
			t.Errorf("the repos tally is missing %q", phrase)
		}
	}
	if !strings.Contains(def, "Queued") || !strings.Contains(def, "Exfiltrated") {
		t.Error("the telegraph facts (Queued / Exfiltrated) are missing")
	}
	if strings.Contains(def, "Delivery is UNCONFIRMED") || strings.Contains(def, "CONFIRMED DELIVERED") {
		t.Error("legacy logistics essay leaked into the human report")
	}
}

func TestToolFooterIsAbsoluteBottom(t *testing.T) {
	rep := compromised()
	rep.Tool = model.ToolInfo{Name: "grokpatrol", Version: "9.9.9"}
	rep.Host = model.HostInfo{GOOS: "darwin", GOARCH: "arm64"}
	rep.Duration = "1.2s"

	wantFooter := "grokpatrol 9.9.9  (darwin/arm64)  scanned in 1.2s"
	for _, s := range []Style{{}, {Quiet: true}} {
		out := renderStyle(rep, s)
		if !strings.HasPrefix(strings.TrimLeft(out, "\n"), "VERDICT:") {
			t.Errorf("Style%+v: report does not lead with VERDICT", s)
		}
		if !strings.HasSuffix(strings.TrimSpace(out), wantFooter) {
			t.Errorf("Style%+v: tool/duration is not the absolute last line", s)
		}
	}
}

func TestActionBannerRotateAndMitigate(t *testing.T) {
	rep := compromised()
	rep.Verdict = model.VerdictExposed
	rep.Findings = append(rep.Findings, model.Finding{
		ID: "config.not_mitigated", Detector: "config", Severity: model.SevHigh,
		Title: "config.toml does not disable codebase upload",
	})
	out := renderStyle(rep, Style{})
	if !strings.Contains(out, "ACTION") {
		t.Fatal("ACTION block missing")
	}
	if !strings.Contains(out, "Rotate credentials") {
		t.Error("ACTION missing rotate")
	}
	if !strings.Contains(out, "Mitigate uploads") || !strings.Contains(out, "disable_codebase_upload") || !strings.Contains(out, "trace_upload = false") {
		t.Error("default ACTION should name both mitigation knobs")
	}
	// The default ACTION block itself must not inline full TOML -- but the MITIGATIONS
	// lookup table it points to DOES print "[harness]" further down (unconditionally,
	// in both modes), so the check is scoped to the ACTION block, not the whole report.
	actionBlock, _, _ := strings.Cut(out[strings.Index(out, "ACTION"):], "\n\n")
	if strings.Contains(actionBlock, "[harness]") {
		t.Errorf("default ACTION must not inline full TOML; got:\n%s", actionBlock)
	}
	verb := renderStyle(rep, Style{Verbose: true})
	verbActionBlock, _, _ := strings.Cut(verb[strings.Index(verb, "ACTION"):], "\n\n")
	if !strings.Contains(verbActionBlock, "[harness]") || !strings.Contains(verbActionBlock, "trace_upload = false") {
		t.Error("--verbose ACTION should expand the TOML knobs")
	}
}

// Change C: a many-repo ledger is capped in the default report, with a pointer to the
// withheld repositories; --verbose lists every one. The collection window survives.
func TestLedgerTableIsCappedInDefault(t *testing.T) {
	rep := &model.Report{Verdict: model.VerdictExposed}
	for i := 0; i < 15; i++ {
		rep.Repos = append(rep.Repos, model.RepoStatus{
			RepoPath:  fmt.Sprintf("~/work/repo-%02d", i),
			Status:    model.StatusQueued,
			FirstSeen: time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
			LastSeen:  time.Date(2026, 7, 11, 0, 0, 0, 0, time.UTC),
			Archives:  []model.Archive{{GCSPath: fmt.Sprintf("gs://b/%02d/before_codebase.tar.gz", i)}},
		})
	}

	def := renderStyle(rep, Style{})
	// Only maxLedgerRepos rows print, plus a pointer to the rest.
	if got := strings.Count(def, "~/work/repo-"); got != maxLedgerRepos {
		t.Errorf("default ledger printed %d repo rows, want %d", got, maxLedgerRepos)
	}
	want := fmt.Sprintf("... and %d more repositories", 15-maxLedgerRepos)
	if !strings.Contains(def, want) {
		t.Errorf("the capped ledger does not name the withheld repositories; want %q", want)
	}
	if !strings.Contains(def, "2026-06-30 -> 2026-07-11") {
		t.Error("the collection window vanished under the ledger cap")
	}

	// --verbose lists every repository, uncapped.
	verb := renderStyle(rep, Style{Verbose: true})
	if strings.Contains(verb, "more repositories") {
		t.Error("--verbose should list every repository, not cap them")
	}
	if !strings.Contains(verb, "~/work/repo-14") {
		t.Error("--verbose is missing a repository the default capped away")
	}
}

// Change C: the default report carries the archive counts in the ledger table's
// ARCHIVES cell, so the separate "ARCHIVES QUEUED FOR UPLOAD" block is gone by
// default and present under --verbose (where it lists every gs:// object).
func TestArchivesQueuedBlockIsVerboseOnly(t *testing.T) {
	if strings.Contains(renderStyle(compromised(), Style{}), "ARCHIVES QUEUED FOR UPLOAD") {
		t.Error("the default report still prints the separate ARCHIVES QUEUED block; it was consolidated into the table")
	}
	verb := renderStyle(compromised(), Style{Verbose: true})
	if !strings.Contains(verb, "ARCHIVES QUEUED FOR UPLOAD") {
		t.Error("--verbose dropped the full gs:// archive list")
	}
	if !strings.Contains(verb, "gs://bucket/sess-a1/3/before_codebase.tar.gz") {
		t.Error("--verbose is missing the gs:// object it promises")
	}
}
