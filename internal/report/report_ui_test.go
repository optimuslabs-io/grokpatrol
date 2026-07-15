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

	if !strings.Contains(def, "examples:") {
		t.Fatal("the default secrets section shows no examples block")
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
	// The example risk phrase is deliberately DISTINCT from the count line's phrase, so
	// the two can never be confused. The count line keeps "...the checkout...".
	if !strings.Contains(def, "deleted from checkout, still in history") {
		t.Error("the deleted example is not flagged as the priority class")
	}
}

// Change D: the default report leads with a concrete noun tally, not severity buckets.
func TestFoundTallyLeadsWithNouns(t *testing.T) {
	def := renderStyle(compromised(), Style{})
	if !strings.Contains(def, "Found:") {
		t.Error("the default report does not lead with a concrete 'found' tally")
	}
	// These contiguous phrases are unique to the tally (the headline says
	// "repository collected" / "archive built and queued", not these).
	for _, phrase := range []string{"repo collected", "archive queued", "secret exposed"} {
		if !strings.Contains(def, phrase) {
			t.Errorf("the found tally is missing %q", phrase)
		}
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
