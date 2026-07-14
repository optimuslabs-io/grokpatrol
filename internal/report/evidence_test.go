package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/optimuslabs/grokpatrol/internal/model"
)

func turn(n int64) *int64 { return &n }

// compromised is the shape of a real positive result: an archive queued for a
// repository, the log line that says so, and a secret that is gone from the
// checkout but was still in the uploaded object set.
func compromised() *model.Report {
	return &model.Report{
		Verdict: model.VerdictCompromised,
		Repos: []model.RepoStatus{{
			RepoPath:        "~/work/payments-api",
			Status:          model.StatusQueued,
			OnDisk:          true,
			IsGitRepo:       true,
			CollectAttempts: 2,
			Sessions:        []string{"sess-a1"},
			FirstSeen:       time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC),
			LastSeen:        time.Date(2026, 7, 11, 9, 0, 0, 0, time.UTC),
			HistoryObjects:  12431,
			SecretsScanned:  true,
			Archives: []model.Archive{{
				Phase:      "before",
				GCSPath:    "gs://bucket/sess-a1/3/before_codebase.tar.gz",
				SID:        "sess-a1",
				TurnNumber: turn(3),
				Timestamp:  time.Date(2026, 6, 30, 10, 0, 5, 0, time.UTC),
				LogFile:    "~/.grok/logs/unified.jsonl",
				LogLine:    27,
			}},
			SecretFiles: []model.SecretHit{{
				Path:                ".env.production",
				Class:               "dotenv",
				Blob:                "4f2a1c9deadbeef0000000000000000000000000",
				InHistory:           true,
				DeletedFromCheckout: true,
			}},
		}},
	}
}

// The gs:// destination is the single most important string in the report -- the
// model calls it the smoking gun -- and the terminal used to collapse it to a digit
// in an ARCHIVES column. Being told two archives were queued, without being told
// where they went, is being told you were robbed without being shown the receipt.
func TestLedgerPrintsTheDestinationAndItsWitness(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, compromised(), Style{})
	out := buf.String()

	if !strings.Contains(out, "gs://bucket/sess-a1/3/before_codebase.tar.gz") {
		t.Error("the gs:// destination is missing: the report asserts an upload without showing where it went")
	}
	// The witness. Grok's own log is the evidence, and a reader who cannot go and
	// look at the line is being asked to take the ledger on faith.
	if !strings.Contains(out, "~/.grok/logs/unified.jsonl:27") {
		t.Error("the log file and line behind the archive are missing; the claim cannot be checked by hand")
	}
	if !strings.Contains(out, "session sess-a1") || !strings.Contains(out, "turn 3") {
		t.Error("the session and turn that built the archive are missing")
	}
	// One date reads like one event. This repo was being collected for a fortnight.
	if !strings.Contains(out, "2026-06-30 -> 2026-07-11") {
		t.Error("the collection window is missing: a reader who sees only the last date cannot tell a fortnight from a moment")
	}
}

// The blob id is what lets the USER verify a claim grokpatrol structurally cannot:
// `git cat-file -p <blob>` shows them the secret this tool refuses to read. It came
// free from rev-list, which the parser had been splitting and discarding.
func TestSecretsPrintTheBlobAndHowToVerifyIt(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, compromised(), Style{})
	out := buf.String()

	if !strings.Contains(out, "blob 4f2a1c9deadb") {
		t.Error("the git object id is missing: the user cannot verify that the deleted secret was really in the uploaded set")
	}
	if !strings.Contains(out, "cat-file -p") {
		t.Error("the report does not tell the user how to check the blob it just handed them")
	}
	if !strings.Contains(out, "12431 git objects") {
		t.Error("the size of the uploaded object set is missing")
	}
}

// The report must keep pointing at locations, never at values. This is invariant 4
// and it is the reason model.Evidence has no excerpt field: a forensic tool that
// prints the secret it found has become the leak it was hunting.
func TestReportNeverPrintsASecretValue(t *testing.T) {
	rep := compromised()
	// A value that would only ever appear if something read the file's contents.
	const secretValue = "postgres://user:hunter2@prod/db"

	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	if strings.Contains(buf.String(), secretValue) {
		t.Fatal("a secret VALUE reached the report")
	}
	// The location, by contrast, is the entire deliverable.
	if !strings.Contains(buf.String(), ".env.production") {
		t.Error("the secret's filename is missing: a rotation checklist you cannot locate is useless")
	}
}

// The renderer picks findings by hardcoded ID, so any finding nobody listed printed
// NOTHING in the terminal while --json carried it in full. logs.raw_bucket_reference
// is the case that matters: it is CRITICAL, it is tagged exfil, and it fires exactly
// when Grok's log schema has drifted and no upload event could be parsed -- so the
// ledger is empty and this is the ONLY evidence there is. The terminal printed a
// COMPROMISED banner over an empty report.
func TestUnrecognizedFindingIsStillPrinted(t *testing.T) {
	// The evidence is built exactly as logs.handleLine builds it -- Path plus a
	// "line:N" Locator, and no Source -- so this test fails if the renderer only
	// happens to work for the Source/SourceLine shape.
	rep := &model.Report{
		Verdict: model.VerdictCompromised,
		Findings: []model.Finding{{
			ID:       "logs.raw_bucket_reference",
			Detector: "logs",
			Severity: model.SevCritical,
			Tags:     []string{model.TagExfil, model.TagSchema},
			Title:    "3 log lines reference the exfiltration bucket, but no upload event could be parsed",
			Detail:   "The log schema has probably changed. Treat these lines as evidence of upload.",
			Evidence: []model.Evidence{{
				Path:    "~/.grok/logs/unified.jsonl",
				Locator: "line:412",
				Note:    "log line references the exfiltration bucket",
			}},
		}},
	}

	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	out := buf.String()

	if !strings.Contains(out, "no upload event could be parsed") {
		t.Fatal("a CRITICAL exfil finding was invisible in the terminal: the schema-drift hole is open again")
	}
	if !strings.Contains(out, "CRITICAL") {
		t.Error("the severity of an uncurated finding is not shown")
	}
	if !strings.Contains(out, "~/.grok/logs/unified.jsonl") || !strings.Contains(out, "line:412") {
		t.Error("the log line behind the finding is missing: the reader cannot go and look at the evidence")
	}
}

// The other provenance shape: an event whose detector recorded Source/SourceLine
// rather than a Locator. Both must render, because the two are built by different
// code paths in the same package.
func TestSourceCitationRenders(t *testing.T) {
	rep := &model.Report{
		Verdict: model.VerdictCompromised,
		Findings: []model.Finding{{
			ID:       "logs.unknown_upload_event",
			Detector: "logs",
			Severity: model.SevHigh,
			Tags:     []string{model.TagExfil, model.TagSchema},
			Title:    "Unrecognized repo_state.upload events found in the logs",
			Evidence: []model.Evidence{{
				Path:       "~/work/api",
				Source:     "~/.grok/logs/unified.jsonl",
				SourceLine: 9,
				Note:       "unrecognized upload event",
			}},
		}},
	}

	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	if !strings.Contains(buf.String(), "~/.grok/logs/unified.jsonl:9") {
		t.Error("a finding citing Source/SourceLine did not print its citation")
	}
}

// A finding a curated section already renders must not also appear in the catch-all.
// Printing the rotation list twice would teach the reader to skim it.
func TestCuratedFindingsAreNotPrintedTwice(t *testing.T) {
	rep := compromised()
	rep.Findings = []model.Finding{{
		ID:       "secrets.deleted_from_checkout",
		Detector: "secrets",
		Severity: model.SevCritical,
		Title:    "1 secret files are gone from the checkout but were still in the uploaded git history",
	}}

	var buf bytes.Buffer
	Human(&buf, rep, Style{})
	if strings.Contains(buf.String(), "OTHER FINDINGS") {
		t.Error("a finding the secrets section already renders was repeated in the catch-all")
	}
}
