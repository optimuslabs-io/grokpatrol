package logs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func findingByID(res engine.Result, id string) *model.Finding {
	for i := range res.Findings {
		if res.Findings[i].ID == id {
			return &res.Findings[i]
		}
	}
	return nil
}

// The veto event used to fall through to kindUnknownUpload: High, tagged upload, and
// therefore COMPROMISED -- the kill switch working was read as proof of exfiltration.
// It must now be context only, even when the line names xAI's bucket.
func TestUploadSkipIsNotAnUpload(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"event":"repo_state.upload.skip","sid":"s9","ctx":{"turn_number":1,"repo_path":"/work/api","reason":"disabled"},"gcs_path":"gs://grok-code-session-traces/s9/before_codebase.tar.gz"}`,
		),
	})
	res := run(t, home)

	for _, f := range res.Findings {
		if f.IsUpload() || f.Severity >= model.SevMedium {
			t.Errorf("a veto event produced %s (%v, tags %v); it must not move the verdict", f.ID, f.Severity, f.Tags)
		}
	}
	if findingByID(res, "logs.unknown_upload_event") != nil {
		t.Error("the veto was filed as an unrecognised upload event")
	}
	if findingByID(res, "logs.raw_bucket_reference") != nil {
		t.Error("the veto line's bucket name tripped the raw-reference net")
	}
	if len(res.Repos) != 0 {
		t.Errorf("a veto alone put a repository in the ledger: %+v", res.Repos)
	}
	f := findingByID(res, "logs.upload_skipped")
	if f == nil {
		t.Fatal("the veto was not reported at all")
	}
	if f.Severity != model.SevInfo || len(f.Tags) != 0 {
		t.Errorf("logs.upload_skipped must be untagged info, got %v %v", f.Severity, f.Tags)
	}
}

// Conservative in the other direction too: a skip never softens what else the log
// shows. A turn that was collected and enqueued is still QUEUED, skip or no skip.
func TestUploadSkipDoesNotSoftenAnEnqueue(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"event":"repo_state.upload.start","sid":"s1","ctx":{"turn_number":1,"repo_path":"/work/api"}}`,
			`{"event":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":1},"gcs_path":"gs://grok-code-session-traces/s1/turn_1/before_codebase.tar.gz"}`,
			`{"event":"repo_state.upload.skip","sid":"s1","ctx":{"turn_number":2}}`,
		),
	})
	res := run(t, home)
	r := findRepo(res, "api")
	if r == nil || r.Status != model.StatusQueued {
		t.Fatalf("an enqueue next to a skip must stay QUEUED, got %+v", r)
	}
	if findingByID(res, "logs.archive_enqueued") == nil {
		t.Error("logs.archive_enqueued disappeared because a skip was logged")
	}
}

// A redirected upload never names xAI's bucket, so the configured bucket is a marker
// too. A reference is exposure (High, exfil), not proof of an upload to xAI.
func TestConfiguredBucketIsSearched(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"kind":"renamed.event","target":"gs://acme-traces/team-a/s1/turn_1/x.tar"}`,
			`{"kind":"other","target":"gs://acme-traces-other/x"}`,
		),
	})
	cfg := "[endpoints]\ntrace_upload_bucket = \"gs://acme-traces/team-a\"\n"
	if err := os.WriteFile(filepath.Join(home, ".grok", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	res := run(t, home)

	f := findingByID(res, "logs.configured_bucket_reference")
	if f == nil {
		t.Fatalf("the configured bucket was not searched for: %+v", res.Findings)
	}
	if len(f.Evidence) != 1 {
		t.Errorf("want exactly the one line naming gs://acme-traces/, got %+v", f.Evidence)
	}
	if f.Severity != model.SevHigh || f.IsUpload() {
		t.Errorf("configured bucket reference must be High exfil, never upload: %v %v", f.Severity, f.Tags)
	}
	if findingByID(res, "logs.raw_bucket_reference") != nil {
		t.Error("a configured-bucket line was read as xAI's bucket")
	}
}

// Without a configured bucket nothing extra is searched for.
func TestNoConfiguredBucketNoExtraFinding(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(`{"kind":"other","target":"gs://acme-traces/x"}`),
	})
	if f := findingByID(run(t, home), "logs.configured_bucket_reference"); f != nil {
		t.Errorf("unexpected configured-bucket finding with no config: %+v", f)
	}
}
