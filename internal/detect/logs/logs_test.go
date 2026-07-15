package logs

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// grokHome builds a fake ~/.grok/logs containing the given files. Fixtures are
// generated, never committed: a repo full of files carrying a live malware IoC
// string trips corporate EDR, which is a real practical problem for anyone who
// clones this.
func grokHome(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".grok", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if strings.HasSuffix(name, ".gz") {
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			zw := gzip.NewWriter(f)
			if _, err := zw.Write([]byte(content)); err != nil {
				t.Fatal(err)
			}
			zw.Close()
			f.Close()
			continue
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

func run(t *testing.T, home string) engine.Result {
	t.Helper()
	env := &engine.Env{Home: home, GrokHome: filepath.Join(home, ".grok")}
	res, err := New().Run(context.Background(), env)
	if err != nil {
		t.Fatalf("Run returned a fatal error, which it never should: %v", err)
	}
	return res
}

func findRepo(res engine.Result, substr string) *model.RepoStatus {
	for i := range res.Repos {
		if strings.Contains(res.Repos[i].RepoPath, substr) {
			return &res.Repos[i]
		}
	}
	return nil
}

func hasFinding(res engine.Result, id string) bool {
	for _, f := range res.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

// A .gz log the tool cannot decompress must DEGRADE the scan, not pass silently.
//
// gzip.NewReader failing means zero bytes were read from that file -- strictly worse
// than a truncated-but-readable log. If the failure is not material, Report.Degraded
// stays false and a host whose only evidence sat in a corrupt (or misnamed-plaintext)
// rotated log comes back CLEAN. This is the worst failure the tool can have, so the
// error must be marked material.
func TestUnreadableGzipDegradesTheScan(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".grok", "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A .gz that is not valid gzip: plaintext someone renamed, or a header-truncated
	// archive. gzip.NewReader rejects it before a single byte is read.
	if err := os.WriteFile(filepath.Join(dir, "unified.jsonl.1.gz"), []byte("this is not gzip\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	res := run(t, home)

	var material *model.ScanError
	for i := range res.Errors {
		if strings.HasSuffix(res.Errors[i].Path, "unified.jsonl.1.gz") && res.Errors[i].Material {
			material = &res.Errors[i]
			break
		}
	}
	if material == nil {
		t.Fatalf("the unreadable .gz produced no MATERIAL error, so the scan would not degrade "+
			"and a host with only this (unreadable) evidence would report CLEAN; errors=%+v", res.Errors)
	}
}

// The single most important correctness test in the package.
//
// A start event and its enqueue routinely land in DIFFERENT files, because the
// log rotated between them. Correlating per-file would report this repo as
// COLLECTED-ONLY when an archive was in fact queued -- a false negative on the
// most severe status the tool can assign.
func TestCorrelationAcrossRotatedFiles(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl.1": line(`{"event":"repo_state.upload.start","sid":"s1","ctx":{"turn_number":3,"repo_path":"/work/payments-api"},"ts":"2026-06-30T10:00:00Z"}`),
		"unified.jsonl": line(
			`{"event":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":3},"gcs_path":"gs://grok-code-session-traces/s1/3/before_codebase.tar.gz","ts":"2026-06-30T10:00:05Z"}`,
			`{"event":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":3},"gcs_path":"gs://grok-code-session-traces/s1/3/after_codebase.tar.gz","ts":"2026-06-30T10:02:00Z"}`,
		),
	})

	res := run(t, home)

	r := findRepo(res, "payments-api")
	if r == nil {
		t.Fatal("payments-api missing from the ledger entirely")
	}
	if r.Status != model.StatusQueued {
		t.Errorf("status = %q, want %q -- the enqueue in the rotated sibling file was not correlated",
			r.Status, model.StatusQueued)
	}
	if len(r.Archives) != 2 {
		t.Fatalf("archives = %d, want 2", len(r.Archives))
	}
	phases := map[string]bool{}
	for _, a := range r.Archives {
		phases[a.Phase] = true
	}
	if !phases["before"] || !phases["after"] {
		t.Errorf("phases = %v, want both before and after", phases)
	}
	if !hasFinding(res, "logs.archive_enqueued") {
		t.Error("no archive_enqueued finding was raised")
	}
}

// A gzipped rotated log is still a log.
func TestGzippedRotation(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl.2.gz": line(`{"event":"repo_state.upload.start","sid":"s9","ctx":{"turn_number":1,"repo_path":"/work/old-repo"},"ts":"2026-05-01T00:00:00Z"}`),
	})
	res := run(t, home)
	if r := findRepo(res, "old-repo"); r == nil || r.Status != model.StatusCollectedOnly {
		t.Fatalf("gzipped log was not read; repos=%+v", res.Repos)
	}
}

// Collection with no enqueue is COLLECTED-ONLY -- reported, not dismissed.
func TestCollectedOnly(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"event":"repo_state.upload.start","sid":"s2","ctx":{"turn_number":1,"repo_path":"/work/scratch"},"ts":"2026-06-12T09:00:00Z"}`,
			`{"event":"some.other.event","sid":"s2"}`,
		),
	})
	res := run(t, home)
	r := findRepo(res, "scratch")
	if r == nil || r.Status != model.StatusCollectedOnly {
		t.Fatalf("want collected_only, got %+v", r)
	}
	if r.CollectAttempts != 1 {
		t.Errorf("attempts = %d, want 1", r.CollectAttempts)
	}
	if !hasFinding(res, "logs.collected_only") {
		t.Error("collected_only finding missing")
	}
}

// An enqueue whose start event rotated away must still be reported. An
// unattributable archive upload is still an archive upload.
func TestOrphanEnqueueIsNeverDropped(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(`{"event":"repo_state.upload.enqueued","sid":"gone","ctx":{"turn_number":7},"gcs_path":"gs://grok-code-session-traces/gone/7/after_codebase.tar.gz"}`),
	})
	res := run(t, home)
	r := findRepo(res, model.UnknownRepo)
	if r == nil {
		t.Fatal("orphan enqueue was dropped -- it must surface as an unattributed upload")
	}
	if r.Status != model.StatusQueued {
		t.Errorf("status = %q, want queued", r.Status)
	}
	if !hasFinding(res, "logs.archive_enqueued") {
		t.Error("orphan enqueue did not raise an archive_enqueued finding")
	}
}

// If xAI renames every field, the structured parse yields nothing -- and the raw
// substring net is the only thing standing between a compromised host and a
// "clean" report.
func TestSchemaDriftSafetyNet(t *testing.T) {
	home := grokHome(t, map[string]string{
		// Completely unrecognized shape: no known event key, no known field names.
		"unified.jsonl": line(`{"kind":"totally.renamed","blob_target":"gs://grok-code-session-traces/x/before_codebase.tar.gz"}`),
	})
	res := run(t, home)
	if len(res.Repos) != 0 {
		t.Fatalf("structured parse should have found nothing here, got %+v", res.Repos)
	}
	if !hasFinding(res, "logs.raw_bucket_reference") {
		t.Fatal("raw-substring safety net did not fire -- a renamed schema would silently report CLEAN")
	}
}

// An upload event with a suffix we do not know is treated as an upload, not ignored.
func TestUnknownUploadEventCountsAsUpload(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"event":"repo_state.upload.start","sid":"s3","ctx":{"turn_number":1,"repo_path":"/work/api"}}`,
			`{"event":"repo_state.upload.completed_v2","sid":"s3","ctx":{"turn_number":1},"gcs_path":"gs://x/after_codebase.tar.gz"}`,
		),
	})
	res := run(t, home)
	r := findRepo(res, "api")
	if r == nil || r.Status != model.StatusQueued {
		t.Fatalf("an unrecognized upload event must escalate to QUEUED, got %+v", r)
	}
	if !hasFinding(res, "logs.unknown_upload_event") {
		t.Error("schema-drift finding missing")
	}
}

// The torture file. Every line here is something a real log could contain and a
// naive parser would die on. The contract: extract everything recoverable, record
// the rest as errors, never panic, never return early.
func TestHostileLinesNeverAbortTheRun(t *testing.T) {
	hostile := strings.Join([]string{
		``,
		`   `,
		`{`,                  // truncated JSON
		`[1,2,3]`,            // valid JSON, but an array
		`null`,               // valid JSON, but not an object
		`{"no":"event key"}`, // object with nothing we recognize
		`not json at all`,    //
		`{"event":"repo_state.upload.start","sid":"h1","ctx":{"turn_number":"3","repo_path":"/work/stringturn"}}`,                          // turn as a string
		`{"event":"repo_state.upload.start","sid":"h2","ctx":{"turn_number":4.0,"repo_path":"/work/floatturn"}}`,                           // turn as a float
		`{"event":"repo_state.upload.start","sid":"h3","repo_path":"/work/noctx"}`,                                                         // no ctx wrapper
		`{"event":"repo_state.upload.enqueued","sid":"h3","gcs_path":"gs://grok-code-session-traces/h3/before_codebase.tar.gz?sig=abc"}`,   // query string on the path
		`{"event":"repo_state.upload.enqueued","sid":"h4","gcs_path":"gs://grok-code-session-traces/h4/mystery.tar.gz"}`,                   // unrecognized basename
		"{\"event\":\"repo_state.upload.start\",\"sid\":\"h5\",\"ctx\":{\"repo_path\":\"/work/crlf\"}}\r",                                  // CRLF
		`{"event":"repo_state.upload.start","sid":"h6","ctx":{"repo_path":"/work/bigline"},"junk":"` + strings.Repeat("A", 200_000) + `"}`, // a very long line
		`{"event":"repo_state.upload.start","sid":"h7","ctx":{"repo_path":"/work/nofinalnewline"}}`,                                        // no trailing newline
	}, "\n")

	home := grokHome(t, map[string]string{"unified.jsonl": hostile})
	res := run(t, home) // a panic here fails the test by definition

	for _, want := range []string{"stringturn", "floatturn", "noctx", "crlf", "bigline", "nofinalnewline"} {
		if findRepo(res, want) == nil {
			t.Errorf("recoverable event for %q was lost among the malformed lines", want)
		}
	}
	if r := findRepo(res, "noctx"); r == nil || r.Status != model.StatusQueued {
		t.Errorf("h3's enqueue (query string on gcs_path) did not correlate to its start: %+v", r)
	}
	if len(res.Errors) == 0 {
		t.Error("malformed lines were silently ignored; they must be reported as parse errors")
	}
}

func TestPhaseOf(t *testing.T) {
	cases := map[string]string{
		"gs://grok-code-session-traces/s/1/before_codebase.tar.gz":      "before",
		"gs://grok-code-session-traces/s/1/after_codebase.tar.gz":       "after",
		"gs://grok-code-session-traces/s/1/after_codebase.tar.gz?sig=x": "after",
		"gs://grok-code-session-traces/s/1/before_codebase.tar.gz/":     "before",
		`gs:\\bucket\s\before_codebase.tar.gz`:                          "before",
		"gs://grok-code-session-traces/s/1/something_else.tar.gz":       "unknown",
		"": "unknown",
	}
	for in, want := range cases {
		if got := phaseOf(in); got != want {
			t.Errorf("phaseOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// The parser must not panic on arbitrary bytes. A crash on a weird log line is a
// crash that reports nothing, which reads as "clean".
func FuzzParseLine(f *testing.F) {
	f.Add([]byte(`{"event":"repo_state.upload.start","sid":"s","ctx":{"turn_number":1}}`))
	f.Add([]byte(`{"ctx":`))
	f.Add([]byte("\x00\xff\xfe"))
	f.Add([]byte(`{"event":{"nested":"object"}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, ok := parseLine(b)
		if !ok {
			return
		}
		e := eventFrom(m)
		_ = phaseOf(e.GCSPath)
		_ = key(e.SID, e.Turn)
	})
}

func line(s ...string) string { return strings.Join(s, "\n") + "\n" }
