package logs

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/model"
)

// runEnv runs the detector against an Env the caller built, so a test can set
// Discovered.GrokHomes directly rather than going through the default home.
func runEnv(t *testing.T, env *engine.Env) engine.Result {
	t.Helper()
	res, err := New().Run(context.Background(), env)
	if err != nil {
		t.Fatalf("Run returned a fatal error, which it never should: %v", err)
	}
	return res
}

// homeWithFiles writes log files at paths RELATIVE TO THE GROK HOME, so a test can put
// unified.jsonl at the top level, under logs/, or both.
func homeWithFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	home := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(home, ".grok", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

const (
	startLine = `{"msg":"repo_state.upload.start","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`
	enqLine   = `{"msg":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/after_codebase.tar.gz","ts":"2026-06-12T10:01:00Z"}`
)

// THE REGRESSION GUARD for a false negative found on a real host.
//
// A real ~/.grok keeps unified.jsonl at the TOP LEVEL, with no logs/ subdirectory at
// all. discover() used to read <home>/logs and nothing else, so on that machine
// grokpatrol reported "No evidence was found that it has uploaded anything from this
// machine yet" -- EXPOSED, not degraded, no warning -- while a log holding 68 collection
// events and 64 queued archives sat unread in the directory it had just named as the
// grok home.
//
// A confident all-clear on a compromised host is the worst thing this tool can print.
func TestLogsAtGrokHomeRootAreFound(t *testing.T) {
	home := homeWithFiles(t, map[string]string{
		"unified.jsonl": line(startLine, enqLine), // top level -- NO logs/ subdir
	})

	res := run(t, home)

	r := findRepo(res, "/work/api")
	if r == nil {
		t.Fatalf("the ledger is EMPTY: a unified.jsonl at the root of the grok home was never read, "+
			"so 1 collected repo and 1 queued archive vanished. Repos=%v Findings=%v",
			res.Repos, res.Findings)
	}
	if r.Status != model.StatusQueued {
		t.Errorf("status = %q, want %q", r.Status, model.StatusQueued)
	}
	if !hasFinding(res, "logs.archive_enqueued") {
		t.Error("logs.archive_enqueued did not fire -- the verdict would not reach COMPROMISED")
	}
}

// The conventional layout must keep working, obviously.
func TestLogsUnderLogsSubdirStillFound(t *testing.T) {
	home := homeWithFiles(t, map[string]string{
		"logs/unified.jsonl": line(startLine, enqLine),
	})
	if findRepo(run(t, home), "/work/api") == nil {
		t.Error("a log under <grok-home>/logs/ was not read")
	}
}

// Both locations populated at once: every event must land, and no file may be counted
// twice. A repo whose archive was double-counted would report two uploads where one
// happened -- inventing evidence is as bad as losing it.
func TestBothLocationsAreReadWithoutDoubleCounting(t *testing.T) {
	home := homeWithFiles(t, map[string]string{
		"unified.jsonl":        line(startLine, enqLine),
		"logs/unified.jsonl.1": line(startLine, enqLine),
	})

	res := run(t, home)
	r := findRepo(res, "/work/api")
	if r == nil {
		t.Fatal("repo missing entirely")
	}
	// Two distinct files, each with one archive: two archives total, not one (a dropped
	// file) and not four (a file read twice).
	if len(r.Archives) != 2 {
		t.Errorf("archives = %d, want 2 (one per file; 1 means a file was skipped, 4 means one was read twice)",
			len(r.Archives))
	}
}

// A grok home with no logs anywhere is not an error, and must not be reported as one --
// it is simply a home whose logs rotated away or never existed. But it must also never
// read as reassurance: the summary has to say so.
func TestGrokHomeWithNoLogsIsNotAnError(t *testing.T) {
	home := homeWithFiles(t, map[string]string{})
	if err := os.MkdirAll(filepath.Join(home, ".grok"), 0o755); err != nil {
		t.Fatal(err)
	}
	res := run(t, home)
	for _, e := range res.Errors {
		if e.Material {
			t.Errorf("a grok home with no log files produced a material error: %+v", e)
		}
	}
	if len(res.Limitations) == 0 {
		t.Error("a host with no logs must state that as a limitation, not pass silently")
	}
}

// discover must honour every grok home deepscan found, not just the default one -- a
// stray .grok under ~/work has its own logs, and its own uploads.
func TestAllDiscoveredGrokHomesAreRead(t *testing.T) {
	base := t.TempDir()
	strayHome := filepath.Join(base, "work", ".grok")
	if err := os.MkdirAll(strayHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(strayHome, "unified.jsonl"),
		[]byte(line(startLine, enqLine)), 0o644); err != nil {
		t.Fatal(err)
	}

	env := &engine.Env{Home: base, GrokHome: filepath.Join(base, ".grok")}
	env.Discovered.GrokHomes = []string{strayHome}

	res := runEnv(t, env)
	if findRepo(res, "/work/api") == nil {
		t.Errorf("a stray grok home discovered by deepscan was not read: %v", res.Repos)
	}
}
