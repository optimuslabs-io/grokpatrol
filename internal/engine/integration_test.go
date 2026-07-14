package engine_test

import (
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cfgdet "github.com/optimuslabs/grokpatrol/internal/detect/config"
	"github.com/optimuslabs/grokpatrol/internal/detect/deepscan"
	"github.com/optimuslabs/grokpatrol/internal/detect/logs"
	"github.com/optimuslabs/grokpatrol/internal/detect/queue"
	"github.com/optimuslabs/grokpatrol/internal/detect/secrets"
	"github.com/optimuslabs/grokpatrol/internal/detect/version"
	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/model"
	"github.com/optimuslabs/grokpatrol/internal/scan"
)

// This is the end-to-end regression net for the COMPROMISED path.
//
// There is no real Grok install to test against, so the compromised case has to be
// constructed: a synthetic home with every host-side indicator planted, including
// a repository whose secrets were committed and then deleted. Without this test,
// someone could rewire the detector phases, `make check` would stay green, and the
// tool would quietly stop reporting COMPROMISED on a genuinely compromised host --
// which is the only failure that actually matters here.
func TestCompromisedHostEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := buildFakeHome(t)
	rep := scanHome(t, home)

	if rep.Verdict != model.VerdictCompromised {
		t.Fatalf("verdict = %s, want COMPROMISED\nfindings: %s", rep.Verdict, ids(rep))
	}
	if got := rep.Verdict.ExitCode(); got != 4 {
		t.Errorf("exit code = %d, want 4", got)
	}

	// Every detector must have fired. If one silently stops contributing, the verdict
	// can still come out right for the wrong reason -- so each is asserted by name.
	for _, want := range []string{
		"logs.archive_enqueued",         // proof of upload, from the log ledger
		"logs.collected_only",           // a repo collected but never enqueued
		"queue.present",                 // a populated upload_queue
		"queue.metadata_bucket",         // a manifest naming the bucket
		"queue.codebase_archive",        // staged tar.gz archives
		"deepscan.binary_marker",        // the bucket name inside the binary
		"version.confirmed_affected",    // 0.2.93
		"config.not_mitigated",          // neither mitigation set
		"config.auth_present",           // auth.json exists (and was not read)
		"secrets.deleted_from_checkout", // THE headline finding
		"secrets.in_head",               //
	} {
		if !has(rep, want) {
			t.Errorf("finding %q is missing -- a detector stopped contributing", want)
		}
	}

	// The rotation-boundary case: the start event is in unified.jsonl.1 and its
	// enqueues are in unified.jsonl. A per-file correlator reports this repo as
	// COLLECTED-ONLY and understates the worst finding the tool can make.
	pay := repoBySuffix(rep, "payments-api")
	if pay == nil {
		t.Fatal("payments-api is missing from the ledger")
	}
	if pay.Status != model.StatusQueued {
		t.Errorf("payments-api status = %q, want queued -- the enqueue in the rotated sibling file was not correlated",
			pay.Status)
	}
	if len(pay.Archives) != 2 {
		t.Errorf("payments-api archives = %d, want 2 (before + after)", len(pay.Archives))
	}

	// The gzipped rotation must be read too.
	if infra := repoBySuffix(rep, "infra"); infra == nil || infra.Status != model.StatusQueued {
		t.Errorf("the repo recorded only in the gzipped rotated log was not picked up: %+v", infra)
	}

	// The headline: secrets that are GONE from the checkout but were in the uploaded
	// object set. The user cannot find these by looking at their own repo.
	deleted := map[string]bool{}
	for _, h := range pay.SecretFiles {
		if h.DeletedFromCheckout {
			deleted[h.Path] = true
		}
	}
	for _, want := range []string{".env.production", "certs/prod.pem"} {
		if !deleted[want] {
			t.Errorf("%s was not flagged as deleted-from-checkout; that is the whole point of the tool", want)
		}
	}
	if len(pay.SecretFiles) == 0 || !pay.SecretsScanned {
		t.Error("payments-api was never secret-scanned")
	}
}

// The auth token must never appear anywhere in the report -- not in a finding, not
// in evidence, not in an error message. grokpatrol notes that auth.json exists and
// never opens it.
func TestAuthTokenNeverLeaks(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	home := buildFakeHome(t)
	rep := scanHome(t, home)

	blob := fmt.Sprintf("%+v", *rep)
	for _, forbidden := range []string{
		"xai-SECRET-TOKEN", // the token in the fixture's auth.json
		"hunter2",          // the password inside the fixture's .env.production
	} {
		if strings.Contains(blob, forbidden) {
			t.Errorf("the report contains %q -- grokpatrol must report secret LOCATIONS, never secret VALUES", forbidden)
		}
	}
}

// A host with no Grok on it must not be reported as EXPOSED. This is the
// false-positive guard: the first real run of grokpatrol against a clean machine
// reported EXPOSED because it detected its own binary.
func TestCleanHostIsNotExposed(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "projects", "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "projects", "app", "main.go"), []byte("package main"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := scanHome(t, home)

	if rep.Verdict == model.VerdictExposed || rep.Verdict == model.VerdictCompromised {
		t.Errorf("a clean host was reported %s\nfindings: %s", rep.Verdict, ids(rep))
	}
}

func scanHome(t *testing.T, home string) *model.Report {
	t.Helper()
	env := &engine.Env{
		Home:          home,
		GrokHome:      filepath.Join(home, ".grok"),
		ScanRoots:     []string{home}, // do not wander outside the fixture
		Concurrency:   4,
		MaxFileSize:   512 << 20,
		UseGit:        true,
		HistoryScope:  "head",
		MaxGitObjects: 1_000_000,
		GitTimeout:    30 * time.Second,
	}
	eng := &engine.Engine{
		Discover:        deepscan.New(),
		Readers:         []engine.Detector{logs.New(), queue.New(), cfgdet.New(), version.New()},
		Triage:          secrets.New(),
		DetectorTimeout: 2 * time.Minute,
	}
	return eng.Run(context.Background(), env)
}

// buildFakeHome plants every host-side indicator. It is generated rather than
// committed: files carrying a live IoC string trip corporate EDR, which is a real
// problem for anyone who clones this repo.
func buildFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	bucket := scan.MarkerBucket

	grok := filepath.Join(home, ".grok")
	mkdirs(t, filepath.Join(grok, "logs"), filepath.Join(grok, "upload_queue", "sess-a1"),
		filepath.Join(home, ".local", "bin"))

	repo := filepath.Join(home, "work", "payments-api")

	// The start event lands in the ROTATED file; its enqueues land in the current
	// one. Correlation has to be global across files or this repo is misreported.
	write(t, filepath.Join(grok, "logs", "unified.jsonl.1"), lines(
		ev(`{"event":"%s.start","sid":"sess-a1","ctx":{"turn_number":3,"repo_path":%q},"ts":"2026-06-30T10:00:00Z","version":"0.2.93"}`, scan.MarkerEvent, repo),
		ev(`{"event":"%s.start","sid":"sess-a1","ctx":{"turn_number":3,"repo_path":%q},"ts":"2026-06-30T10:00:01Z"}`, scan.MarkerEvent, repo),
	))
	write(t, filepath.Join(grok, "logs", "unified.jsonl"), lines(
		ev(`{"event":"%s.enqueued","sid":"sess-a1","ctx":{"turn_number":3},"gcs_path":"gs://%s/sess-a1/3/before_codebase.tar.gz","ts":"2026-06-30T10:00:05Z"}`, scan.MarkerEvent, bucket),
		ev(`{"event":"%s.enqueued","sid":"sess-a1","ctx":{"turn_number":3},"gcs_path":"gs://%s/sess-a1/3/after_codebase.tar.gz","ts":"2026-06-30T10:02:00Z"}`, scan.MarkerEvent, bucket),
		ev(`{"event":"%s.start","sid":"sess-b2","ctx":{"turn_number":1,"repo_path":%q},"ts":"2026-06-12T09:00:00Z"}`, scan.MarkerEvent, filepath.Join(home, "work", "scratch")),
	))
	writeGz(t, filepath.Join(grok, "logs", "unified.jsonl.2.gz"), lines(
		ev(`{"event":"%s.start","sid":"sess-c3","ctx":{"turn_number":1,"repo_path":%q},"ts":"2026-05-01T00:00:00Z"}`, scan.MarkerEvent, filepath.Join(home, "work", "infra")),
		ev(`{"event":"%s.enqueued","sid":"sess-c3","ctx":{"turn_number":1},"gcs_path":"gs://%s/sess-c3/1/after_codebase.tar.gz","ts":"2026-05-01T00:01:00Z"}`, scan.MarkerEvent, bucket),
	))

	// config.toml with NEITHER mitigation.
	write(t, filepath.Join(grok, "config.toml"), "[harness]\nmodel = \"grok-code-fast\"\n")
	// A token that must never be printed.
	write(t, filepath.Join(grok, "auth.json"), `{"key":"xai-SECRET-TOKEN-DO-NOT-PRINT"}`)
	write(t, filepath.Join(grok, "version"), "0.2.93\n")

	// A staged manifest naming the bucket, plus the archives themselves.
	write(t, filepath.Join(grok, "upload_queue", "sess-a1", "metadata.json"), fmt.Sprintf(
		`{"session_id":"sess-a1","files":[{"local":%q,"gcs":"gs://%s/sess-a1/3/before_codebase.tar.gz"}]}`,
		filepath.Join(repo, ".env.production"), bucket))
	writeGz(t, filepath.Join(grok, "upload_queue", "sess-a1", "before_codebase.tar.gz"), "fake archive payload")
	writeGz(t, filepath.Join(grok, "upload_queue", "sess-a1", "after_codebase.tar.gz"), "fake archive payload")

	// A fake grok binary with the bucket name planted so it STRADDLES a 256 KiB
	// chunk boundary -- exercising the matcher's overlap carry against a real file.
	writeFakeBinary(t, filepath.Join(home, ".local", "bin", "grok"), bucket)

	// The repo that was taken: secrets committed, then deleted. Gone from the working
	// tree, alive in history, and therefore in the uploaded object set.
	gitRepo(t, repo, func(g func(...string), w func(string, string)) {
		w("src/main.go", "package main")
		w(".env.production", "DATABASE_URL=postgres://user:hunter2@prod/db")
		w("certs/prod.pem", "-----BEGIN PRIVATE KEY-----")
		w(".env.example", "DATABASE_URL=")
		g("add", "-A")
		g("commit", "-qm", "initial")
		g("rm", "-q", ".env.production", "certs/prod.pem")
		g("commit", "-qm", "remove secrets (they live on in history)")
		w("terraform.tfvars", `api_token = "abc"`)
		g("add", "-A")
		g("commit", "-qm", "add tfvars")
	})

	// A second repo: collected, never enqueued -> COLLECTED-ONLY.
	gitRepo(t, filepath.Join(home, "work", "scratch"), func(g func(...string), w func(string, string)) {
		w("README.md", "notes")
		g("add", "-A")
		g("commit", "-qm", "init")
	})

	return home
}

// --- fixture helpers ---------------------------------------------------------

func ev(format string, args ...any) string { return fmt.Sprintf(format, args...) }

func lines(s ...string) string { return strings.Join(s, "\n") + "\n" }

func mkdirs(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	mkdirs(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeGz(t *testing.T, path, content string) {
	t.Helper()
	mkdirs(t, filepath.Dir(path))
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := gzip.NewWriter(f)
	if _, err := zw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeFakeBinary plants the marker across a 256 KiB boundary, on disk, in a file
// with real ELF magic -- so the candidate gate and the overlap carry are both
// exercised end to end rather than only in a unit-test buffer.
func writeFakeBinary(t *testing.T, path, marker string) {
	t.Helper()
	const chunk = 256 << 10
	mkdirs(t, filepath.Dir(path))

	blob := make([]byte, chunk*2)
	for i := range blob {
		blob[i] = 'A'
	}
	copy(blob, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	copy(blob[chunk-len(marker)/2:], marker) // straddles the boundary
	copy(blob[1000:], `{"name":"grok","version":"0.2.93"}`)

	if err := os.WriteFile(path, blob, 0o755); err != nil {
		t.Fatal(err)
	}
}

func gitRepo(t *testing.T, dir string, build func(git func(...string), write func(string, string))) {
	t.Helper()
	mkdirs(t, dir)
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2026-06-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-06-01T00:00:00Z",
	)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	w := func(rel, content string) {
		t.Helper()
		write(t, filepath.Join(dir, filepath.FromSlash(rel)), content)
	}
	git("init", "-q", "--initial-branch=main")
	build(git, w)
}

// --- assertions --------------------------------------------------------------

func has(rep *model.Report, id string) bool {
	for _, f := range rep.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func ids(rep *model.Report) string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.ID)
	}
	return strings.Join(out, ", ")
}

func repoBySuffix(rep *model.Report, suffix string) *model.RepoStatus {
	for i := range rep.Repos {
		if strings.HasSuffix(filepath.ToSlash(rep.Repos[i].RepoPath), suffix) {
			return &rep.Repos[i]
		}
	}
	return nil
}
