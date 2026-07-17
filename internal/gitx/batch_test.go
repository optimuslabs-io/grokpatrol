package gitx

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// mkRepo builds a throwaway repo with one commit. Returns the repo path and
// the blob sha of each committed file, keyed by name.
func mkRepo(t *testing.T, files map[string][]byte) (string, map[string]string) {
	t.Helper()
	if !Available() {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_AUTHOR_DATE=2026-01-01T00:00:00Z",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
			"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q")
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")
	run("commit", "-qm", "x")

	shas := map[string]string{}
	for name := range files {
		shas[name] = run("rev-parse", "HEAD:"+name)
	}
	return dir, shas
}

// TestBatchRoundTripsBinaryBlobs: the framing must survive bytes that would
// wreck a line scanner -- NULs, CRLFs, a fake batch header inside the payload.
func TestBatchRoundTripsBinaryBlobs(t *testing.T) {
	evil := append([]byte("line1\r\n\x00\x00"), []byte("deadbeef blob 999999\n")...)
	evil = append(evil, bytes.Repeat([]byte{0xff, 0x00, '\n'}, 1000)...)
	files := map[string][]byte{
		"bin.dat":  evil,
		"text.txt": []byte("hello\n"),
	}
	repo, shas := mkRepo(t, files)

	got := map[string][]byte{}
	order := []string{shas["bin.dat"], shas["text.txt"]}
	err := CatFileBatch(context.Background(), repo, 10*time.Second, 1<<20, order, func(sha string, data []byte) error {
		got[sha] = append([]byte(nil), data...) // the callback buffer is transient; copy to compare
		return nil
	})
	if err != nil {
		t.Fatalf("CatFileBatch: %v", err)
	}
	for name, content := range files {
		if !bytes.Equal(got[shas[name]], content) {
			t.Errorf("%s: round-trip mismatch (%d bytes in, %d out)", name, len(content), len(got[shas[name]]))
		}
	}
}

// TestBatchSkipsOversizedAndDrains: an over-cap blob comes back as nil data,
// and -- the part that matters -- the NEXT object still parses, proving the
// oversized payload was drained off the pipe, not left to corrupt the framing.
func TestBatchSkipsOversizedAndDrains(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 8192)
	files := map[string][]byte{
		"big.bin":   big,
		"small.txt": []byte("small\n"),
	}
	repo, shas := mkRepo(t, files)

	var calls []int // data length per callback, -1 for nil
	order := []string{shas["big.bin"], shas["small.txt"]}
	err := CatFileBatch(context.Background(), repo, 10*time.Second, 1024, order, func(sha string, data []byte) error {
		if data == nil {
			calls = append(calls, -1)
		} else {
			calls = append(calls, len(data))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("CatFileBatch: %v", err)
	}
	if len(calls) != 2 || calls[0] != -1 || calls[1] != len("small\n") {
		t.Fatalf("calls = %v, want [-1 6]", calls)
	}
}

// TestBatchCheckReportsTypeAndSize, including missing objects as size -1.
func TestBatchCheckReportsTypeAndSize(t *testing.T) {
	files := map[string][]byte{"f.txt": []byte("12345")}
	repo, shas := mkRepo(t, files)

	missing := strings.Repeat("42", 20)
	type row struct {
		typ  string
		size int64
	}
	got := map[string]row{}
	err := CatFileBatchCheck(context.Background(), repo, 10*time.Second, []string{shas["f.txt"], missing}, func(sha, objType string, size int64) error {
		got[sha] = row{objType, size}
		return nil
	})
	if err != nil {
		t.Fatalf("CatFileBatchCheck: %v", err)
	}
	if r := got[shas["f.txt"]]; r.typ != "blob" || r.size != 5 {
		t.Errorf("f.txt: got %+v, want {blob 5}", r)
	}
	if r := got[missing]; r.size != -1 {
		t.Errorf("missing object: got %+v, want size -1", r)
	}
}

// TestBatchDoesNotDeadlockOnManyObjects pushes enough requests that the
// request stream alone (41 bytes each) overflows a 64 KB pipe: if requests
// were written before reading, this would hang, not pass.
func TestBatchDoesNotDeadlockOnManyObjects(t *testing.T) {
	files := map[string][]byte{"f.txt": []byte("payload payload payload\n")}
	repo, shas := mkRepo(t, files)

	// The same sha over and over is fine: each request gets its own response.
	shaList := make([]string, 5000)
	for i := range shaList {
		shaList[i] = shas["f.txt"]
	}
	n := 0
	err := CatFileBatch(context.Background(), repo, 30*time.Second, 1<<20, shaList, func(sha string, data []byte) error {
		n++
		return nil
	})
	if err != nil {
		t.Fatalf("CatFileBatch: %v", err)
	}
	if n != len(shaList) {
		t.Fatalf("callbacks = %d, want %d", n, len(shaList))
	}
}

// TestBatchLeavesRepositoryUntouched mirrors the secrets detector's
// repository-integrity test: cat-file must not write anything.
func TestBatchLeavesRepositoryUntouched(t *testing.T) {
	files := map[string][]byte{"f.txt": []byte("content\n")}
	repo, shas := mkRepo(t, files)

	before := snapshotDir(t, filepath.Join(repo, ".git"))
	err := CatFileBatch(context.Background(), repo, 10*time.Second, 1<<20, []string{shas["f.txt"]}, func(string, []byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	after := snapshotDir(t, filepath.Join(repo, ".git"))
	if before != after {
		t.Fatal(".git changed during a cat-file batch: a forensic tool must not touch the evidence")
	}
}

func snapshotDir(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return nil
		}
		b.WriteString(p)
		b.WriteByte('|')
		b.WriteString(fi.ModTime().String())
		b.WriteByte('|')
		b.WriteString(strconv.FormatInt(fi.Size(), 10))
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
