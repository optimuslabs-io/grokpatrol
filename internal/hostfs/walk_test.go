package hostfs

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type record struct {
	base    string
	isDir   bool
	regular bool
}

// walkRecords walks root and returns one record per visited entry, keyed by basename.
func walkRecords(t *testing.T, w *Walker, root string) map[string][]record {
	t.Helper()
	out := map[string][]record{}
	err := w.Walk(context.Background(), root, func(path string, d fs.DirEntry) error {
		b := filepath.Base(path)
		out[b] = append(out[b], record{base: b, isDir: d.IsDir(), regular: d.Type().IsRegular()})
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return out
}

func mustSymlink(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		t.Skipf("symlinks unavailable on this platform/filesystem: %v", err)
	}
}

// By default a symlinked directory's contents are invisible -- the entire reason the
// flag exists is that this is a safe but incomplete answer.
func TestWalkDoesNotFollowSymlinksByDefault(t *testing.T) {
	tmp := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(tmp, "root"), 0o755))
	must(t, os.MkdirAll(filepath.Join(tmp, "target"), 0o755))
	must(t, os.WriteFile(filepath.Join(tmp, "target", "secret.txt"), []byte("x"), 0o644))
	mustSymlink(t, filepath.Join(tmp, "target"), filepath.Join(tmp, "root", "link"))

	got := walkRecords(t, &Walker{FollowSymlinks: false, CrossFilesystem: true}, filepath.Join(tmp, "root"))
	if _, ok := got["secret.txt"]; ok {
		t.Error("a file reachable only through a symlink was visited with FollowSymlinks off")
	}
}

// With the flag on, the symlinked directory is descended into and its contents are
// visited -- the behavior the flag has always advertised but never delivered.
func TestWalkFollowsSymlinkedDirectory(t *testing.T) {
	tmp := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(tmp, "root"), 0o755))
	must(t, os.MkdirAll(filepath.Join(tmp, "target"), 0o755))
	must(t, os.WriteFile(filepath.Join(tmp, "target", "secret.txt"), []byte("x"), 0o644))
	mustSymlink(t, filepath.Join(tmp, "target"), filepath.Join(tmp, "root", "link"))

	got := walkRecords(t, &Walker{FollowSymlinks: true, CrossFilesystem: true}, filepath.Join(tmp, "root"))
	if _, ok := got["secret.txt"]; !ok {
		t.Error("a file behind a followed symlink was not visited")
	}
}

// A symlink whose NAME is a structural indicator (a `.grok` home, an `upload_queue`)
// is reported under its own name and as a directory, so name-based detection fires
// even though the target directory is named something else.
func TestWalkFollowedSymlinkKeepsItsOwnName(t *testing.T) {
	tmp := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(tmp, "root"), 0o755))
	must(t, os.MkdirAll(filepath.Join(tmp, "grokstate"), 0o755))
	mustSymlink(t, filepath.Join(tmp, "grokstate"), filepath.Join(tmp, "root", ".grok"))

	got := walkRecords(t, &Walker{FollowSymlinks: true, CrossFilesystem: true}, filepath.Join(tmp, "root"))
	recs := got[".grok"]
	if len(recs) == 0 {
		t.Fatal("the .grok symlink was not visited under its own name")
	}
	if !recs[0].isDir {
		t.Error("the .grok symlink was not presented as a directory, so structuralDir would miss it")
	}
}

// A symlink to a FILE is handed over as a regular entry so a symlinked grok binary or
// staged archive gets inspected.
func TestWalkFollowsSymlinkedFile(t *testing.T) {
	tmp := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(tmp, "root"), 0o755))
	must(t, os.WriteFile(filepath.Join(tmp, "realbin"), []byte("ELF..."), 0o644))
	mustSymlink(t, filepath.Join(tmp, "realbin"), filepath.Join(tmp, "root", "binlink"))

	got := walkRecords(t, &Walker{FollowSymlinks: true, CrossFilesystem: true}, filepath.Join(tmp, "root"))
	recs := got["binlink"]
	if len(recs) == 0 {
		t.Fatal("the symlinked file was not visited")
	}
	if !recs[0].regular {
		t.Error("the symlinked file was not presented as a regular file, so it would never be inspected")
	}
}

// A symlink cycle must terminate. Without the resolved-path guard this hangs forever;
// the test completing at all is the assertion.
func TestWalkFollowSymlinkCycleTerminates(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "root")
	must(t, os.MkdirAll(filepath.Join(root, "a"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "marker.txt"), []byte("x"), 0o644))
	// loop -> root: descending it re-enters root, which the cycle guard must catch.
	mustSymlink(t, root, filepath.Join(root, "a", "loop"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = (&Walker{FollowSymlinks: true, CrossFilesystem: true}).
			Walk(context.Background(), root, func(string, fs.DirEntry) error { return nil })
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Walk did not terminate on a symlink cycle")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
