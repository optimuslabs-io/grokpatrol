package hostfs

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// ResolveOnPath must behave like the shell: search $PATH in order, return the first
// entry named grok, and -- the whole reason it exists -- resolve a symlink to its real
// target so the caller can match it against a discovered install whose recorded path is
// that target, not the symlink. This is the normal npm/homebrew/bun layout.
func TestResolveOnPathFollowsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()

	// The real install, under a bundle dir that is NOT on $PATH and is named cli.js --
	// exactly the case where matching by the $PATH entry's name or directory would miss.
	bundle := filepath.Join(root, "lib", "node_modules", "grok")
	if err := os.MkdirAll(bundle, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(bundle, "cli.js")
	if err := os.WriteFile(real, []byte("bundle"), 0o755); err != nil {
		t.Fatal(err)
	}

	// The $PATH entry: a symlink named grok pointing at the bundle.
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(binDir, "grok")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	// An earlier $PATH dir with no grok must be skipped, not stop the search.
	empty := filepath.Join(root, "empty")
	if err := os.MkdirAll(empty, 0o755); err != nil {
		t.Fatal(err)
	}

	entry, resolved, ok := ResolveOnPath([]string{empty, binDir}, grokNames())
	if !ok {
		t.Fatal("expected grok to resolve on $PATH")
	}
	if entry != link {
		t.Errorf("entry = %q, want the $PATH symlink %q", entry, link)
	}
	// EvalSymlinks canonicalizes the whole path (on macOS TempDir sits under /var, itself
	// a symlink to /private/var), so compare against the target's own canonical form.
	wantReal, _ := filepath.EvalSymlinks(real)
	if resolved != wantReal {
		t.Errorf("resolved = %q, want the symlink target %q", resolved, wantReal)
	}
}

// $PATH order decides which grok runs when two are present; the first wins.
func TestResolveOnPathHonorsOrder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	for _, d := range []string{first, second} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "grok"), []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	_, resolved, ok := ResolveOnPath([]string{first, second}, grokNames())
	want, _ := filepath.EvalSymlinks(filepath.Join(first, "grok"))
	if !ok || resolved != want {
		t.Errorf("resolved = %q (ok=%v), want the first $PATH entry %q", resolved, ok, want)
	}
}

// No grok anywhere on $PATH is the clean case: ok is false and nothing is highlighted.
func TestResolveOnPathAbsent(t *testing.T) {
	root := t.TempDir()
	if _, _, ok := ResolveOnPath([]string{root}, grokNames()); ok {
		t.Error("expected ok=false when no grok is on $PATH")
	}
}

// grokNames mirrors scan.GrokCommandNames without importing it: hostfs sits below scan
// in the layering, so the test supplies the same fixed command names by hand.
func grokNames() []string { return []string{"grok", "grok.exe"} }
