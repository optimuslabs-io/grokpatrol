package deepscan

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// findings() must stamp PathEntry onto the ONE discovered install that the grok command
// resolves to on $PATH, and leave every other install's evidence unmarked. This wires
// hostfs.ResolveOnPath (symlink resolution) to activeInstall (matching against the
// installs deepscan recorded) end to end.
func TestFindingsMarksPathInstall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()

	// The real install the walk would have recorded, plus a $PATH symlink pointing at it.
	realDir := filepath.Join(root, "app")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(realDir, "cli.js")
	if err := os.WriteFile(realFile, []byte("bundle"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The walk records a canonical path; canonicalize so activeInstall's cleaned match
	// holds even under macOS's /var -> /private/var TempDir symlink.
	realCanon, err := filepath.EvalSymlinks(realFile)
	if err != nil {
		t.Fatal(err)
	}
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(binDir, "grok")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}

	install := func(path string) engine.BinaryHit {
		return engine.BinaryHit{
			Path:       path,
			Executable: true, // makes IsInstall() true
			SizeBytes:  40 << 20,
			Markers:    []engine.MarkerHit{{Marker: scan.MarkerBucket, Offset: 0x10}},
		}
	}
	disc := &engine.Discovered{Binaries: []engine.BinaryHit{
		install(filepath.Join(root, "other", "grok")),
		install(realCanon),
	}}
	env := &engine.Env{PathDirs: []string{binDir}, GrokHome: filepath.Join(root, ".grok")}

	out := findings(disc, env)
	var got []string // paths whose evidence carries a PathEntry
	var entryFor string
	for _, f := range out {
		if f.ID != "deepscan.binary_marker" {
			continue
		}
		for _, e := range f.Evidence {
			if e.PathEntry != "" {
				got = append(got, e.Path)
				entryFor = e.PathEntry
			}
		}
	}

	if len(got) != 1 || got[0] != realCanon {
		t.Fatalf("PathEntry marked on %v, want only the on-$PATH install %q", got, realCanon)
	}
	if entryFor != link {
		t.Errorf("PathEntry = %q, want the $PATH symlink %q", entryFor, link)
	}
}

// With no grok on $PATH, no install is marked -- the report has nothing to highlight and
// must not invent a claim about which one runs.
func TestFindingsMarksNothingWithoutPathGrok(t *testing.T) {
	root := t.TempDir()
	disc := &engine.Discovered{Binaries: []engine.BinaryHit{{
		Path:       filepath.Join(root, "grok"),
		Executable: true,
		Markers:    []engine.MarkerHit{{Marker: scan.MarkerBucket, Offset: 0x10}},
	}}}
	env := &engine.Env{PathDirs: []string{root}, GrokHome: filepath.Join(root, ".grok")}

	for _, f := range findings(disc, env) {
		for _, e := range f.Evidence {
			if e.PathEntry != "" {
				t.Errorf("no grok on $PATH, but %q was marked active (entry %q)", e.Path, e.PathEntry)
			}
		}
	}
}
