package apps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// runWith scans a fake home with a fixed environment and returns each host found
// with the evidence that cites it.
func runWith(t *testing.T, home string, vars map[string]string) (map[string][]model.Evidence, engine.Result) {
	t.Helper()
	env := &engine.Env{
		Home: home, GrokHome: filepath.Join(home, ".grok"), MaxFileSize: 1 << 20,
		Getenv: func(k string) string { return vars[k] },
	}
	res, err := New().Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]model.Evidence{}
	for _, a := range res.Apps {
		got[a.Host] = a.Seen
	}
	return got, res
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Grok backs up every copy to <grok home>/last-copy.txt, so an app address copied
// out of a session is found there.
func TestClipboardBackupInGrokHome(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".grok", "last-copy.txt"), "https://copied-app.grok.me/")

	got, _ := runWith(t, home, nil)
	seen := got["copied-app.grok.me"]
	if len(seen) != 1 || seen[0].Note != "Grok clipboard backup" {
		t.Fatalf("copied-app.grok.me evidence = %+v, want one Grok clipboard backup row", seen)
	}
}

// GROK_COPY_FILE moves the backup; absolute and home-relative forms are both found.
func TestClipboardBackupMovedByEnv(t *testing.T) {
	for _, tc := range []struct{ name, value, file string }{
		{"absolute", "", "elsewhere/copy.txt"},
		{"home-relative", "~/notes/copy.txt", "notes/copy.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, tc.file)
			writeFile(t, path, "moved-app.grok.me")
			value := tc.value
			if value == "" {
				value = path
			}
			got, _ := runWith(t, home, map[string]string{"GROK_COPY_FILE": value})
			seen := got["moved-app.grok.me"]
			if len(seen) != 1 || seen[0].Path != path {
				t.Fatalf("moved-app.grok.me evidence = %+v, want one row citing %s", seen, path)
			}
		})
	}
}

// GROK_COPY_FILE pointing at the default file must not cite it twice.
func TestClipboardBackupNotCitedTwice(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".grok", "last-copy.txt")
	writeFile(t, path, "once.grok.me")

	got, _ := runWith(t, home, map[string]string{"GROK_COPY_FILE": path})
	if n := len(got["once.grok.me"]); n != 1 {
		t.Fatalf("once.grok.me cited %d times, want 1", n)
	}
}

// A relative GROK_COPY_FILE depends on where Grok was started. It is not guessed
// at; the report says the backup was not searched, without printing the value.
func TestClipboardBackupRelativeEnvIsReported(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, "rel-copy.txt"), "guessed.grok.me")

	got, res := runWith(t, home, map[string]string{"GROK_COPY_FILE": "rel-copy.txt"})
	if _, ok := got["guessed.grok.me"]; ok {
		t.Error("a relative GROK_COPY_FILE was resolved against a guessed directory")
	}
	var said bool
	for _, l := range res.AppLimitations {
		if strings.Contains(l, "GROK_COPY_FILE") {
			said = true
			if strings.Contains(l, "rel-copy.txt") {
				t.Errorf("limitation prints the variable's value: %q", l)
			}
		}
	}
	if !said {
		t.Errorf("no limitation about the relative GROK_COPY_FILE: %v", res.AppLimitations)
	}
}

// sandbox-events.jsonl is a sandbox debug log (profile applied, denied paths), not a
// place app addresses are written, so it is deliberately not a source.
func TestSandboxEventsIsNotASource(t *testing.T) {
	home := t.TempDir()
	writeFile(t, filepath.Join(home, ".grok", "sandbox-events.jsonl"), `{"workspace":"https://not-searched.grok.me"}`)

	got, _ := runWith(t, home, nil)
	if len(got) != 0 {
		t.Fatalf("found %v in sandbox-events.jsonl", got)
	}
}
