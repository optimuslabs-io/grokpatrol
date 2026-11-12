package version

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/grokver"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func grokHome(t *testing.T, files map[string]string) *engine.Env {
	t.Helper()
	home := filepath.Join(t.TempDir(), ".grok")
	for name, body := range files {
		p := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return &engine.Env{Home: filepath.Dir(home), GrokHome: home}
}

func run(t *testing.T, env *engine.Env) engine.Result {
	t.Helper()
	res, err := New().Run(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func find(vs []model.VersionEvidence, version, conf string) bool {
	for _, v := range vs {
		if v.Version == version && v.Confidence == conf {
			return true
		}
	}
	return false
}

// Grok 1.x records its version in ~/.grok/version.json. stable_version is what the
// updater would install next, not what is installed, so it must never be read as
// the installed version.
func TestVersionJSON(t *testing.T) {
	env := grokHome(t, map[string]string{
		"version.json": `{"version":"1.0.77","stable_version":"1.0.80","checked_at":"2026-11-11T22:47:09Z"}`,
	})
	res := run(t, env)
	if !find(res.Versions, "1.0.77", "high") {
		t.Errorf("version.json's version was not read at high confidence: %+v", res.Versions)
	}
	if !find(res.Versions, "1.0.80", "low") {
		t.Errorf("stable_version should be kept at low confidence: %+v", res.Versions)
	}
	if find(res.Versions, "1.0.80", "high") || find(res.Versions, "1.0.80", "medium") {
		t.Error("stable_version was read as the installed version")
	}
	// A low-confidence stable_version above LatestObserved must not raise the
	// newer-than-known finding: it is not installed.
	for _, f := range res.Findings {
		if f.ID == "version.newer_than_known" {
			t.Error("stable_version alone raised version.newer_than_known")
		}
	}
}

// The updater's staged binaries carry the version in their names. Medium confidence:
// a download may be an old one or one not yet switched to.
func TestDownloadsAreMediumConfidence(t *testing.T) {
	env := grokHome(t, map[string]string{
		"downloads/grok-0.2.111-macos-aarch64": "x",
		"downloads/grok-1.0.77-macos-aarch64":  "x",
		"downloads/grok-macos-aarch64":         "x", // unversioned: ignored
		"downloads/notes.txt":                  "x",
	})
	res := run(t, env)
	if !find(res.Versions, "0.2.111", "medium") || !find(res.Versions, "1.0.77", "medium") {
		t.Errorf("download filenames not read at medium confidence: %+v", res.Versions)
	}
	if len(res.Versions) != 2 {
		t.Errorf("want exactly two versions, got %+v", res.Versions)
	}
	for _, v := range res.Versions {
		if !strings.Contains(v.Source, "download:grok-") {
			t.Errorf("source does not name the download: %q", v.Source)
		}
	}
}

func TestNewerThanKnownIsReported(t *testing.T) {
	env := grokHome(t, map[string]string{"version.json": `{"version":"1.1.0"}`})
	res := run(t, env)

	var f *model.Finding
	for i := range res.Findings {
		if res.Findings[i].ID == "version.newer_than_known" {
			f = &res.Findings[i]
		}
	}
	if f == nil {
		t.Fatalf("no version.newer_than_known for 1.1.0: %+v", res.Findings)
	}
	if f.Severity != model.SevInfo || len(f.Tags) != 0 {
		t.Errorf("newer_than_known must be untagged info, got %v %v", f.Severity, f.Tags)
	}
	if !strings.Contains(f.Title, grokver.LatestObserved) {
		t.Errorf("title does not name the latest observed release: %q", f.Title)
	}
	var lim bool
	for _, l := range res.Limitations {
		if strings.Contains(l, "config keys, log event names and upload_queue layout may have changed") {
			lim = true
		}
	}
	if !lim {
		t.Errorf("no limitation about a newer build: %v", res.Limitations)
	}
}

func TestLatestObservedIsNotNewer(t *testing.T) {
	env := grokHome(t, map[string]string{"version.json": `{"version":"` + grokver.LatestObserved + `"}`})
	for _, f := range run(t, env).Findings {
		if f.ID == "version.newer_than_known" {
			t.Fatal("the latest observed release was reported as newer than itself")
		}
	}
}
