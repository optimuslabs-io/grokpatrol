package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// A secrets limitation begins with a repository path, and a path can contain any
// word, including "grok.me" or a source name. --apps-only must select app caveats
// by origin, so such a limitation never reaches it however it is worded.
func TestAppsJSONSelectsCaveatsByOriginNotText(t *testing.T) {
	const repoCaveat = "~/sites/tiny.grok.me-OTX-crt.sh: 3 files exceeded --max-blob-scan-bytes and were not content-scanned"
	rep := &model.Report{
		Apps: []model.PublishedApp{{Host: "tiny.grok.me", Source: model.AppSourceLocal,
			Seen: []model.Evidence{{Path: "~/.grok/sessions/%2Fwork%2Fprivate-repo/events.jsonl", Note: "Grok CLI sessions"}}}},
		Limitations: []string{repoCaveat},
		Repos:       []model.RepoStatus{{RepoPath: "~/sites/tiny.grok.me-OTX-crt.sh"}},
		Errors: []model.ScanError{
			{Detector: "secrets", Path: "~/sites/tiny.grok.me-OTX-crt.sh", Message: "git failed"},
			{Detector: "apps", Path: "~/.grok/sessions/%2Fwork%2Fprivate-repo/events.jsonl", Message: "open: operation not permitted"},
		},
	}
	rep.AddAppLimitations("Grok Build apps are published from grok.com.")

	var b strings.Builder
	if err := AppsJSON(&b, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "~/sites") || strings.Contains(b.String(), "private-repo") {
		t.Fatalf("--apps-only carried a local path:\n%s", b.String())
	}
	var out struct {
		Limitations []string             `json:"limitations"`
		Apps        []model.PublishedApp `json:"published_apps"`
		Errors      []model.ScanError    `json:"errors"`
	}
	if err := json.Unmarshal([]byte(b.String()), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Limitations) != 1 || len(out.Errors) != 1 || out.Errors[0].Detector != "apps" {
		t.Errorf("limitations=%v errors=%v", out.Limitations, out.Errors)
	}
	if out.Errors[0].Path != "" || len(out.Apps) != 1 || out.Apps[0].Seen[0].Path != "" ||
		out.Apps[0].Seen[0].Note != "Grok CLI sessions" {
		t.Errorf("apps-only local evidence was not safely copied: apps=%+v errors=%+v", out.Apps, out.Errors)
	}
	if rep.Apps[0].Seen[0].Path == "" || rep.Errors[1].Path == "" {
		t.Error("AppsJSON mutated the full report")
	}
	if len(rep.Limitations) != 2 {
		t.Errorf("the full report lost a caveat: %v", rep.Limitations)
	}
}
