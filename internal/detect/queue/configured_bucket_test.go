package queue

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// A manifest naming the configured trace bucket is staging for an upload that never
// names xAI's bucket. It is reported the same way the xAI manifest is.
func TestManifestNamingConfiguredBucket(t *testing.T) {
	home := t.TempDir()
	grok := filepath.Join(home, ".grok")
	dir := filepath.Join(grok, "upload_queue", "turn_1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(grok, "config.toml"), "[endpoints]\ntrace_upload_bucket = \"s3://acme-traces/team-a\"\n")
	write(filepath.Join(dir, "metadata.json"), `{"destination":"s3://acme-traces/team-a/s1/turn_1/x"}`)

	res := runQueue(t, context.Background(), home)
	var got *model.Finding
	for i := range res.Findings {
		switch res.Findings[i].ID {
		case "queue.metadata_configured_bucket":
			got = &res.Findings[i]
		case "queue.metadata_bucket":
			t.Error("a configured-bucket manifest was reported as naming xAI's bucket")
		}
	}
	if got == nil {
		t.Fatalf("configured bucket manifest not reported: %+v", res.Findings)
	}
	if got.Severity != model.SevHigh || got.IsUpload() || got.Evidence[0].Locator != "s3://acme-traces/" {
		t.Errorf("want High staging naming s3://acme-traces/, got %v %v %+v", got.Severity, got.Tags, got.Evidence)
	}
}
