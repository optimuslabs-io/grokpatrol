package report

import (
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Public apps that serve keys get an ACTION line for server secrets and a Check
// line for browser keys, naming rule ids only.
func TestAppsSecretBanners(t *testing.T) {
	rep := &model.Report{
		Options: model.Options{CheckExposure: true, ScanPublic: true},
		Apps: []model.PublishedApp{
			{Host: "leaky.grok.me", Exposure: model.ExposurePublic, Seen: []model.Evidence{{Path: "~/h", Note: "browser history"}},
				Secrets: []model.AppSecret{
					{Rule: "openai-api-key", Kind: model.SecretServer, Asset: "/assets/index.js"},
					{Rule: "gcp-api-key", Kind: model.SecretBrowser, Asset: "/assets/index.js"},
				}, SecretScan: "scanned the home page and 1 of 1 same-host scripts"},
			{Host: "web.grok.me", Exposure: model.ExposurePublic, Seen: []model.Evidence{{Path: "~/h", Note: "browser history"}},
				Secrets: []model.AppSecret{{Rule: "gcp-api-key", Kind: model.SecretBrowser, Asset: "/"}}},
			{Host: "quiet.grok.me", Exposure: model.ExposurePublic, Seen: []model.Evidence{{Path: "~/h", Note: "browser history"}}},
		},
	}
	var b strings.Builder
	apps(&b, rep, Style{Verbose: true})
	out := b.String()
	for _, want := range []string{
		"ACTION: Anyone who opens 1 public app gets a server secret (openai-api-key)",
		"Check: Keys made for browsers ship in 2 public apps (gcp-api-key)",
		"PUBLIC + SECRET",
		"PUBLIC + browser key",
		"secret: openai-api-key in /assets/index.js (server secret: rotate)",
		"secret scan: scanned the home page",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestAppsNoSecretBannersWithoutSecrets(t *testing.T) {
	rep := &model.Report{
		Options: model.Options{CheckExposure: true},
		Apps:    []model.PublishedApp{{Host: "quiet.grok.me", Exposure: model.ExposurePublic}},
	}
	var b strings.Builder
	apps(&b, rep, Style{})
	if strings.Contains(b.String(), "ACTION:") || strings.Contains(b.String(), "Check:") {
		t.Errorf("banner without secrets:\n%s", b.String())
	}
}
