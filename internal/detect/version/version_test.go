package version

import (
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// The stderr headline must apply the same low-confidence filter as findings() and the
// report banners. A semver scraped out of the grok bundle is as likely a dependency's
// as grok's own, so a single low-confidence "0.2.93" must not make the progress line
// shout "CONFIRMED AFFECTED" while the finding, verdict banner and install table --
// which all skip low confidence -- correctly stay silent.
func TestSummarizeIgnoresLowConfidenceHeadline(t *testing.T) {
	low := []model.VersionEvidence{
		{Version: "0.2.93", Source: "binary-strings", Confidence: "low", Class: model.VersionConfirmedAffected},
	}
	if got := summarize(low); strings.Contains(got, "CONFIRMED AFFECTED") {
		t.Errorf("low-confidence evidence produced the loudest headline in the tool: %q", got)
	}

	// A high-confidence source of the same class still earns the headline.
	high := append(low, model.VersionEvidence{
		Version: "0.2.93", Source: "manifest:~/.grok/version", Confidence: "high", Class: model.VersionConfirmedAffected,
	})
	if got := summarize(high); !strings.Contains(got, "CONFIRMED AFFECTED") {
		t.Errorf("high-confidence CONFIRMED AFFECTED was suppressed: %q", got)
	}
}
