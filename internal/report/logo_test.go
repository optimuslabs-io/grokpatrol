package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// The logo's one hard invariant: with colour off (a pipe, a redirect, NO_COLOR), it
// emits NO ANSI escape at all, so a captured stderr stays clean and `--json | jq` --
// which shares nothing with this stderr path anyway -- is never at risk. The plain
// fallback still carries the wordmark's subtitle and the attribution.
func TestLogoIsPipeSafeWithoutColor(t *testing.T) {
	var b bytes.Buffer
	NewProgress(&b, Style{Color: false}).Splash()
	out := b.String()

	if strings.Contains(out, "\033[") {
		t.Error("the logo emitted ANSI escapes with colour disabled -- a pipe or log file would see them")
	}
	if !strings.Contains(out, "Optimus Labs") || !strings.Contains(out, "Grok Build repo exfil exposure check") {
		t.Error("the plain logo fallback is missing its subtitle")
	}
	// A forensic scanner that hunts for the bucket marker must not carry it in its own
	// splash, or it would detect itself. (The compiled-binary self-check covers the
	// whole artifact; this catches the logo at unit-test speed.)
	if strings.Contains(out, scan.MarkerBucket) {
		t.Error("the logo contains the exfiltration bucket marker -- the binary would detect itself")
	}
}
