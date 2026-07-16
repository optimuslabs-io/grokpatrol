package report

import (
	"fmt"
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func TestDegradedSummarizesByDefault(t *testing.T) {
	var errs []model.ScanError
	for i := 0; i < 10; i++ {
		errs = append(errs, model.ScanError{
			Detector: "deepscan",
			Kind:     "permission",
			Path:     fmt.Sprintf("~/Library/Application Support/App%d", i),
			Message:  "open /Users/u/Library/Application Support/App: operation not permitted",
			Material: true,
		})
	}
	errs = append(errs, model.ScanError{
		Detector: "logs", Kind: "parse", Path: "~/.grok/logs/x.jsonl",
		Message: "truncated line", Material: false,
	})
	rep := &model.Report{Verdict: model.VerdictIndeterminate, Degraded: true, Errors: errs}

	def := renderStyle(rep, Style{})
	if !strings.Contains(def, "10 permission denials") || !strings.Contains(def, "1 other errors") {
		t.Errorf("header must keep true totals; got:\n%s", def)
	}
	if n := strings.Count(def, "\n  ! "); n != maxDegradedExamples {
		t.Errorf("default: want %d example lines, got %d:\n%s", maxDegradedExamples, n, def)
	}
	if strings.Contains(def, "operation not permitted") {
		t.Errorf("default permission samples should be path-only; got:\n%s", def)
	}
	if !strings.Contains(def, "... and 8 more") {
		t.Errorf("default must point at the remainder; got:\n%s", def)
	}
	if !strings.Contains(def, "--verbose") || !strings.Contains(def, "--json") {
		t.Errorf("default remainder must name --verbose and --json; got:\n%s", def)
	}

	verb := renderStyle(rep, Style{Verbose: true})
	if n := strings.Count(verb, "\n  ! "); n != len(errs) {
		t.Errorf("--verbose: want every error (%d), got %d:\n%s", len(errs), n, verb)
	}
	if strings.Contains(verb, "... and") {
		t.Errorf("--verbose must not truncate; got:\n%s", verb)
	}
}
