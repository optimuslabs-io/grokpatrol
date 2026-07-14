package report

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/optimuslabs/grokpatrol/internal/model"
)

// bigQueue models the case that motivated the display cap: a real host whose
// upload_queue held tens of thousands of staged archives, which the report printed
// one per line.
func bigQueue(n int) *model.Report {
	ev := make([]model.Evidence, 0, n)
	for i := 0; i < n; i++ {
		ev = append(ev, model.Evidence{
			Path:      fmt.Sprintf("/home/u/.grok/upload_queue/turn_%d/after_codebase.tar.gz", i),
			SizeBytes: 16 << 10,
			Note:      "codebase archive (recorded, not opened)",
		})
	}
	return &model.Report{
		Verdict: model.VerdictCompromised,
		Findings: []model.Finding{{
			ID:       "queue.codebase_archive",
			Detector: "queue",
			Severity: model.SevHigh,
			Tags:     []string{model.TagStaging, model.TagExfil},
			Title:    fmt.Sprintf("%d codebase archives staged on disk (312.5 MB)", n),
			Evidence: ev,
		}},
	}
}

// The report must not bury its own conclusions. 20,000 staged archives once
// produced a 30,040-line report: the tool got the verdict right and then made the
// reader scroll past thirty thousand paths to reach anything they could act on.
func TestHugeQueueDoesNotFloodTheReport(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, bigQueue(20000), Style{})

	lines := strings.Count(buf.String(), "\n")
	if lines > 100 {
		t.Errorf("report is %d lines for a 20k-archive queue; the display cap is not holding", lines)
	}

	paths := strings.Count(buf.String(), "after_codebase.tar.gz")
	if paths > maxEvidenceRows {
		t.Errorf("printed %d archive paths, want at most %d", paths, maxEvidenceRows)
	}
}

// Capping the rows without printing the finding's title would delete the only
// place a terminal reader can learn the true scale. "20 archives shown" must never
// be mistakable for "20 archives exist".
func TestCappedStagingStillReportsTheTrueTotal(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, bigQueue(20000), Style{})
	out := buf.String()

	if !strings.Contains(out, "20000 codebase archives staged on disk") {
		t.Error("the true total is missing from the report: a reader sees 20 paths and cannot tell there are 20,000")
	}
	// Derived from the cap, not hardcoded: the number is allowed to change, the
	// promise that the reader is told what was withheld is not.
	want := fmt.Sprintf("and %d more", 20000-maxEvidenceRows)
	if !strings.Contains(out, want) {
		t.Errorf("the withheld count is missing or wrong; want %q", want)
	}
}

// The pointer the terminal prints must be one the JSON can keep. This used to be
// false: logs capped evidence at CONSTRUCTION and then told the reader to consult
// --json for a full list that construction had already truncated. Truncation now
// happens only here, in the renderer, so the finding itself stays complete.
func TestDisplayCapDoesNotTruncateTheRecord(t *testing.T) {
	rep := bigQueue(20000)
	var buf bytes.Buffer
	Human(&buf, rep, Style{})

	if !strings.Contains(buf.String(), "full list in --json") {
		t.Fatal("the report does not point the reader at the complete list")
	}
	if got := len(rep.Findings[0].Evidence); got != 20000 {
		t.Errorf("rendering mutated the finding: %d evidence items left, want 20000. "+
			"--json is the forensic record and the renderer must not truncate it", got)
	}
}

// A queue small enough to print in full must print in full, with no truncation
// notice. The cap is for the pathological host, not the ordinary one.
func TestSmallQueueIsNotCapped(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, bigQueue(3), Style{})
	out := buf.String()

	if n := strings.Count(out, "after_codebase.tar.gz"); n != 3 {
		t.Errorf("printed %d of 3 archive paths", n)
	}
	if strings.Contains(out, "more") && strings.Contains(out, "full list in --json") {
		t.Error("a 3-archive queue was given a truncation notice it does not need")
	}
}
