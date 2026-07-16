package report

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestPulseRewritesCheckingLineWithColor(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Style{Color: true})
	p.Checking("deepscan", "walking the filesystem")
	p.Pulse("deepscan", "~/Library  ·  12 dirs")
	out := buf.String()
	if !strings.Contains(out, "\033[1A\033[2K") {
		t.Errorf("Pulse must rewind and clear the Checking line; got %q", out)
	}
	if !strings.Contains(out, "~/Library  ·  12 dirs") {
		t.Errorf("Pulse status missing; got %q", out)
	}
	p.Checked("deepscan", "nothing found", time.Millisecond)
	if !strings.Contains(buf.String(), "nothing found") {
		t.Errorf("Checked must still print the summary; got %q", buf.String())
	}
}

func TestPulseNoopWithoutColor(t *testing.T) {
	var buf bytes.Buffer
	p := NewProgress(&buf, Style{Color: false})
	p.Checking("deepscan", "walking")
	before := buf.Len()
	p.Pulse("deepscan", "should not appear")
	if buf.Len() != before {
		t.Errorf("Pulse must be silent without colour (pipes/logs); got %q", buf.String())
	}
	if strings.Contains(buf.String(), "should not appear") {
		t.Error("Pulse leaked status into a non-colour stream")
	}
}
