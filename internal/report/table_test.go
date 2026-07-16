package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestVisibleWidthStripsANSI(t *testing.T) {
	s := Style{Color: true}
	plain := "QUEUED"
	colored := s.c(red, plain)
	if visibleWidth(colored) != len(plain) {
		t.Fatalf("visibleWidth(%q) = %d, want %d", colored, visibleWidth(colored), len(plain))
	}
	if visibleWidth(colored) >= len(colored) {
		t.Fatal("visibleWidth did not strip ANSI escape bytes")
	}
}

func TestWriteTableAlignsDespiteColour(t *testing.T) {
	s := Style{Color: true}
	var buf bytes.Buffer
	writeTable(&buf, "", [][]string{
		{s.c(dim, "PATH"), s.c(dim, "STATUS")},
		{s.c(cyan, "~/a"), s.c(red, "QUEUED")},
		{s.c(cyan, "~/longer/path"), s.c(yellow, "COLLECTED")},
	})
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines:\n%s", len(lines), buf.String())
	}
	// STATUS column should start at the same visible offset on every row.
	type col struct{ start int }
	starts := make([]int, len(lines))
	for i, line := range lines {
		// Find second column by stripping ANSI then locating the pad after PATH.
		stripped := stripANSIForTest(line)
		// After first cell + pad, STATUS token.
		fields := strings.Fields(stripped)
		if len(fields) < 2 {
			t.Fatalf("line %d has no second column: %q", i, stripped)
		}
		starts[i] = strings.Index(stripped, fields[len(fields)-1])
	}
	if starts[0] != starts[1] || starts[1] != starts[2] {
		t.Fatalf("STATUS column misaligned: starts=%v\n%s", starts, buf.String())
	}
}

func stripANSIForTest(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == ';') {
				j++
			}
			if j < len(s) && s[j] == 'm' {
				i = j + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func TestTruncatePathKeepsEnds(t *testing.T) {
	long := "~/Users/someone/very/deep/nested/project/payments-api"
	got := truncatePath(long, 24)
	if got == long {
		t.Fatal("expected truncation")
	}
	if !strings.Contains(got, "…") {
		t.Fatalf("missing ellipsis: %q", got)
	}
	if !strings.HasPrefix(got, "~/") {
		t.Fatalf("lost home prefix: %q", got)
	}
	if !strings.HasSuffix(got, "payments-api") {
		t.Fatalf("lost basename: %q", got)
	}
	if visibleWidth(got) > 24 {
		t.Fatalf("still too long: %q (%d)", got, visibleWidth(got))
	}
}
