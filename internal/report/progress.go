package report

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// Progress prints, live, what the scan is looking for and what it found.
//
// Two reasons it exists, and the second is the important one:
//
//  1. The filesystem walk takes a minute or two on a large disk. Someone who has
//     just been told their source code may be in someone else's bucket should not
//     watch a blank terminal and wonder whether the tool has hung.
//
//  2. A verdict is only worth the list of things that were checked to reach it.
//     CLEAN means nothing until you know what was searched for, and that list
//     should not be something you have to read the source to find. The progress
//     output is the tool stating its own coverage, every run, out loud.
//
// It writes to stderr. Nothing but the report goes to stdout, so
// `grokpatrol --json | jq` keeps working while a human still sees the scan.
type Progress struct {
	w  io.Writer
	s  Style
	mu sync.Mutex
	n  int
	// open is the detector name whose Checking line is still the last thing on
	// screen and may be rewritten by Pulse. Empty when no line is open (after
	// Checked, or when colour is off and we refuse in-place rewrites).
	open string
}

func NewProgress(w io.Writer, s Style) *Progress {
	return &Progress{w: w, s: s}
}

// Splash plays the animated GROKPATROL logo before the scan narration begins. It is
// UX personality and writes ONLY to the progress stream (stderr) -- the caller gates
// it on stderr being a TTY with colour, so a pipe, a redirect, or `--quiet` (which
// never constructs a Progress) all skip it, and `grokpatrol --json | jq` is untouched.
func (p *Progress) Splash() {
	animateLogo(p.w, p.s)
}

// Header names the machine being scanned. Printed before the first check, so the
// output says what it is looking at before it says what it is looking for.
func (p *Progress) Header(home string) {
	fmt.Fprintf(p.w, "%s %s\n\n", p.s.c(bold, "grokpatrol"), p.s.c(dim, "scanning "+home))
}

func (p *Progress) Checking(detector, what string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	p.writeCheckingLocked(detector, what)
	// Only a colour (TTY) session rewrites in place: pipes and log captures must
	// not fill with hundreds of Pulse lines, and without ANSI we cannot erase.
	if p.s.Color {
		p.open = detector
	}
}

// Pulse rewrites the open Checking line with a live status so a long deepscan walk
// does not look hung. No-op when colour is off (no in-place rewrite) or when no
// Checking line is open for this detector.
func (p *Progress) Pulse(detector, status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.s.Color || p.open != detector || status == "" {
		return
	}
	// Move to the previous line, clear it, reprint. Checking ended with \n, so the
	// cursor sits on the blank line below; one CUU puts us on the → row.
	fmt.Fprint(p.w, "\033[1A\033[2K\r")
	p.writeCheckingLocked(detector, status)
}

// Checked prints what the detector found. The detector is named again here, and not
// only on the Checking line: the four readers run in parallel, so their results are
// printed as a block after the barrier and a result you cannot attribute to a check
// is noise.
//
// A detector that found nothing says so out loud. A silent line is indistinguishable
// from a detector that died, and this tool's worst failure mode is a crash that reads
// like a clean host.
func (p *Progress) Checked(detector, summary string, took time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.open = ""
	if summary == "" {
		summary = "nothing found"
	}
	fmt.Fprintf(p.w, "    %s %-9s %s %s\n",
		p.s.c(green, "✓"), p.s.c(dim, detector), summary, p.s.c(dim, "("+fmtDur(took)+")"))
}

func (p *Progress) Done(total time.Duration) {
	fmt.Fprintf(p.w, "\n  %s\n\n", p.s.c(dim, fmt.Sprintf("%d checks in %s", p.n, fmtDur(total))))
}

func (p *Progress) writeCheckingLocked(detector, what string) {
	fmt.Fprintf(p.w, "  %s %-9s %s\n", p.s.c(cyan, "→"), detector, p.s.c(dim, what))
}

// fmtDur never prints "0s" for work that did happen: a check reported as taking no
// time at all looks like a check that was skipped.
func fmtDur(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return "<1ms"
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}
