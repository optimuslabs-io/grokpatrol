package engine

import (
	"strconv"
	"strings"
	"time"
)

// Progress narrates the scan while it runs.
//
// It exists because this tool is slow in the one situation where it matters. A
// full disk walk takes a minute or two on a large machine, and the person running
// it has just been told their source code may be in someone else's bucket. A blank
// terminal for two minutes invites them to kill it and conclude nothing was wrong.
//
// It also answers a question the final report cannot: what did you LOOK for? A
// verdict of CLEAN is only worth as much as the list of things that were checked to
// reach it, and that list should not be something you have to read the source to
// discover.
//
// Progress goes to stderr, never stdout: `grokpatrol --json | jq` must keep working.
type Progress interface {
	// Checking announces what a detector is about to look for, before it starts.
	Checking(detector, what string)
	// Checked reports what it found. summary is the detector's own one-liner.
	Checked(detector, summary string, took time.Duration)
	// Done closes out the run.
	Done(total time.Duration)
}

// Describer lets a detector say, in its own words, what it is about to search for.
//
// It is an optional interface rather than a method on Detector so that adding a
// detector does not force one -- but a detector without it appears in the progress
// output as a bare name, which is exactly the "trust me" opacity this is meant to
// remove. Implement it.
type Describer interface {
	Describe() string
}

// describe returns a detector's own description of what it hunts for.
func describe(d Detector) string {
	if x, ok := d.(Describer); ok {
		return x.Describe()
	}
	return ""
}

// Plural renders a count with its noun: "1 archive", "2 archives". Every detector
// writes progress lines a human reads, and "1 repositories found" is the kind of
// detail that makes a reader trust the rest of the output slightly less.
func Plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	if strings.HasSuffix(noun, "y") {
		return strconv.Itoa(n) + " " + strings.TrimSuffix(noun, "y") + "ies"
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// nopProgress is used when nothing is watching (--quiet, or a piped stderr).
type nopProgress struct{}

func (nopProgress) Checking(string, string)               {}
func (nopProgress) Checked(string, string, time.Duration) {}
func (nopProgress) Done(time.Duration)                    {}
