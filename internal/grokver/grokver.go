// Package grokver classifies Grok Build version strings against the known-bad range.
package grokver

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// Semver matches a bare version, with or without a leading v.
var Semver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.\-]+)?$`)

// ConfirmedAffected is the version publicly reproduced as uploading whole repos.
const ConfirmedAffected = "0.2.93"

// ReportedAffectedMax is the highest version reported to still carry the
// collector. It is *reported*, not independently verified by this tool -- which
// is exactly why nothing above it is ever called clean.
const ReportedAffectedMax = "0.2.99"

// LatestObserved is the newest Grok release this version of grokpatrol was checked
// against: its config keys, log event names and upload_queue layout were compared with
// that build's own documentation. A newer release is not suspect, it is unexamined,
// and the report says so rather than assuming nothing moved. Bump it only after
// re-checking those three things against the newer build.
const LatestObserved = "1.0.77"

// NewerThanObserved reports whether v is a parseable version above LatestObserved.
// An unparseable version is not "newer": it is unknown, and Class already says that.
func NewerThanObserved(v string) bool {
	if _, ok := triple(v); !ok {
		return false
	}
	return Compare(v, LatestObserved) > 0
}

// Compare orders two versions by major.minor.patch, ignoring any pre-release or
// build suffix: -1, 0 or +1. An unparseable version sorts below every parseable one.
func Compare(a, b string) int {
	x, okA := triple(a)
	y, okB := triple(b)
	switch {
	case !okA && !okB:
		return 0
	case !okA:
		return -1
	case !okB:
		return 1
	}
	for i := range x {
		switch {
		case x[i] < y[i]:
			return -1
		case x[i] > y[i]:
			return 1
		}
	}
	return 0
}

func triple(v string) ([3]int, bool) {
	m := Semver.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		out[i], _ = strconv.Atoi(m[i+1])
	}
	return out, true
}

// Class buckets a version string.
//
// There is deliberately no "SAFE" class. This tool has no ground truth for a
// fixed version, so a version above the reported range is UNKNOWN, not clean --
// the verdict is driven by artifacts on disk (logs, queue, marker strings), never
// by a version number we would have to take on faith.
func Class(v string) string {
	v = strings.TrimSpace(v)
	m := Semver.FindStringSubmatch(v)
	if m == nil {
		return model.VersionUnknown
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])

	if maj == 0 && min == 2 && patch == 93 {
		return model.VersionConfirmedAffected
	}
	if maj == 0 && min == 2 && patch <= 99 {
		return model.VersionReportedAffected
	}
	if maj == 0 && min < 2 {
		return model.VersionReportedAffected // older than the analyzed range; assume it collects too
	}
	return model.VersionUnknown
}

// Plausible filters the semver-shaped strings pulled out of a binary. A packed
// CLI contains dozens of unrelated dependency versions, so this is only ever used
// as low-confidence evidence.
func Plausible(v string) bool { return Semver.MatchString(v) }
