// Package grokver classifies Grok Build version strings against the known-bad range.
package grokver

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/optimuslabs/grokpatrol/internal/model"
)

// Semver matches a bare version, with or without a leading v.
var Semver = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.\-]+)?$`)

// ConfirmedAffected is the version publicly reproduced as uploading whole repos.
const ConfirmedAffected = "0.2.93"

// ReportedAffectedMax is the highest version reported to still carry the
// collector. It is *reported*, not independently verified by this tool -- which
// is exactly why nothing above it is ever called clean.
const ReportedAffectedMax = "0.2.99"

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
