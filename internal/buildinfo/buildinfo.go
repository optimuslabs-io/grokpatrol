// Package buildinfo carries build-time identity stamped in via -ldflags -X.
package buildinfo

import "runtime"

// Version is the tool's own release version. It is a real number rather than "dev"
// so that a report pasted into a ticket, or compared across a fleet, says which build
// produced it -- a forensic report whose provenance is "dev" is one nobody can
// reproduce. The Makefile overrides this from `git describe` when a tag exists.
var (
	Version = "0.1.0"
	Commit  = "none"
	Date    = "unknown"
)

// GoVersion is reported so a user can reproduce the build.
func GoVersion() string { return runtime.Version() }
