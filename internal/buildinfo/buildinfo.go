// Package buildinfo carries build-time identity stamped in via -ldflags -X.
package buildinfo

import "runtime"

var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// GoVersion is reported so a user can reproduce the build.
func GoVersion() string { return runtime.Version() }
