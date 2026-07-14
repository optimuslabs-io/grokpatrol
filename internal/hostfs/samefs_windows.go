//go:build windows

package hostfs

import (
	"os"
	"syscall"
)

// deviceID has no Windows equivalent: there is no st_dev, so the walker cannot
// make an exact same-filesystem decision. Reporting ok=false makes that honest
// rather than silently wrong; the caller falls back to isMountBarrier and states
// the limitation in the report.
func deviceID(os.FileInfo) (uint64, bool) { return 0, false }

// isMountBarrier reports whether a directory is a reparse point. That covers
// junctions, mounted volumes and OneDrive-style placeholder dirs -- the best
// available stand-in for the Unix device check.
func isMountBarrier(fi os.FileInfo) bool {
	d, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return false
	}
	return d.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
