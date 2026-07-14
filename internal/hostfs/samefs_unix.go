//go:build !windows

package hostfs

import (
	"os"
	"syscall"
)

// deviceID returns the filesystem device number, which lets the walker refuse to
// cross a mount point (a network share or an external drive under ~ would
// otherwise turn a home scan into an hours-long one).
func deviceID(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Dev), true
}

// isMountBarrier is a Windows-only concept; on Unix the device check above is
// exact, so nothing extra is needed.
func isMountBarrier(os.FileInfo) bool { return false }
