package hostfs

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
)

// Walker traverses a tree read-only.
//
// It deliberately has NO prune list. Directory traversal is cheap -- it is a
// getdents loop returning names and types -- and the structural indicators we
// hunt for (an upload_queue dir, a stray .grok, a *codebase.tar.gz) are visible
// from the directory entry alone. Skipping node_modules or Library/Caches to
// "go faster" would only skip places a staged archive could actually be hiding.
// The expense in this tool is content-reading, and that is gated separately by
// the caller's filter cascade -- not here.
type Walker struct {
	FollowSymlinks  bool
	CrossFilesystem bool

	// OnError is called for every unreadable directory or file (macOS TCC will
	// deny ~/Documents and friends). It must record and continue: an EPERM has to
	// degrade the verdict, never abort the walk.
	OnError func(path string, err error)
}

// Visit is called for each entry. Return fs.SkipDir to skip a directory's
// contents; any other error aborts the walk.
type Visit func(path string, d fs.DirEntry) error

// Walk traverses root. Symlinks are never followed (which kills traversal
// cycles, cross-filesystem escapes and ~/Library/CloudStorage download storms in
// a single rule), and by default the walk does not leave the filesystem it
// started on.
func (w *Walker) Walk(ctx context.Context, root string, visit Visit) error {
	rootDev, haveRootDev := uint64(0), false
	fi, err := os.Lstat(root)
	if err != nil {
		// A root that does not exist is NOT an error and must not be reported as one.
		// We probe a fixed list of plausible install locations (~/bin, /opt/homebrew,
		// %LOCALAPPDATA%), and most of them are absent on any given machine. Reporting
		// each absence would set Degraded and downgrade a genuinely clean host to
		// INDETERMINATE -- which is exactly the kind of noise that trains people to
		// ignore the tool.
		if !os.IsNotExist(err) {
			w.reportErr(root, err)
		}
		return nil
	}
	rootDev, haveRootDev = deviceID(fi)

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// Unreadable dir or entry: record it, keep walking. This is the single
			// most common real-world case (macOS TCC) and it must not stop the scan.
			w.reportErr(path, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		if d.Type()&fs.ModeSymlink != 0 && !w.FollowSymlinks {
			return nil // never even stat it
		}

		if d.IsDir() && path != root && !w.CrossFilesystem {
			fi, ferr := os.Lstat(path)
			if ferr != nil {
				w.reportErr(path, ferr)
				return fs.SkipDir
			}
			// Windows has no st_dev; the best available barrier is the reparse point
			// attribute, which covers junctions and mounted volumes. The asymmetry is
			// surfaced in the report's Limitations rather than papered over.
			if isMountBarrier(fi) {
				return fs.SkipDir
			}
			if dev, ok := deviceID(fi); ok && haveRootDev && dev != rootDev {
				return fs.SkipDir
			}
		}

		return visit(path, d)
	})
}

func (w *Walker) reportErr(path string, err error) {
	if w.OnError != nil {
		w.OnError(path, err)
	}
}
