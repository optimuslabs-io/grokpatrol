package hostfs

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// maxSymlinkDepth backstops the cycle guard. The resolved-real-path set below is the
// real protection; this only bounds a pathological chain of DISTINCT symlinks
// (a -> b -> c -> ...) that never repeats a directory and so never trips the set.
const maxSymlinkDepth = 40

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
	// FollowSymlinks, off by default, descends into symlinked directories and hands
	// symlinked files to the visitor. It is off by default because a naive follow
	// cycles and escapes mounts; when on, cycles are caught by a resolved-real-path
	// set and mount escapes by the same device check a real directory gets (see
	// followLink). filepath.WalkDir never follows a symlink on its own, so this
	// behavior is implemented here explicitly rather than delegated to it.
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

// Walk traverses root. By default symlinks are not followed (which kills traversal
// cycles, cross-filesystem escapes and ~/Library/CloudStorage download storms in a
// single rule) and the walk does not leave the filesystem it started on. With
// FollowSymlinks set, symlinks ARE followed, but under both guards restored
// explicitly: a resolved-real-path set prevents cycles, and the device check is
// measured against the ORIGINAL root so a link cannot smuggle the walk onto a mount
// it would otherwise refuse.
func (w *Walker) Walk(ctx context.Context, root string, visit Visit) error {
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
	rootDev, haveRootDev := deviceID(fi)

	// seen holds the resolved real paths of directories already descended into via a
	// symlink. It is what makes following cycle-safe: ~/a/loop -> ~/a resolves to a
	// directory already on the descent and is refused. Because filepath.WalkDir never
	// follows a symlink itself, without this set there would be nothing to guard.
	seen := map[string]bool{}
	return w.walkDir(ctx, root, visit, seen, rootDev, haveRootDev, 0)
}

// walkDir runs one filepath.WalkDir pass over root. It is called again by followLink
// for each symlinked directory, so all of rootDev/haveRootDev/seen/depth thread
// through unchanged: the mount barrier stays measured against the original root and
// the cycle set stays shared across every nested pass.
func (w *Walker) walkDir(ctx context.Context, root string, visit Visit, seen map[string]bool, rootDev uint64, haveRootDev bool, depth int) error {
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

		if d.Type()&fs.ModeSymlink != 0 {
			if !w.FollowSymlinks {
				return nil // default: never even stat it
			}
			return w.followLink(ctx, path, visit, seen, rootDev, haveRootDev, depth)
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

// followLink handles a symlink encountered with FollowSymlinks set. A link to a file
// is handed to the visitor as a regular entry under the link's own path (OpenRead
// follows the link, so the target's bytes are what a later content scan reads); a
// link to a directory is descended into, under the same cross-filesystem policy a
// real directory gets and guarded against cycles by the resolved-path set.
func (w *Walker) followLink(ctx context.Context, linkPath string, visit Visit, seen map[string]bool, rootDev uint64, haveRootDev bool, depth int) error {
	if depth >= maxSymlinkDepth {
		w.reportErr(linkPath, fmt.Errorf("symlink nesting exceeds %d levels; not followed", maxSymlinkDepth))
		return nil
	}

	ti, err := os.Stat(linkPath) // Stat (not Lstat) resolves the link to its target
	if err != nil {
		w.reportErr(linkPath, err) // a dangling or unreadable target
		return nil
	}

	if !ti.IsDir() {
		if ti.Mode().IsRegular() {
			// A symlinked grok binary or staged *codebase.tar.gz: give the visitor a
			// regular-file entry so it is inspected. Not a socket/fifo/device -- reading
			// those could block the scanner forever.
			return skipDirToNil(visit(linkPath, namedEntry{filepath.Base(linkPath), ti}))
		}
		return nil
	}

	// A symlink to a directory. Apply the SAME cross-filesystem policy as a real dir,
	// measured against the original root: following a link must not become a backdoor
	// across a mount the walk would otherwise refuse.
	if !w.CrossFilesystem {
		if isMountBarrier(ti) {
			return nil
		}
		if dev, ok := deviceID(ti); ok && haveRootDev && dev != rootDev {
			return nil
		}
	}

	real, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		w.reportErr(linkPath, err)
		return nil
	}
	if seen[real] {
		return nil // already descended into this real directory: a cycle or a duplicate
	}
	seen[real] = true

	// Let a symlink that is itself a structural indicator be recognized by its own
	// name -- a `.grok` or `upload_queue` symlink, whose target directory is named
	// something else -- before descending into the target's contents.
	if err := skipDirToNil(visit(linkPath, namedEntry{filepath.Base(linkPath), ti})); err != nil {
		return err
	}
	return w.walkDir(ctx, real, visit, seen, rootDev, haveRootDev, depth+1)
}

// skipDirToNil swallows fs.SkipDir returned by a visitor for a synthesized entry:
// followLink calls visit directly rather than through WalkDir, so SkipDir ("do not
// descend") is not an abort -- it just means the caller has seen this path already.
func skipDirToNil(err error) error {
	if errors.Is(err, fs.SkipDir) {
		return nil
	}
	return err
}

// namedEntry is an fs.DirEntry for a symlink target that reports the LINK's name
// (so a `.grok` symlink is recognized as such) while carrying the TARGET's type and
// info (so it is walked/inspected as the directory or file it resolves to).
type namedEntry struct {
	name string
	info os.FileInfo
}

func (e namedEntry) Name() string               { return e.name }
func (e namedEntry) IsDir() bool                { return e.info.IsDir() }
func (e namedEntry) Type() fs.FileMode          { return e.info.Mode().Type() }
func (e namedEntry) Info() (fs.FileInfo, error) { return e.info, nil }

func (w *Walker) reportErr(path string, err error) {
	if w.OnError != nil {
		w.OnError(path, err)
	}
}
