package queue

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/optimuslabs/grokpatrol/internal/hostfs"
)

// repoRootCache memoizes the two things that made manifest parsing quadratic on a
// large queue.
//
// repoRootOf walks up to 64 parent directories calling os.Stat at each level,
// looking for .git. A manifest lists every file in a repository, so the SAME repo
// root was rediscovered from scratch for every path in every manifest: tens of
// thousands of manifests, each holding many paths, each path triggering its own
// stat climb. On a fast disk that is merely wasteful. On the host that motivated
// this -- where `ls` on the queue took minutes -- it is millions of syscalls
// against the slowest thing in the system.
//
// Directory -> repo root is a pure function of the filesystem for the duration of
// one scan, so it is memoized, negative results included: "this directory is not
// inside a repo" is exactly the answer that cost a full 64-level climb to learn,
// and it is the common case for a path that is not in a git checkout at all.
type repoRootCache struct {
	roots     map[string]string // dir -> repo root ("" = not in a repo)
	manifests map[string]bool   // manifests already read during the walk
}

func newRepoRootCache() *repoRootCache {
	return &repoRootCache{roots: map[string]string{}, manifests: map[string]bool{}}
}

func (c *repoRootCache) markManifest(path string) { c.manifests[path] = true }
func (c *repoRootCache) seenManifest(path string) bool {
	return c.manifests[path]
}

// repoHintsFrom recovers local repository roots from a staged manifest, so that a
// repo sitting in the upload queue still gets secret-triaged even when its log
// lines have already rotated away.
//
// Only paths are extracted. Nothing else from the manifest reaches the report.
func repoHintsFrom(path string, roots *repoRootCache) []string {
	b, err := hostfs.ReadFileCapped(path, maxMetadataBytes)
	if err != nil {
		return nil
	}
	return hintsFromBytes(b, roots)
}

// hintsFromBytes is the parse half, split from the read so that walkQueue -- which
// has already read the manifest to test it for the bucket name -- does not read it
// a second time.
func hintsFromBytes(b []byte, roots *repoRootCache) []string {
	var doc any
	if json.Unmarshal(b, &doc) != nil {
		return nil
	}

	set := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for _, val := range t {
				walk(val)
			}
		case []any:
			for _, val := range t {
				walk(val)
			}
		case string:
			if repo := roots.repoRootOf(t); repo != "" {
				set[repo] = true
			}
		}
	}
	walk(doc)

	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// repoRootOf walks up from a per-file path looking for the directory that holds
// .git -- a manifest lists individual files, so the repo root has to be recovered.
//
// Every directory visited on the way up is memoized with the answer, so a second
// path from the same repository resolves without a single syscall.
func (c *repoRootCache) repoRootOf(p string) string {
	if !filepath.IsAbs(p) {
		return ""
	}
	// Starts at the path itself, not its parent: a manifest that names a repository
	// root directly must still resolve, and stat'ing <file>/.git simply fails.
	cur := filepath.Clean(p)

	var climbed []string
	for i := 0; i < 64; i++ { // bounded: no manifest path is 64 levels deep
		// Only DIRECTORIES are cached, which is why i == 0 (the path itself, almost
		// always a leaf file) is neither looked up nor recorded. A leaf never recurs --
		// a manifest lists each file once -- so caching it buys nothing and costs an
		// entry, and on a queue with millions of manifest paths those entries are the
		// whole map. Its parent, by contrast, is shared by every other file in the same
		// directory, so the second path in a repo resolves with no climb at all.
		if i > 0 {
			if root, ok := c.roots[cur]; ok {
				c.memoize(climbed, root)
				return root
			}
			climbed = append(climbed, cur)
		}

		if fi, err := os.Stat(filepath.Join(cur, ".git")); err == nil && (fi.IsDir() || fi.Mode().IsRegular()) {
			c.memoize(climbed, cur)
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// Cache the misses too. A path outside any repo is the expensive case -- it costs
	// the full climb to learn -- and on a queue full of them, not caching it is what
	// turns the stat storm quadratic.
	c.memoize(climbed, "")
	return ""
}

func (c *repoRootCache) memoize(dirs []string, root string) {
	for _, d := range dirs {
		c.roots[d] = root
	}
}
