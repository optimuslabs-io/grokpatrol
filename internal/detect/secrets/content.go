package secrets

// Content scanning: the --full-secrets-search half of this detector. The
// default path never calls anything in this file.
//
// Same contract as rules.go: blob bytes live in a transient buffer inside
// these functions and the ONLY things that leave are rule ids, paths, object
// ids, and counts. No error, note, or limitation string may interpolate
// scanned bytes.

import (
	"bytes"
	"context"
	"fmt"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/gitx"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// objRef is one blob version of one path in the uploaded object set. A path
// with five committed versions yields five refs: the deleted secret usually
// lives in an OLD version of a file that still exists, which the path->sha
// map (last version wins) cannot represent.
type objRef struct {
	sha  string
	path string
}

// contentHit is a content-rule match for a path: which rule, in which blob.
type contentHit struct {
	rule string
	blob string
}

// defaultMaxBlobScan guards tests (and future callers) that build an Env by
// hand: a zero cap would silently skip every blob, which is the one failure
// mode this detector must never have.
const defaultMaxBlobScan = 10 << 20

func blobCap(env *engine.Env) int64 {
	if env.MaxBlobScanBytes > 0 {
		return env.MaxBlobScanBytes
	}
	return defaultMaxBlobScan
}

// contentScanHistory fetches every implicated blob and runs the rule table
// over it. Returns path -> first matching rule. Failures are recorded on res
// and degrade to the filename floor rather than aborting the triage.
func contentScanHistory(ctx context.Context, env *engine.Env, repo string, pairs []objRef, res *engine.Result) map[string]contentHit {
	rs, err := compiledRules()
	if err != nil {
		// A build defect (the compile-all test pins every pattern), but never a
		// silent one: the scan downgrades to filename-only and says so.
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "secrets", Kind: "internal", Path: repo, Material: true,
			Message: "content rules failed to compile: " + err.Error(),
		})
		return nil
	}

	// The global path allowlist goes first so lockfiles, images and vendored
	// trees are never even fetched -- they are the bulk of many histories.
	shaPath := map[string]string{}
	var shas []string
	for _, pr := range pairs {
		if rs.pathSkipped(pr.path) {
			continue
		}
		if _, dup := shaPath[pr.sha]; dup {
			// Same blob under several paths is scanned once and attributed to the
			// first path seen. A deliberate fidelity gap: the credential inside is one
			// secret however many names it goes by, and one rotation entry suffices.
			continue
		}
		shaPath[pr.sha] = pr.path
		shas = append(shas, pr.sha)
	}
	if len(shas) == 0 {
		return nil
	}

	// Pass 1: types and sizes. Trees fall out here (rev-list --objects lists
	// them alongside blobs), and so does anything over the scan cap.
	cap := blobCap(env)
	var keep []string
	oversized := 0
	err = gitx.CatFileBatchCheck(ctx, repo, env.GitTimeout, shas, func(sha, objType string, size int64) error {
		if objType != "blob" || size < 0 {
			return nil
		}
		if size > cap {
			oversized++
			return nil
		}
		keep = append(keep, sha)
		return nil
	})
	if err != nil {
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "secrets", Kind: "io", Path: repo, Material: true,
			Message: "content scan could not size blobs: " + err.Error(),
		})
		return nil
	}
	if oversized > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%s: %s exceeded --max-blob-scan-bytes (%d) and were not content-scanned; filename matching still applied.",
			repo, engine.Plural(oversized, "blob"), cap))
	}

	// Pass 2: contents. The callback buffer is transient and reused; the rule
	// ids extracted from it are the only thing kept.
	hits := map[string]contentHit{}
	err = gitx.CatFileBatch(ctx, repo, env.GitTimeout, cap, keep, func(sha string, data []byte) error {
		if data == nil || looksBinary(data) {
			return nil // oversized/missing (already counted) or not text
		}
		path := shaPath[sha]
		if _, seen := hits[path]; seen {
			return nil // one content hit per path is all the checklist needs
		}
		if ids := rs.scan(path, data); len(ids) > 0 {
			hits[path] = contentHit{rule: ids[0], blob: sha}
		}
		return nil
	})
	if err != nil {
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "secrets", Kind: "io", Path: repo, Material: true,
			Message: "content scan could not read blobs: " + err.Error(),
		})
		// Partial hits are still real hits; fall through and report them.
	}
	return hits
}

// contentScanFile is the working-tree analogue, for repositories where git
// (and therefore history) is unavailable. One file, read through hostfs --
// the only sanctioned filesystem door -- and matched in memory.
func contentScanFile(env *engine.Env, absPath, relPath string) (rule string, ok bool, readErr error) {
	rs, err := compiledRules()
	if err != nil || rs.pathSkipped(relPath) {
		return "", false, err
	}
	data, err := hostfs.ReadFileCapped(absPath, blobCap(env))
	if err != nil {
		return "", false, err
	}
	if looksBinary(data) {
		return "", false, nil
	}
	if ids := rs.scan(relPath, data); len(ids) > 0 {
		return ids[0], true, nil
	}
	return "", false, nil
}

// looksBinary is git's own text/binary heuristic: a NUL byte in the first
// 8000 bytes means binary. The rule table is text-oriented (keystores and
// other binary credentials are the filename floor's job), so binary blobs
// are skipped rather than regexed byte soup.
func looksBinary(data []byte) bool {
	n := len(data)
	if n > 8000 {
		n = 8000
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}
