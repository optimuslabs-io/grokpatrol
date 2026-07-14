// Package queue reports on Grok's upload staging area: the upload_queue
// directory, the codebase archives inside it, and the metadata.json manifests
// that name the destination bucket.
//
// It owns these findings rather than deepscan, which merely discovers them, and it
// re-checks every known grok home directly instead of trusting the walk. A populated
// upload_queue is one of the strongest indicators there is, so it does not depend on
// the expensive code path finding it first: if the walk is cut short by a timeout, or
// misses ~/.grok because the disk is enormous, the queue is still read.
package queue

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/hostfs"
	"github.com/optimuslabs/grokpatrol/internal/model"
	"github.com/optimuslabs/grokpatrol/internal/scan"
)

const maxMetadataBytes = 4 << 20

// maxHashedArchives bounds how many archives get a SHA-256.
//
// Hashing is the most expensive thing this detector does -- it reads every staged
// archive end to end -- and it is corroborating evidence, not detection: an archive
// is reported by path and size whether or not it is hashed, so skipping a hash
// cannot hide an indicator. That asymmetry is what makes a cap safe here when it
// would not be in a detector that finds things.
//
// A real host's upload_queue held tens of thousands of archives on a disk slow
// enough that `ls` took minutes. Hashing all of them would have read many gigabytes
// off that disk before printing a single line. A thousand hashes is more than enough
// to prove what the queue holds; the INVENTORY (every path, every size, the totals)
// stays complete regardless, and anything skipped is reported as a limitation rather
// than silently dropped.
const maxHashedArchives = 1000

const rotateAdvice = "Treat every credential reachable from the affected repositories' git history as compromised and rotate it. " +
	"Deleting these files locally does not recall what was already uploaded."

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "queue" }

func (d *Detector) Run(ctx context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result

	queues := append([]string{}, env.Discovered.UploadQueues...)
	metadata := append([]string{}, env.Discovered.MetadataFiles...)
	archives := append([]engine.ArchiveFile{}, env.Discovered.Archives...)
	hints := append([]string{}, env.Discovered.RepoHints...)
	sizes := map[string]queueSize{}

	// Direct check of every known grok home, independent of the deep scan: the queue
	// is too important to be reported only if the walk happened to reach it.
	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}
	roots := newRepoRootCache()
	for _, h := range homes {
		q := filepath.Join(h, "upload_queue")
		if fi, err := os.Stat(q); err == nil && fi.IsDir() {
			queues = appendUnique(queues, q)
			sc := walkQueue(ctx, q, roots, &res)
			sizes[q] = queueSize{Files: sc.files, Bytes: sc.bytes, Truncated: sc.truncated}
			for _, x := range sc.metadata {
				metadata = appendUnique(metadata, x)
			}
			for _, r := range sc.hints {
				hints = appendUnique(hints, r)
			}
			archives = append(archives, sc.archives...)
		}
	}

	// Manifests found by the deep scan were not read during our walk, so they still
	// need one read apiece. Those found by walkQueue were already read and are
	// skipped -- reading them twice is what the old code did.
	for _, m := range metadata {
		if roots.seenManifest(m) {
			continue
		}
		for _, r := range repoHintsFrom(m, roots) {
			hints = appendUnique(hints, r)
		}
	}

	archives = dedupeArchives(archives)
	hashArchives(ctx, archives, &res)

	sort.Strings(queues)
	sort.Strings(metadata)
	sort.Strings(hints)

	res.RepoHints = hints
	res.Findings = findings(queues, metadata, archives, sizes)
	res.Summary = summarize(queues, metadata, archives)
	return res, nil
}

func (*Detector) Describe() string {
	return "listing the upload_queue: staged codebase archives, and manifests naming the destination bucket"
}

func summarize(queues, metadata []string, archives []engine.ArchiveFile) string {
	if len(queues) == 0 {
		return "no upload queue on disk"
	}
	var parts []string
	if n := len(archives); n > 0 {
		var total int64
		for _, a := range archives {
			total += a.SizeBytes
		}
		parts = append(parts, fmt.Sprintf("%s staged (%s)", engine.Plural(n, "codebase archive"), humanBytes(total)))
	}
	if n := len(metadata); n > 0 {
		parts = append(parts, engine.Plural(n, "manifest")+" naming the bucket")
	}
	if len(parts) == 0 {
		// An empty queue is not an absence of evidence. It is either "nothing was ever
		// queued" or "the queue was drained" -- and a drained queue means the archives
		// went out. The progress line must not let a reader hear only the first one.
		return "upload queue present but empty (drained, or never used -- these look identical)"
	}
	return strings.Join(parts, ", ")
}

type queueSize struct {
	Files int
	Bytes int64
	// Truncated means the walk did not finish, so Files/Bytes are a FLOOR. Reporting
	// them as a total would understate a queue on exactly the host where it matters.
	Truncated bool
}

type scanResult struct {
	files     int
	bytes     int64
	archives  []engine.ArchiveFile
	metadata  []string
	hints     []string
	truncated bool
}

// walkQueue looks inside a staging directory in a SINGLE pass.
//
// It used to take three. The directory was walked once to collect archives and
// manifests, then walked again by sizeOf() to count files and bytes it had already
// seen, and every metadata.json was read twice -- once to test for the bucket name
// and again to recover repo hints. On an ordinary queue that waste is invisible. On
// the host that motivated this, where `ls` alone took minutes, it tripled the cost
// of the slowest thing the tool does.
//
// Archives are recorded by name and size and never opened. Those files are the
// user's own source code; a forensic tool does not unpack the data whose theft it
// is investigating. (Hashing happens later, in hashArchives, and even that only
// reads -- see the maxHashedArchives comment.)
func walkQueue(ctx context.Context, q string, roots *repoRootCache, res *engine.Result) scanResult {
	var sc scanResult

	err := filepath.WalkDir(q, func(path string, e fs.DirEntry, err error) error {
		// Cancellation is checked per entry rather than per directory: on a queue with
		// tens of thousands of files in one directory, a per-directory check would let
		// an un-cancellable walk run to completion inside a single WalkDir callback
		// sequence, which is precisely the case the timeout exists for.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			res.Errors = append(res.Errors, model.ScanError{
				Detector: "queue", Kind: "io", Path: path, Message: err.Error(), Material: true,
			})
			return nil
		}
		if e.IsDir() {
			return nil
		}

		info, ierr := e.Info()
		if ierr != nil {
			return nil
		}
		sc.files++
		sc.bytes += info.Size()

		name := strings.ToLower(e.Name())
		switch {
		case name == "metadata.json":
			// ONE read, both answers.
			b, rerr := hostfs.ReadFileCapped(path, maxMetadataBytes)
			if rerr != nil {
				return nil
			}
			roots.markManifest(path)
			if strings.Contains(string(b), scan.MarkerBucket) {
				sc.metadata = append(sc.metadata, path)
			}
			sc.hints = append(sc.hints, hintsFromBytes(b, roots)...)
		case strings.HasSuffix(name, ".tar.gz") || strings.HasSuffix(name, ".tgz"):
			sc.archives = append(sc.archives, engine.ArchiveFile{Path: path, SizeBytes: info.Size()})
		}
		return nil
	})

	// A cancelled walk is MATERIAL: the queue is one of the strongest indicators
	// there is, and a partial listing of it could have missed archives. It is
	// reported, and everything found before the deadline is kept -- returning an
	// error here instead would throw away proof we already hold.
	if err != nil && ctx.Err() != nil {
		sc.truncated = true
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "queue", Kind: "timeout", Path: q, Material: true,
			Message: fmt.Sprintf("upload_queue scan was interrupted after %d files; the queue may hold more than is reported here", sc.files),
		})
	}
	return sc
}

// hashArchives fills in SHA-256s, bounded by maxHashedArchives and interruptible.
// Anything left unhashed keeps its path and size: the inventory is complete even
// when the hashes are not.
func hashArchives(ctx context.Context, archives []engine.ArchiveFile, res *engine.Result) {
	hashed := 0
	for i := range archives {
		if ctx.Err() != nil || hashed >= maxHashedArchives {
			break
		}
		sum, err := scan.HashFile(archives[i].Path)
		if err != nil {
			continue
		}
		archives[i].SHA256 = sum
		hashed++
	}

	if hashed < len(archives) {
		// Immaterial: a missing hash cannot hide an archive, because the archive is
		// already in the report by path and size. Recording it as a material error
		// would degrade the verdict of every host with a large queue, for no gain.
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%d of %d staged archives were not hashed (limit %d, or the scan ran out of time). "+
				"Every archive is still listed by path and size; only the SHA-256 corroboration is missing.",
			len(archives)-hashed, len(archives), maxHashedArchives))
	}
}

func findings(queues, metadata []string, archives []engine.ArchiveFile, sizes map[string]queueSize) []model.Finding {
	var out []model.Finding

	for _, q := range queues {
		// Counted during the walk. sizeOf() used to re-walk the whole tree here to
		// recompute numbers walkQueue had already seen.
		sz := sizes[q]
		files, bytes := sz.Files, sz.Bytes

		var sev model.Severity
		var title, detail string
		switch {
		// An INTERRUPTED walk must never be described as an empty queue. The timeout
		// that stops the walk is likeliest to fire on exactly the host whose queue is
		// enormous -- so the case where we know least is the case where the queue is
		// probably fullest, and "present but empty ... nothing was ever queued" would
		// be the single most dangerous sentence this tool could print. What we saw is a
		// floor, never a total, and the wording has to say so.
		case sz.Truncated && files == 0:
			sev = model.SevHigh
			title = "Grok upload queue present, but the scan was interrupted before it could be read"
			detail = "The queue could not be enumerated within the time allowed. This is NOT evidence that it is empty -- " +
				"nothing at all is known about its contents. Re-run with a longer --detector-timeout."
		case sz.Truncated:
			sev = model.SevHigh
			title = fmt.Sprintf("Grok upload queue holds AT LEAST %d files (%s); the scan was interrupted before it finished",
				files, humanBytes(bytes))
			detail = "These are archives of your repositories, staged for transmission to xAI. The counts are a floor, not a " +
				"total: the walk was cut short, so the queue may hold considerably more."
		case files > 0:
			sev = model.SevHigh
			title = fmt.Sprintf("Grok upload queue holds %d files (%s)", files, humanBytes(bytes))
			detail = "These are archives of your repositories, staged for transmission to xAI."
		default:
			sev = model.SevMedium
			title = "Grok upload queue present but empty"
			detail = "The upload staging directory exists but is empty. That means either nothing was ever queued, or the " +
				"queue was drained -- and a drained queue means the archives went out, not that they never existed."
		}

		note := fmt.Sprintf("%d files", files)
		if sz.Truncated {
			note = fmt.Sprintf("at least %d files (scan interrupted)", files)
		}
		out = append(out, model.Finding{
			ID:          "queue.present",
			Detector:    "queue",
			Severity:    sev,
			Tags:        []string{model.TagStaging, model.TagExfil},
			Title:       title,
			Detail:      detail,
			Remediation: "Inspect the contents before deleting them: they are evidence of what was taken.",
			Evidence:    []model.Evidence{{Path: q, SizeBytes: bytes, Note: note}},
		})
	}

	if len(metadata) > 0 {
		ev := make([]model.Evidence, 0, len(metadata))
		for _, m := range metadata {
			ev = append(ev, model.Evidence{Path: m, Locator: "gs://" + scan.MarkerBucket + "/",
				Note: "manifest names the exfiltration bucket"})
		}
		out = append(out, model.Finding{
			ID:       "queue.metadata_bucket",
			Detector: "queue",
			Severity: model.SevCritical,
			Tags:     []string{model.TagExfil, model.TagStaging},
			Title:    fmt.Sprintf("%d staged manifests point at gs://%s/", len(metadata), scan.MarkerBucket),
			Detail: "A metadata.json mapping your local files to destination paths inside the exfiltration bucket means an " +
				"upload of your code was prepared with a concrete destination.",
			Remediation: rotateAdvice,
			Evidence:    ev,
		})
	}

	if len(archives) > 0 {
		var total int64
		ev := make([]model.Evidence, 0, len(archives))
		for _, a := range archives {
			total += a.SizeBytes
			ev = append(ev, model.Evidence{Path: a.Path, SizeBytes: a.SizeBytes, SHA256: a.SHA256,
				Note: "codebase archive (recorded, not opened)"})
		}
		out = append(out, model.Finding{
			ID:       "queue.codebase_archive",
			Detector: "queue",
			Severity: model.SevHigh,
			Tags:     []string{model.TagStaging, model.TagExfil},
			Title:    fmt.Sprintf("%d codebase archives staged on disk (%s)", len(archives), humanBytes(total)),
			Detail: "tar.gz snapshots of repositories, of the kind Grok uploads. grokpatrol recorded their names, sizes and " +
				"SHA-256 hashes but did not open them.",
			Remediation: "Keep these as evidence -- their contents are what was sent.",
			Evidence:    ev,
		})
	}

	return out
}

func appendUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func dedupeArchives(in []engine.ArchiveFile) []engine.ArchiveFile {
	seen := map[string]bool{}
	var out []engine.ArchiveFile
	for _, a := range in {
		if seen[a.Path] {
			continue
		}
		seen[a.Path] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
