// Package deepscan walks the host looking for Grok artifacts: the binary itself
// (identified by the exfiltration bucket name embedded in it), stray .grok homes,
// staged upload_queue directories, codebase archives, and metadata.json files
// that name the destination bucket.
//
// It walks EVERYTHING -- node_modules, caches, the Trash -- because traversal is
// cheap (a getdents loop yielding names and types) and a staged archive can sit
// anywhere. What it does not do is read everything: content reads are gated behind
// a magic-byte filter, and that gate is what keeps a whole-home scan to seconds.
package deepscan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// maxMetadataBytes caps a metadata.json read. It is a manifest, not a payload.
const maxMetadataBytes = 4 << 20

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "deepscan" }

type candidate struct {
	path string
	size int64
}

func (d *Detector) Run(ctx context.Context, env *engine.Env) (engine.Result, error) {
	var (
		res  engine.Result
		mu   sync.Mutex // guards res and disc during the worker fan-out
		disc = engine.Discovered{}
	)

	// A failure is MATERIAL if it could have hidden a grok artifact from us: a
	// directory we could not enter, or a file we could not open that might have been
	// an executable. A denied read on a .plist could not have hidden anything, and
	// counting it would make every macOS run INDETERMINATE forever.
	addErr := func(kind, path, msg string, material bool) {
		mu.Lock()
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "deepscan", Kind: kind, Path: path, Message: msg, Material: material,
		})
		mu.Unlock()
	}

	// There is no way to skip this walk. --quick used to, and the limitation it had
	// to print said everything: "the filesystem was not searched, so a grok binary, a
	// staged archive, or a second .grok home would not have been seen". It reported
	// CLEAN with exactly the same confidence as a scan that had looked. A fast answer
	// that is permitted to miss the evidence is not a cheaper version of this tool,
	// it is a different and worse one.
	candidates := make(chan candidate, 1024)
	var wg sync.WaitGroup

	workers := env.Concurrency
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range candidates {
				if ctx.Err() != nil {
					return
				}
				hit, err := inspect(c)
				if err != nil {
					addErr("permission", c.path, err.Error(), true)
					continue
				}
				if hit == nil {
					continue
				}
				mu.Lock()
				disc.Binaries = append(disc.Binaries, *hit)
				mu.Unlock()
			}
		}()
	}

	// One producer. Directory traversal is getdents-bound and does not parallelize
	// usefully on a single volume; splitting it would buy lock contention and
	// nondeterministic output, not speed.
	walker := &hostfs.Walker{
		FollowSymlinks:  env.FollowSymlinks,
		CrossFilesystem: env.CrossFilesystem,
		OnError: func(path string, err error) {
			kind := "io"
			if os.IsPermission(err) {
				kind = "permission"
			}
			// If the thing we could not read cannot possibly be a grok binary (a .plist,
			// an image, a database), the failure is real but immaterial: it did not hide
			// an indicator, so it must not degrade the verdict.
			addErr(kind, path, err.Error(), !scan.SkipByName(path))
		},
	}

	seenDir := map[string]bool{}
	var (
		dirsVisited int
		lastPulse   time.Time
		lastPath    string
	)
	// pulseInterval is how often the → deepscan line may rewrite. Faster feels
	// livelier; much faster burns CPU redrawing ANSI for no new information.
	const pulseInterval = 150 * time.Millisecond
	pulse := func(force bool) {
		if env.Progress == nil {
			return
		}
		now := time.Now()
		if !force && now.Sub(lastPulse) < pulseInterval {
			return
		}
		lastPulse = now
		mu.Lock()
		finds := len(disc.Installs()) + len(disc.UploadQueues) + len(disc.Archives)
		if n := len(disc.GrokHomes); n > 1 {
			// Configured home alone is not a "find"; extras are.
			finds += n - 1
		}
		mu.Unlock()
		where := lastPath
		if where == "" {
			where = "starting"
		} else {
			where = truncatePulsePath(hostfs.Display(where, env.Home), 48)
		}
		status := fmt.Sprintf("%s  ·  %s", where, engine.Plural(dirsVisited, "dir"))
		if finds > 0 {
			status += "  ·  " + engine.Plural(finds, "find")
		}
		env.Progress.Pulse("deepscan", status)
	}

	for _, root := range roots(env) {
		if ctx.Err() != nil {
			break
		}
		_ = walker.Walk(ctx, root, func(path string, e fs.DirEntry) error {
			lastPath = path
			if e.IsDir() {
				if seenDir[path] {
					return fs.SkipDir // priority roots overlap the home walk; do not redo them
				}
				seenDir[path] = true
				dirsVisited++
				structuralDir(path, e, &mu, &disc)
				pulse(false)
				return nil
			}
			if !hostfs.IsRegular(e) {
				return nil
			}
			if structuralFile(path, e, &mu, &disc, addErr) {
				pulse(true) // archives / metadata are real finds -- show immediately
				return nil
			}
			// The upload_queue holds the victim's OWN staged data, not grok installs. Its
			// codebase archives and metadata.json manifests are already recorded by name
			// above (structuralFile); everything else here is queue bookkeeping. Marker-
			// scanning it for an "installed binary" is meaningless -- a file in the outbound
			// queue is payload, not the collector -- and on a queue of tens of thousands of
			// files it is the walk's most expensive dead end. Record nothing else from it.
			if underUploadQueue(path) {
				return nil
			}
			// Reject by NAME before paying for an open+read+close. A home directory holds
			// hundreds of thousands of files and syscalls dominated the first real run;
			// an image or a font cannot be a grok binary whatever its bytes say.
			if scan.SkipByName(path) {
				return nil
			}
			info, err := e.Info()
			if err != nil {
				return nil
			}
			if info.Size() == 0 || info.Size() > env.MaxFileSize {
				return nil
			}
			select {
			case candidates <- candidate{path: path, size: info.Size()}:
			case <-ctx.Done():
				return ctx.Err()
			}
			pulse(false)
			return nil
		})
	}
	close(candidates)
	wg.Wait()
	pulse(true) // final counts before Checked replaces the narrative

	// The configured grok home is always in play, whether or not the walk saw it.
	disc.GrokHomes = appendUnique(disc.GrokHomes, env.GrokHome)
	sortAll(&disc)

	res.Discovered = &disc
	res.Findings = findings(&disc, env)
	res.Summary = summarize(&disc)
	return res, nil
}

// Describe is what the progress display prints before the walk starts. It is the
// tool stating its own coverage: a reader who is about to be told CLEAN deserves to
// know what was searched for before the answer arrives.
func (*Detector) Describe() string {
	return "walking the filesystem for grok homes, upload queues, staged archives, " +
		"and executables carrying the bucket name"
}

// summarize is what the walk found, said out loud. A scan that found nothing says
// so explicitly: silence is indistinguishable from a detector that died, and a
// crash that produces no findings reads exactly like a clean host.
func summarize(d *engine.Discovered) string {
	installs := len(d.Installs())
	// The configured grok home is always counted in, walk or no walk, so it is not
	// evidence of anything by itself and must not be reported as if it were.
	homes := len(d.GrokHomes)

	var parts []string
	if installs > 0 {
		parts = append(parts, engine.Plural(installs, "executable")+" carrying the bucket name")
	}
	if n := len(d.UploadQueues); n > 0 {
		parts = append(parts, engine.Plural(n, "upload queue"))
	}
	if n := len(d.Archives); n > 0 {
		parts = append(parts, engine.Plural(n, "staged archive"))
	}
	if homes > 1 {
		parts = append(parts, engine.Plural(homes, "grok home"))
	}
	if len(parts) == 0 {
		return "no grok install, queue or staged archive on disk"
	}
	return strings.Join(parts, ", ")
}

// roots: priority locations first, so an install is reported in well under a
// second even when the full home walk takes a minute.
func roots(env *engine.Env) []string {
	// A confined walk (tests only) covers exactly the configured roots plus the grok
	// home and deliberately skips the system-bin dirs. A production scan cannot do
	// this -- an install lands in /usr/local/bin as readily as under home -- but a
	// test fixture is self-contained, and walking the runner's system dirs (8 GB of
	// /opt/hostedtoolcache on a CI box) added minutes to every engine test under
	// -race for coverage the fixture never needed. See engine.Env.ConfineWalk.
	if env.ConfineWalk {
		return dedupe(append(append([]string{}, env.ScanRoots...), env.GrokHome))
	}
	var out []string
	out = append(out, hostfs.PriorityRoots(env.Home)...)
	out = append(out, hostfs.SystemBinDirs()...)
	out = append(out, env.GrokHome)
	if len(env.ScanRoots) > 0 {
		out = append(out, env.ScanRoots...)
	} else {
		out = append(out, env.Home)
	}
	return dedupe(out)
}

// structuralDir handles the indicators visible from a directory entry alone --
// no file is opened, which is why the walk can afford to cover everything.
func structuralDir(path string, e fs.DirEntry, mu *sync.Mutex, disc *engine.Discovered) {
	name := strings.ToLower(e.Name())
	mu.Lock()
	defer mu.Unlock()
	switch name {
	case "upload_queue":
		disc.UploadQueues = appendUnique(disc.UploadQueues, path)
	case ".grok":
		disc.GrokHomes = appendUnique(disc.GrokHomes, path)
	}
}

// underUploadQueue reports whether any ancestor directory in path is an upload_queue --
// the same name structuralDir keys the queue off. A file below one is staged outbound
// data, never a grok install, so the content scan skips it.
func underUploadQueue(path string) bool {
	for _, seg := range strings.Split(path, string(filepath.Separator)) {
		if strings.EqualFold(seg, "upload_queue") {
			return true
		}
	}
	return false
}

// structuralFile reports whether the file was fully handled by a name-based rule
// and needs no content scan.
func structuralFile(path string, e fs.DirEntry, mu *sync.Mutex, disc *engine.Discovered, addErr func(kind, path, msg string, material bool)) bool {
	name := strings.ToLower(e.Name())

	// A *codebase.tar.gz is the victim's own source code, staged for upload. It is
	// recorded by name, size and hash and NEVER opened: a forensic tool does not
	// unpack the data it is investigating the theft of.
	if strings.HasSuffix(name, "codebase.tar.gz") {
		info, err := e.Info()
		if err != nil {
			return true
		}
		sum, herr := scan.HashFile(path)
		if herr != nil {
			addErr("io", path, herr.Error(), true)
		}
		mu.Lock()
		disc.Archives = append(disc.Archives, engine.ArchiveFile{
			Path: path, SizeBytes: info.Size(), SHA256: sum,
		})
		mu.Unlock()
		return true
	}

	if name == "metadata.json" {
		if inspectMetadata(path, mu, disc) {
			return true
		}
		return true // a metadata.json is never an executable candidate either way
	}
	return false
}

// inspectMetadata records a staged manifest that names the destination bucket.
// The queue detector is what interprets it; deepscan only finds it. The
// manifest's contents are never echoed into the report.
func inspectMetadata(path string, mu *sync.Mutex, disc *engine.Discovered) bool {
	b, err := hostfs.ReadFileCapped(path, maxMetadataBytes)
	if err != nil {
		return false
	}
	if !strings.Contains(string(b), scan.MarkerBucket) {
		return false
	}
	mu.Lock()
	disc.MetadataFiles = appendUnique(disc.MetadataFiles, path)
	mu.Unlock()
	return true
}

// inspect runs the candidate gate and, if it passes, the streaming marker search.
func inspect(c candidate) (*engine.BinaryHit, error) {
	f, err := hostfs.OpenRead(c.path)
	if err != nil {
		if os.IsPermission(err) {
			return nil, err
		}
		return nil, nil // vanished between walk and open: not worth reporting
	}
	defer f.Close()

	head := make([]byte, 4)
	n, _ := f.Read(head)
	kind := scan.ClassifyHeader(head[:n], c.path)
	if kind == scan.KindNone && !scan.IsGrokBinaryName(filepath.Base(c.path)) {
		return nil, nil // rejected after one stat and a 4-byte read: the whole perf story
	}

	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	res, err := scan.Stream(f, scan.DefaultMarkers)
	if err != nil {
		return nil, err
	}
	if len(res.Hits) == 0 {
		return nil, nil
	}

	// Only now, for the two or three files that actually matched, is a hash worth
	// paying for.
	sum, _ := scan.HashFile(c.path)

	hit := &engine.BinaryHit{
		Path:       c.path,
		SizeBytes:  c.size,
		SHA256:     sum,
		Kind:       kind.String(),
		Executable: kind == scan.KindELF || kind == scan.KindMachO || kind == scan.KindPE,
	}
	for _, h := range res.Hits {
		hit.Markers = append(hit.Markers, engine.MarkerHit{Marker: h.Marker, Offset: h.Offset})
	}
	return hit, nil
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

// truncatePulsePath keeps the progress line from wrapping. Prefer the trailing
// path segments so `~/Library/.../Foo` still names the leaf being walked.
func truncatePulsePath(p string, max int) string {
	if max < 8 || utf8.RuneCountInString(p) <= max {
		return p
	}
	runes := []rune(p)
	return "…" + string(runes[len(runes)-(max-1):])
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func sortAll(d *engine.Discovered) {
	sort.Strings(d.GrokHomes)
	sort.Strings(d.UploadQueues)
	sort.Strings(d.MetadataFiles)
	sort.Strings(d.RepoHints)
	sort.Slice(d.Binaries, func(i, j int) bool { return d.Binaries[i].Path < d.Binaries[j].Path })
	sort.Slice(d.Archives, func(i, j int) bool { return d.Archives[i].Path < d.Archives[j].Path })
}
