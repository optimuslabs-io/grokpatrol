// Package logs parses Grok's unified*.jsonl logs into an exfiltration ledger:
// which repositories were collected, which had archives queued for upload to
// the exfiltration bucket, how many times, and when.
//
// This is the only detector that can produce proof (rather than suspicion), so
// it is the one place where dropping a single event is unacceptable.
package logs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/optimuslabs/grokpatrol/internal/engine"
	"github.com/optimuslabs/grokpatrol/internal/grokver"
	"github.com/optimuslabs/grokpatrol/internal/hostfs"
	"github.com/optimuslabs/grokpatrol/internal/model"
	"github.com/optimuslabs/grokpatrol/internal/scan"
)

// The bucket name and the archive suffix are searched for in the RAW bytes of
// every log line, before any JSON parsing. This is the schema-drift safety net:
// even if every field were renamed and the JSON were malformed, the destination
// bucket still appears as a plain substring in the line.
//
// Sourced from scan, which assembles them at runtime -- see the comment there:
// a scanner that stores its indicator as a literal finds itself.
var (
	markerBucket  = []byte(scan.MarkerBucket)
	markerArchive = []byte("codebase" + ".tar.gz")
)

// maxLineBytes caps a single log line. A 2 MiB line is pathological but real
// (a stack trace, a base64 blob); an unbounded read is a memory DoS.
const maxLineBytes = 8 << 20

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "logs" }

func (d *Detector) Run(ctx context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result

	files := discover(env, &res)
	if len(files) == 0 {
		// Not reassurance, and the summary must not sound like it: a host whose logs
		// rotated away looks exactly like a host that was never touched.
		res.Summary = "no Grok log files on disk -- rotated-away logs leave no trace either"
		res.Limitations = append(res.Limitations,
			"No Grok log files were found. If Grok ran and its logs were rotated away or deleted, "+
				"collection could still have happened without leaving a log trace.")
		return res, nil
	}

	var (
		events   []event
		rawHits  []model.Evidence
		versions = map[string]bool{}
	)

	for _, f := range files {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		ingest(f, &events, &rawHits, versions, &res)
	}

	// Correlation is GLOBAL, across every log file at once. A start event in
	// unified.jsonl.1 whose enqueue landed in unified.jsonl is the normal case at a
	// rotation boundary; correlating per-file would report that repo as
	// COLLECTED-ONLY instead of QUEUED -- a false negative on the most severe
	// status the tool can assign.
	repos, authSummary := correlate(events)
	res.Repos = repos

	for _, v := range sortedKeys(versions) {
		res.Versions = append(res.Versions, model.VersionEvidence{
			Version:    v,
			Source:     "logs",
			Confidence: "high", // it is what the running binary said about itself
			Class:      classifyVersion(v),
		})
	}

	res.Findings = append(res.Findings, findings(repos, rawHits, events, authSummary)...)
	res.Summary = summarize(files, repos, rawHits)
	return res, nil
}

// Describe names the exact events being hunted, composed from the markers rather
// than written out: a scanner that stores the string it searches for contains that
// string, and would find itself. See internal/scan/markers.go.
func (*Detector) Describe() string {
	return "reading Grok's logs (incl. rotated and gzipped) for " + eventStart + " / " + eventEnqueued + " events"
}

func summarize(files []string, repos []model.RepoStatus, rawHits []model.Evidence) string {
	queued, collected, archives := 0, 0, 0
	for _, r := range repos {
		switch r.Status {
		case model.StatusQueued:
			queued++
			archives += len(r.Archives)
		case model.StatusCollectedOnly:
			collected++
		}
	}

	var parts []string
	if queued > 0 {
		parts = append(parts, fmt.Sprintf("%s with %s QUEUED FOR UPLOAD",
			engine.Plural(queued, "repository"), engine.Plural(archives, "archive")))
	}
	if collected > 0 {
		parts = append(parts, fmt.Sprintf("%s collected, upload unconfirmed", engine.Plural(collected, "repository")))
	}
	if len(rawHits) > 0 && queued == 0 {
		parts = append(parts, engine.Plural(len(rawHits), "raw bucket reference")+", no parseable upload event")
	}
	if len(parts) == 0 {
		// Said explicitly, and worded to forbid the reassuring misreading: logs that
		// rotated away leave a host that was uploaded looking exactly like one that
		// never was.
		return fmt.Sprintf("no upload events in %s -- which is not proof none happened",
			engine.Plural(len(files), "log file"))
	}
	return strings.Join(parts, ", ")
}

// discover globs broadly. The rotation naming convention is unverified, so
// anything that starts with "unified" and mentions .jsonl is fair game:
// unified.jsonl, unified.jsonl.1, unified.jsonl.2.gz, unified-2026-07-01.jsonl.
func discover(env *engine.Env, res *engine.Result) []string {
	seen := map[string]bool{}
	var out []string

	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}
	for _, home := range homes {
		dir := filepath.Join(home, "logs")
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				res.Errors = append(res.Errors, model.ScanError{
					Detector: "logs", Kind: "io", Path: dir, Message: err.Error(), Material: true,
				})
			}
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !isLogName(e.Name()) {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func isLogName(name string) bool {
	n := strings.ToLower(name)
	return strings.HasPrefix(n, "unified") && strings.Contains(n, ".jsonl")
}

func ingest(path string, events *[]event, rawHits *[]model.Evidence, versions map[string]bool, res *engine.Result) {
	f, err := hostfs.OpenRead(path)
	if err != nil {
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "logs", Kind: "permission", Path: path, Message: err.Error(), Material: true,
		})
		return
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, gerr := gzip.NewReader(f)
		if gerr != nil {
			res.Errors = append(res.Errors, model.ScanError{
				Detector: "logs", Kind: "io", Path: path,
				Message: "gzip open failed: " + gerr.Error(),
			})
			return
		}
		defer gz.Close()
		r = gz
	}

	// bufio.Reader, NOT bufio.Scanner: Scanner hard-errors on a line longer than
	// its buffer and abandons the rest of the file. One monster line must not
	// blind us to every event after it.
	br := bufio.NewReaderSize(r, 64<<10)
	lineNo := 0
	parseErrs := 0

	for {
		line, err := readLine(br)
		if len(line) > 0 {
			lineNo++
			if !handleLine(line, path, lineNo, events, rawHits, versions) {
				parseErrs++
			}
		}
		if err != nil {
			// A truncated gzip member yields ErrUnexpectedEOF *after* handing us valid
			// bytes. Keep everything we got; a partially-readable log is still evidence.
			if !errors.Is(err, io.EOF) {
				res.Errors = append(res.Errors, model.ScanError{
					Detector: "logs", Kind: "io", Path: path, Material: true,
					Message: fmt.Sprintf("truncated after line %d: %v (processed what was readable)", lineNo, err),
				})
			}
			break
		}
	}

	if parseErrs > 0 {
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "logs", Kind: "parse", Path: path, Material: true,
			Message: fmt.Sprintf("%d of %d lines were not valid JSON (they were still scanned for raw indicators)", parseErrs, lineNo),
		})
	}
}

// readLine returns one line without its terminator, capped at maxLineBytes.
func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) <= maxLineBytes {
			buf = append(buf, chunk...)
		} else if len(buf) < maxLineBytes {
			buf = append(buf, chunk[:maxLineBytes-len(buf)]...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // long line: keep pulling
		}
		return bytes.TrimRight(buf, "\r\n"), err
	}
}

// handleLine reports whether the line decoded as JSON. Note the ordering: the raw
// substring check runs FIRST, so it fires even on a line that fails to parse.
func handleLine(line []byte, path string, lineNo int, events *[]event, rawHits *[]model.Evidence, versions map[string]bool) bool {
	if bytes.Contains(line, markerBucket) || bytes.Contains(line, markerArchive) {
		*rawHits = append(*rawHits, model.Evidence{
			Path:    path,
			Locator: fmt.Sprintf("line:%d", lineNo),
			Note:    "log line references the exfiltration bucket or a codebase archive",
		})
	}

	m, ok := parseLine(line)
	if !ok {
		return false
	}
	ev := eventFrom(m)
	ev.File, ev.Line = path, lineNo

	if ev.Version != "" {
		versions[ev.Version] = true
	}
	if ev.Kind != kindOther {
		*events = append(*events, ev)
	}
	return true
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func classifyVersion(v string) string { return grokver.Class(v) }

// foldTime folds a possibly-zero timestamp into a first/last range without
// letting the zero time win the "earliest" comparison.
func foldTime(first, last *time.Time, ts time.Time) {
	if ts.IsZero() {
		return
	}
	if first.IsZero() || ts.Before(*first) {
		*first = ts
	}
	if last.IsZero() || ts.After(*last) {
		*last = ts
	}
}
