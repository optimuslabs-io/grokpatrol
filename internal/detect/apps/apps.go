// Package apps finds Grok Build app addresses (<name>.grok.me) in files on this host.
//
// Grok Build on the web and on mobile publishes each app at its own hostname under
// grok.me, and the publish panel has defaulted to "Anyone with the link". Those
// hostnames reach passive DNS the first time anyone opens one, and passive DNS can be
// searched by pattern, so "only people with the link" in practice means anyone. The
// app is built and hosted in xAI's cloud; the only trace on a laptop is the address
// itself, in the places a person or an agent used it: browser history, Grok CLI
// sessions, shell history.
//
// This detector only reads. It never contacts an app; whether one is open to the
// public is answered by the separate, opt-in online check (internal/exposure, built
// only with -tags online).
package apps

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/hostfs"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "apps" }

func (*Detector) Describe() string {
	return "looking for Grok Build app addresses (*.grok.me) in browser history, Grok CLI sessions and shell history " +
		"(read-only; no app is contacted)"
}

// source is one file to search and the plain-language name of what it is.
type source struct {
	path string
	kind string
}

func (d *Detector) Run(ctx context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result
	found := map[string][]model.Evidence{}

	for _, src := range sources(ctx, env, &res) {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		hosts, err := scanFile(src.path, env.MaxFileSize)
		if err != nil {
			res.Errors = append(res.Errors, readError(src.path, err))
			continue
		}
		for _, h := range hosts {
			found[h] = append(found[h], model.Evidence{Path: src.path, Note: src.kind})
		}
	}

	for host, seen := range found {
		res.Apps = append(res.Apps, model.PublishedApp{Host: host, Seen: seen, Source: model.AppSourceLocal})
	}
	sort.Slice(res.Apps, func(i, j int) bool { return res.Apps[i].Host < res.Apps[j].Host })

	res.Summary = summarize(len(res.Apps))
	res.AppLimitations = append(res.AppLimitations,
		"Grok Build apps are published from grok.com and the Grok mobile apps, in xAI's cloud. This host only "+
			"shows the addresses someone opened or typed here; an app published but never opened on this machine "+
			"leaves no trace, and an address in browser history may be somebody else's app.")
	return res, nil
}

func summarize(n int) string {
	if n == 0 {
		return "no grok.me app addresses found"
	}
	return engine.Plural(n, "grok.me app address") + " found"
}

// readError classifies a failed read. None of these sources can hide a sign that
// repositories were taken, so a failure here never degrades the verdict; it is still
// reported, because a blocked browser history means the app list is incomplete.
func readError(path string, err error) model.ScanError {
	kind := "io"
	if errors.Is(err, fs.ErrPermission) {
		kind = "permission"
	}
	return model.ScanError{Detector: "apps", Kind: kind, Path: path, Message: ErrText(err), Material: false}
}

// ErrText is an error's message without the absolute path an *fs.PathError
// repeats. The path already sits in ScanError.Path, which report.Display shows
// home-relative; left in the message it would carry the user's home directory
// (and username) into --apps-only, which agents read.
func ErrText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + ": " + pe.Err.Error()
	}
	return err.Error()
}

// sources lists every file worth searching, in a stable order. Browser profiles are
// globbed because each browser keeps one History file per profile (Default,
// Profile 1, ...). SQLite's write-ahead log is searched alongside the database: a
// browser that is open holds its newest visits there, not in the main file.
func sources(ctx context.Context, env *engine.Env, res *engine.Result) []source {
	h := env.Home
	var out []source
	add := func(kind string, patterns ...string) {
		for _, p := range patterns {
			matches, _ := filepath.Glob(p) // the only error Glob returns is a malformed pattern
			sort.Strings(matches)
			for _, m := range matches {
				for _, f := range []string{m, m + "-wal"} {
					if fi, err := os.Lstat(f); err == nil && fi.Mode().IsRegular() {
						out = append(out, source{path: f, kind: kind})
					}
				}
			}
		}
	}

	mac := filepath.Join(h, "Library", "Application Support")
	cfg := filepath.Join(h, ".config")
	add("Chrome history",
		filepath.Join(mac, "Google", "Chrome", "*", "History"),
		filepath.Join(cfg, "google-chrome", "*", "History"))
	add("Chromium history",
		filepath.Join(mac, "Chromium", "*", "History"),
		filepath.Join(cfg, "chromium", "*", "History"))
	add("Brave history",
		filepath.Join(mac, "BraveSoftware", "Brave-Browser", "*", "History"),
		filepath.Join(cfg, "BraveSoftware", "Brave-Browser", "*", "History"))
	add("Edge history",
		filepath.Join(mac, "Microsoft Edge", "*", "History"),
		filepath.Join(cfg, "microsoft-edge", "*", "History"))
	add("Arc history", filepath.Join(mac, "Arc", "User Data", "*", "History"))
	add("Firefox history",
		filepath.Join(mac, "Firefox", "Profiles", "*", "places.sqlite"),
		filepath.Join(h, ".mozilla", "firefox", "*", "places.sqlite"))
	// Safari's history sits behind macOS TCC. Without Full Disk Access the read fails
	// with a permission error, which is reported rather than silently skipped.
	add("Safari history", filepath.Join(h, "Library", "Safari", "History.db"))
	add("shell history",
		filepath.Join(h, ".zsh_history"),
		filepath.Join(h, ".bash_history"),
		filepath.Join(h, ".local", "share", "fish", "fish_history"))

	homes := env.Discovered.GrokHomes
	if len(homes) == 0 {
		homes = []string{env.GrokHome}
	}
	w := &hostfs.Walker{
		FollowSymlinks:  env.FollowSymlinks,
		CrossFilesystem: env.CrossFilesystem,
		OnError: func(path string, err error) {
			res.Errors = append(res.Errors, readError(path, err))
		},
	}
	for _, gh := range homes {
		for _, sub := range []string{"sessions", "logs"} {
			root := filepath.Join(gh, sub)
			if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
				continue
			}
			_ = w.Walk(ctx, root, func(path string, d fs.DirEntry) error {
				if hostfs.IsRegular(d) {
					out = append(out, source{path: path, kind: "Grok CLI " + sub})
				}
				return nil
			})
		}
	}
	return out
}

// chunkSize bounds memory per file: History databases run to hundreds of megabytes.
// overlap carries the tail of one chunk into the next so an address split across the
// boundary is still seen whole; it only needs to cover the longest possible match.
const (
	chunkSize = 1 << 20
	overlap   = 128
)

// scanFile returns the distinct grok.me hosts in one file, reading at most max bytes.
func scanFile(path string, max int64) ([]string, error) {
	f, err := hostfs.OpenRead(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if max > 0 {
		r = io.LimitReader(f, max)
	}
	seen := map[string]bool{}
	buf := make([]byte, 0, chunkSize+overlap)
	tmp := make([]byte, chunkSize)
	var read int64
	for {
		n, rerr := io.ReadFull(r, tmp)
		read += int64(n)
		buf = append(buf, tmp[:n]...)
		final := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if final && max > 0 && read >= max {
			fi, statErr := f.Stat()
			final = statErr == nil && fi.Size() <= read
		}
		for _, h := range hosts(buf, final) {
			seen[h] = true
		}
		if rerr != nil {
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				break
			}
			return nil, rerr
		}
		if len(buf) > overlap {
			buf = append(buf[:0], buf[len(buf)-overlap:]...)
		}
	}
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}

// suffix is the registrable domain Grok Build publishes under.
var suffix = []byte(".grok.me")

// reserved are names under grok.me that are xAI's, not a user's app.
var reserved = map[string]bool{"www": true}

// Hosts returns every <label>.grok.me in b, lowercased, in order of first
// appearance. The check is strict on purpose, because whatever it returns is
// printed: exactly one DNS label (1-63 of a-z, 0-9 and '-', not starting or ending
// with '-'), nothing label-like immediately before it, and nothing that would make
// grok.me part of a longer name after it (grok.me.example.com, grok.meow).
func Hosts(b []byte) []string {
	return hosts(b, true)
}

func hosts(b []byte, allowEOF bool) []string {
	lower := bytes.ToLower(b)
	var out []string
	seen := map[string]bool{}
	for i := 0; ; {
		j := bytes.Index(lower[i:], suffix)
		if j < 0 {
			return out
		}
		at := i + j
		i = at + len(suffix)
		if !endsName(lower, i, allowEOF) {
			continue
		}
		start := at
		for start > 0 && isLabelByte(lower[start-1]) {
			start--
		}
		// A URL-encoded "//" or ":" (…%2F%2Fname.grok.me) leaves "2f"/"3a" glued to the
		// front of the label. Peel it off rather than invent a host.
		for start >= 1 && lower[start-1] == '%' && at-start > 2 && (bytes.HasPrefix(lower[start:], []byte("2f")) || bytes.HasPrefix(lower[start:], []byte("3a"))) {
			start += 2
		}
		if start > 0 && lower[start-1] == '.' {
			continue // a.b.grok.me: not a Grok app address
		}
		label := lower[start:at]
		if !validLabel(label) || reserved[string(label)] {
			continue
		}
		host := string(label) + string(suffix)
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
}

// endsName reports whether the hostname really stops at i.
func endsName(b []byte, i int, allowEOF bool) bool {
	if i >= len(b) {
		return allowEOF
	}
	c := b[i]
	if isLabelByte(c) {
		return false
	}
	if c == '.' && i+1 < len(b) && isLabelByte(b[i+1]) {
		return false
	}
	return true
}

func isLabelByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}

func validLabel(l []byte) bool {
	if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, c := range l {
		if !isLabelByte(c) {
			return false
		}
	}
	return true
}
