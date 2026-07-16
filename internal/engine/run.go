package engine

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/buildinfo"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

type Detector interface {
	Name() string
	Run(ctx context.Context, env *Env) (Result, error)
}

type Engine struct {
	// Phase 1 discovers what is on disk (deepscan). Phase 2 reads what it found
	// (logs, config, version, queue) in parallel. Phase 3 triages the repositories
	// phase 2 implicated (secrets).
	//
	// The ordering is not cosmetic: a stray .grok under ~/work has logs and a config
	// of its own, and assuming ~/.grok is the only grok home would be a false negative.
	Discover Detector
	Readers  []Detector
	Triage   Detector

	DetectorTimeout time.Duration

	// Progress narrates the run on stderr. Nil is fine: it becomes a no-op.
	Progress Progress
}

func (e *Engine) Run(ctx context.Context, env *Env) *model.Report {
	if e.Progress == nil {
		e.Progress = nopProgress{}
	}
	// deepscan Pulses through Env so the long walk can narrate without importing
	// report. Later phases do not pulse; leaving it set is harmless.
	if _, ok := e.Progress.(nopProgress); ok {
		env.Progress = nil
	} else {
		env.Progress = e.Progress
	}
	started := time.Now()
	rep := &model.Report{
		Schema:    model.SchemaVersion,
		StartedAt: started.UTC(),
		Tool: model.ToolInfo{
			Name: "grokpatrol", Version: buildinfo.Version, Commit: buildinfo.Commit,
			BuiltAt: buildinfo.Date, GoVersion: buildinfo.GoVersion(),
		},
		Host: model.HostInfo{
			GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
			Home: env.Home, GrokHome: env.GrokHome,
		},
		Options: model.Options{
			HistoryScope: env.HistoryScope, UseGit: env.UseGit,
			Concurrency: env.Concurrency, MaxFileSize: env.MaxFileSize,
		},
		Counts: map[string]int{},
	}

	absorb := func(r Result) {
		rep.Findings = append(rep.Findings, r.Findings...)
		rep.Versions = append(rep.Versions, r.Versions...)
		rep.Errors = append(rep.Errors, r.Errors...)
		rep.Limitations = append(rep.Limitations, r.Limitations...)
	}

	// Phase 1.
	if e.Discover != nil {
		e.Progress.Checking(e.Discover.Name(), describe(e.Discover))
		r, took := e.runTimed(ctx, e.Discover, env)
		e.Progress.Checked(e.Discover.Name(), r.Summary, took)
		absorb(r)
		if r.Discovered != nil {
			env.Discovered = *r.Discovered
		}
	}
	rep.Host.ScannedRoots = env.Discovered.GrokHomes

	// Phase 2, in parallel: each reader is a handful of file reads.
	//
	// Every reader announces itself BEFORE the fan-out, and reports back in the
	// order it was declared once the barrier clears. Narrating a parallel phase in
	// completion order would interleave four detectors' output nondeterministically,
	// and a progress display that shuffles itself between runs is one nobody trusts.
	//
	// DO NOT move a Progress call inside the goroutine below to make results appear
	// "live". Progress is called only from this goroutine, and that -- not the mutex
	// inside the renderer -- is what keeps its output ordered and race-free.
	var (
		mu      sync.Mutex
		wg      sync.WaitGroup
		results = make([]Result, len(e.Readers))
		times   = make([]time.Duration, len(e.Readers))
	)
	for _, d := range e.Readers {
		e.Progress.Checking(d.Name(), describe(d))
	}
	for i, d := range e.Readers {
		wg.Add(1)
		go func(i int, d Detector) {
			defer wg.Done()
			r, took := e.runTimed(ctx, d, env)
			mu.Lock()
			results[i], times[i] = r, took
			mu.Unlock()
		}(i, d)
	}
	wg.Wait()

	for i, r := range results {
		e.Progress.Checked(e.Readers[i].Name(), r.Summary, times[i])
		absorb(r)
		rep.Repos = append(rep.Repos, r.Repos...)
		env.Discovered.RepoHints = appendUnique(env.Discovered.RepoHints, r.RepoHints...)
	}

	// Phase 3: triage the repositories the ledger implicated.
	for _, r := range rep.Repos {
		if r.RepoPath != model.UnknownRepo {
			env.SeedRepos = appendUnique(env.SeedRepos, r.RepoPath)
		}
	}
	if e.Triage != nil {
		e.Progress.Checking(e.Triage.Name(), describe(e.Triage))
		r, took := e.runTimed(ctx, e.Triage, env)
		e.Progress.Checked(e.Triage.Name(), r.Summary, took)
		absorb(r)
		mergeSecrets(rep, r.Repos)
	}

	finalize(rep, env, time.Since(started))
	e.Progress.Done(time.Since(started))
	return rep
}

func (e *Engine) runTimed(ctx context.Context, d Detector, env *Env) (Result, time.Duration) {
	start := time.Now()
	r := e.runOne(ctx, d, env)
	return r, time.Since(start)
}

// runOne isolates a detector. A panic in deepscan must still let the log ledger
// reach the report: a crash that produces no findings reads exactly like a clean
// host, which is the worst failure this tool could have.
func (e *Engine) runOne(ctx context.Context, d Detector, env *Env) (res Result) {
	defer func() {
		if r := recover(); r != nil {
			res.Errors = append(res.Errors, model.ScanError{
				Detector: d.Name(),
				Kind:     "panic",
				Material: true,
				// The stack is deliberately not included: a panic on a bad slice could carry
				// file bytes into it, and this string ends up in the JSON report.
				Message: fmt.Sprint(r),
			})
		}
	}()

	dctx := ctx
	if e.DetectorTimeout > 0 {
		var cancel context.CancelFunc
		dctx, cancel = context.WithTimeout(ctx, e.DetectorTimeout)
		defer cancel()
	}

	r, err := d.Run(dctx, env)
	if err != nil {
		kind := "io"
		if dctx.Err() != nil {
			kind = "timeout"
		}
		r.Errors = append(r.Errors, model.ScanError{Detector: d.Name(), Kind: kind, Message: err.Error(), Material: true})
	}
	return r
}

// mergeSecrets folds the triage results into the ledger rows they belong to.
// A repo that the triage found but the ledger never saw (it came from a staged
// manifest) is appended.
func mergeSecrets(rep *model.Report, triaged []model.RepoStatus) {
	byPath := map[string]int{}
	for i, r := range rep.Repos {
		byPath[r.RepoPath] = i
	}
	for _, t := range triaged {
		if i, ok := byPath[t.RepoPath]; ok {
			rep.Repos[i].SecretFiles = t.SecretFiles
			rep.Repos[i].HistoryObjects = t.HistoryObjects
			rep.Repos[i].SecretsScanned = t.SecretsScanned
			rep.Repos[i].SecretsNote = t.SecretsNote
			rep.Repos[i].OnDisk = t.OnDisk
			rep.Repos[i].IsGitRepo = t.IsGitRepo
			continue
		}
		t.Status = model.StatusUnknown // implicated by a staged manifest, not by the logs
		rep.Repos = append(rep.Repos, t)
	}
}

func finalize(rep *model.Report, env *Env, elapsed time.Duration) {
	rep.Duration = elapsed.Round(time.Millisecond).String()
	for _, e := range rep.Errors {
		if e.Material {
			rep.Degraded = true
			break
		}
	}

	sort.SliceStable(rep.Findings, func(i, j int) bool {
		if rep.Findings[i].Severity != rep.Findings[j].Severity {
			return rep.Findings[i].Severity > rep.Findings[j].Severity
		}
		return rep.Findings[i].ID < rep.Findings[j].ID
	})
	for _, f := range rep.Findings {
		rep.Counts[f.Severity.String()]++
	}

	rep.GrokPresent = grokFound(rep, env)
	rep.Verdict = verdict(rep)
	rep.Limitations = append(rep.Limitations, standingLimitations(env)...)
	rep.Limitations = dedupeStrings(rep.Limitations)
}

// verdict is deliberately conservative. The rule that matters is the last one:
// a degraded scan can never come back CLEAN, because "I was blocked from reading
// half your disk and found nothing" is not the same statement as "there is
// nothing here".
func verdict(rep *model.Report) model.Verdict {
	upload, exposure := false, false
	for _, f := range rep.Findings {
		// COMPROMISED asserts the code LEFT the machine. Collection and queueing
		// (IsExfil) are not enough -- only a confirmed or unclassifiable delivery
		// (IsUpload) clears this bar. A queued-but-undelivered host is EXPOSED.
		if f.Severity >= model.SevHigh && f.IsUpload() {
			upload = true
		}
		if f.Severity >= model.SevMedium {
			exposure = true
		}
	}
	switch {
	case upload:
		return model.VerdictCompromised
	case exposure:
		return model.VerdictExposed
	case rep.Degraded:
		return model.VerdictIndeterminate
	default:
		return model.VerdictClean
	}
}

// grokFound reports whether any Grok Build artifact was actually discovered on this
// host. It is the report-layer signal behind Report.GrokPresent and gates the wording
// that states grok's absence outright.
//
// The check is authoritative rather than findings-shaped where it can be: env.Discovered
// is deepscan's own inventory, and Installs()/UploadQueues/Archives/RepoHints are counted
// there directly -- deliberately NOT GrokHomes, which always carries the configured home
// whether or not it exists on disk and would read as "present" on every clean host. The
// findings sweep then covers what Discovered does not: a config detector finding fires
// only once a grok home, config.toml or cached credential was found, and a binary_marker
// means a marker-carrying executable is on disk. Either is proof grok is here.
func grokFound(rep *model.Report, env *Env) bool {
	d := env.Discovered
	if len(d.Installs()) > 0 || len(d.UploadQueues) > 0 || len(d.Archives) > 0 || len(d.RepoHints) > 0 {
		return true
	}
	if len(rep.Repos) > 0 {
		return true
	}
	// A version counts as presence only at the same evidentiary bar versionBanner
	// displays one: NOT "low", which means a semver scraped from a marker-carrying text
	// file's string table (an IoC list, notes, another scanner). deepscan classifies
	// those files as "not a Grok install", so a host whose only grok-shaped signal is one
	// of them is grok-absent, and must still get the plain "no grok" headline.
	for _, v := range rep.Versions {
		if v.Confidence != "low" {
			return true
		}
	}
	for _, f := range rep.Findings {
		if f.Detector == "config" || f.ID == "deepscan.binary_marker" {
			return true
		}
	}
	return false
}

func standingLimitations(env *Env) []string {
	out := []string{
		"grokpatrol only sees what is still on this host. Logs that were rotated away, an upload queue that was " +
			"already drained, or a repository that has since been deleted leave no local trace -- and none of that " +
			"undoes an upload that already happened.",
		"This tool makes no network calls. It cannot tell you whether xAI still holds your archives, only whether " +
			"this machine shows that they were collected and queued.",
	}
	if runtime.GOOS == "darwin" {
		out = append(out, "On macOS, ~/Documents, ~/Desktop, ~/Downloads and ~/Library/Containers are protected by TCC. "+
			"If your terminal lacks Full Disk Access, those directories were skipped -- grant it and re-run for full coverage.")
	}
	if runtime.GOOS == "windows" {
		out = append(out, "On Windows there is no filesystem-device check, so the walker uses reparse points to avoid "+
			"crossing mounts. A volume mounted under a junction may have been skipped.")
	}
	return out
}

func appendUnique(list []string, vals ...string) []string {
	for _, v := range vals {
		if v == "" {
			continue
		}
		found := false
		for _, x := range list {
			if x == v {
				found = true
				break
			}
		}
		if !found {
			list = append(list, v)
		}
	}
	return list
}

func dedupeStrings(in []string) []string {
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
