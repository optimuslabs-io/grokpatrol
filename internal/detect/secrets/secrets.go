// Package secrets answers the question the user actually cares about: given that
// a repository was uploaded, what has to be rotated?
//
// The exfiltrated set was "every git object reachable from HEAD", which is exactly
// what `git rev-list --objects HEAD` enumerates. Subtracting the working tree
// (`git ls-tree HEAD`) from that set yields the files that are GONE from the
// checkout but still alive in history -- the deleted .env, the rotated-out key --
// which is the category the user cannot see by looking at their own repo, and the
// one the incident specifically shipped.
//
// Detection has two tiers. The default matches FILENAMES only (patterns.go) and
// never reads a file. --full-secrets-search additionally reads each implicated
// blob (gitx cat-file, transient buffers) and matches its contents against the
// transcribed gitleaks rule table (rules.go, rules_gen.go). In both tiers the
// report carries paths, classes/rule ids and object ids -- never a value: no
// model struct has a field that could hold one, and the leak tests grep every
// output channel for planted secrets. The filename tier also stays on as the
// floor under the content tier, because a deleted .env whose blob cannot be
// fetched (or is too big to scan) must still make the rotation checklist.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/gitx"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

type Detector struct{}

func New() *Detector           { return &Detector{} }
func (*Detector) Name() string { return "secrets" }

// Run triages every repository the earlier phases implicated.
func (d *Detector) Run(ctx context.Context, env *engine.Env) (engine.Result, error) {
	var res engine.Result

	if env.HistoryScope == "none" {
		res.Summary = "skipped: --history-scope=none, so nothing was triaged"
		res.Limitations = append(res.Limitations, "--history-scope=none: no secret triage was performed.")
		return res, nil
	}

	targets := targetsOf(env)
	if len(targets) == 0 {
		// Says WHY there is nothing to report. "No secrets found" would be a different
		// claim entirely, and a false one: nothing was searched.
		res.Summary = "no repositories were implicated, so none were triaged"
		return res, nil
	}

	useGit := env.UseGit && gitx.Available()
	if env.UseGit && !gitx.Available() {
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "secrets", Kind: "io", Material: true,
			Message: "git is not installed, so git history could not be examined",
		})
		res.Limitations = append(res.Limitations,
			"git was not available: only the current working tree was searched for secrets. Files deleted from the "+
				"checkout but still present in git history -- exactly what the collector uploaded -- were NOT examined.")
	}

	// Triage repositories in parallel, bounded by --concurrency. An affected
	// machine usually has many collected repos, and each triage is independent --
	// its own git subprocesses (gitx is stateless per call) and its own file reads
	// (hostfs is read-only), over an immutable compiled rule set. So this loop, not
	// any single repo, is where the wall time lives once per-blob scanning is fast.
	//
	// Determinism is preserved exactly: every worker fills its OWN result slot and
	// its OWN Result, and the two are merged back in target order below. The report
	// is therefore byte-identical to a serial run -- the same rule the engine's
	// phase-2 fan-out holds to, and the reason the merge is here and not in the
	// goroutine.
	repos := make([]model.RepoStatus, len(targets))
	subs := make([]engine.Result, len(targets))
	launched := make([]bool, len(targets))
	workers := env.Concurrency
	if workers < 1 {
		workers = 1 // a hand-built Env (tests) may leave it zero: never spawn zero workers
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, repo := range targets {
		if ctx.Err() != nil {
			break // stop launching new work once cancelled; in-flight repos still finish
		}
		launched[i] = true
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, repo string) {
			defer wg.Done()
			defer func() { <-sem }()
			// triage returns this repo's RepoStatus and accumulates any errors and
			// limitations on its private Result; both are merged in order below.
			repos[i] = triage(ctx, env, repo, useGit, &subs[i])
		}(i, repo)
	}
	wg.Wait()

	for i := range targets {
		if !launched[i] {
			continue // ctx was cancelled before this repo started
		}
		res.Errors = append(res.Errors, subs[i].Errors...)
		res.Limitations = append(res.Limitations, subs[i].Limitations...)
		res.Repos = append(res.Repos, repos[i])
	}

	res.Findings = findings(res.Repos)
	if l := untriagedLimitation(res.Repos); l != "" {
		res.Limitations = append(res.Limitations, l)
	}
	res.Summary = summarizeRepos(res.Repos)
	return res, nil
}

// Describe states the method, because the method IS the finding: the uploaded set
// was every object reachable from HEAD, so subtracting the working tree from it is
// what surfaces the deleted .env that the user cannot see in their own checkout.
func (*Detector) Describe() string {
	return "git rev-list --objects HEAD minus the working tree, per implicated repository " +
		"(finds secrets deleted from the checkout but still in history); " +
		"--full-secrets-search additionally matches blob contents against the gitleaks rule set"
}

func summarizeRepos(repos []model.RepoStatus) string {
	if len(repos) == 0 {
		return "no repositories were implicated, so none were triaged"
	}
	secrets, deleted, unscanned := 0, 0, 0
	for _, r := range repos {
		if !r.SecretsScanned {
			unscanned++
		}
		for _, h := range r.SecretFiles {
			secrets++
			if h.DeletedFromCheckout {
				deleted++
			}
		}
	}

	var parts []string
	if secrets > 0 {
		parts = append(parts, fmt.Sprintf("%s across %s",
			engine.Plural(secrets, "secret file"), engine.Plural(len(repos), "repository")))
	}
	if deleted > 0 {
		// The headline: the category the user cannot find by looking at their own repo.
		parts = append(parts, fmt.Sprintf("%d DELETED FROM THE CHECKOUT but still in history", deleted))
	}
	if unscanned > 0 {
		// An absence of information, never a clean bill of health.
		parts = append(parts, engine.Plural(unscanned, "repository")+" could not be fully triaged")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s triaged, no credential files in their history", engine.Plural(len(repos), "repository"))
	}
	return strings.Join(parts, ", ")
}

// targetsOf collects every repo worth triaging: those the logs implicated, those
// named in a staged manifest, and any the user forced with --repo.
func targetsOf(env *engine.Env) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || p == model.UnknownRepo || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, r := range env.SeedRepos {
		add(r)
	}
	for _, r := range env.Discovered.RepoHints {
		add(r)
	}
	for _, r := range env.ExtraRepos {
		add(r)
	}
	sort.Strings(out)
	return out
}

func triage(ctx context.Context, env *engine.Env, repo string, useGit bool, res *engine.Result) model.RepoStatus {
	st := model.RepoStatus{RepoPath: repo}

	fi, err := os.Stat(repo)
	if err != nil || !fi.IsDir() {
		// A repo that is gone from your disk is not gone from their bucket. It stays in
		// the ledger; we simply cannot enumerate what was in it.
		st.SecretsNote = "repository is no longer on disk, so its exfiltrated contents cannot be enumerated"
		return st
	}
	st.OnDisk = true

	if _, gerr := os.Stat(filepath.Join(repo, ".git")); gerr == nil {
		st.IsGitRepo = true
	}

	if !useGit || !st.IsGitRepo {
		hits := scanWorkingTree(env, repo, res)
		st.SecretFiles = hits
		st.SecretsScanned = false // working tree only: this is NOT a full answer
		if !st.IsGitRepo {
			st.SecretsNote = "not a git repository: only the working tree was searched"
		} else {
			st.SecretsNote = "git unavailable: only the working tree was searched, not history"
		}
		return st
	}

	head, objects, histErr := historySet(ctx, env, repo, res)
	if histErr != nil {
		if errors.Is(histErr, gitx.ErrDubiousOwnership) {
			// Do NOT work around this by injecting safe.directory=*: that would disable a
			// real guardrail the user never asked us to touch.
			st.SecretsNote = "git refused this repository (dubious ownership). Run: git config --global --add safe.directory " + repo
		} else {
			st.SecretsNote = "git history could not be read: " + histErr.Error()
		}
		res.Errors = append(res.Errors, model.ScanError{
			Detector: "secrets", Kind: "io", Path: repo, Message: histErr.Error(), Material: true,
		})
		st.SecretFiles = scanWorkingTree(env, repo, res)
		st.SecretsScanned = false
		return st
	}

	st.SecretFiles = head
	st.HistoryObjects = objects
	st.SecretsScanned = true
	return st
}

// historySet is the heart of it: the object set that was uploaded, minus the
// working tree, tells you what is hiding in history.
//
// It also returns how many objects that set held. That number is the uploaded
// payload, counted -- "12,431 objects went out, 4 of them are credentials" says
// something "your history was uploaded" cannot.
func historySet(ctx context.Context, env *engine.Env, repo string, res *engine.Result) (hits []model.SecretHit, objects int, err error) {
	rev := "HEAD"
	revArgs := []string{"rev-list", "--objects", rev}
	if env.HistoryScope == "all" {
		revArgs = []string{"rev-list", "--objects", "--all"}
	}

	// The exfiltrated object set: path -> git object id.
	//
	// The blob id is kept, not discarded. rev-list prints it on every line and this
	// loop was already splitting it off to reach the path; carrying it costs nothing
	// and it is the only thing in the report a user can independently verify
	// (`git cat-file -p <blob>` shows them the secret this tool refuses to read on
	// a default run).
	history := map[string]string{}
	// Under --full-secrets-search, every (sha, path) pair is also kept: the map
	// above holds one version per path, but a rotated-out secret usually lives in
	// an OLD version of a file that still exists, and only the full pair list can
	// reach it.
	var pairs []objRef
	count := 0
	truncated := false
	err = gitx.Stream(ctx, repo, env.GitTimeout, revArgs, func(line string) error {
		count++
		if count > env.MaxGitObjects {
			truncated = true
			return errStopEarly
		}
		// Format: "<sha> <path>". Commits and trees have no path.
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			return nil
		}
		if p := strings.TrimSpace(line[sp+1:]); p != "" {
			sha := strings.TrimSpace(line[:sp])
			history[p] = sha
			if env.FullSecretsSearch {
				pairs = append(pairs, objRef{sha: sha, path: p})
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopEarly) {
		return nil, 0, err
	}

	// The current checkout.
	headSet := map[string]bool{}
	err = gitx.StreamNUL(ctx, repo, env.GitTimeout, []string{"ls-tree", "-r", "--name-only", "-z", "HEAD"}, func(p string) error {
		headSet[p] = true
		return nil
	})
	if err != nil {
		return nil, 0, err
	}

	// `git rev-list --objects` emits TREE (directory) objects as well as blobs, while
	// the ls-tree below lists files only. A directory whose name is secret-shaped
	// (secrets/, app-secrets/) would therefore land in `history`, never appear in
	// headSet, and be reported as "deleted from the checkout" -- a fabricated
	// SevCritical finding whose blob id points at a tree, so the `git cat-file -p` we
	// invite the user to run prints a directory listing. We cannot ask git to type-tag
	// the objects (cat-file is off the allowlist by design), but we do not need to: a
	// directory path is always a strict ancestor of some other path in the listing,
	// and a file path never is. dirs collects those ancestors so they can be skipped.
	dirs := map[string]bool{}
	for p := range history {
		for i := strings.LastIndexByte(p, '/'); i >= 0; i = strings.LastIndexByte(p, '/') {
			p = p[:i]
			dirs[p] = true
		}
	}

	// Under --full-secrets-search, fetch and match blob contents. This runs on
	// the full pair list minus directory paths; failures inside degrade to the
	// filename floor below and are recorded on res, never swallowed.
	var contentHits map[string]contentHit
	if env.FullSecretsSearch {
		scannable := pairs[:0]
		for _, pr := range pairs {
			if !dirs[pr.path] {
				scannable = append(scannable, pr)
			}
		}
		contentHits = contentScanHistory(ctx, env, repo, scannable, res)
	}

	byPath := map[string]int{} // path -> index into hits, for the content merge
	for p, blob := range history {
		if dirs[p] {
			continue // a directory object, not a file: never a secret to rotate
		}
		class := Classify(p)
		if class == "" {
			continue
		}
		inHead := headSet[p]
		byPath[p] = len(hits)
		hits = append(hits, model.SecretHit{
			Path:      p,
			Class:     class,
			Blob:      blob,
			InHEAD:    inHead,
			InHistory: true,
			// The one that matters: present in the uploaded object set, absent from the
			// checkout. The user cannot see this by looking at their own repo.
			DeletedFromCheckout: !inHead,
		})
	}

	// Merge: a content hit on an already-flagged path upgrades its class to the
	// rule id (which credential it is beats which shape its name has) and points
	// Blob at the version that actually matched; a content hit on a new path
	// becomes its own row with the same InHEAD/deleted semantics.
	for p, ch := range contentHits {
		if i, ok := byPath[p]; ok {
			hits[i].Class = ch.rule
			hits[i].Blob = ch.blob
			continue
		}
		inHead := headSet[p]
		hits = append(hits, model.SecretHit{
			Path:                p,
			Class:               ch.rule,
			Blob:                ch.blob,
			InHEAD:              inHead,
			InHistory:           true,
			DeletedFromCheckout: !inHead,
		})
	}
	// A file can be in HEAD but (pathologically) not enumerated above; catch it. It
	// gets no blob id: we never saw one for it, and inventing one would be a lie
	// about the one field a user is invited to go and check.
	for p := range headSet {
		if _, ok := history[p]; ok {
			continue
		}
		if class := Classify(p); class != "" {
			hits = append(hits, model.SecretHit{Path: p, Class: class, InHEAD: true})
		}
	}

	sortHits(hits)
	if truncated {
		return hits, count, fmt.Errorf("repository exceeds --max-git-objects (%d): history results are incomplete", env.MaxGitObjects)
	}
	return hits, count, nil
}

var errStopEarly = errors.New("stop")

// scanWorkingTree is the degraded path: no git, so only what is on disk right
// now. Under --full-secrets-search it reads file contents too (through hostfs,
// the only sanctioned filesystem door) -- still a working-tree-only answer,
// but a deeper one.
func scanWorkingTree(env *engine.Env, repo string, res *engine.Result) []model.SecretHit {
	var hits []model.SecretHit
	oversized, unreadable := 0, 0
	_ = filepath.WalkDir(repo, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if e.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(repo, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		class := Classify(rel)

		if env.FullSecretsSearch {
			if fi, serr := e.Info(); serr != nil || !fi.Mode().IsRegular() {
				if serr != nil {
					unreadable++
				}
			} else if fi.Size() > blobCap(env) {
				oversized++
			} else if rule, ok, cerr := contentScanFile(env, p, rel); cerr != nil {
				unreadable++
			} else if ok {
				class = rule // the rule id names the credential; the filename only shapes it
			}
		}

		if class != "" {
			hits = append(hits, model.SecretHit{Path: rel, Class: class, InHEAD: true})
		}
		return nil
	})
	if oversized > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%s: %s exceeded --max-blob-scan-bytes and were not content-scanned; filename matching still applied.",
			repo, engine.Plural(oversized, "file")))
	}
	if unreadable > 0 {
		res.Limitations = append(res.Limitations, fmt.Sprintf(
			"%s: %s could not be read for content scanning; filename matching still applied.",
			repo, engine.Plural(unreadable, "file")))
	}
	sortHits(hits)
	return hits
}

func sortHits(h []model.SecretHit) {
	sort.Slice(h, func(i, j int) bool {
		// Deleted-from-checkout first: it is the finding the user cannot discover on
		// their own, so it gets top billing.
		if h[i].DeletedFromCheckout != h[j].DeletedFromCheckout {
			return h[i].DeletedFromCheckout
		}
		if h[i].Class != h[j].Class {
			return h[i].Class < h[j].Class
		}
		return h[i].Path < h[j].Path
	})
}
