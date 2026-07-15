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
// Filenames are reported. Contents are never read: see gitx, whose allowlist has
// no cat-file.
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

	for _, repo := range targets {
		if ctx.Err() != nil {
			break
		}
		st := triage(ctx, env, repo, useGit, &res)
		res.Repos = append(res.Repos, st)
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
		"(finds secrets deleted from the checkout but still in history)"
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
		hits := scanWorkingTree(repo, res)
		st.SecretFiles = hits
		st.SecretsScanned = false // working tree only: this is NOT a full answer
		if !st.IsGitRepo {
			st.SecretsNote = "not a git repository: only the working tree was searched"
		} else {
			st.SecretsNote = "git unavailable: only the working tree was searched, not history"
		}
		return st
	}

	head, objects, histErr := historySet(ctx, env, repo)
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
		st.SecretFiles = scanWorkingTree(repo, res)
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
func historySet(ctx context.Context, env *engine.Env, repo string) (hits []model.SecretHit, objects int, err error) {
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
	// (`git cat-file -p <blob>` shows them the secret this tool refuses to read).
	history := map[string]string{}
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
			history[p] = strings.TrimSpace(line[:sp])
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

	for p, blob := range history {
		class := Classify(p)
		if class == "" {
			continue
		}
		inHead := headSet[p]
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

// scanWorkingTree is the degraded path: no git, so only what is on disk right now.
func scanWorkingTree(repo string, res *engine.Result) []model.SecretHit {
	var hits []model.SecretHit
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
		if class := Classify(rel); class != "" {
			hits = append(hits, model.SecretHit{Path: filepath.ToSlash(rel), Class: class, InHEAD: true})
		}
		return nil
	})
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
