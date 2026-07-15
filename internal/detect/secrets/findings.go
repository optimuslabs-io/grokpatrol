package secrets

import (
	"fmt"
	"sort"
	"strings"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

func findings(repos []model.RepoStatus) []model.Finding {
	var (
		deleted []model.Evidence // in the uploaded object set, gone from the checkout
		present []model.Evidence // in the uploaded object set and still in HEAD
		classes = map[string]int{}
	)

	for _, r := range repos {
		for _, h := range r.SecretFiles {
			classes[h.Class]++
			ev := model.Evidence{
				// The full path is reported on purpose. A rotation checklist you cannot
				// locate is useless; only the file's CONTENTS are off-limits.
				Path: r.RepoPath + "/" + h.Path,
				// The blob id locates the file in git's object database, which is what a
				// Locator is for. The class moves into the note, where it reads better
				// anyway. A file seen only in the working tree has no blob and gets none.
				Locator: blobLocator(h),
			}
			if h.DeletedFromCheckout {
				ev.Note = h.Class + ", deleted from the checkout but still in git history -- it was in the uploaded object set"
				deleted = append(deleted, ev)
			} else {
				ev.Note = h.Class + ", tracked at HEAD"
				present = append(present, ev)
			}
		}
	}

	var out []model.Finding

	// NOT tagged exfil, and that is load-bearing. See engine.verdict: COMPROMISED is
	// (SevHigh AND exfil), so an exfil tag here would let a secret PROMOTE THE VERDICT
	// BY ITSELF -- and this detector never establishes that an upload happened. It is
	// downstream triage: it inherits its repositories from the log ledger, from staged
	// manifests, or from an operator's --repo, and then says what was in them.
	//
	// The bug that motivated this: `grokpatrol --repo ~/myproject` on a machine with no
	// Grok at all -- no ~/.grok, no logs, no upload queue, no binary -- found a .env
	// committed at HEAD and reported COMPROMISED. The tool announced an exfiltration on
	// a host the collector had never touched, which is the false positive that teaches
	// people to stop believing the red banner.
	//
	// Removing the tag cannot hide a real one. Every repository the ledger or the queue
	// implicates already carries its own exfil finding -- logs.archive_enqueued,
	// logs.collected_only, or queue.metadata_bucket (RepoHints come only from staged
	// manifests, which raise that one) -- so a genuinely collected repo is COMPROMISED
	// on that evidence, and these findings stay Critical/High and still force EXPOSED.
	// This is the same doctrine CLAUDE.md already states for config: a High config
	// finding is exposure, not exfiltration. A secret is what WOULD leak if the repo
	// went out; it is not proof that it did.

	// Top billing: the user cannot find these by looking at their own working tree.
	if len(deleted) > 0 {
		out = append(out, model.Finding{
			ID:       "secrets.deleted_from_checkout",
			Detector: "secrets",
			Severity: model.SevCritical,
			Tags:     []string{model.TagSecret},
			Title:    fmt.Sprintf("%d secret files are gone from the checkout but were still in the uploaded git history", len(deleted)),
			Detail: "You will not find these by looking at your repository: they were deleted from the working tree, but they " +
				"remain reachable in git history, and the collector uploaded every object reachable from HEAD. " +
				"grokpatrol reports their names and never read their contents.",
			Remediation: "Rotate these credentials first. Deleting a secret from a repo does not remove it from git history, " +
				"and it did not stop it being uploaded.",
			Evidence: sortEv(deleted),
		})
	}

	if len(present) > 0 {
		out = append(out, model.Finding{
			ID:          "secrets.in_head",
			Detector:    "secrets",
			Severity:    model.SevHigh,
			Tags:        []string{model.TagSecret}, // never exfil -- see the block above
			Title:       fmt.Sprintf("%d secret files tracked at HEAD were in the uploaded object set", len(present)),
			Detail:      "These files are committed in a repository that Grok archived. Their contents went with the archive.",
			Remediation: "Rotate these credentials. " + summarize(classes),
			Evidence:    sortEv(present),
		})
	}

	return out
}

// untriagedLimitation reports the repositories that could not be triaged.
//
// This used to be a MEDIUM finding, secrets.not_scanned, and it was the wrong shape
// twice over. A finding is something we FOUND; this is something we could not LOOK at,
// which is what the limitations section exists to say. And at SevMedium it counted
// toward the report's severity tally and could push an otherwise-clean host to EXPOSED
// on the strength of a repository that is simply no longer on this disk -- an absence
// of information promoted to evidence.
//
// What it must never do is disappear. A repository whose history we could not read is
// not a repository we read and found clean, and a report that says nothing at all about
// it invites exactly that reading. So it is demoted, not deleted: it no longer inflates
// the counts or moves the verdict, and it still says plainly that these repos went out
// and we cannot tell you what was in them. Per-repo detail stays in --json
// (RepoStatus.SecretsScanned and SecretsNote).
func untriagedLimitation(repos []model.RepoStatus) string {
	var names []string
	for _, r := range repos {
		if !r.SecretsScanned && r.SecretsNote != "" {
			names = append(names, r.RepoPath)
		}
	}
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	return fmt.Sprintf("%s could not be triaged (%s). Their git history was not examined, so this "+
		"report cannot tell you what was in them -- an absence of information, not a clean bill of health.",
		engine.Plural(len(names), "affected repository"), strings.Join(names, ", "))
}

// summarize turns the class counts into the one line a person actually acts on.
func summarize(classes map[string]int) string {
	if len(classes) == 0 {
		return ""
	}
	keys := make([]string, 0, len(classes))
	for k := range classes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d x %s", classes[k], k))
	}
	return "Exposed: " + strings.Join(parts, ", ") + "."
}

// blobLocator renders the git object id, or nothing at all. An empty locator is
// the honest output for a working-tree-only hit: we have no object id for it,
// and a reader who is being told to run `git cat-file` on a blob deserves one
// that exists.
func blobLocator(h model.SecretHit) string {
	if h.Blob == "" {
		return ""
	}
	return "blob:" + h.Blob
}

func sortEv(ev []model.Evidence) []model.Evidence {
	sort.Slice(ev, func(i, j int) bool { return ev[i].Path < ev[j].Path })
	return ev
}
