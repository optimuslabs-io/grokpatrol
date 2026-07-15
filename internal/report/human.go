package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/detect/config"
	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

type Style struct {
	Color bool
	Quiet bool
	// Verbose prints every row this report would otherwise sample: every archive, every
	// secret file, every evidence line. The default report is a SUMMARY that names its
	// own totals and points at --verbose and --json; it is not a shorter truth.
	//
	// Truncation is display-only and always has been. The findings keep every item and
	// --json is the complete forensic record, which is what makes the "N more" pointer a
	// promise rather than a lie.
	Verbose bool
}

// Colour is semantic, not decorative: a reader must be able to triage by colour
// alone, so each code means one thing throughout this file.
//
//	red    -- act now: rotate, a confirmed delivery, a secret deleted-but-in-history,
//	          a CRITICAL finding, a repository that was queued/collected.
//	yellow -- exposure: EXPOSED verdict, a REPORTED-affected build, a MEDIUM finding.
//	green  -- good: a mitigated config, a CLEAN verdict.
//	cyan   -- a path the reader will act on (a repository, a secret's location).
//	dim    -- context and provenance: the "how do you know" lines, source citations,
//	          counts that are scale rather than a call to action.
//	bold   -- a heading or the single most important token on its line.
//
// Nothing in this file should reach for a colour for emphasis alone; if a span is
// coloured, the colour is carrying one of the meanings above.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
)

func (s Style) c(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + reset
}

// Human writes the report a person actually reads. The ordering is deliberate:
// the verdict, then what was taken, then what to rotate, then what we could not
// see, then what to do. Anything that would bury the rotation list goes below it.
func Human(w io.Writer, rep *model.Report, s Style) {
	fmt.Fprintf(w, "%s %s  (%s/%s)  scanned in %s\n\n",
		s.c(bold, "grokpatrol"), rep.Tool.Version, rep.Host.GOOS, rep.Host.GOARCH, rep.Duration)

	verdictBanner(w, rep, s)
	if s.Quiet {
		return
	}

	versionBanner(w, rep, s)
	installation(w, rep, s)
	mitigations(w, rep, s)
	ledger(w, rep, s)
	staging(w, rep, s)
	secrets(w, rep, s)
	otherFindings(w, rep, s)
	degraded(w, rep, s)
	limitations(w, rep, s)
	footer(w, rep, s)
}

// footer restates the tool identity at the bottom of the report so a reader who
// scrolled past the header (or is looking at a paged/piped report) still knows
// which grokpatrol build produced it.
func footer(w io.Writer, rep *model.Report, s Style) {
	fmt.Fprintf(w, "%s %s  (%s/%s)  scanned in %s\n",
		s.c(dim, "grokpatrol"), s.c(dim, rep.Tool.Version), rep.Host.GOOS, rep.Host.GOARCH, rep.Duration)
}

// curated lists every finding ID that a section above renders in its own words.
// Anything NOT in this set falls through to otherFindings.
//
// The fallback is not a nicety, it is a safety net over a real hole. Every section
// in this file selects findings by hardcoded ID, so a finding whose ID nobody
// listed here printed NOTHING in the terminal -- while --json carried it in full.
// logs.raw_bucket_reference was the worst case: it is CRITICAL, it is tagged exfil,
// and it fires precisely when Grok's log schema has drifted and no upload event
// could be parsed. On such a host the ledger is empty, so the terminal printed a
// COMPROMISED banner above a report with no evidence in it at all -- the one
// scenario where the reader most needs to see what we found.
//
// A finding this renderer has never heard of now prints generically rather than
// silently. That is also the contract for anyone adding a detector: your finding
// will appear without touching this file, and if you want it somewhere nicer, add
// its ID here and render it.
var curated = map[string]bool{
	"deepscan.binary_marker":        true, // installation
	"config.mitigated":              true,
	"config.not_mitigated":          true,
	"config.absent":                 true,
	"config.explicitly_disabled":    true,
	"config.unparseable":            true,
	"config.auth_present":           true,
	"config.other_keys":             true,
	"version.confirmed_affected":    true, // installation, via rep.Versions
	"version.reported_affected":     true,
	"logs.archive_enqueued":         true, // ledger
	"logs.collected_only":           true,
	"logs.upload_auth_failure":      true,
	"logs.upload_confirmed":         true,
	"queue.present":                 true, // staging
	"queue.codebase_archive":        true,
	"queue.metadata_bucket":         true,
	"secrets.deleted_from_checkout": true, // secrets, via rep.Repos
	"secrets.in_head":               true,
}

// otherFindings renders everything the curated sections did not claim: severity,
// title, the detector's own prose, and its evidence.
func otherFindings(w io.Writer, rep *model.Report, s Style) {
	var rest []model.Finding
	for _, f := range rep.Findings {
		if !curated[f.ID] {
			rest = append(rest, f)
		}
	}
	if len(rest) == 0 {
		return
	}

	fmt.Fprintln(w, s.c(bold, "OTHER FINDINGS"))
	for _, f := range rest {
		fmt.Fprintf(w, "  %s  %s\n", sevLabel(f.Severity, s), f.Title)
		if f.Detail != "" {
			fmt.Fprintf(w, "    %s\n", s.c(dim, wrap(f.Detail, 88, "    ")))
		}

		shown, omitted := s.capRows(f.Evidence)
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, e := range shown {
			fmt.Fprintf(tw, "    %s\t%s\t%s\n", evidenceWhere(e), e.Locator, s.c(dim, e.Note))
		}
		tw.Flush()
		if omitted > 0 {
			fmt.Fprintf(w, "    %s\n", s.c(dim, fmt.Sprintf("... and %d more (full list in --json)", omitted)))
		}
		fmt.Fprintln(w)
	}
}

// evidenceWhere renders the location of a piece of evidence: the artifact it was
// found in, and -- when the detector recorded one -- the log file and line it was
// read from, so the claim can be checked by hand.
func evidenceWhere(e model.Evidence) string {
	where := e.Path
	if src := sourceRef(e); src != "" {
		if where == "" {
			return src
		}
		return where + "  " + src
	}
	return where
}

// sourceRef formats "file:line", or just the file when no line was recorded.
func sourceRef(e model.Evidence) string {
	if e.Source == "" {
		return ""
	}
	if e.SourceLine > 0 {
		return fmt.Sprintf("%s:%d", e.Source, e.SourceLine)
	}
	return e.Source
}

func sevLabel(sev model.Severity, s Style) string {
	name := strings.ToUpper(sev.String())
	switch sev {
	case model.SevCritical:
		return s.c(red+bold, name)
	case model.SevHigh:
		return s.c(red, name)
	case model.SevMedium:
		return s.c(yellow, name)
	}
	return s.c(dim, name)
}

// maxEvidenceRows bounds what the TERMINAL prints per finding. The findings
// themselves keep every item -- --json is the forensic record and must stay
// complete -- so this is a display cap only, which is what makes the "full list in
// --json" pointer it prints true rather than a lie.
//
// It exists because a real host's upload_queue held tens of thousands of staged
// archives. One row per archive produced a 30,040-line report with the VERDICT on
// line 3 and everything actionable below 30,000 paths: the tool got the answer right
// and then buried it. A report that makes you scroll past its own conclusions trains
// you to skim it, which is the same failure the "don't report IoC noise" rule exists
// to prevent -- and it is worse here, because the noise is the tool's own output
// rather than someone else's.
//
// Ten, not twenty: the sample exists to show you the SHAPE of what was found, and the
// true total is always in the finding's title regardless. Ten rows fit on a screen
// alongside the verdict; twenty push it off.
const maxEvidenceRows = 10

// staging shows what is sitting on disk right now, waiting to go out (or already
// gone). A populated upload_queue and a manifest naming the bucket are among the
// strongest indicators there are, so they get their own section rather than being
// buried in the findings list.
func staging(w io.Writer, rep *model.Report, s Style) {
	// Each block is one finding: its TITLE, which carries the true total, followed
	// by a bounded sample of the paths behind it.
	//
	// Printing the title is not decoration. Before the display cap existed this
	// section emitted one row per archive, and the scale was conveyed -- badly -- by
	// the sheer length of the list. Capping the rows without promoting the title
	// would have deleted the only place the reader could learn that there were
	// twenty thousand archives and not twenty: the counts live in the finding titles
	// and nothing else in the terminal ever printed them.
	type block struct {
		title string
		rows  [][2]string
	}
	var blocks []block

	for _, f := range rep.Findings {
		switch f.ID {
		case "queue.present", "queue.codebase_archive", "queue.metadata_bucket":
			b := block{title: f.Title}
			if f.Severity >= model.SevCritical {
				b.title = s.c(red, f.Title)
			}
			shown, omitted := s.capRows(f.Evidence)
			for _, e := range shown {
				var label string
				if s.Verbose {
					// The full receipt: the detector's note, the size, and the sha256. The
					// hash is what lets the reader prove later that a file they still have
					// is the file that was staged -- so it is preserved, just moved off the
					// default report, where a 64-char digest per row is pure noise.
					label = e.Note
					if e.SizeBytes > 0 {
						label = fmt.Sprintf("%s, %s", e.Note, humanBytes(e.SizeBytes))
					}
					if e.SHA256 != "" {
						label = fmt.Sprintf("%s, sha256:%s", label, short(e.SHA256))
					}
				} else if e.SizeBytes > 0 {
					// Default: just the size. The section header already says every archive
					// was recorded, not opened, so repeating "codebase archive (recorded,
					// not opened)" on every row adds length without information.
					label = humanBytes(e.SizeBytes)
				} else {
					// No size (a manifest, the queue dir): the note carries the meaning.
					label = e.Note
				}
				b.rows = append(b.rows, [2]string{e.Path, label})
			}
			if omitted > 0 {
				b.rows = append(b.rows, [2]string{
					s.c(dim, fmt.Sprintf("... and %d more", omitted)),
					s.c(dim, "full list in --json"),
				})
			}
			blocks = append(blocks, b)
		}
	}
	if len(blocks) == 0 {
		return
	}

	stagingNote := "   (recorded by name and hash, never opened -- --verbose for the hashes)"
	if s.Verbose {
		stagingNote = "   (recorded by name and hash, never opened)"
	}
	fmt.Fprintln(w, s.c(bold, "STAGING")+s.c(dim, stagingNote))
	for _, b := range blocks {
		fmt.Fprintf(w, "  %s\n", b.title)
		if len(b.rows) == 0 {
			continue
		}
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, r := range b.rows {
			fmt.Fprintf(tw, "    %s\t%s\n", r[0], r[1])
		}
		tw.Flush()
	}
	fmt.Fprintln(w)
}

func verdictBanner(w io.Writer, rep *model.Report, s Style) {
	var color, headline string
	switch rep.Verdict {
	case model.VerdictCompromised:
		color = red
		// COMPROMISED means a delivery is proven. Only the delivered branch of
		// exfilHeadline may render here: its queued/collected branches say "delivery
		// UNCONFIRMED", which is a direct contradiction under this verdict -- and that
		// case is reachable, because a schema-drift upload signal (TagUpload) can promote
		// a host whose repos were merely queued or collected. When no repo was confirmed
		// delivered, the signal is a changed log schema, so say exactly that.
		if hasDelivered(rep) {
			headline = exfilHeadline(rep)
		} else {
			headline = "An upload event was found in Grok's logs, but the log schema has changed and no\n" +
				"confirmed delivery could be attributed to a repository. Treat this as evidence of\n" +
				"upload and rotate every repository this machine touched."
		}
	case model.VerdictExposed:
		color = yellow
		// A collected-or-queued host is now EXPOSED (delivery unproven), and its
		// collection facts are the most actionable line in the report -- lead with them.
		// Only an install-only host (grok present, nothing collected) gets the generic line.
		if headline = exfilHeadline(rep); headline == "" {
			headline = "The Grok Build CLI is present and whole-repository upload is not disabled.\n" +
				"No evidence was found that it has uploaded anything from this machine yet."
		}
	case model.VerdictIndeterminate:
		color = yellow
		// When nothing grok-related was found at all, say so plainly -- the scan just
		// walked the disk and reported "no install, no logs, no queue, no version" step
		// by step, and a verdict headline that then retreats to "no indicators were
		// found" reads as evasive next to it. But INDETERMINATE is ALSO reachable with
		// grok PRESENT-but-mitigated plus a material read error, and there the absence
		// wording would be a false negative -- the one failure this tool is built to
		// avoid. So the plain "no grok" line is gated on grok actually being absent.
		if rep.GrokPresent {
			headline = "No evidence of collection or upload was found, but parts of this machine could\n" +
				"not be read. This is not a clean bill of health -- see WHAT THIS SCAN COULD NOT\n" +
				"SEE below."
		} else {
			headline = "No Grok Build artifacts were found on this machine, but parts of it could not be\n" +
				"read -- so this is not a clean bill of health. See WHAT THIS SCAN COULD NOT SEE below."
		}
	default:
		color = green
		headline = "No Grok Build artifacts were found on this machine."
	}

	fmt.Fprintln(w, s.c(color+bold, "VERDICT: "+string(rep.Verdict)))
	for _, line := range strings.Split(headline, "\n") {
		fmt.Fprintln(w, "  "+line)
	}
	// The scale line, in the nouns the reader acts on rather than severity buckets.
	// --verbose keeps the severity counts (countsLine); the default leads with what
	// happened (foundTally), falling back to the severity line on an install-only host
	// where nothing was collected, queued, or exposed to tally.
	var scale string
	if s.Verbose {
		scale = countsLine(rep)
	} else if scale = foundTally(rep); scale == "" {
		scale = countsLine(rep)
	}
	if scale != "" {
		fmt.Fprintf(w, "  %s\n", s.c(dim, scale))
	}
	fmt.Fprintln(w)
}

// countsLine gives the scale of the report in one line. Report.Counts was computed
// on every run and printed nowhere, so a reader had to scroll the whole report to
// learn whether it held two findings or forty.
//
// Ordered most severe first, and severities with no findings are omitted rather
// than printed as a zero: "0 critical" is a sentence about nothing, and it reads
// like reassurance in a report whose job is the opposite.
func countsLine(rep *model.Report) string {
	order := []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}
	var parts []string
	for _, sev := range order {
		if n := rep.Counts[sev.String()]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ")
}

// foundTally is the default report's one-line scale, in the nouns the reader acts on
// rather than severity buckets. "3 critical, 2 high" tells a security engineer the
// shape of the finding list; "3 repos implicated · 5 archives queued · 4 secrets
// exposed" tells the person whose machine it is what happened. The severity counts are
// not lost -- they move to --verbose (countsLine) and stay complete in --json
// (rep.Counts). Returns "" for an install-only host with nothing collected, queued, or
// exposed, so the caller falls back to the severity line rather than printing an empty
// "Found:".
//
// "implicated", not "collected": this counts EVERY repo the ledger touched -- queued
// and collected-only alike -- whereas the verdict headline says "N repository collected
// and queued" about the queued set only. Reusing "collected" for the wider set here put
// two different repo counts ("1 repository collected" vs "2 repos collected") on
// adjacent lines, reading as a contradiction when both were correct.
func foundTally(rep *model.Report) string {
	repos, archives := 0, 0
	for _, r := range rep.Repos {
		switch r.Status {
		case model.StatusDelivered, model.StatusQueued, model.StatusCollectedOnly:
			repos++
		}
		archives += len(r.Archives)
	}
	secretFiles, _ := secretTotals(rep)

	var parts []string
	if repos > 0 {
		parts = append(parts, engine.Plural(repos, "repo")+" implicated")
	}
	if archives > 0 {
		parts = append(parts, engine.Plural(archives, "archive")+" queued")
	}
	if secretFiles > 0 {
		parts = append(parts, engine.Plural(secretFiles, "secret")+" exposed")
	}
	if len(parts) == 0 {
		return ""
	}
	return "Found: " + strings.Join(parts, " · ")
}

// secretTotals counts secret files across all repositories, and how many are the
// priority class -- deleted from the checkout but still alive in the uploaded history.
// Extracted so the secrets section, its examples block, and the found tally agree on
// one set of numbers.
func secretTotals(rep *model.Report) (total, deleted int) {
	for _, r := range rep.Repos {
		for _, h := range r.SecretFiles {
			total++
			if h.DeletedFromCheckout {
				deleted++
			}
		}
	}
	return total, deleted
}

// hasDelivered reports whether any repository's upload was confirmed landed. It
// gates the COMPROMISED banner: only a confirmed delivery may render the "in xAI's
// possession" wording, never a queued-or-collected repo promoted by a schema-drift
// upload signal.
func hasDelivered(rep *model.Report) bool {
	for _, r := range rep.Repos {
		if r.Status == model.StatusDelivered {
			return true
		}
	}
	return false
}

// exfilHeadline describes what was collected, queued, or delivered, strongest
// evidence first. It renders under BOTH verdicts: COMPROMISED (a confirmed
// delivery) and EXPOSED (collection or queueing with no proof of delivery). On
// either, the collection facts are the most actionable thing in the report, so the
// banner must lead with them rather than bury them under a generic line. Returns ""
// when no repository was implicated, leaving the caller to supply a
// verdict-appropriate fallback.
func exfilHeadline(rep *model.Report) string {
	queued, collected, archives := 0, 0, 0
	delivered, confirmed := 0, 0
	for _, r := range rep.Repos {
		switch r.Status {
		case model.StatusDelivered:
			delivered++
			confirmed += r.DeliveriesConfirmed
			queued++ // a delivered repo was also queued; it is not a separate population
			archives += len(r.Archives)
		case model.StatusQueued:
			queued++
			archives += len(r.Archives)
		case model.StatusCollectedOnly:
			collected++
		}
	}
	switch {
	// The one case where this tool may state delivery as fact. Everywhere else the
	// banner is careful to say the log cannot speak to it; here the log did.
	case delivered > 0:
		return fmt.Sprintf(
			"%s CONFIRMED DELIVERED to %s (%s collected, %s built and queued).\n"+
				"This is not an inference: Grok's log records the transfer completing.\n"+
				"Their full git history -- including files you deleted -- is in xAI's possession. Rotate now.",
			engine.Plural(confirmed, "archive"), scan.BucketURL(),
			engine.Plural(queued, "repository"), engine.Plural(archives, "archive"))
	case queued > 0:
		// Says what is PROVEN, then what is NOT, and does not blur the two.
		//
		// This line used to end "Assume their full git history ... is in xAI's
		// possession." -- which asserts DELIVERY, the one thing in the whole chain that
		// cannot be shown from a log. Grok emits no upload-completion event: collection
		// and enqueue are recorded, the PUT that follows is not. So a delivered archive
		// and an archive whose upload silently failed leave exactly the same trace, and
		// a banner that states possession as fact is describing an event this tool never
		// saw. Overclaiming on the headline is how a report loses the reader who checks
		// it -- and this report's whole authority is that everything in it is checkable.
		//
		// This is an EXPOSED headline, not a COMPROMISED one: collection and queueing
		// are proven, delivery is not, and the verdict says exactly that. What the
		// wording must NOT do is soften the collection facts or read as reassurance --
		// these repositories were read and packaged, and the rotation advice follows
		// from that alone. COMPROMISED is reserved for a confirmed (or unclassifiable)
		// delivery; a queued-but-undelivered host is EXPOSED, and must still rotate.
		return fmt.Sprintf(
			"%s collected and %s built and queued for upload to %s.\n"+
				"Delivery is UNCONFIRMED -- Grok logs no upload-completion event -- but it is not\n"+
				"disproven either: the queue may have drained on a run whose logs have since rotated.\n"+
				"Treat their full git history -- including files you deleted -- as exposed, and rotate.",
			engine.Plural(queued, "repository"), engine.Plural(archives, "archive"), scan.BucketURL())
	case collected > 0:
		return fmt.Sprintf(
			"%d repositories were collected by Grok. Whether the upload completed is unconfirmed,\n"+
				"which is not the same as disproven: the enqueue records may simply have rotated away.", collected)
	default:
		// No repository was implicated by the ledger or the queue. The caller supplies
		// a fallback appropriate to the verdict (a schema-drift upload signal under
		// COMPROMISED, an install-only host under EXPOSED).
		return ""
	}
}

// versionBanner hoists an affected build out of the INSTALLATION table and puts it
// directly beneath the verdict.
//
// It used to render as one row among several -- "version  0.2.93  (logs)  CONFIRMED
// AFFECTED" -- in a table below the fold, in the same weight as the config.toml row
// beside it. But an affected version is not a detail of the installation. 0.2.93 is
// the build that was publicly REPRODUCED collecting whole repositories and uploading
// them, so on a host running it the question stops being whether this collector is
// capable of that and becomes only what it took. A reader who skims past the tables
// must not be able to miss it, and next to the verdict is the one place nobody skims.
//
// It prints on EVERY verdict, deliberately -- including EXPOSED and CLEAN. A machine
// with the confirmed-affected build and no upload evidence yet is the single most
// actionable state this tool can report: there is still time to act. Gating this on
// COMPROMISED would hide it from exactly the user who could still do something.
func versionBanner(w io.Writer, rep *model.Report, s Style) {
	var confirmed, reported []string
	for _, v := range rep.Versions {
		// Low confidence means a semver scraped out of a binary's string table, where a
		// packed CLI carries dozens of unrelated dependency versions. Shouting
		// "CONFIRMED AFFECTED" on one of those would be this tool inventing its loudest
		// claim out of a coincidence.
		if v.Confidence == "low" {
			continue
		}
		switch v.Class {
		case model.VersionConfirmedAffected:
			confirmed = addUnique(confirmed, v.Version)
		case model.VersionReportedAffected:
			reported = addUnique(reported, v.Version)
		}
	}

	switch {
	case len(confirmed) > 0:
		fmt.Fprintln(w, s.c(red+bold, "  GROK BUILD "+strings.Join(confirmed, ", ")+"  --  CONFIRMED AFFECTED"))
		fmt.Fprintf(w, "  %s\n", s.c(red, "This exact build was publicly reproduced collecting whole repositories and"))
		fmt.Fprintf(w, "  %s\n", s.c(red, "uploading them to xAI. That is not an inference from the version number."))
	case len(reported) > 0:
		fmt.Fprintln(w, s.c(yellow+bold, "  GROK BUILD "+strings.Join(reported, ", ")+"  --  REPORTED AFFECTED"))
		fmt.Fprintf(w, "  %s\n", s.c(yellow, "This build is within the range reported to carry the collector. grokpatrol has"))
		fmt.Fprintf(w, "  %s\n", s.c(yellow, "not independently verified that, which is why nothing above the range is called clean."))
	default:
		return
	}
	fmt.Fprintln(w)
}

// addUnique appends v if it is not already present, preserving order.
func addUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// installation is the inventory of the Grok install on this host. In the DEFAULT
// report it is a summary: the config mitigation state -- which on an EXPOSED host is
// the entire basis for the verdict -- and the grok binary's path. The receipt behind
// it (the binary's sha256, the per-version inventory and the file each version was
// read from, auth.json, and the other upload-related keys) prints under --verbose.
//
// The affected-build WARNING is not what moves: versionBanner hoists it directly
// under the verdict on every run. What --verbose gates here is the version INVENTORY
// -- the paths and the un-flagged versions behind that warning -- not the warning.
// dedupeBinaries collapses the per-marker evidence of deepscan.binary_marker to one
// entry per binary, and orders them so the install on the user's $PATH -- the grok
// that runs when they type `grok` -- comes first. deepscan emits one evidence row per
// marker OFFSET, so a binary carrying the bucket name three times used to render as
// three identical rows; this keeps the first offset as the sample.
func dedupeBinaries(ev []model.Evidence) []model.Evidence {
	idx := map[string]int{}
	var out []model.Evidence
	for _, e := range ev {
		if i, ok := idx[e.Path]; ok {
			// A later offset's row may be the one carrying the $PATH marker; do not lose it.
			if out[i].PathEntry == "" && e.PathEntry != "" {
				out[i].PathEntry = e.PathEntry
			}
			// Prefer the bucket marker as the sample -- it is the meaningful one -- but an
			// install can be flagged on a DIFFERENT marker and never carry the bucket at all
			// (deepscan builds a hit on any DefaultMarkers match). Filtering to the bucket
			// here would drop such a binary from INSTALLATION entirely, highlight and all, so
			// whatever marker was seen first still stands when the bucket is absent.
			if !strings.Contains(out[i].Note, scan.MarkerBucket) && strings.Contains(e.Note, scan.MarkerBucket) {
				pe := out[i].PathEntry
				out[i] = e
				out[i].PathEntry = pe
			}
			continue
		}
		idx[e.Path] = len(out)
		out = append(out, e)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].PathEntry != "" && out[j].PathEntry == ""
	})
	return out
}

// binLabel is the INSTALLATION left column. The install on $PATH is called out so a
// reader scanning a host with several copies on disk sees which one actually runs.
func binLabel(e model.Evidence, s Style) string {
	if e.PathEntry != "" {
		return s.c(red+bold, "grok binary")
	}
	return "grok binary"
}

// binDesc is the right column: path, size, marker location and hash of one binary. For
// the install on $PATH it also shows the $PATH entry -- the command that runs -- and,
// when that entry is a symlink into a bundle, that it points at the resolved file above.
// Used only under --verbose; the default report's own inline rendering in installation()
// stays terse (path, size, and the $PATH highlight only).
func binDesc(e model.Evidence, s Style) string {
	desc := fmt.Sprintf("%s (%s)", e.Path, humanBytes(e.SizeBytes))
	if e.PathEntry != "" {
		desc += "  " + s.c(red+bold, "<- runs when you type `grok`")
		if e.PathEntry != e.Path {
			desc += fmt.Sprintf("\n%s on your $PATH at %s (symlink to the file above)", pad, e.PathEntry)
		} else {
			desc += fmt.Sprintf("\n%s on your $PATH", pad)
		}
	}
	// The marker actually found, not a hardcoded bucket string: a binary flagged on a
	// different DefaultMarkers hit must report the marker it really carries. This parses
	// the marker back out of the Note, whose "contains marker " prefix is written by
	// deepscan's findings(); the two must stay in sync.
	marker := strings.TrimPrefix(e.Note, "contains marker ")
	desc += fmt.Sprintf("\n%s contains %q at %s", pad, marker, e.Locator)
	// Identifies the exact build sitting on this disk -- what anyone comparing notes
	// across a fleet, or against a vendor's published hashes, actually needs.
	if e.SHA256 != "" {
		desc += fmt.Sprintf("\n%s sha256:%s", pad, e.SHA256)
	}
	return desc
}

func installation(w io.Writer, rep *model.Report, s Style) {
	var lines [][2]string
	withheld := false // did the default report drop receipt detail it should point at?

	for _, f := range rep.Findings {
		if f.ID == "deepscan.binary_marker" {
			// One row per BINARY, not per marker hit. The evidence is emitted once per
			// marker offset, so a binary carrying the bucket name at three offsets used to
			// print as three identical "grok binary" rows. dedupeBinaries collapses them to
			// one representative per path and floats the install on $PATH to the top.
			for _, b := range dedupeBinaries(f.Evidence) {
				label := binLabel(b, s)
				if !s.Verbose {
					// The path, size, and -- for the install that actually runs -- the $PATH
					// highlight are what locate and identify the live install: a summary-level
					// fact, printed in BOTH modes. The marker offset and sha256 are for someone
					// diffing this build against a vendor's published hashes, a receipt task,
					// so they wait for --verbose.
					desc := fmt.Sprintf("%s (%s)", b.Path, humanBytes(b.SizeBytes))
					if b.PathEntry != "" {
						desc += "  " + s.c(red+bold, "<- runs when you type `grok`")
						if b.PathEntry != b.Path {
							desc += fmt.Sprintf("\n%s on your $PATH at %s (symlink to the file above)", pad, b.PathEntry)
						}
					}
					lines = append(lines, [2]string{label, desc})
					withheld = withheld || b.SHA256 != ""
					continue
				}
				lines = append(lines, [2]string{label, binDesc(b, s)})
			}
		}
	}

	// The per-version inventory is verbose-only: versionBanner already carried the
	// one fact that matters -- this build is affected -- to the top of the report. The
	// rows here add the PATH each version was read from and the versions that are not
	// flagged at all, which is inventory, not headline.
	if s.Verbose {
		for _, v := range rep.Versions {
			if v.Confidence == "low" {
				continue
			}
			// The PATH, not the word "logs". A row reading "0.2.51  (logs)  REPORTED AFFECTED"
			// names a category, not a location -- and on a host with four versions strewn across
			// a rotated log history, which FILE each was read from is the difference between a
			// build that ran once in May and the one running now. Every other evidence line in
			// this report cites where it came from; this one asserted a version from nowhere.
			//
			// Source is the fallback for evidence that genuinely has no path.
			where := v.Path
			if where == "" {
				where = "(" + v.Source + ")"
			}
			// Version-row rendering from upstream v0.1.5: UNKNOWN gets no verdict-shaped
			// label -- "UNKNOWN" reads as an error, not a deliberate absence of one (see
			// grokver.Class) -- but "read from" still cites where the version came from.
			var row string
			switch v.Class {
			case model.VersionConfirmedAffected:
				row = fmt.Sprintf("%s  %s  %s", v.Version, s.c(red, "CONFIRMED AFFECTED"), s.c(dim, where))
			case model.VersionReportedAffected:
				row = fmt.Sprintf("%s  %s  %s", v.Version, s.c(yellow, "REPORTED AFFECTED"), s.c(dim, where))
			default:
				row = fmt.Sprintf("%s  read from %s", v.Version, s.c(dim, where))
			}
			lines = append(lines, [2]string{"version", row})
		}
	} else {
		for _, v := range rep.Versions {
			if v.Confidence != "low" {
				withheld = true
				break
			}
		}
	}

	// The config.toml state, as ONE row per file. The detector emits a finding PER
	// mitigation (there are two), so a config with neither set produced two identical
	// "not both set" rows; configRows collapses them and names the specific mitigations.
	lines = append(lines, configRows(rep, s)...)

	for _, f := range rep.Findings {
		switch f.ID {
		case "config.auth_present":
			// Verbose-only. auth.json's presence is inventory, not a lever the reader pulls,
			// and it is a detail beside the config state that actually drives the verdict.
			if s.Verbose {
				lines = append(lines, [2]string{"auth.json", "present"})
			} else {
				withheld = true
			}
		case "config.other_keys":
			if s.Verbose {
				lines = append(lines, [2]string{"other options", strings.TrimPrefix(f.Title, "Other upload-related options are set: ")})
			} else {
				withheld = true
			}
		}
	}

	if len(lines) == 0 {
		return
	}
	fmt.Fprintln(w, s.c(bold, "INSTALLATION"))
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, l := range lines {
		fmt.Fprintf(tw, "  %s\t%s\n", l[0], l[1])
	}
	tw.Flush()
	// A summary that drops detail has to say it did, or it reads as the whole
	// inventory -- and on an EXPOSED host with no exfil sections below, this may be
	// the only place the default report names --verbose at all.
	if withheld && !s.Verbose {
		fmt.Fprintf(w, "  %s\n", s.c(dim, "run --verbose for the version inventory, binary hash, and the rest of the install"))
	}
	fmt.Fprintln(w)
}

// configRows renders the config.toml state as ONE row per file. The config detector
// evaluates the two upload mitigations independently and emits a finding for EACH, so a
// config with neither set produced two findings that installation() rendered as two
// identical "the upload mitigations are not both set" rows. This groups every config
// finding by the file it came from and, instead of that vague phrase, names the actual
// mitigations at fault -- which is what the reader has to change.
func configRows(rep *model.Report, s Style) [][2]string {
	type cfg struct {
		absent, unparse, mitigated bool
		notSet, wrongValue         []string // mitigation keys, e.g. harness.disable_codebase_upload
	}
	byPath := map[string]*cfg{}
	var order []string
	get := func(path string) *cfg {
		c, ok := byPath[path]
		if !ok {
			c = &cfg{}
			byPath[path] = c
			order = append(order, path)
		}
		return c
	}
	key := func(f model.Finding) string {
		if len(f.Evidence) > 0 {
			return f.Evidence[0].Locator // "table.key", set by the config detector
		}
		return ""
	}
	path := func(f model.Finding) string {
		if len(f.Evidence) > 0 {
			return f.Evidence[0].Path
		}
		return ""
	}
	for _, f := range rep.Findings {
		switch f.ID {
		case "config.absent":
			get(path(f)).absent = true
		case "config.unparseable":
			get(path(f)).unparse = true
		case "config.mitigated":
			get(path(f)).mitigated = true
		case "config.not_mitigated":
			c := get(path(f))
			c.notSet = append(c.notSet, key(f))
		case "config.explicitly_disabled":
			c := get(path(f))
			c.wrongValue = append(c.wrongValue, key(f))
		}
	}

	var rows [][2]string
	for _, p := range order {
		c := byPath[p]
		var val string
		switch {
		case c.mitigated:
			val = s.c(green, "MITIGATED") + " -- both upload mitigations set"
		case c.absent:
			val = s.c(yellow, "EXPOSED") + " -- no config.toml, so neither upload mitigation is set"
		case c.unparse:
			val = s.c(yellow, "EXPOSED") + " -- config.toml could not be fully read, so the mitigations are " +
				"UNCONFIRMED -- verify it by hand"
		default:
			val = s.c(yellow, "EXPOSED") + " -- " + mitigationDetail(c.wrongValue, c.notSet)
		}
		// Every branch above names "mitigation(s)" without saying what they actually are.
		// "(see below)" points at the MITIGATIONS section printed right after this table.
		rows = append(rows, [2]string{"config.toml", val + " (see below)"})
	}
	return rows
}

// mitigations is the short lookup table the config.toml row's "(see below)" points at:
// the two settings that must both hold, named exactly as they must appear in
// config.toml. It is NOT the remediation prose the rest of this file deliberately
// omits (see the note near the end) -- just the two lines, so a reader who was told
// "mitigations" has something to check them against without leaving the terminal.
//
// Printed only when a config finding actually mentioned mitigations: a host with no
// grok install never reaches this, and a section nothing points to is noise.
func mitigations(w io.Writer, rep *model.Report, s Style) {
	if !hasConfigFinding(rep) {
		return
	}
	fmt.Fprintln(w, s.c(bold, "MITIGATIONS"))
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, m := range config.Mitigations() {
		fmt.Fprintf(tw, "  [%s]\t%s = %s\n", m.Table, m.Key, m.Want)
	}
	tw.Flush()
	fmt.Fprintln(w)
}

func hasConfigFinding(rep *model.Report) bool {
	for _, f := range rep.Findings {
		switch f.ID {
		case "config.mitigated", "config.not_mitigated", "config.absent", "config.explicitly_disabled", "config.unparseable":
			return true
		}
	}
	return false
}

// mitigationDetail names the mitigations at fault in one phrase: which are set to the
// wrong value and which are missing entirely. Falls back to the generic wording only if
// the finding carried no key (it always should).
func mitigationDetail(wrong, notSet []string) string {
	var parts []string
	if n := joinKeys(wrong); n != "" {
		parts = append(parts, n+" set to the wrong value")
	}
	if n := joinKeys(notSet); n != "" {
		parts = append(parts, n+" not set")
	}
	if len(parts) == 0 {
		return "the upload mitigations are not both set"
	}
	return strings.Join(parts, "; ")
}

// joinKeys drops empties and joins the mitigation keys with "and".
func joinKeys(keys []string) string {
	var out []string
	for _, k := range keys {
		if k != "" {
			out = append(out, k)
		}
	}
	return strings.Join(out, " and ")
}

const pad = "               "

func ledger(w io.Writer, rep *model.Report, s Style) {
	delivery := findingByID(rep, "logs.upload_auth_failure")

	// A host with no ledger rows but upload-leg 401s is a real state: the upload
	// client was rejected and nothing was ever collected, or the collection events
	// rotated away and only the failures remain. Returning early there would print
	// nothing at all in the terminal while --json carried a finding, which is the
	// one case where this note is the only thing there is to say.
	if len(rep.Repos) == 0 && delivery == nil {
		return
	}
	fmt.Fprintln(w, s.c(bold, "EXFILTRATION LEDGER"))
	if len(rep.Repos) == 0 {
		fmt.Fprintf(w, "  %s\n", s.c(dim, "No repository was recorded as collected."))
	}

	// The upload-401 column appears only when there is something in it. Printing a
	// column of zeros would invite exactly the misreading the whole feature is meant
	// to avoid -- "0 auth failures" is not "delivered fine", it is "no local trace
	// either way", and a silent column says that better than a zero does.
	showAuth := false
	for _, r := range rep.Repos {
		if r.UploadAuthFailures > 0 {
			showAuth = true
			break
		}
	}

	if len(rep.Repos) > 0 {
		// Worst repos first, and in the DEFAULT report only the top maxLedgerRepos of
		// them: a host with dozens of collected repos would otherwise push the verdict
		// off the screen, the same failure the archive display cap exists to prevent.
		// --verbose lists every repository; the true total is one line below the table.
		rows := rep.Repos
		omitted := 0
		if !s.Verbose && len(rows) > maxLedgerRepos {
			rows = append([]model.RepoStatus(nil), rep.Repos...)
			sort.SliceStable(rows, func(i, j int) bool {
				if a, b := statusRank(rows[i].Status), statusRank(rows[j].Status); a != b {
					return a > b
				}
				return len(rows[i].Archives) > len(rows[j].Archives)
			})
			omitted = len(rows) - maxLedgerRepos
			rows = rows[:maxLedgerRepos]
		}

		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintf(tw, "  %s\t%s", s.c(dim, "REPOSITORY"), s.c(dim, "STATUS"))
		// ATTEMPTS is verbose-only: how many archives went OUT is what to act on, and
		// the collect-attempt count is a second-order detail beside it.
		if s.Verbose {
			fmt.Fprintf(tw, "\t%s", s.c(dim, "ATTEMPTS"))
		}
		fmt.Fprintf(tw, "\t%s", s.c(dim, "ARCHIVES"))
		if showAuth {
			fmt.Fprintf(tw, "\t%s", s.c(dim, "UPLOAD 401s"))
		}
		fmt.Fprintf(tw, "\t%s\n", s.c(dim, "COLLECTED"))

		for _, r := range rows {
			status := r.Status
			switch r.Status {
			case model.StatusDelivered:
				status = s.c(red+bold, "DELIVERED")
			case model.StatusQueued:
				status = s.c(red, "QUEUED")
			case model.StatusCollectedOnly:
				status = s.c(yellow, "COLLECTED-ONLY")
			default:
				status = s.c(dim, strings.ToUpper(r.Status))
			}
			fmt.Fprintf(tw, "  %s\t%s", r.RepoPath, status)
			if s.Verbose {
				fmt.Fprintf(tw, "\t%d", r.CollectAttempts)
			}
			// The archive count carries BOTH total and unique now -- the gap between
			// them separates sustained collection from a retried failing upload -- so
			// the separate "ARCHIVES QUEUED FOR UPLOAD" counts block is gone from the
			// default report; --verbose still lists every gs:// object below.
			fmt.Fprintf(tw, "\t%s", archiveSummary(r, s))
			if showAuth {
				fmt.Fprintf(tw, "\t%s", authSummary(r, s))
			}
			fmt.Fprintf(tw, "\t%s\n", collectedWindow(r))
		}
		tw.Flush()
		if omitted > 0 {
			noun := "repositories"
			if omitted == 1 {
				noun = "repository"
			}
			fmt.Fprintf(w, "  %s\n", s.c(dim, fmt.Sprintf("... and %d more %s (--verbose for all, --json for the record)", omitted, noun)))
		}
		archiveDetail(w, rep, s)
	}

	// The delivery note belongs here rather than in its own section: it exists only
	// to be read against the rows above, and a reader who sees QUEUED without it can
	// reasonably wonder whether the bytes ever left. It is printed dim because it is
	// context, not a finding to act on -- the ARCHIVES column is what to act on.
	//
	// The per-repo UPLOAD 401s columns can overlap: one failure inside two repos'
	// windows counts against both, so the columns are not a total and must not be
	// summed. The count in this note is the global one.
	// The standing "delivery is unconfirmable" caveat is TRUE ONLY WHILE NO COMPLETION
	// EVENT WAS FOUND. Printing it unconditionally would have the report deny, in dim
	// text under the table, the very confirmation the table above it is reporting --
	// so a host where delivery WAS proven says so instead.
	if anyDelivered(rep) {
		// The verdict headline already states the confirmed delivery in full ("CONFIRMED
		// DELIVERED ... Grok's log records the transfer completing"), and the STATUS
		// column reads DELIVERED. Repeating it a third time here is noise in the default
		// report, so the elaboration is --verbose only.
		if s.Verbose {
			fmt.Fprintf(w, "\n  %s %s\n", s.c(red+bold, "delivery:"),
				s.c(red, "CONFIRMED -- Grok's log records the transfer completing."))
			fmt.Fprintf(w, "  %s\n", s.c(dim, "This is the strongest statement this tool can make. It is not inferred from"))
			fmt.Fprintf(w, "  %s\n", s.c(dim, "collection or queueing: the upload itself was logged as finished."))
		}
	} else if delivery != nil {
		fmt.Fprintf(w, "\n  %s %s\n", s.c(dim, "delivery:"), s.c(dim, delivery.Title))
		// The standing "no upload-completion event" explanation is receipt-grade context,
		// not a finding to act on -- the ARCHIVES column above is what to act on -- so the
		// default report keeps just the one-line status and the reasoning waits for
		// --verbose. A trim, not a retraction: the one-line status still says unconfirmed.
		if s.Verbose {
			fmt.Fprintf(w, "  %s\n", s.c(dim, "Grok logs no upload-completion event, so neither this tool nor the log can confirm"))
			fmt.Fprintf(w, "  %s\n", s.c(dim, "the archives were delivered -- only that they were built and queued."))
		}
	}
	fmt.Fprintln(w)
}

// capRows truncates for display only, never for the record. It returns the items
// to print and how many were withheld.
func (s Style) capRows(ev []model.Evidence) (shown []model.Evidence, omitted int) {
	if s.Verbose || len(ev) <= maxEvidenceRows {
		return ev, 0
	}
	return ev[:maxEvidenceRows], len(ev) - maxEvidenceRows
}

// anyDelivered reports whether any archive's upload was confirmed to have landed.
func anyDelivered(rep *model.Report) bool {
	for _, r := range rep.Repos {
		if r.DeliveriesConfirmed > 0 {
			return true
		}
	}
	return false
}

func findingByID(rep *model.Report, id string) *model.Finding {
	for i := range rep.Findings {
		if rep.Findings[i].ID == id {
			return &rep.Findings[i]
		}
	}
	return nil
}

// authSummary renders the in-window upload-401 count. A dash, never a zero: see
// the showAuth comment above.
func authSummary(r model.RepoStatus, s Style) string {
	if r.UploadAuthFailures == 0 {
		return s.c(dim, "-")
	}
	return s.c(yellow, fmt.Sprintf("%d", r.UploadAuthFailures))
}

// archiveSummary is the ARCHIVES cell: total, and how many DISTINCT gs:// objects
// that total names. The gap between the two is the signal -- "64 (12 unique)" is a
// retried failing upload, "64 (64 unique)" is 64 separate snapshots -- which is why
// this cell now carries both numbers and the separate ARCHIVES QUEUED counts block
// was removed from the default report. A repo that was collected but never queued
// shows a dash, not "0 (0 unique)": nothing went out to count.
func archiveSummary(r model.RepoStatus, s Style) string {
	total, unique, delivered := archiveCounts(r)
	if total == 0 {
		return s.c(dim, "-")
	}
	cell := fmt.Sprintf("%d (%d unique)", total, unique)
	if delivered > 0 {
		cell += ", " + s.c(red+bold, fmt.Sprintf("%d delivered", delivered))
	}
	return cell
}

// statusRank orders repositories worst-first for the capped ledger table, so the
// top rows are the ones the reader most needs to see when the full list is withheld.
func statusRank(status string) int {
	switch status {
	case model.StatusDelivered:
		return 3
	case model.StatusQueued:
		return 2
	case model.StatusCollectedOnly:
		return 1
	}
	return 0
}

// maxLedgerRepos bounds the per-repo ledger table in the DEFAULT report, mirroring
// maxEvidenceRows: a host with dozens of collected repositories would otherwise bury
// the verdict. --verbose lists every repository and --json is the complete record, so
// the cap is display-only and the true total is printed beside it.
const maxLedgerRepos = 10

// collectedWindow shows the span over which Grok was reading this repository,
// rather than the single date the ledger used to print. One date reads like one
// event; "2026-06-30 → 2026-07-11" is a fortnight of collection, and a reader who
// only sees the last day cannot tell the difference.
func collectedWindow(r model.RepoStatus) string {
	const day = "2006-01-02"
	switch {
	case r.FirstSeen.IsZero() && r.LastSeen.IsZero():
		return "-"
	case r.FirstSeen.IsZero():
		return r.LastSeen.Format(day)
	case r.LastSeen.IsZero():
		return r.FirstSeen.Format(day)
	}
	first, last := r.FirstSeen.Format(day), r.LastSeen.Format(day)
	if first == last {
		return first
	}
	return first + " -> " + last
}

// archiveDetail prints the evidence behind the ARCHIVES column: for each archive,
// the gs:// object it was queued to, the session and turn that built it, and the
// log line Grok wrote when it did.
//
// The gs:// path is the single most important string in the report -- the model
// calls it the smoking gun and keeps it verbatim for that reason -- and until now
// the terminal collapsed it to a digit. A reader could see that two archives were
// queued and never learn where they went, which is the difference between being
// told you were robbed and being shown the receipt.
func archiveDetail(w io.Writer, rep *model.Report, s Style) {
	// WITHOUT --verbose the per-repo archive counts live in the ledger table's ARCHIVES
	// column ("64 (12 unique)"), so this section prints nothing in the default report
	// except the collected-only citations -- the separate "ARCHIVES QUEUED FOR UPLOAD"
	// counts block was consolidated into the table. --verbose still lists every gs://
	// object with its provenance, and --json is complete.
	if !s.Verbose {
		citations(w, rep, s)
		return
	}

	var withArchives []model.RepoStatus
	for _, r := range rep.Repos {
		if len(r.Archives) > 0 {
			withArchives = append(withArchives, r)
		}
	}
	if len(withArchives) == 0 {
		// Nothing was queued, but something was collected: cite the line that says so,
		// or a COLLECTED-ONLY row is an assertion with no visible basis.
		citations(w, rep, s)
		return
	}

	// The gs:// path is the single most important string in the report -- the model
	// calls it the smoking gun -- so --verbose prints every one with its provenance.
	fmt.Fprintf(w, "\n  %s%s\n", s.c(bold, "ARCHIVES QUEUED FOR UPLOAD"),
		s.c(dim, "   (one line per archive, as recorded in Grok's own logs)"))

	for _, r := range withArchives {
		fmt.Fprintf(w, "  %s\n", s.c(cyan, r.RepoPath))
		for _, a := range r.Archives {
			line := s.c(red, a.GCSPath)
			if a.Delivered {
				line += "  " + s.c(red+bold, "<- DELIVERY CONFIRMED")
			}
			fmt.Fprintf(w, "    %s\n", line)
			if p := archiveProvenance(a); p != "" {
				fmt.Fprintf(w, "      %s\n", s.c(dim, p))
			}
		}
	}
	citations(w, rep, s)
}

// archiveCounts returns how many archives were enqueued for a repo, how many DISTINCT
// gs:// objects they name, and how many had their delivery confirmed.
func archiveCounts(r model.RepoStatus) (total, unique, delivered int) {
	seen := map[string]bool{}
	for _, a := range r.Archives {
		total++
		// An archive with no recorded destination still happened; it just cannot be
		// deduplicated, so it counts as its own object rather than collapsing every
		// path-less archive into one.
		if a.GCSPath == "" || !seen[a.GCSPath] {
			unique++
			seen[a.GCSPath] = true
		}
		if a.Delivered {
			delivered++
		}
	}
	return total, unique, delivered
}

// archiveProvenance is the "how do you know" line: session, turn, timestamp, and
// the log file and line the enqueue was read from. Each part appears only if it
// was actually recorded -- a turn number of 0 that Grok never wrote would be this
// tool inventing evidence, which is worse than having none.
func archiveProvenance(a model.Archive) string {
	var parts []string
	if a.SID != "" {
		parts = append(parts, "session "+a.SID)
	}
	if a.TurnNumber != nil {
		parts = append(parts, fmt.Sprintf("turn %d", *a.TurnNumber))
	}
	if !a.Timestamp.IsZero() {
		parts = append(parts, a.Timestamp.UTC().Format(time.RFC3339))
	}
	if a.LogFile != "" {
		ref := a.LogFile
		if a.LogLine > 0 {
			ref = fmt.Sprintf("%s:%d", a.LogFile, a.LogLine)
		}
		parts = append(parts, ref)
	}
	return strings.Join(parts, "   ")
}

// citations prints the log line behind each COLLECTED-ONLY row. Those rows have no
// archive to show, so this is the only evidence they have.
func citations(w io.Writer, rep *model.Report, s Style) {
	var rows [][2]string
	for _, r := range rep.Repos {
		if len(r.Archives) > 0 || r.LogFile == "" {
			continue
		}
		ref := r.LogFile
		if r.LogLine > 0 {
			ref = fmt.Sprintf("%s:%d", r.LogFile, r.LogLine)
		}
		rows = append(rows, [2]string{r.RepoPath, "collection first recorded at " + ref})
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintf(tw, "  %s\t%s\n", r[0], s.c(dim, r[1]))
	}
	tw.Flush()
}

// secrets is the section that gets acted on, so it prints full paths. Only the
// contents of these files are off-limits -- their names and locations are the
// entire deliverable.
func secrets(w io.Writer, rep *model.Report, s Style) {
	any := false
	for _, r := range rep.Repos {
		if len(r.SecretFiles) > 0 {
			any = true
			break
		}
	}
	if !any {
		return
	}

	fmt.Fprintln(w, s.c(bold, "LIKELY EXPOSED SECRETS")+
		s.c(dim, "   (filenames and object ids only -- contents were never read by this tool)"))

	// WITHOUT --verbose this is a COUNT, not the rotation list.
	//
	// The count is not a summary of the list, it is a pointer to it: the number that
	// survives into the default report is the one the reader acts on first -- how many
	// secrets are gone from the checkout but still alive in the uploaded history, which
	// they cannot find by looking at their own repository. The names, classes and blob
	// ids are one --verbose away and complete in --json.
	if !s.Verbose {
		// Per-repo counts first -- this loop carries the headline number the reader acts
		// on: how many secrets, and how many are gone from the checkout but still in the
		// uploaded history (the ones they cannot find by looking at their own repo).
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, r := range rep.Repos {
			if len(r.SecretFiles) == 0 {
				continue
			}
			deleted := 0
			for _, h := range r.SecretFiles {
				if h.DeletedFromCheckout {
					deleted++
				}
			}
			count := engine.Plural(len(r.SecretFiles), "secret file")
			if deleted > 0 {
				count += ", " + s.c(red+bold, fmt.Sprintf("%d deleted from the checkout but still in history", deleted))
			}
			fmt.Fprintf(tw, "  %s\t%s\n", s.c(cyan, r.RepoPath), count)
		}
		tw.Flush()

		// Numbers + a few EXAMPLES: the default report now names WHICH files to rotate
		// -- deleted-from-checkout first, diversified by risk class -- without becoming
		// the full rotation list. Filename, class and risk only; never a value, and the
		// blob id stays a --verbose receipt.
		if shown, omitted := secretExamples(rep); len(shown) > 0 {
			fmt.Fprintf(w, "\n  %s\n", s.c(dim, "examples:"))
			etw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
			for _, h := range shown {
				name, class, risk := secretExampleRow(h, s)
				fmt.Fprintf(etw, "    %s\t%s\t%s\n", name, class, risk)
			}
			etw.Flush()
			if omitted > 0 {
				fmt.Fprintf(w, "    %s\n", s.c(dim, fmt.Sprintf("... and %d more (--verbose)", omitted)))
			}
		}

		// External-scanner findings (e.g. Betterleaks) render here, under their own
		// sub-header, without touching the counts or examples above.

		if total, totalDeleted := secretTotals(rep); total > 0 {
			fmt.Fprintf(w, "\n  %s\n", s.c(dim,
				fmt.Sprintf("%s found. --verbose lists them by name, class and blob id; --json has the full record.",
					engine.Plural(total, "secret file"))))
			if totalDeleted > 0 {
				fmt.Fprintf(w, "  %s\n", s.c(red,
					fmt.Sprintf("Rotate the %d you cannot see in your own checkout first.", totalDeleted)))
			}
		}
		fmt.Fprintln(w)
		return
	}

	for _, r := range rep.Repos {
		if len(r.SecretFiles) == 0 {
			continue
		}
		fmt.Fprintf(w, "  %s%s\n", s.c(cyan, r.RepoPath), s.c(dim, uploadedSetSize(r)))

		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, h := range r.SecretFiles {
			note := "in HEAD"
			if h.DeletedFromCheckout {
				note = s.c(red, "deleted from checkout, still in history") + "  " + s.c(red+bold, "<- ROTATE")
			}
			// The blob id rides in a column rather than on a line of its own: one row per
			// secret keeps the rotation list scannable, and this list is read under
			// pressure by someone deciding what to revoke first.
			fmt.Fprintf(tw, "    %s\t%s\t%s\t%s\n", h.Path, s.c(dim, h.Class), note, s.c(dim, blobCol(h)))
		}
		tw.Flush()
	}

	// The invitation, printed once. grokpatrol is telling the user how to read files
	// it will not read itself -- and that is not a gap in the guarantee, it IS the
	// guarantee: cat-file is absent from the gitx allowlist, so no code path in this
	// tool can follow the pointer it just handed over. Their git can.
	if anyBlob(rep) {
		fmt.Fprintf(w, "\n  %s\n", s.c(dim, "Every blob above is in your local git object store. To see what leaked:"))
		fmt.Fprintf(w, "  %s\n", s.c(dim, "    git -C <repository> cat-file -p <blob>"))
		fmt.Fprintf(w, "  %s\n", s.c(dim, "grokpatrol never runs that command: it cannot read a secret it reports."))
	}
	fmt.Fprintln(w)
}

// maxSecretExamples bounds the example rows in the DEFAULT secrets section. Three,
// not ten: the examples exist to show WHICH files to rotate first and what CLASSES are
// exposed, not to be the rotation list -- that is --verbose. Three fit under the
// verdict, and the true total is always in the count lines and --json.
const maxSecretExamples = 3

// secretExamples picks a few representative hits for the default report: deleted-from-
// checkout first (they already sort first, from detect/secrets sortHits), and
// diversified by class so the sample shows a range of risk shapes rather than three
// dotenvs. Returns the chosen hits and how many were withheld.
func secretExamples(rep *model.Report) (shown []model.SecretHit, omitted int) {
	var all []model.SecretHit
	for _, r := range rep.Repos {
		all = append(all, r.SecretFiles...)
	}

	sort.SliceStable(all, func(i, j int) bool {
		if all[i].DeletedFromCheckout != all[j].DeletedFromCheckout {
			return all[i].DeletedFromCheckout
		}
		if all[i].Class != all[j].Class {
			return all[i].Class < all[j].Class
		}
		return all[i].Path < all[j].Path
	})
	picked := make([]bool, len(all))
	seenClass := map[string]bool{}
	// First pass: one hit per unseen class, preserving the deleted-first order.
	for i, h := range all {
		if len(shown) >= maxSecretExamples {
			break
		}
		if !seenClass[h.Class] {
			seenClass[h.Class] = true
			picked[i] = true
			shown = append(shown, h)
		}
	}
	// Second pass: if there were fewer distinct classes than the cap, fill the rest in
	// order so the sample is still full.
	for i, h := range all {
		if len(shown) >= maxSecretExamples {
			break
		}
		if !picked[i] {
			picked[i] = true
			shown = append(shown, h)
		}
	}
	return shown, len(all) - len(shown)
}

// secretExampleRow formats one example: the filename, the risk class in brackets, and
// the risk phrase. No blob id -- that is a --verbose receipt. The deleted phrase is
// deliberately distinct from the per-repo count line's "deleted from the checkout but
// still in history" so neither a reader nor a guard test can confuse the sample row
// with the headline count.
func secretExampleRow(h model.SecretHit, s Style) (name, class, risk string) {
	name = h.Path
	class = s.c(dim, "["+h.Class+"]")
	if h.DeletedFromCheckout {
		risk = s.c(red, "deleted from checkout, still in history")
	} else {
		risk = s.c(dim, "in HEAD")
	}
	return name, class, risk
}

// blobCol renders the object id, abbreviated. A working-tree-only hit has no blob
// and gets an empty cell rather than a fabricated one.
func blobCol(h model.SecretHit) string {
	if h.Blob == "" {
		return ""
	}
	return "blob " + short(h.Blob)
}

func anyBlob(rep *model.Report) bool {
	for _, r := range rep.Repos {
		for _, h := range r.SecretFiles {
			if h.Blob != "" {
				return true
			}
		}
	}
	return false
}

// uploadedSetSize turns "your git history was uploaded" into the size of the thing
// that went out. Printed only when the history was actually enumerated: on a repo
// we could not read, a count of 0 would read as "nothing was in it".
func uploadedSetSize(r model.RepoStatus) string {
	if r.HistoryObjects == 0 {
		return ""
	}
	return fmt.Sprintf("      %d git objects were reachable from HEAD and went out with the archive",
		r.HistoryObjects)
}

// short abbreviates an object id the way git does. The full id stays in --json:
// the terminal is for reading, the JSON is the record.
func short(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12]
}

func degraded(w io.Writer, rep *model.Report, s Style) {
	if len(rep.Errors) == 0 {
		return
	}
	perm, other := 0, 0
	for _, e := range rep.Errors {
		if e.Kind == "permission" {
			perm++
		} else {
			other++
		}
	}
	fmt.Fprintln(w, s.c(bold+yellow, "DEGRADED")+s.c(dim, fmt.Sprintf("   (%d permission denials, %d other errors)", perm, other)))

	shown := 0
	for _, e := range rep.Errors {
		if shown >= 8 {
			fmt.Fprintf(w, "  %s\n", s.c(dim, fmt.Sprintf("... and %d more (use --json for all)", len(rep.Errors)-shown)))
			break
		}
		loc := e.Path
		if loc == "" {
			loc = e.Detector
		}
		fmt.Fprintf(w, "  ! %s: %s\n", loc, e.Message)
		shown++
	}
	fmt.Fprintln(w)
}

func limitations(w io.Writer, rep *model.Report, s Style) {
	if len(rep.Limitations) == 0 {
		return
	}
	// Printed on EVERY run, including a clean one. Nobody should read "CLEAN" without
	// also reading what this tool structurally cannot see. But five fully-wrapped
	// paragraphs bury the rest of the report, so the default shortens each caveat to its
	// first sentence -- enough to NAME the blind spot -- and --verbose gives the full text.
	// Every caveat still appears; the invariant is that none is dropped, not that each is
	// spelled out in full.
	fmt.Fprintln(w, s.c(bold, "WHAT THIS SCAN COULD NOT SEE"))
	truncated := false
	for _, l := range rep.Limitations {
		text := l
		if !s.Verbose {
			var cut bool
			if text, cut = firstSentence(l, 96); cut {
				truncated = true
			}
		}
		fmt.Fprintf(w, "  %s %s\n", s.c(dim, "-"), wrap(text, 92, "    "))
	}
	if truncated {
		fmt.Fprintf(w, "  %s\n", s.c(dim, "  --verbose spells out each caveat in full."))
	}
	fmt.Fprintln(w)
}

// firstSentence returns the first sentence of s (through the first ". "), or s cut on
// a word boundary at max with an ellipsis when there is no early sentence break. The
// bool reports whether anything was dropped, so the caller can point at --verbose.
func firstSentence(s string, max int) (string, bool) {
	// The first clause break -- a sentence end (". ") or a lead-in colon (": ") -- gives
	// a clean summary; some caveats front-load the point before a colon.
	end := -1
	for _, sep := range []string{". ", ": "} {
		if i := strings.Index(s, sep); i >= 0 && (end < 0 || i < end) {
			end = i + 1 // keep the '.' or ':'
		}
	}
	if end >= 0 && end <= max {
		return s[:end], true
	}
	if len(s) <= max {
		return s, false
	}
	cut := s[:max]
	if sp := strings.LastIndex(cut, " "); sp > 0 {
		cut = cut[:sp]
	}
	return cut + " ...", true
}

// There is no REMEDIATION section. The terminal report says what was found and
// where; what to do about it is the reader's call, and a fixed list of steps
// appended to every positive verdict is the part of a security report people learn
// to scroll past.
//
// The full advice is NOT lost either way: every finding still carries its own
// Remediation string, written by the detector that raised it and emitted in --json. The
// config detector in particular owns the text naming BOTH required settings, which is
// the one piece of advice this tool must never get wrong.

func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if lineLen+len(w)+1 > width && i > 0 {
			b.WriteString("\n" + indent)
			lineLen = len(indent)
		} else if i > 0 {
			b.WriteString(" ")
			lineLen++
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
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
