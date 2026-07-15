package report

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

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
	ledger(w, rep, s)
	staging(w, rep, s)
	secrets(w, rep, s)
	otherFindings(w, rep, s)
	degraded(w, rep, s)
	limitations(w, rep, s)
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
				label := e.Note
				if e.SizeBytes > 0 {
					label = fmt.Sprintf("%s, %s", e.Note, humanBytes(e.SizeBytes))
				}
				// The hash was always computed and always dropped before the terminal saw
				// it -- while the section header promised "recorded by name and hash". An
				// archive is the user's stolen source code and the only evidence of what
				// was in it; the hash is what lets them prove later that the file they
				// still have is the file that was staged.
				if e.SHA256 != "" {
					label = fmt.Sprintf("%s, sha256:%s", label, short(e.SHA256))
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

	fmt.Fprintln(w, s.c(bold, "STAGING")+s.c(dim, "   (archives were recorded by name and hash, never opened)"))
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
		color, headline = red, compromisedHeadline(rep)
	case model.VerdictExposed:
		color = yellow
		headline = "The Grok Build CLI is present and whole-repository upload is not disabled.\n" +
			"No evidence was found that it has uploaded anything from this machine yet."
	case model.VerdictIndeterminate:
		color = yellow
		headline = "No indicators were found, but parts of this machine could not be read.\n" +
			"This is not a clean bill of health -- see WHAT THIS SCAN COULD NOT SEE below."
	default:
		color = green
		headline = "No Grok Build artifacts were found on this machine."
	}

	fmt.Fprintln(w, s.c(color+bold, "VERDICT: "+string(rep.Verdict)))
	for _, line := range strings.Split(headline, "\n") {
		fmt.Fprintln(w, "  "+line)
	}
	if line := countsLine(rep); line != "" {
		fmt.Fprintf(w, "  %s\n", s.c(dim, line))
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

func compromisedHeadline(rep *model.Report) string {
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
		// The verdict does NOT soften with the wording, and must not. COMPROMISED rests
		// on collection, not delivery: these repositories were read and packaged, which
		// is proven, and the rotation advice follows from that alone. Requiring proven
		// delivery would make COMPROMISED unreachable on every host forever, since the
		// event that would prove it does not exist -- a verdict nothing can trigger is
		// not a cautious verdict, it is a disabled one.
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
		return "Evidence of repository collection was found on this machine."
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

func installation(w io.Writer, rep *model.Report, s Style) {
	var lines [][2]string

	for _, f := range rep.Findings {
		if f.ID == "deepscan.binary_marker" {
			for _, e := range f.Evidence {
				if strings.Contains(e.Note, scan.MarkerBucket) {
					desc := fmt.Sprintf("%s (%s)\n%s contains %q at %s",
						e.Path, humanBytes(e.SizeBytes), pad, scan.MarkerBucket, e.Locator)
					// Identifies the exact build sitting on this disk -- which is what anyone
					// comparing notes across a fleet, or against a vendor's published hashes,
					// actually needs. It was computed and then thrown away.
					if e.SHA256 != "" {
						desc += fmt.Sprintf("\n%s sha256:%s", pad, e.SHA256)
					}
					lines = append(lines, [2]string{"grok binary", desc})
				}
			}
		}
	}

	for _, v := range rep.Versions {
		if v.Confidence == "low" {
			continue
		}
		note := v.Class
		if v.Class == model.VersionConfirmedAffected {
			note = s.c(red, "CONFIRMED AFFECTED")
		} else if v.Class == model.VersionReportedAffected {
			note = s.c(yellow, "REPORTED AFFECTED")
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
		lines = append(lines, [2]string{"version",
			fmt.Sprintf("%s  %s  %s", v.Version, note, s.c(dim, where))})
	}

	for _, f := range rep.Findings {
		switch f.ID {
		case "config.mitigated":
			lines = append(lines, [2]string{"config.toml", s.c(green, "MITIGATED") + " -- both upload mitigations set"})
		case "config.not_mitigated", "config.absent", "config.explicitly_disabled", "config.unparseable":
			// A short, plain phrase per case rather than the finding's Title. The titles are
			// written to stand alone in --json and one of them ("config.toml uses constructs
			// this scanner does not model") is parser jargon that tells a reader nothing they
			// can act on. What this row owes them is the state and the consequence.
			//
			// The unparseable case is NOT dropped, only reworded: a config we could not read
			// is a config whose mitigations are UNCONFIRMED, which is why the tool fails closed
			// to EXPOSED. Deleting the row would delete the reason for the verdict.
			lines = append(lines, [2]string{"config.toml", s.c(yellow, "EXPOSED") + " -- " + configState(f.ID)})
		case "config.auth_present":
			// Just "present". The parenthetical used to read "(grokpatrol did not read it)",
			// which is true, but the INSTALLATION table is an inventory of what is on the
			// machine -- not the place to advertise what this tool declines to do. The
			// guarantee lives in the code (auth.json is never opened) and in the docs; a
			// reader scanning an inventory column does not need it re-litigated per row.
			lines = append(lines, [2]string{"auth.json", "present"})
		case "config.other_keys":
			lines = append(lines, [2]string{"other options", strings.TrimPrefix(f.Title, "Other upload-related options are set: ")})
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
	fmt.Fprintln(w)
}

// configState is the INSTALLATION row's plain-language reading of a config finding.
// The detector's own Title still carries the full technical statement into --json.
func configState(id string) string {
	switch id {
	case "config.absent":
		return "no config.toml, so neither upload mitigation is set"
	case "config.explicitly_disabled":
		return "the upload mitigations are explicitly turned off"
	case "config.unparseable":
		return "config.toml could not be fully read, so the mitigations are UNCONFIRMED -- verify it by hand"
	}
	return "the upload mitigations are not both set"
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
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s", s.c(dim, "REPOSITORY"), s.c(dim, "STATUS"), s.c(dim, "ATTEMPTS"), s.c(dim, "ARCHIVES"))
		if showAuth {
			fmt.Fprintf(tw, "\t%s", s.c(dim, "UPLOAD 401s"))
		}
		fmt.Fprintf(tw, "\t%s\n", s.c(dim, "COLLECTED"))

		for _, r := range rep.Repos {
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
			fmt.Fprintf(tw, "  %s\t%s\t%d\t%s", r.RepoPath, status, r.CollectAttempts, archiveSummary(r))
			if showAuth {
				fmt.Fprintf(tw, "\t%s", authSummary(r, s))
			}
			fmt.Fprintf(tw, "\t%s\n", collectedWindow(r))
		}
		tw.Flush()
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
		fmt.Fprintf(w, "\n  %s %s\n", s.c(red+bold, "delivery:"),
			s.c(red, "CONFIRMED -- Grok's log records the transfer completing."))
		fmt.Fprintf(w, "  %s\n", s.c(dim, "This is the strongest statement this tool can make. It is not inferred from"))
		fmt.Fprintf(w, "  %s\n", s.c(dim, "collection or queueing: the upload itself was logged as finished."))
	} else if delivery != nil {
		fmt.Fprintf(w, "\n  %s %s\n", s.c(dim, "delivery:"), s.c(dim, delivery.Title))
		fmt.Fprintf(w, "  %s\n", s.c(dim, "Grok logs no upload-completion event, so neither this tool nor the log can confirm"))
		fmt.Fprintf(w, "  %s\n", s.c(dim, "the archives were delivered -- only that they were built and queued."))
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

// archiveSummary gives the archive count and the phase breakdown behind it.
//
// It COUNTS the phases rather than listing one letter per archive. The old form
// printed the phase multiset literally -- a repo with 64 archives rendered as
// "64 (a,a,a,...,b,b,b)", a 130-character cell that pushed the COLLECTED column off
// the right edge of the terminal. The letters carried no information the counts do
// not: sorted, they only ever said "some afters, then some befores". This is the
// same fact, spelled short.
//
// Unrecognized phases are counted too, never dropped: phaseOf can return "unknown",
// and a phase this renderer has not heard of still happened. An archive that
// vanishes from the ARCHIVES column because nobody taught the printer its phase name
// is a missing row in the one table that says what was taken.
// archiveSummary is the count, and only the count. The phase breakdown that used to
// ride along here ("64 (32 before, 32 after)") said nothing this table needs: Grok
// snapshots the repo twice per turn, so the split is always just half and half, and
// the phase of any individual archive is already spelled out in its gs:// path in
// ARCHIVES QUEUED FOR UPLOAD below. What the ledger row owes the reader is the
// magnitude -- how many full copies of this repository went out -- and that is one
// number.
func archiveSummary(r model.RepoStatus) string {
	return fmt.Sprintf("%d", len(r.Archives))
}

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

	// WITHOUT --verbose this section is COUNTS, not paths.
	//
	// Unique is reported alongside the total because they are different facts and the gap
	// between them means something. An enqueue event is logged per ATTEMPT, so the same
	// gs:// object can be enqueued repeatedly when an upload is retried; correlate counts
	// those retries rather than deduping them, on purpose ("duplicates are retries; they
	// are counted, not deduped"). So the total is how many times Grok tried to ship an
	// archive, and unique is how many distinct objects your code was written to. A host
	// with 64 archives and 12 unique objects retried hard; one with 64 and 64 shipped 64
	// separate snapshots. Printing only the total would hide which happened.
	//
	// --verbose prints every gs:// object with its provenance; --json is complete.
	fmt.Fprintf(w, "\n  %s", s.c(bold, "ARCHIVES QUEUED FOR UPLOAD"))
	if s.Verbose {
		fmt.Fprintf(w, "%s\n", s.c(dim, "   (one line per archive, as recorded in Grok's own logs)"))
	} else {
		fmt.Fprintf(w, "%s\n", s.c(dim, "   (counts only -- --verbose lists every gs:// object)"))
	}

	if !s.Verbose {
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, r := range withArchives {
			total, unique, delivered := archiveCounts(r)
			cell := fmt.Sprintf("%s, %d unique %s",
				engine.Plural(total, "archive"), unique, plainPlural(unique, "object"))
			if delivered > 0 {
				cell += ", " + s.c(red+bold, fmt.Sprintf("%d DELIVERY CONFIRMED", delivered))
			}
			fmt.Fprintf(tw, "  %s\t%s\n", s.c(cyan, r.RepoPath), s.c(red, cell))
		}
		tw.Flush()
		citations(w, rep, s)
		return
	}

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

// plainPlural pluralizes a noun without prefixing the count, for use inside a phrase
// that has already printed the number.
func plainPlural(n int, noun string) string {
	if n == 1 {
		return noun
	}
	return noun + "s"
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
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		total, totalDeleted := 0, 0
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
			total += len(r.SecretFiles)
			totalDeleted += deleted

			count := engine.Plural(len(r.SecretFiles), "secret file")
			if deleted > 0 {
				count += ", " + s.c(red+bold, fmt.Sprintf("%d deleted from the checkout but still in history", deleted))
			}
			fmt.Fprintf(tw, "  %s\t%s\n", s.c(cyan, r.RepoPath), count)
		}
		tw.Flush()
		if total > 0 {
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
	// Printed on EVERY run, including a clean one. Nobody should read "CLEAN"
	// without also reading what this tool structurally cannot see.
	fmt.Fprintln(w, s.c(bold, "WHAT THIS SCAN COULD NOT SEE"))
	for _, l := range rep.Limitations {
		fmt.Fprintf(w, "  %s %s\n", s.c(dim, "-"), wrap(l, 92, "    "))
	}
	fmt.Fprintln(w)
}

// There is no REMEDIATION section. The terminal report says what was found and
// where; what to do about it is the reader's call, and a fixed list of steps
// appended to every positive verdict is the part of a security report people learn
// to scroll past.
//
// The advice itself is NOT lost: every finding still carries its own Remediation
// string, written by the detector that raised it and emitted in --json. The config
// detector in particular owns the text naming BOTH required settings, which is the
// one piece of advice this tool must never get wrong.

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
