package logs

import (
	"fmt"
	"sort"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

const rotateAdvice = "Treat every credential reachable from this repository's git history as compromised and rotate it. " +
	"Deleting the repo locally does not remove the copy already uploaded."

func findings(repos []model.RepoStatus, rawHits []model.Evidence, events []event, auth uploadAuthSummary) []model.Finding {
	var out []model.Finding

	// A DELIVERED repo is a QUEUED repo whose upload was additionally confirmed, so it
	// belongs in BOTH buckets: it still gets logs.archive_enqueued (its archives were
	// built and queued -- that did not stop being true) and it additionally gets
	// logs.upload_confirmed. Selecting on Status alone would have dropped a delivered
	// repo out of the queued bucket entirely, so the strongest possible host would have
	// lost the finding that names its archives -- a promotion that silently deletes
	// evidence.
	var queued, collected, delivered []model.RepoStatus
	for _, r := range repos {
		switch r.Status {
		case model.StatusDelivered:
			delivered = append(delivered, r)
			queued = append(queued, r)
		case model.StatusQueued:
			queued = append(queued, r)
		case model.StatusCollectedOnly:
			collected = append(collected, r)
		}
	}

	// Top of the report, because nothing else in it can say this. Every other exfil
	// finding proves COLLECTION and leaves delivery unconfirmable; this one proves the
	// bytes LANDED, and it is the ONLY log finding that drives COMPROMISED (TagUpload).
	// It is unreachable against Grok as it ships today -- see kindUploadSuccess -- and
	// exists so that the day a completion event appears, the tool reports it as the
	// proof it is rather than as an unrecognized event.
	if len(delivered) > 0 {
		ev := make([]model.Evidence, 0, len(delivered))
		confirmed := 0
		for _, r := range delivered {
			confirmed += r.DeliveriesConfirmed
			for _, a := range r.Archives {
				if !a.Delivered {
					continue
				}
				ev = append(ev, model.Evidence{
					Path:       r.RepoPath,
					Locator:    a.GCSPath,
					Note:       "upload CONFIRMED landed -- " + archiveNote(a),
					Source:     a.LogFile,
					SourceLine: a.LogLine,
				})
			}
		}
		out = append(out, model.Finding{
			ID:       "logs.upload_confirmed",
			Detector: "logs",
			Severity: model.SevCritical,
			Tags:     []string{model.TagExfil, model.TagUpload},
			Title: fmt.Sprintf("%s CONFIRMED DELIVERED to xAI (%s)",
				engine.Plural(confirmed, "archive"), engine.Plural(len(delivered), "repository")),
			Detail: "Grok's logs record an upload-completion event for these archives. This is not an inference from " +
				"collection or queueing: the log says the transfer finished. The code in these repositories is in xAI's " +
				"possession, and every credential reachable from their git history should be treated as disclosed.",
			Remediation: rotateAdvice,
			Evidence:    sortEvidence(ev),
		})
	}

	if len(queued) > 0 {
		ev := make([]model.Evidence, 0, len(queued))
		archives := 0
		for _, r := range queued {
			archives += len(r.Archives)
			for _, a := range r.Archives {
				ev = append(ev, model.Evidence{
					Path:    r.RepoPath,
					Locator: a.GCSPath, // the smoking gun, kept verbatim
					Note:    archiveNote(a),
					// Grok's own log is the witness. Citing the file and line is what makes
					// this finding checkable by hand rather than taken on trust.
					Source:     a.LogFile,
					SourceLine: a.LogLine,
				})
			}
		}
		out = append(out, model.Finding{
			ID:       "logs.archive_enqueued",
			Detector: "logs",
			// SevHigh, not Critical, and TagExfil without TagUpload: an enqueue proves
			// the archive was BUILT and QUEUED, not that it was delivered. That is
			// collection -> EXPOSED, not COMPROMISED. Only a confirmed delivery
			// (logs.upload_confirmed) or an unclassifiable upload event crosses that line.
			Severity: model.SevHigh,
			Tags:     []string{model.TagExfil},
			Title:    fmt.Sprintf("%d repositories had %d archives queued for upload to xAI", len(queued), archives),
			Detail: "Grok's own logs record " + eventEnqueued + " events for these repositories. " +
				"Each archive contains every tracked file at HEAD and every git object reachable from HEAD -- " +
				"including files deleted from the checkout but preserved in history. The logs record the archive " +
				"being QUEUED; Grok logs no completion event, so delivery is unconfirmed -- treat these repositories " +
				"as exposed and rotate regardless.",
			Remediation: rotateAdvice,
			Evidence:    ev,
		})
	}

	if len(collected) > 0 {
		ev := make([]model.Evidence, 0, len(collected))
		for _, r := range collected {
			ev = append(ev, model.Evidence{
				Path:       r.RepoPath,
				Note:       fmt.Sprintf("%d collection attempts, no enqueue event found", r.CollectAttempts),
				Source:     r.LogFile,
				SourceLine: r.LogLine,
			})
		}
		out = append(out, model.Finding{
			ID:       "logs.collected_only",
			Detector: "logs",
			Severity: model.SevHigh,
			Tags:     []string{model.TagExfil},
			Title:    fmt.Sprintf("%d repositories were collected, upload unconfirmed", len(collected)),
			Detail: eventStart + " was logged for these repositories but no matching enqueue event was found. " +
				"Collection is confirmed. Upload is unconfirmed -- which is not the same as disproven: the enqueue line " +
				"may simply have rotated out of the logs.",
			Remediation: rotateAdvice,
			Evidence:    ev,
		})
	}

	// The raw-substring net. It fires on lines that never parsed as JSON, so it is
	// the last line of defense against a schema change that silences everything above.
	if len(rawHits) > 0 && len(queued) == 0 {
		out = append(out, model.Finding{
			ID:       "logs.raw_bucket_reference",
			Detector: "logs",
			// TagUpload: the structured events this tool knows about were not found, so
			// the schema has moved. The safe reading of a bucket reference we cannot
			// otherwise classify is that an upload happened -- so this crosses to
			// COMPROMISED rather than hiding behind a schema change.
			Severity: model.SevCritical,
			Tags:     []string{model.TagExfil, model.TagSchema, model.TagUpload},
			Title:    fmt.Sprintf("%d log lines reference the exfiltration bucket, but no upload event could be parsed", len(rawHits)),
			Detail: "Log lines mention " + scan.MarkerBucket + " or a codebase archive, yet the structured upload events " +
				"this tool knows about were not found. The log schema has probably changed. Treat these lines as evidence of upload.",
			Remediation: rotateAdvice,
			Evidence:    sortEvidence(rawHits),
		})
	}

	// Delivery context. SevInfo and untagged, both on purpose.
	//
	// It is NOT tagged exfil or upload, even though it is about exfiltration, and that
	// is a deliberate belt-and-braces: engine.verdict promotes COMPROMISED on (SevHigh
	// AND upload) and EXPOSED on SevMedium+, so SevInfo already cannot promote -- but
	// leaving the tags off means this finding cannot promote even if someone later
	// lowers those thresholds. The finding is a reader aid; it is not allowed to be
	// load-bearing in either direction.
	if auth.any() {
		var title, detail string
		switch {
		case auth.Windows == 0:
			// No collection window exists, so there is nothing to correlate against.
			// Saying these failures fell "outside the window in which archives were
			// queued" would assert a window that never existed.
			title = fmt.Sprintf("%d auth failures on the upload leg, with no collected repository to attribute them to", auth.Total)
			detail = "Grok's upload client was rejected, but these logs record no repository collection at all, so there is " +
				"no window to correlate the failures against. That is not reassurance: the collection events may have " +
				"rotated out of the logs while the failures survived. Read the ledger, not this line, for what was collected."
		case auth.InWindow == 0:
			title = fmt.Sprintf("Upload leg showed no auth failures while archives were being queued (%d occurred outside that window)", auth.OutOfWindow)
			detail = "Every auth rejection on the upload client falls OUTSIDE the window in which archives were queued. " +
				"Nothing here suggests the uploads were blocked. Read this as the absence of a known obstacle, not as " +
				"confirmation of delivery: Grok logs no upload-completion event, so a successful upload and an upload " +
				"that never happened leave the same trace -- none."
		case auth.OutOfWindow == 0:
			title = fmt.Sprintf("%d auth failures on the upload leg, all during archive collection", auth.InWindow)
			detail = "Auth rejections on the upload client coincide with the window in which archives were queued, so some " +
				"deliveries were probably refused. This does NOT mean the repositories are safe: collection still " +
				"happened, the archives were still built, and a later run whose logs have rotated away may have drained " +
				"the queue successfully."
		default:
			title = fmt.Sprintf("%d auth failures on the upload leg (%d during archive collection, %d outside it)", auth.Total, auth.InWindow, auth.OutOfWindow)
			detail = "Some auth rejections on the upload client coincide with the window in which archives were queued, so " +
				"some deliveries may have been refused -- but not all of them, and collection happened regardless."
		}
		out = append(out, model.Finding{
			ID:       "logs.upload_auth_failure",
			Detector: "logs",
			Severity: model.SevInfo,
			Title:    title,
			Detail: detail + "\n\nThis is context for reading the ledger above; it does not change the verdict. " +
				"Only the archives that were queued do that.",
			Evidence: []model.Evidence{{
				Locator: fmt.Sprintf("%d upload-leg auth failures between %s and %s",
					auth.Total, fmtTime(auth.First), fmtTime(auth.Last)),
				Note: "HTTP 401 attributed to the client that uploads the archives",
			}},
		})
	}

	if unknown := unknownEventNames(events); len(unknown) > 0 {
		ev := make([]model.Evidence, 0, len(unknown))
		for _, name := range unknown {
			ev = append(ev, model.Evidence{Locator: name, Note: "unrecognized " + eventPrefix + " event"})
		}
		out = append(out, model.Finding{
			ID:       "logs.unknown_upload_event",
			Detector: "logs",
			// TagUpload: an unrecognized repo_state.upload.* event is read as a delivery
			// (fail-safe), so it drives COMPROMISED. The day the schema gains a real
			// completion event, this is the net that still catches it.
			Severity: model.SevHigh,
			Tags:     []string{model.TagExfil, model.TagSchema, model.TagUpload},
			Title:    "Unrecognized " + eventPrefix + " events found in the logs",
			Detail: "These event names were not in the set this tool was built against, so Grok's logging has changed. " +
				"They were counted as uploads, because the safe reading of an upload event we cannot classify is that an upload happened.",
			Remediation: rotateAdvice,
			Evidence:    ev,
		})
	}

	return out
}

// archiveNote spells out the session and turn an archive was built for. Each field
// is printed only when it is present: a "turn 0" invented for an event that never
// carried one would be a fact this tool made up, and TurnNumber is a pointer
// precisely so that absent and zero stay distinguishable.
func archiveNote(a model.Archive) string {
	note := fmt.Sprintf("%s-turn archive queued for upload", a.Phase)
	if a.SID != "" {
		note += ", session " + a.SID
	}
	if a.TurnNumber != nil {
		note += fmt.Sprintf(", turn %d", *a.TurnNumber)
	}
	if !a.Timestamp.IsZero() {
		note += ", " + a.Timestamp.UTC().Format(time.RFC3339)
	}
	return note
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Format("2006-01-02")
}

func unknownEventNames(events []event) []string {
	set := map[string]bool{}
	for _, e := range events {
		if e.Kind == kindUnknownUpload {
			set[e.Raw] = true
		}
	}
	return sortedKeys(set)
}

// sortEvidence orders evidence deterministically. It does NOT truncate, and that
// is the point: this used to cap the list at 20 and append a note reading "use
// --json for the full list" -- but it capped at CONSTRUCTION, so --json was
// truncated too and the note pointed at a list that did not exist. Findings now
// carry every item, --json is the complete forensic record, and truncation happens
// only in the terminal renderer (see maxEvidenceRows in report/human.go), where
// the promise it prints is one the JSON can actually keep.
func sortEvidence(ev []model.Evidence) []model.Evidence {
	sort.Slice(ev, func(i, j int) bool {
		if ev[i].Path != ev[j].Path {
			return ev[i].Path < ev[j].Path
		}
		return ev[i].Locator < ev[j].Locator
	})
	return ev
}
