package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// key pairs a start event with its enqueue events. turn_number may be absent, in
// which case every event for that session shares the "-" bucket; that over-groups
// rather than under-groups, which is the safe direction (it can only promote a
// repo to QUEUED, never demote one).
func key(sid string, turn *int64) string {
	t := "-"
	if turn != nil {
		t = fmt.Sprintf("%d", *turn)
	}
	return sid + "\x00" + t
}

type agg struct {
	repoPath  string
	displayed string // first-seen casing, for display
	attempts  int
	archives  []model.Archive
	sessions  map[string]bool
	first     time.Time
	last      time.Time
	lowConf   bool
	// delivered counts upload-completion events attributed to this repo, and
	// deliveredGCS records WHICH objects they named, so an individual archive can be
	// marked confirmed rather than the whole repo being flagged on one event. Both are
	// zero/empty on every host we have seen: no Grok build emits a completion event.
	delivered    int
	deliveredGCS map[string]bool
	// Where collection was first recorded, so a COLLECTED-ONLY row can cite the line
	// it is based on rather than asserting it.
	logFile string
	logLine int
}

// uploadAuthSummary reports auth failures on the upload leg. It answers the one
// question the enqueue ledger cannot: an archive was queued -- did it actually go?
//
// THE ASYMMETRY IS THE WHOLE DESIGN, and it is why this is reported context and
// never a verdict input:
//
//	a 401 on the upload leg proves a delivery attempt was REFUSED.
//	no 401 on the upload leg proves NOTHING about whether one SUCCEEDED.
//
// So this can lower a reader's confidence that the bytes landed; it can never
// raise it, and it must never downgrade the verdict. A host whose uploads all
// 401'd still had its repositories collected and queued -- that is EXPOSED on the
// collection evidence alone -- and the queue may well have drained on a later run
// whose logs have since rotated away. Wiring these 401s into engine.verdict as a
// downgrade path would let a refused-delivery signal argue a collected host down
// toward CLEAN, converting a true positive into a false negative. (A 401 is also
// not the inverse signal: it never promotes to COMPROMISED either, which requires
// a confirmed delivery -- TagUpload -- not merely the absence of a refusal.)
//
// Correlation is by TIME, not by session, and that is forced by the data: on the
// only host we have logs from, every upload-leg 401 carries no sid at all (the
// 401s that DO carry one all come from the telemetry client, which is a different
// consumer and not the codebase upload path). Session correlation would silently
// match zero events.
type uploadAuthSummary struct {
	Total       int
	InWindow    int // fell inside some repo's collection window
	OutOfWindow int
	// Windows counts the repos that had a usable collection window at all. Without
	// it, a host with 401s and no collection events is indistinguishable from one
	// where every 401 missed the window -- both have InWindow == 0 -- and the report
	// would claim failures fell "outside the window in which archives were queued"
	// when no archive was ever queued. There is no window to be outside of.
	Windows int
	First   time.Time
	Last    time.Time
}

func (s uploadAuthSummary) any() bool { return s.Total > 0 }

// correlate turns a flat event stream into the per-repository ledger.
func correlate(events []event) ([]model.RepoStatus, uploadAuthSummary) {
	starts := map[string][]event{}    // key -> start events
	enqueues := map[string][]event{}  // key -> enqueue events
	successes := map[string][]event{} // key -> delivery-confirmation events
	sidRepo := map[string]string{}    // sid -> any repo path seen for it (orphan fallback)
	var authFails []event

	for _, e := range events {
		switch e.Kind {
		case kindStart:
			k := key(e.SID, e.Turn)
			starts[k] = append(starts[k], e)
			if e.Repo != "" && e.SID != "" {
				sidRepo[e.SID] = e.Repo
			}
		case kindEnqueued, kindUnknownUpload:
			// An upload event with a suffix we do not recognize is treated as an
			// enqueue. If the schema drifted, the safe reading of "an upload event we
			// cannot classify" is "an upload happened".
			k := key(e.SID, e.Turn)
			enqueues[k] = append(enqueues[k], e)
		case kindUploadSuccess:
			successes[key(e.SID, e.Turn)] = append(successes[key(e.SID, e.Turn)], e)
		case kindUploadAuthFail:
			authFails = append(authFails, e)
		}
	}

	byRepo := map[string]*agg{}
	get := func(repo string) *agg {
		norm := normalizeRepo(repo)
		a, ok := byRepo[norm]
		if !ok {
			a = &agg{repoPath: norm, displayed: repo, sessions: map[string]bool{},
				deliveredGCS: map[string]bool{}}
			byRepo[norm] = a
		}
		return a
	}

	// Collection attempts.
	for _, evs := range starts {
		for _, e := range evs {
			repo := e.Repo
			if repo == "" {
				repo = model.UnknownRepo
			}
			a := get(repo)
			a.attempts++ // duplicates are retries; they are counted, not deduped
			if e.SID != "" {
				a.sessions[e.SID] = true
			}
			if a.logFile == "" {
				a.logFile, a.logLine = e.File, e.Line
			}
			foldTime(&a.first, &a.last, e.TS)
		}
	}

	// Queued archives -- the proof.
	for k, evs := range enqueues {
		for _, e := range evs {
			repo, lowConf := attribute(k, e, starts, sidRepo)
			a := get(repo)
			if lowConf {
				a.lowConf = true
			}
			if e.SID != "" {
				a.sessions[e.SID] = true
			}
			a.archives = append(a.archives, model.Archive{
				Phase:      phaseOf(e.GCSPath),
				GCSPath:    e.GCSPath,
				SID:        e.SID,
				TurnNumber: e.Turn,
				Timestamp:  e.TS,
				// The witness. parseLine has always recorded which file and line each
				// event came from; until now correlate dropped both on the floor, so the
				// ledger asserted an upload without ever saying where it had seen one.
				LogFile: e.File,
				LogLine: e.Line,
			})
			foldTime(&a.first, &a.last, e.TS)
		}
	}

	// Delivery confirmations -- the proof the other findings can never have.
	//
	// Attributed exactly like an enqueue, and for the same reason: a confirmation whose
	// start event rotated away is still a confirmation, so it falls back to sid, then to
	// <unattributed>, and is never dropped. It is counted per repo AND recorded per
	// gcs_path, so a repo with 64 archives and one confirmation reports one archive
	// delivered rather than claiming all 64 landed.
	for k, evs := range successes {
		for _, e := range evs {
			repo, lowConf := attribute(k, e, starts, sidRepo)
			a := get(repo)
			if lowConf {
				a.lowConf = true
			}
			if e.SID != "" {
				a.sessions[e.SID] = true
			}
			a.delivered++
			if e.GCSPath != "" {
				a.deliveredGCS[e.GCSPath] = true
			}
			foldTime(&a.first, &a.last, e.TS)
		}
	}

	summary := uploadAuthSummary{Total: len(authFails)}
	for _, e := range authFails {
		foldTime(&summary.First, &summary.Last, e.TS)
	}

	out := make([]model.RepoStatus, 0, len(byRepo))
	for _, a := range byRepo {
		for i := range a.archives {
			if a.deliveredGCS[a.archives[i].GCSPath] {
				a.archives[i].Delivered = true
			}
		}
		st := model.RepoStatus{
			RepoPath:            a.displayed,
			CollectAttempts:     a.attempts,
			Archives:            a.archives,
			FirstSeen:           a.first,
			LastSeen:            a.last,
			Sessions:            sortedKeys(a.sessions),
			LowConfidence:       a.lowConf,
			LogFile:             a.logFile,
			LogLine:             a.logLine,
			DeliveriesConfirmed: a.delivered,
		}
		switch {
		// DELIVERED outranks QUEUED: a confirmed upload is strictly more than a queued
		// one. The reverse promotion never happens -- no confirmation leaves a repo at
		// QUEUED, it does not demote it to anything.
		case a.delivered > 0:
			st.Status = model.StatusDelivered
		case len(a.archives) > 0:
			st.Status = model.StatusQueued
		case a.attempts > 0:
			// COLLECTED-ONLY is not a reassurance. The enqueue line may simply have
			// rotated out of the logs. Collection is confirmed; upload is unconfirmed,
			// which is not the same as disproven.
			st.Status = model.StatusCollectedOnly
		default:
			st.Status = model.StatusUnknown
		}
		st.UploadAuthFailures = countInWindow(authFails, a)
		st.OnDisk, st.IsGitRepo = repoOnDisk(a.displayed)
		sortArchives(st.Archives)
		out = append(out, st)
	}

	// A 401 counts as in-window if it lands inside ANY repo's collection window, so
	// the two counts can overlap when windows do. They are presented as "during
	// collection" versus "only outside it", never summed.
	for _, a := range byRepo {
		if _, _, ok := a.window(); ok {
			summary.Windows++
		}
	}
	for _, e := range authFails {
		if inAnyWindow(e.TS, byRepo) {
			summary.InWindow++
		} else {
			summary.OutOfWindow++
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Status != out[j].Status {
			return statusRank(out[i].Status) > statusRank(out[j].Status)
		}
		return out[i].RepoPath < out[j].RepoPath
	})
	return out, summary
}

// uploadGrace extends a repo's collection window past its last logged event.
//
// It is not padding, it is causally required: the PUT that a 401 rejects happens
// AFTER the enqueue that queued the archive, so the refusal of the LAST archive
// always lands outside [first, last]. Without a grace period the window
// systematically misses the very failures it exists to find -- the first version
// of this code scored zero on a fixture where every single upload was refused.
//
// An hour is chosen to cover the PUT and its retries while excluding the unrelated
// auth churn a machine produces days later (on the host this was built from, the
// upload-leg 401s came four days after the last archive was queued, and calling
// those "during collection" would have been a fiction). The bound is a heuristic
// and is allowed to be: it moves a count in an advisory finding, never a verdict.
const uploadGrace = time.Hour

// window returns the interval in which an auth failure is attributable to this
// repo's uploads. A repo with no usable timestamps has no window: counting every
// failure against it would be a fabrication, so it gets none.
func (a *agg) window() (start, end time.Time, ok bool) {
	if a.first.IsZero() || a.last.IsZero() {
		return time.Time{}, time.Time{}, false
	}
	return a.first, a.last.Add(uploadGrace), true
}

func within(ts, start, end time.Time) bool {
	return !ts.IsZero() && !ts.Before(start) && !ts.After(end)
}

func countInWindow(authFails []event, a *agg) int {
	start, end, ok := a.window()
	if !ok {
		return 0
	}
	n := 0
	for _, e := range authFails {
		if within(e.TS, start, end) {
			n++
		}
	}
	return n
}

func inAnyWindow(ts time.Time, byRepo map[string]*agg) bool {
	for _, a := range byRepo {
		if start, end, ok := a.window(); ok && within(ts, start, end) {
			return true
		}
	}
	return false
}

// attribute finds the repo an enqueue belongs to. An enqueue whose start event
// rotated away is an orphan -- and an unattributable archive upload is still an
// archive upload, so it is never dropped. It falls back to sid-only correlation,
// then to the explicit <unattributed> bucket.
func attribute(k string, e event, starts map[string][]event, sidRepo map[string]string) (repo string, lowConf bool) {
	if evs, ok := starts[k]; ok {
		for _, s := range evs {
			if s.Repo != "" {
				return s.Repo, false
			}
		}
	}
	if e.SID != "" {
		if r, ok := sidRepo[e.SID]; ok && r != "" {
			return r, true // same session, different turn: probable but not certain
		}
	}
	if e.Repo != "" {
		return e.Repo, false
	}
	return model.UnknownRepo, true
}

// normalizeRepo groups paths that differ only by trailing separators or case.
// macOS (APFS default) and Windows are case-insensitive, so /Users/x/Repo and
// /users/x/repo are the same repo and must not appear as two ledger rows.
func normalizeRepo(p string) string {
	if p == model.UnknownRepo {
		return p
	}
	n := filepath.Clean(p)
	if caseInsensitiveFS {
		n = strings.ToLower(n)
	}
	return n
}

func repoOnDisk(p string) (onDisk, isGit bool) {
	if p == "" || p == model.UnknownRepo {
		return false, false
	}
	fi, err := os.Stat(p)
	if err != nil || !fi.IsDir() {
		return false, false
	}
	// A repo gone from your disk is not gone from their bucket; OnDisk only tells
	// us whether we can go look for secrets in it.
	if _, err := os.Stat(filepath.Join(p, ".git")); err == nil {
		return true, true
	}
	return true, false
}

func sortArchives(a []model.Archive) {
	sort.Slice(a, func(i, j int) bool {
		if !a[i].Timestamp.Equal(a[j].Timestamp) {
			return a[i].Timestamp.Before(a[j].Timestamp)
		}
		return a[i].GCSPath < a[j].GCSPath
	})
}

func statusRank(s string) int {
	switch s {
	case model.StatusDelivered:
		return 4
	case model.StatusQueued:
		return 3
	case model.StatusCollectedOnly:
		return 2
	}
	return 1
}
