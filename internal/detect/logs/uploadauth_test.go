package logs

import (
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// The upload leg is the client that PUTs the archives. The telemetry client 401s
// for its own unrelated reasons, and counting those as blocked codebase deliveries
// would invent a failure that never happened -- so the consumer field, not the 401
// itself, is what makes an event interesting.
func TestOnlyUploadLegAuthFailuresAreCounted(t *testing.T) {
	cases := []struct {
		name     string
		event    string
		consumer string
		want     eventKind
	}{
		{"storage client upload", "auth 401 attribution", "StorageClient.upload_file", kindUploadAuthFail},
		{"renamed method still matches", "auth 401 attribution", "StorageClient.put_object", kindUploadAuthFail},
		{"case folded", "auth 401 attribution", "storageclient.UPLOAD_file", kindUploadAuthFail},
		{"telemetry client is NOT the upload leg", "auth 401 attribution", "FeedbackClient.Signals update", kindOther},
		{"401 with no consumer is unattributable", "auth 401 attribution", "", kindOther},
		{"non-401 auth noise", "auth lock: acquired", "StorageClient.upload_file", kindOther},
		{"an upload event is an upload, not an auth failure", eventEnqueued, "StorageClient.upload_file", kindEnqueued},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.event, tc.consumer, 0); got != tc.want {
				t.Errorf("classify(%q, %q) = %v, want %v", tc.event, tc.consumer, got, tc.want)
			}
		})
	}
}

// THE INVARIANT. A 401 on the upload leg means a delivery was refused -- it does
// NOT mean the repository is safe. Collection still happened, the archive was
// still built, and a later run whose logs have rotated away may have drained the
// queue. If this test ever fails, the tool has been taught to talk a user out of
// rotating credentials that are in xAI's possession.
func TestUploadAuthFailuresNeverDowngradeTheVerdict(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"msg":"repo_state.upload.start","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/payments-api"},"ts":"2026-06-12T10:00:00Z"}`,
			`{"msg":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":0,"gcs_path":"gs://grok-code-session-traces/s1/turn_0/before_codebase.tar.gz"},"ts":"2026-06-12T10:00:05Z"}`,
			// Every upload attempt was refused, over and over.
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-12T10:00:06Z"}`,
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-12T10:00:07Z"}`,
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-12T10:00:08Z"}`,
		),
	})

	res := run(t, home)

	r := findRepo(res, "payments-api")
	if r == nil {
		t.Fatal("payments-api missing from the ledger entirely")
	}
	if r.Status != model.StatusQueued {
		t.Errorf("status = %q, want %q -- a refused delivery is still a queued archive", r.Status, model.StatusQueued)
	}
	if r.UploadAuthFailures != 3 {
		t.Errorf("UploadAuthFailures = %d, want 3", r.UploadAuthFailures)
	}
	if !hasFinding(res, "logs.archive_enqueued") {
		t.Error("the CRITICAL exfil finding vanished when 401s were present -- this is the false negative the tool exists to prevent")
	}

	// The exfil finding must still be the one that drives the verdict.
	if sev, ok := exfilSeverity(res); !ok || sev < model.SevHigh {
		t.Errorf("no exfil-tagged finding at >= SevHigh survived; verdict would not be COMPROMISED")
	}
}

// The delivery-context finding must be inert: SevInfo and untagged, so it cannot
// promote a verdict on its own even if the promotion threshold is later lowered.
// A host that only ever 401'd, with nothing collected, is not COMPROMISED.
func TestAuthFailuresAloneAreNotExfiltration(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-19T10:00:00Z"}`,
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-19T10:00:01Z"}`,
		),
	})

	res := run(t, home)

	if len(res.Repos) != 0 {
		t.Errorf("repos = %v, want none: a 401 is not a collection event", res.Repos)
	}
	f := finding(res, "logs.upload_auth_failure")
	if f == nil {
		t.Fatal("the upload_auth_failure finding was not reported")
	}

	// With nothing collected there is NO collection window, so the report must not
	// describe these failures as falling "outside" one -- that asserts a window that
	// never existed, and reads as "the uploads that happened were unobstructed" on a
	// host where no upload was ever queued.
	if strings.Contains(f.Title, "outside that window") || strings.Contains(f.Detail, "in which archives were queued") {
		t.Errorf("finding claims a collection window that does not exist:\n  title: %s", f.Title)
	}
	if !strings.Contains(f.Title, "no collected repository") {
		t.Errorf("title = %q, want it to say there is nothing to attribute the failures to", f.Title)
	}
	for _, f := range res.Findings {
		if f.ID != "logs.upload_auth_failure" {
			continue
		}
		if f.Severity != model.SevInfo {
			t.Errorf("severity = %v, want SevInfo -- this finding must never be able to move a verdict", f.Severity)
		}
		if f.IsExfil() {
			t.Error("finding is tagged exfil; at SevInfo it still cannot promote, but the tag makes it one " +
				"threshold change away from doing so. Leave it untagged.")
		}
	}
}

// Time is the only correlation available: on real hosts the upload-leg 401s carry
// no sid at all (only the telemetry 401s do), so session correlation would match
// exactly zero events. A 401 long after collection ended is a different story from
// one during it, and the report must not conflate them.
func TestAuthFailuresAreWindowedByTime(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"msg":"repo_state.upload.start","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/payments-api"},"ts":"2026-06-12T10:00:00Z"}`,
			`{"msg":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":0,"gcs_path":"gs://grok-code-session-traces/s1/turn_0/after_codebase.tar.gz"},"ts":"2026-06-15T10:00:00Z"}`,
			// Inside the collection window.
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-13T04:00:00Z"}`,
			// Four days after the last archive was queued: unrelated to these uploads.
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-19T04:00:00Z"}`,
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-19T04:00:01Z"}`,
		),
	})

	res := run(t, home)

	r := findRepo(res, "payments-api")
	if r == nil {
		t.Fatal("payments-api missing from the ledger")
	}
	if r.UploadAuthFailures != 1 {
		t.Errorf("UploadAuthFailures = %d, want 1 -- only the 401 inside the collection window counts", r.UploadAuthFailures)
	}

	f := finding(res, "logs.upload_auth_failure")
	if f == nil {
		t.Fatal("the upload_auth_failure finding was not reported")
	}
	if !strings.Contains(f.Title, "2 outside") {
		t.Errorf("title = %q, want it to separate the 2 out-of-window failures from the 1 during collection", f.Title)
	}
}

// The reassuring case, which is the one most likely to be misread. When no 401
// lands in the collection window, the tool must say "no known obstacle" and must
// NOT say "delivered" -- Grok logs no upload-completion event, so a successful
// upload and an upload that never happened leave the same trace: none.
func TestCleanUploadLegIsNotReportedAsDelivered(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"msg":"repo_state.upload.start","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/payments-api"},"ts":"2026-06-12T10:00:00Z"}`,
			`{"msg":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":0,"gcs_path":"gs://grok-code-session-traces/s1/turn_0/after_codebase.tar.gz"},"ts":"2026-06-12T10:00:05Z"}`,
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-19T04:00:00Z"}`,
		),
	})

	res := run(t, home)

	f := finding(res, "logs.upload_auth_failure")
	if f == nil {
		t.Fatal("the upload_auth_failure finding was not reported")
	}
	body := f.Title + " " + f.Detail
	for _, forbidden := range []string{"delivered successfully", "upload succeeded", "confirmed delivery"} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("finding claims %q; the absence of a 401 is not evidence of delivery", forbidden)
		}
	}
	if !strings.Contains(f.Detail, "not as") && !strings.Contains(f.Detail, "no upload-completion event") {
		t.Errorf("finding does not disclaim delivery confirmation:\n%s", f.Detail)
	}
}

// Two repos collected in the same stretch of time share a window, so ONE 401 is
// attributable to both and counts against both. The per-repo columns therefore
// overlap and must never be read as a total: summing them here gives 4 from 2
// actual failures. The finding's own count is the global one, and it is the only
// number that is a total.
//
// This is a display contract, not a bug -- but it is the one place the ledger can
// mislead a reader who adds the column up, so it is pinned.
func TestOverlappingWindowsCountAgainstBothRepos(t *testing.T) {
	home := grokHome(t, map[string]string{
		"unified.jsonl": line(
			`{"msg":"repo_state.upload.start","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/payments-api"},"ts":"2026-06-12T10:00:00Z"}`,
			`{"msg":"repo_state.upload.enqueued","sid":"s1","ctx":{"turn_number":0,"gcs_path":"gs://grok-code-session-traces/s1/turn_0/after_codebase.tar.gz"},"ts":"2026-06-12T10:00:05Z"}`,
			`{"msg":"repo_state.upload.start","sid":"s2","ctx":{"turn_number":0,"repo_path":"/work/billing"},"ts":"2026-06-12T10:00:10Z"}`,
			`{"msg":"repo_state.upload.enqueued","sid":"s2","ctx":{"turn_number":0,"gcs_path":"gs://grok-code-session-traces/s2/turn_0/after_codebase.tar.gz"},"ts":"2026-06-12T10:00:15Z"}`,
			// Both repos' windows (each extended by uploadGrace) cover both failures.
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-12T10:00:20Z"}`,
			`{"msg":"auth 401 attribution","ctx":{"consumer":"StorageClient.upload_file"},"ts":"2026-06-12T10:00:21Z"}`,
		),
	})

	res := run(t, home)

	for _, name := range []string{"payments-api", "billing"} {
		r := findRepo(res, name)
		if r == nil {
			t.Fatalf("%s missing from the ledger", name)
		}
		if r.UploadAuthFailures != 2 {
			t.Errorf("%s: UploadAuthFailures = %d, want 2 -- both failures fall in this repo's window",
				name, r.UploadAuthFailures)
		}
	}

	// The finding reports the GLOBAL count. It must say 2, not the 4 you would get
	// by summing the columns.
	f := finding(res, "logs.upload_auth_failure")
	if f == nil {
		t.Fatal("the upload_auth_failure finding was not reported")
	}
	if !strings.Contains(f.Title, "2 auth failures") {
		t.Errorf("title = %q, want the global total of 2, not the summed per-repo count of 4", f.Title)
	}
}

func finding(res engine.Result, id string) *model.Finding {
	for i := range res.Findings {
		if res.Findings[i].ID == id {
			return &res.Findings[i]
		}
	}
	return nil
}

func exfilSeverity(res engine.Result) (model.Severity, bool) {
	max, found := model.SevInfo, false
	for _, f := range res.Findings {
		if f.IsExfil() && f.Severity >= max {
			max, found = f.Severity, true
		}
	}
	return max, found
}
