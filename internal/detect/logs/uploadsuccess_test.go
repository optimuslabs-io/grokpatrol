package logs

import (
	"strings"
	"testing"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// Delivery confirmation is the one signal grokpatrol has never been able to get: no
// Grok build emits an upload-completion event, the upload events carry no status
// field, and the client that performs the PUT logs only its 401s. It is also the GATE
// for COMPROMISED: that verdict asserts the code left the machine, so it fires only on
// a confirmed (or unclassifiable) delivery. The tests that matter most are the ones
// proving a queued-but-undelivered host still reports EXPOSED -- collection is never
// waved off, it just is not COMPROMISED without proof the bytes landed.

func runLines(t *testing.T, lines ...string) engine.Result {
	t.Helper()
	return run(t, grokHome(t, map[string]string{"unified.jsonl": line(lines...)}))
}

func repoRow(t *testing.T, res engine.Result, path string) model.RepoStatus {
	t.Helper()
	for _, r := range res.Repos {
		if r.RepoPath == path {
			return r
		}
	}
	t.Fatalf("repo %q not in ledger %v", path, res.Repos)
	return model.RepoStatus{}
}

// THE REGRESSION GUARD, and the reason the whole feature is safe.
//
// A host with archives queued and NO completion event -- which is every real host --
// must report EXPOSED: collection is proven, so its credentials still have to be
// rotated. What it must NOT do is read as reassurance (a queued archive can never
// vanish or drop below EXPOSED), and it must NOT falsely read as COMPROMISED -- that
// verdict is reserved for proof the bytes landed, which this host does not have.
func TestAbsentSuccessNeverDowngrades(t *testing.T) {
	res := runLines(t,
		`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
		`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/after_codebase.tar.gz","ts":"2026-06-12T10:01:00Z"}`,
	)

	r := repoRow(t, res, "/work/api")
	if r.Status != model.StatusQueued {
		t.Errorf("status = %q, want %q: no completion event means delivery is UNKNOWN, not failed",
			r.Status, model.StatusQueued)
	}
	if r.DeliveriesConfirmed != 0 {
		t.Errorf("DeliveriesConfirmed = %d, want 0", r.DeliveriesConfirmed)
	}

	f := finding(res, "logs.archive_enqueued")
	if f == nil {
		t.Fatal("logs.archive_enqueued vanished: the exfil finding that forces EXPOSED must not " +
			"depend on a completion event Grok has no code path to write")
	}
	// exfil (forces EXPOSED) at SevHigh+, but NOT upload: a queued archive is collection,
	// and collection alone must never reach COMPROMISED.
	if !f.IsExfil() || f.IsUpload() || f.Severity < model.SevHigh {
		t.Errorf("archive_enqueued = %v/%v, want exfil-not-upload at SevHigh+ so it forces EXPOSED, never COMPROMISED",
			f.Severity, f.Tags)
	}
	if finding(res, "logs.upload_confirmed") != nil {
		t.Error("logs.upload_confirmed fired with no completion event in the log")
	}
}

// The upgrade itself: a named completion event proves the bytes landed.
func TestNamedCompletionEventConfirmsDelivery(t *testing.T) {
	const gcs = "gs://b/after_codebase.tar.gz"
	res := runLines(t,
		`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
		`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"`+gcs+`","ts":"2026-06-12T10:01:00Z"}`,
		`{"msg":"`+scan.MarkerEvent+`.completed","sid":"s1","ctx":{"turn_number":0},"gcs_path":"`+gcs+`","ts":"2026-06-12T10:02:00Z"}`,
	)

	r := repoRow(t, res, "/work/api")
	if r.Status != model.StatusDelivered {
		t.Errorf("status = %q, want %q", r.Status, model.StatusDelivered)
	}
	if r.DeliveriesConfirmed != 1 {
		t.Errorf("DeliveriesConfirmed = %d, want 1", r.DeliveriesConfirmed)
	}
	if len(r.Archives) != 1 || !r.Archives[0].Delivered {
		t.Errorf("the archive named by the completion event was not marked Delivered: %+v", r.Archives)
	}

	f := finding(res, "logs.upload_confirmed")
	if f == nil {
		t.Fatal("logs.upload_confirmed did not fire on a named completion event")
	}
	// Critical + upload: this is the finding that drives COMPROMISED.
	if f.Severity != model.SevCritical || !f.IsUpload() {
		t.Errorf("finding = %v/%v, want Critical+upload so it drives COMPROMISED", f.Severity, f.Tags)
	}

	// A delivered repo is still a queued repo. Promoting it must not delete the finding
	// that names its archives.
	if finding(res, "logs.archive_enqueued") == nil {
		t.Error("logs.archive_enqueued was dropped when the repo was promoted to DELIVERED")
	}
}

// The other shape a success could take: the storage client logging its own 2xx,
// exactly where it logs its 401s today.
func TestStorageClient2xxConfirmsDelivery(t *testing.T) {
	res := runLines(t,
		`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
		`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/after_codebase.tar.gz","ts":"2026-06-12T10:01:00Z"}`,
		`{"msg":"upload ok","sid":"s1","ctx":{"turn_number":0,"consumer":"StorageClient.upload_file","status":200},"ts":"2026-06-12T10:02:00Z"}`,
	)
	if r := repoRow(t, res, "/work/api"); r.Status != model.StatusDelivered || r.DeliveriesConfirmed != 1 {
		t.Errorf("status = %q, confirmed = %d; want %q/1 -- a 2xx on the client that PUTs the archives is delivery proof",
			r.Status, r.DeliveriesConfirmed, model.StatusDelivered)
	}
}

// The consumer test is what keeps this honest. Grok's TELEMETRY client also talks to
// the network and also gets HTTP responses; reading its 200 as "your source code was
// delivered" would be the tool inventing the most consequential fact in the report.
func TestTelemetry2xxIsNotDeliveryProof(t *testing.T) {
	res := runLines(t,
		`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
		`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/after_codebase.tar.gz","ts":"2026-06-12T10:01:00Z"}`,
		`{"msg":"signals ok","sid":"s1","ctx":{"turn_number":0,"consumer":"FeedbackClient.Signals update","status":200},"ts":"2026-06-12T10:02:00Z"}`,
	)
	r := repoRow(t, res, "/work/api")
	if r.Status == model.StatusDelivered || r.DeliveriesConfirmed != 0 {
		t.Errorf("a 200 from the TELEMETRY client was read as codebase delivery: status=%q confirmed=%d",
			r.Status, r.DeliveriesConfirmed)
	}
}

// A non-2xx on the upload leg is not a success. Fails closed.
func TestUploadLegNon2xxIsNotDelivery(t *testing.T) {
	for _, status := range []string{"401", "403", "500", "302"} {
		res := runLines(t,
			`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
			`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/a.tar.gz","ts":"2026-06-12T10:01:00Z"}`,
			`{"msg":"upload result","sid":"s1","ctx":{"turn_number":0,"consumer":"StorageClient.upload_file","status":`+status+`},"ts":"2026-06-12T10:02:00Z"}`,
		)
		if r := repoRow(t, res, "/work/api"); r.DeliveriesConfirmed != 0 {
			t.Errorf("status %s was read as a successful delivery", status)
		}
	}
}

// A completion event must not be swallowed by the unknown-upload net. That fallback
// claims every repo_state.upload.* name it does not recognize, so if it ran first the
// delivery proof would be filed as "an event we don't understand" -- reported, but not
// understood as the strongest evidence in the report.
func TestCompletionEventIsNotFiledAsUnknown(t *testing.T) {
	res := runLines(t,
		`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
		`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/a.tar.gz","ts":"2026-06-12T10:01:00Z"}`,
		`{"msg":"`+scan.MarkerEvent+`.done","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/a.tar.gz","ts":"2026-06-12T10:02:00Z"}`,
	)
	if f := finding(res, "logs.unknown_upload_event"); f != nil {
		t.Errorf("the completion event was classified as an unrecognized upload event: %s", f.Title)
	}
	if repoRow(t, res, "/work/api").Status != model.StatusDelivered {
		t.Error("a .done completion event did not confirm delivery")
	}
}

// Every suffix we guessed at should land. Guessing wrong costs an upgrade, never a
// finding -- but there is no reason to guess narrowly.
func TestAllSuccessSuffixesConfirmDelivery(t *testing.T) {
	for _, suffix := range successSuffixes {
		res := runLines(t,
			`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
			`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/a.tar.gz","ts":"2026-06-12T10:01:00Z"}`,
			`{"msg":"`+scan.MarkerEvent+suffix+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/a.tar.gz","ts":"2026-06-12T10:02:00Z"}`,
		)
		if r := repoRow(t, res, "/work/api"); r.Status != model.StatusDelivered {
			t.Errorf("suffix %q did not confirm delivery (status %q)", suffix, r.Status)
		}
	}
}

// The report must never state delivery as fact on a host where it was not proven --
// and must state it plainly on one where it was.
func TestSummaryDoesNotClaimDeliveryWithoutProof(t *testing.T) {
	res := runLines(t,
		`{"msg":"`+eventStart+`","sid":"s1","ctx":{"turn_number":0,"repo_path":"/work/api"},"ts":"2026-06-12T10:00:00Z"}`,
		`{"msg":"`+eventEnqueued+`","sid":"s1","ctx":{"turn_number":0},"gcs_path":"gs://b/a.tar.gz","ts":"2026-06-12T10:01:00Z"}`,
	)
	for _, forbidden := range []string{"CONFIRMED DELIVERED", "delivered", "confirmed"} {
		for _, f := range res.Findings {
			if strings.Contains(strings.ToLower(f.Title), strings.ToLower(forbidden)) {
				t.Errorf("finding %s claims delivery with no completion event in the log: %q", f.ID, f.Title)
			}
		}
	}
}
