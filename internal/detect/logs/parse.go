package logs

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/scan"
)

// The field names below come from a secondhand report of Grok's log schema, and
// there is no Grok install available to validate them against. That is the single
// most dangerous fact about this detector: a rigid struct decode with
// `json:"gcs_path"` would produce ZERO findings on a genuinely compromised host
// if xAI renamed one field -- and zero findings is indistinguishable from clean.
//
// So every field is looked up through a list of plausible aliases, and anything
// we still cannot parse is escalated rather than dropped (see logs.go).

// pick walks a dotted path ("ctx.repo_path") through nested maps, trying each
// candidate key in turn and returning the first that resolves.
func pick(m map[string]any, keys ...string) any {
	for _, k := range keys {
		cur := any(m)
		parts := strings.Split(k, ".")
		ok := true
		for _, p := range parts {
			mm, isMap := cur.(map[string]any)
			if !isMap {
				ok = false
				break
			}
			v, exists := mm[p]
			if !exists {
				ok = false
				break
			}
			cur = v
		}
		if ok && cur != nil {
			return cur
		}
	}
	return nil
}

func pickStr(m map[string]any, keys ...string) string {
	switch v := pick(m, keys...).(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

// pickInt returns a pointer so that "absent" and "zero" stay distinguishable --
// turn_number 0 is a real turn.
func pickInt(m map[string]any, keys ...string) *int64 {
	switch v := pick(m, keys...).(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return &i
		}
	case float64:
		i := int64(v)
		return &i
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return &i
		}
	}
	return nil
}

var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.000Z",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999 -0700 MST",
	"2006-01-02 15:04:05",
}

// pickTime accepts string timestamps in several layouts and numeric epochs,
// auto-ranging seconds / millis / micros / nanos by magnitude. An unparseable
// timestamp yields the zero time and is never an error: we would rather report
// an exfiltrated repo with an unknown date than drop the event.
func pickTime(m map[string]any, keys ...string) time.Time {
	v := pick(m, keys...)
	switch t := v.(type) {
	case string:
		for _, l := range timeLayouts {
			if ts, err := time.Parse(l, t); err == nil {
				return ts.UTC()
			}
		}
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return epochToTime(f)
		}
	case json.Number:
		if f, err := t.Float64(); err == nil {
			return epochToTime(f)
		}
	case float64:
		return epochToTime(t)
	}
	return time.Time{}
}

func epochToTime(f float64) time.Time {
	switch {
	case f <= 0:
		return time.Time{}
	case f > 1e17: // nanoseconds
		return time.Unix(0, int64(f)).UTC()
	case f > 1e14: // microseconds
		return time.UnixMicro(int64(f)).UTC()
	case f > 1e11: // milliseconds
		return time.UnixMilli(int64(f)).UTC()
	default: // seconds
		sec, frac := int64(f), f-float64(int64(f))
		return time.Unix(sec, int64(frac*1e9)).UTC()
	}
}

// Aliases. Order matters only in that the first hit wins; all are plausible.
var (
	keysEvent = []string{"event", "event_name", "name", "type", "msg", "message", "evt"}
	keysSID   = []string{"sid", "session_id", "ctx.sid", "ctx.session_id", "session"}
	keysTurn  = []string{"ctx.turn_number", "turn_number", "ctx.turn", "turn", "ctx.turn_id"}
	keysRepo  = []string{"ctx.repo_path", "repo_path", "ctx.repo", "repo", "ctx.cwd", "cwd", "ctx.workspace", "workspace"}
	keysGCS   = []string{"gcs_path", "gcsPath", "ctx.gcs_path", "destination", "dest", "object_path", "path"}
	keysTime  = []string{"ts", "time", "timestamp", "@timestamp", "ctx.ts", "datetime"}
	// "ver" is the one Grok actually writes, and its absence here was a live false
	// negative: the real host stamps `"ver":"0.2.51"` on 649 of its log lines, and
	// grokpatrol -- looking only for "version" and friends -- reported "no version
	// evidence found" on a machine that announced its own version on almost every line.
	// The INSTALLATION table simply had no version row, so the reader was never told
	// they were running a build inside the affected range.
	//
	// It is listed AFTER the long-form spellings, not before: pick() takes the first
	// alias that resolves, and a line carrying both should be read from the explicit one.
	keysVer = []string{"version", "ctx.version", "app_version", "cli_version", "ctx.app_version",
		"ver", "ctx.ver"}
	keysConsumer = []string{"ctx.consumer", "consumer", "ctx.client", "client", "ctx.caller", "caller"}
	// keysStatus finds an HTTP response code. No Grok build we have seen writes one on
	// the upload leg -- the upload events have no outcome field at all -- so every alias
	// here is a guess at where a future one would land. Aliased broadly for the same
	// reason as everything else in this file: a rigid decode that misses the field
	// silently reports nothing, and on this signal "nothing" is the default anyway.
	keysStatus = []string{"status", "status_code", "code", "http_status", "response_code",
		"ctx.status", "ctx.status_code", "ctx.code", "ctx.http_status", "ctx.response_code"}
)

type eventKind int

const (
	kindOther eventKind = iota
	kindStart
	kindEnqueued
	// kindUnknownUpload is a repo_state.upload.* event with a suffix we do not
	// recognize. It is reported loudly rather than ignored: an unrecognized upload
	// event means the schema moved, and the safe reading of "an upload event we
	// don't understand" is "an upload".
	kindUnknownUpload
	// kindUploadAuthFail is an auth rejection (HTTP 401) attributed to the client
	// that PUTs the archives -- the upload leg itself. It exists because the logs
	// record that an archive was enqueued and never record whether it was
	// delivered: there is no repo_state.upload.done event, on any host we have
	// seen. A 401 on the upload leg is the only local trace of a delivery that was
	// refused.
	//
	// It is deliberately NOT proof of anything on its own, and must never move the
	// verdict. See uploadAuthSummary in correlate.go for the asymmetry that forces
	// that: a 401 shows a delivery FAILED, but no 401 does not show one SUCCEEDED.
	kindUploadAuthFail
	// kindUploadSuccess is POSITIVE PROOF OF DELIVERY -- the one signal this tool has
	// never been able to get, and the strongest thing it could ever report.
	//
	// It is dead code against Grok as it exists today, and that is deliberate. On the
	// host this was built from, the upload events carry no outcome field at all
	// (repo_state.upload.enqueued is {turn_number, size_bytes, gcs_path, blobs}: no
	// status, no code, no result), and the client that performs the PUT --
	// StorageClient.upload_file -- emits exactly ONE message in the entire log,
	// "auth 401 attribution" at warn level. It logs failures and nothing else. So a
	// delivered archive and an archive whose upload never happened produce byte-identical
	// logs: silence.
	//
	// THE ASYMMETRY IS THE WHOLE POINT, and it runs the opposite way to the 401:
	//
	//	a success event proves a delivery LANDED.
	//	no success event proves NOTHING about whether one did.
	//
	// So this is an UPGRADE PATH, never a GATE. Finding one promotes the report from
	// "delivery unconfirmed" to "delivery CONFIRMED". NOT finding one changes nothing:
	// the verdict still rests on collection, which is proven by the start and enqueue
	// events on their own. Requiring a success before reporting exfiltration would gate
	// COMPROMISED on a line Grok has no code path to write, and the verdict would be
	// unreachable on every host forever -- a false negative on every genuinely
	// compromised machine, which is the one failure this tool exists to never have.
	//
	// It is here so that the day xAI adds repo_state.upload.completed, or the storage
	// client starts logging its 2xx, grokpatrol RECOGNIZES it instead of filing it under
	// "unrecognized event". Do not wire it into engine.verdict as a precondition.
	kindUploadSuccess
)

// Composed at runtime from scan.MarkerEvent, never written as literals: grokpatrol
// searches binaries for "repo_state.upload", so storing it as a plain string here
// makes grokpatrol match itself. See internal/scan/markers.go.
var (
	eventPrefix   = scan.MarkerEvent
	eventStart    = eventPrefix + ".start"
	eventEnqueued = eventPrefix + ".enqueued"
)

// successSuffixes are the names a delivery-confirmation event might plausibly take.
// None exists in Grok today (see kindUploadSuccess), so this is a guess at a schema
// that has not been written yet -- which is why it is a LIST and matched loosely
// rather than a single exact string. Guessing wrong costs us an upgrade we could have
// made; it costs no finding, because the absence of a success never downgrades
// anything. The suffixes are composed onto eventPrefix at init, never spelled out as
// full literals: a scanner that stores the event name it hunts for finds itself.
var successSuffixes = []string{
	".completed", ".complete", ".done", ".success", ".succeeded",
	".finished", ".uploaded", ".delivered", ".ok",
}

// eventSuccess is the set of repo_state.upload.* names read as proof of delivery.
var eventSuccess = func() map[string]bool {
	m := make(map[string]bool, len(successSuffixes))
	for _, s := range successSuffixes {
		m[eventPrefix+s] = true
	}
	return m
}()

// classify decides what an event is from its name and, for the auth and delivery
// signals, the consumer and status that accompany it. Upload events win over auth
// events: an event named repo_state.upload.* is an upload no matter what else it
// carries.
//
// ORDER IS LOAD-BEARING. The success check must come BEFORE the kindUnknownUpload
// fallback: that fallback swallows every repo_state.upload.* name it does not
// recognize, so a repo_state.upload.completed added tomorrow would be filed as an
// unrecognized event -- reported, but not understood as the delivery proof it is.
func classify(event, consumer string, status int) eventKind {
	switch {
	case event == eventStart:
		return kindStart
	case event == eventEnqueued:
		return kindEnqueued
	case eventSuccess[event]:
		return kindUploadSuccess
	case isUploadSuccess(consumer, status):
		return kindUploadSuccess
	case strings.Contains(event, eventPrefix):
		return kindUnknownUpload
	case isUploadAuthFail(event, consumer):
		return kindUploadAuthFail
	}
	return kindOther
}

// isUploadSuccess matches a 2xx recorded against the client that PUTs the archives --
// the storage client logging its own success, rather than a named upload event.
//
// It is gated on the SAME consumer test as isUploadAuthFail, and for the same reason:
// Grok's telemetry client ("FeedbackClient.Signals update") talks to the network for
// its own unrelated purposes, and reading ITS 200 as "your source code was delivered"
// would be the tool inventing the single most consequential fact in the report. Only
// the storage/upload leg carries the archives.
//
// A status we cannot parse is not a success. This fails closed, which costs at most an
// upgrade -- never a finding.
func isUploadSuccess(consumer string, status int) bool {
	if consumer == "" || status < 200 || status > 299 {
		return false
	}
	return isUploadLeg(consumer)
}

// isUploadLeg reports whether a consumer string names the client that ships the
// archives. Substring and case-folded: the consumer is a Rust type path we have seen
// exactly one build emit, and "storage" also matches so that a rename of the method
// (upload_file -> put_object) still lands.
func isUploadLeg(consumer string) bool {
	c := fold(consumer)
	return strings.Contains(c, "upload") || strings.Contains(c, "storage")
}

// isUploadAuthFail matches an auth rejection on the leg that ships the archives.
//
// The consumer test is what makes this narrow, and it is the whole point. Grok
// logs 401s from several clients; only the storage/upload client is the codebase
// upload path. The telemetry client ("FeedbackClient.Signals update") 401s for its
// own unrelated reasons, and counting those as blocked codebase deliveries would
// invent a failure that never happened.
//
// Matching is substring and case-folded rather than exact, because the consumer
// string is a Rust type path we have seen exactly one build emit. "Storage" also
// matches so that a rename of the method (upload_file -> put_object) still lands.
//
// KNOWN AND DELIBERATE GAP. This is the one event class in this package with no
// fail-loud net: a rename of the client CLASS to something carrying neither
// "upload" nor "storage" (BlobPutter, GcsWriter) drops these 401s to kindOther
// silently, and the raw-substring net in logs.go will not catch them either --
// a 401 line carries a key prefix, not the bucket name.
//
// That asymmetry with kindUnknownUpload, which escalates precisely so a drifted
// schema cannot vanish, is intentional rather than an oversight. It is tolerable
// here for one reason only: this signal is ADVISORY and never gates the verdict,
// so a 401 we fail to classify costs a line of context, not a finding. It would
// NOT be tolerable in any detector that feeds engine.verdict. Do not copy this
// pattern into one.
func isUploadAuthFail(event, consumer string) bool {
	if consumer == "" || !strings.Contains(event, "401") {
		return false
	}
	return isUploadLeg(consumer)
}

type event struct {
	Kind     eventKind
	Raw      string // the event name as written
	SID      string
	Turn     *int64
	Repo     string
	GCSPath  string
	Consumer string
	Status   int // HTTP response code, 0 when the line carries none
	Version  string
	TS       time.Time
	File     string
	Line     int
}

// parseLine decodes one JSONL record. It returns ok=false for a line we could
// not decode; the caller records that and moves on. It never panics -- see
// FuzzParseLine.
func parseLine(b []byte) (map[string]any, bool) {
	var m map[string]any
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.UseNumber() // keep big ints exact; float64 would mangle a nanosecond epoch
	if err := dec.Decode(&m); err != nil {
		return nil, false
	}
	if m == nil {
		return nil, false // a bare "null", or a JSON array rather than an object
	}
	return m, true
}

func eventFrom(m map[string]any) event {
	name := pickStr(m, keysEvent...)
	consumer := pickStr(m, keysConsumer...)
	status := 0
	if s := pickInt(m, keysStatus...); s != nil {
		status = int(*s)
	}
	return event{
		Kind:     classify(name, consumer, status),
		Raw:      name,
		SID:      pickStr(m, keysSID...),
		Turn:     pickInt(m, keysTurn...),
		Repo:     pickStr(m, keysRepo...),
		GCSPath:  pickStr(m, keysGCS...),
		Consumer: consumer,
		Status:   status,
		Version:  pickStr(m, keysVer...),
		TS:       pickTime(m, keysTime...),
	}
}

// phaseOf derives before/after from the archive's basename, which is the only
// place the phase is recorded. Query strings and trailing slashes are stripped
// first; an unrecognized basename still counts as an archive (it is an upload
// either way), it just has an unknown phase.
func phaseOf(gcsPath string) string {
	p := gcsPath
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimRight(p, "/")
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		p = p[i+1:]
	}
	switch {
	case strings.HasPrefix(p, "before_codebase"):
		return "before"
	case strings.HasPrefix(p, "after_codebase"):
		return "after"
	}
	return "unknown"
}
