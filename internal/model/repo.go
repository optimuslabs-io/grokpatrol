package model

import "time"

// Repo collection status, derived from the log ledger.
const (
	// StatusDelivered is the strongest status there is: an upload-completion event was
	// found, so the archive is known to have LANDED, not merely to have been built and
	// queued. No Grok build we have seen emits such an event -- see kindUploadSuccess
	// in detect/logs -- so this is unreachable today and exists for the day one does.
	//
	// Its absence means nothing. A repo sitting at QUEUED is not a repo whose upload
	// failed; it is a repo whose delivery the log cannot speak to either way.
	StatusDelivered     = "delivered"      // upload CONFIRMED landed — positive proof
	StatusQueued        = "queued"         // an archive was enqueued for upload — proof of collection
	StatusCollectedOnly = "collected_only" // collection started, no enqueue seen — NOT a reassurance
	StatusUnknown       = "unknown"
)

// UnknownRepo is used when an enqueue event cannot be attributed to a repo
// (its matching start event rotated out of the logs). An unattributable archive
// upload is still an archive upload; it is never dropped.
const UnknownRepo = "<unattributed>"

type Archive struct {
	Phase      string    `json:"phase"`    // "before" | "after" | "unknown"
	GCSPath    string    `json:"gcs_path"` // kept verbatim — this is the smoking gun
	SID        string    `json:"sid"`
	TurnNumber *int64    `json:"turn_number,omitempty"` // pointer: absent is not 0
	Timestamp  time.Time `json:"timestamp,omitzero"`
	// LogFile and LogLine are where this archive's enqueue event was read. Grok's
	// own log is the witness, and a reader who cannot go and look at the line is
	// being asked to take the ledger on faith.
	//
	// They also make the rotation case visible: a start event and its enqueue can
	// land in different files, so two archives of one repo may cite unified.jsonl.1
	// and unified.jsonl. Printing the file per row is what lets a reader see the
	// correlation really did cross a rotation boundary.
	LogFile string `json:"log_file,omitempty"` // display-processed
	LogLine int    `json:"log_line,omitempty"`
	// Delivered means an upload-completion event named THIS archive's gcs_path. It is
	// the only positive proof of delivery the tool can hold. False is not "failed": it
	// is "the log does not say", which is the state of every archive on every host we
	// have seen.
	Delivered bool `json:"delivered,omitempty"`
}

type SecretHit struct {
	// Class is a filename shape ("dotenv", "private-key", ...) on a default run,
	// or a gitleaks rule id ("aws-access-token", "github-pat", ...) when
	// --full-secrets-search matched the file's contents. Either way it names
	// WHAT to rotate; there is no field here -- or anywhere in model -- that
	// could carry the value itself.
	Path      string `json:"path"` // repo-relative: you have to know what to rotate
	Class     string `json:"class"`
	InHEAD    bool   `json:"in_head"`
	InHistory bool   `json:"in_history"`
	// Blob is the git object id of this file's contents, straight out of
	// `git rev-list --objects HEAD` -- the very command whose output defined the
	// uploaded set (under --full-secrets-search it may instead be the historical
	// version whose contents actually matched). It is the strongest evidence in
	// the report: `git cat-file -p <blob>` shows the USER the secret the report
	// refuses to quote. A default run never follows this pointer at all, and a
	// --full-secrets-search run only ever matches contents in memory -- the
	// reader's own git is the only thing that prints the value.
	Blob string `json:"blob,omitempty"`
	// DeletedFromCheckout is the one that matters most: the file is gone from the
	// working tree but still reachable in git history, so it was in the exfiltrated
	// object set — and the user cannot see it by looking at their own checkout.
	DeletedFromCheckout bool `json:"deleted_from_checkout"`
}

type RepoStatus struct {
	RepoPath        string    `json:"repo_path"`
	Status          string    `json:"status"`
	OnDisk          bool      `json:"on_disk"` // gone from your disk is not gone from their bucket
	IsGitRepo       bool      `json:"is_git_repo"`
	Sessions        []string  `json:"sessions,omitempty"`
	CollectAttempts int       `json:"collect_attempts"`
	Archives        []Archive `json:"archives,omitempty"`
	// LogFile and LogLine cite where collection was first recorded for this
	// repository. A COLLECTED-ONLY row has no archive to point at, so without these
	// it is the one claim in the ledger with nothing behind it -- and it is a claim
	// that a repository was read by something that wanted to upload it.
	LogFile     string      `json:"log_file,omitempty"` // display-processed
	LogLine     int         `json:"log_line,omitempty"`
	FirstSeen   time.Time   `json:"first_seen,omitzero"`
	LastSeen    time.Time   `json:"last_seen,omitzero"`
	SecretFiles []SecretHit `json:"secret_files,omitempty"`
	// HistoryObjects is how many git objects were reachable from HEAD -- the size of
	// the set the collector uploaded. It turns "your history went out" into a number,
	// and it is the denominator the secret count is a numerator of.
	HistoryObjects int `json:"history_objects,omitempty"`
	// SecretsScanned false means "we do not know", never "clean".
	SecretsScanned bool   `json:"secrets_scanned"`
	SecretsNote    string `json:"secrets_note,omitempty"` // why the scan was skipped or degraded
	LowConfidence  bool   `json:"low_confidence,omitempty"`
	// DeliveriesConfirmed counts upload-completion events attributed to this repository:
	// positive proof that archives LANDED at xAI. Read it in the direction opposite to
	// UploadAuthFailures -- a non-zero count proves delivery, while zero proves nothing
	// at all, because no Grok build emits the event that would make it non-zero.
	DeliveriesConfirmed int `json:"deliveries_confirmed"`
	// UploadAuthFailures counts auth rejections on the upload leg that fall inside
	// this repo's collection window. Read it in one direction only: a non-zero count
	// is evidence that some delivery was REFUSED, while zero is NOT evidence that
	// delivery succeeded — Grok logs no upload-completion event at all, so a clean
	// upload leg and a silent one look identical. It never affects Status.
	UploadAuthFailures int `json:"upload_auth_failures"`
}

// VersionEvidence is reported rather than resolved to a single answer: a binary
// contains dozens of unrelated semvers from its dependencies, so we present each
// source with its confidence and let the human weigh them.
type VersionEvidence struct {
	Version    string `json:"version"`
	Source     string `json:"source"`     // "logs", "manifest:~/.grok/version", "binary-strings", ...
	Confidence string `json:"confidence"` // "high" | "medium" | "low"
	Class      string `json:"class"`      // see below
	Path       string `json:"path,omitempty"`
}

// Version classification. Note the deliberate absence of a "SAFE" class: this
// tool has no ground truth for a fixed version, and a scanner that hands out
// clean bills of health based on an unverified upper bound is worse than one
// that admits it does not know.
const (
	VersionConfirmedAffected = "CONFIRMED_AFFECTED" // 0.2.93 — reproduced publicly
	VersionReportedAffected  = "REPORTED_AFFECTED"  // <= 0.2.99 — reported, not independently verified here
	VersionUnknown           = "UNKNOWN"            // above the reported range, or unparseable — NOT clean
)
