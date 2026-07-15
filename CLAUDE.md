# CLAUDE.md



## What this is

`grokpatrol` is a single-binary, offline forensic scanner (Go, stdlib only). It runs on a
possibly-compromised host and answers: did the Grok Build CLI collect, queue, and/or upload this machine's git
repositories for upload to xAI, and which secrets went with them. Entry point `cmd/grokpatrol`,
everything else under `internal/`.

## Commands

```sh
make build     # ./dist/grokpatrol
make check     # what CI runs: verify-deps + gofmt + vet + race tests + cross-compile smoke
make test      # go test -race ./...
make demo      # build a synthetic compromised host and scan it (expect exit 4)
make release   # four platforms + SHA256SUMS (runs verify-deps first)
make fuzz      # fuzz the log parser for 60s
make bench     # marker-scanner throughput
```

No Make target for a single test — use `go test -run <Name> ./internal/<pkg>/` directly.
`TestCompiledBinaryDoesNotContainItsOwnMarkers` compiles a real binary and skips under `-short`.

## Invariants (each mechanically enforced — a failed build/test, not a silent regression)

- **No network, no third-party deps.** Don't import `net`, `net/http`, `crypto/tls`, `os/user`; keep
  `go.sum` empty. `make verify-deps` enforces this via `go list -deps`.
- **Read-only.** All host file reads go through `hostfs.OpenRead` (O_RDONLY). `hostfs` is the only
  package touching the filesystem, and never creates/writes/renames/removes.
- **`gitx` is the only package that runs a subprocess**, allowlist `rev-list`, `ls-tree`,
  `rev-parse`, `version` — no `cat-file`, so the tool has no way to read a blob's contents, which is
  what makes "never prints secret values" structural. The `grok` binary itself is never executed.
- **`model.Evidence` has no field that can hold file contents** — no `Excerpt`/`Content`/`Match`.
  Every field is a location, a hash, or tool-authored prose; secret *locations* are reported, secret
  *values* never are. `SecretHit.Blob` hands the user a pointer (`git cat-file -p <blob>`) that
  grokpatrol itself cannot follow.
- **Markers are stored reversed, flipped at init** (`internal/scan/markers.go`). No non-test source
  file may contain a marker as a readable literal (test files may — that binary isn't shipped).
- **A degraded scan never reports CLEAN.** A material `ScanError` sets `Report.Degraded`, forcing
  INDETERMINATE over CLEAN. Immaterial errors are reported but don't degrade the verdict.
- **Exit 1 = tool failure, never a finding.** 0 CLEAN, 2 INDETERMINATE, 3 EXPOSED, 4 COMPROMISED.

### Verdicts (`engine.verdict`, checked in this order)

- **COMPROMISED (4):** a finding with `Severity >= SevHigh` **and** tagged `upload` — proof the code
  LEFT the machine: a confirmed delivery (`logs.upload_confirmed`) or an upload event the tool can't
  classify (schema drift, read as a delivery). `IsUpload()` is tag-based, deliberately independent of
  severity and strictly narrower than `IsExfil()`.
- **EXPOSED (3):** no upload finding, but at least one finding `Severity >= SevMedium` — grok present
  and unmitigated, and/or repositories collected/queued/staged (`exfil`), but no proof of upload.
- **INDETERMINATE (2):** no upload, nothing `>= SevMedium`, but `Report.Degraded` is set — a material
  `ScanError` (e.g. a directory or log the scanner couldn't read) could have hidden a finding.
- **CLEAN (0):** none of the above.

`exfil` (collection/queueing/staging) forces EXPOSED; only `upload` (confirmed or unclassifiable
delivery) reaches COMPROMISED. Grok emits no upload-completion event today, so COMPROMISED is
currently reachable only via a schema-drift fallback or a completion event that does not yet exist —
a collected-and-queued host is EXPOSED, and its credentials must still be rotated.

Severity scale: `SevInfo` < `SevLow` < `SevMedium` (exposed, unmitigated) < `SevHigh` (strong IoC —
populated queue, marker in binary, an archive collected/enqueued/staged) < `SevCritical` (proof of
confirmed upload).

## Architecture

`engine.Engine` runs detectors in three ordered phases:

1. **Discover** (`detect/deepscan`) — walks the host, finds grok homes, upload queues, staged
   archives, marker-carrying binaries. Fills `Env.Discovered`.
2. **Readers** (`detect/logs`, `queue`, `config`, `version`) — run in parallel over what phase 1
   found. Can't run first: a stray `.grok` under `~/work` has its own logs/config.
3. **Triage** (`detect/secrets`) — runs last; needs the repos phases 1–2 implicated
   (`Env.SeedRepos`).

Every detector satisfies `engine.Detector`; errors are non-fatal (`Engine.runOne` recovers panics
per-detector — a crash must never read as a clean host). The walk (phase 1) is not optional — there
is no `--quick`/`DeepScan` flag, because a scan that never touches disk can't see a grok binary or
staged archive. Every detector also implements `engine.Describer` and sets `Result.Summary`, which
`report.Progress` prints on **stderr** as the scan runs (never stdout — `--json | jq` must keep
working); `Describe()` must compose marker names from `scan.Marker*`, never spell them out.

Verdict logic (`engine.verdict`): COMPROMISED requires a finding tagged `upload` (proof of confirmed
delivery), not merely `exfil` (collection/queueing/staging → EXPOSED) or high severity.

| Package | Role |
|---|---|
| `hostfs` | only filesystem access; `walk.go` handles symlink/mount-crossing policy |
| `gitx` | only subprocess execution; read-only allowlist, scrubbed env |
| `scan` | marker matching over candidate files, magic-byte classification |
| `model` | findings, severities, verdicts, exit codes |
| `report` | `human.go`, `json.go`, `display.go` (home-relative paths) |

`detect/secrets`: uploaded set = every object reachable from HEAD (`git rev-list --objects HEAD`)
minus the working tree (`git ls-tree HEAD`) = files deleted from checkout but still alive in
history. Those sort first — the user can't find them by looking at their own repo.

There is no `redact` package — hashing paths/session IDs traded away the one thing the report exists
to tell the reader (which file, which repo). `report.Display` (home-relative path normalization) is
what survived; every path-bearing field must be listed in its walk.

## Display

Three modes: default **summary** (totals + what matters most, points to `--verbose`/`--json`),
`--verbose` (full receipt: every destination, every secret file/blob id), `--json` (canonical
structured record). Archive counts are **total and unique** — the gap between them (e.g. "64
(12 unique)") separates sustained collection from a retried failing upload. Version evidence
cites the specific log file it came from, since rotated logs may disagree.

The default report holds to one rule — lead with the number, show a few examples, point to
`--verbose`/`--json` for the rest. INSTALLATION is a summary (binary path + config state; the
sha256, per-version inventory, `auth.json` and other keys are `--verbose`). SECRETS shows counts
plus a few risk-classified example filenames (deleted-from-checkout first), never a value or blob
id. The EXFILTRATION LEDGER is one table (archive total+unique in the ARCHIVES cell; `ATTEMPTS`
and the full `gs://` list under `--verbose`), capped to the worst `maxLedgerRepos` repositories by
default. The verdict line leads with a concrete `Found: N repos · M archives · K secrets` tally;
severity counts move to `--verbose`. Colour is semantic (red = act now, yellow = exposure, cyan =
a path, green = clean, dim = context). An animated `GROKPATROL` logo (ported from
`optimuslabs-io/perceptron`) plays on **stderr** at scan start — TTY + colour only,
`--no-animation` / `GROKPATROL_NO_ANIM` / `--quiet` skip it — never stdout, so `--json | jq` is
untouched.

## Conventions

- Config mitigation needs **both** `telemetry.trace_upload = false` and
  `harness.disable_codebase_upload = true`; either alone is EXPOSED, not mitigated. Parser fails
  closed.
- A file that merely mentions the bucket is not an install — `BinaryHit.IsInstall` gates on
  executable magic or `BundleMinBytes` (512 KB, for bundled JS builds).
- Compromised-host test fixtures are **generated, never committed**
  (`./testdata/make_fakehome.sh /tmp/fakehome`) — they'd trip corporate EDR.
- Comments in this codebase explain *why* a constraint exists. Preserve that reasoning when you
  touch a guarded path.
