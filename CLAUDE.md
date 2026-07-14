# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`grokpatrol` is a single-binary, offline forensic scanner (Go, stdlib only). It runs on a
possibly-compromised host and answers: did the Grok Build CLI collect and queue this machine's git
repositories for upload to xAI, and which secrets went with them. Entry point `cmd/grokpatrol`,
everything else under `internal/`.

## Commands

```sh
make build                    # ./dist/grokpatrol
make check                    # what CI runs: verify-deps + gofmt + vet + race tests + cross-compile smoke
make test                     # go test -race ./...
make demo                     # build a synthetic compromised host and scan it (expect exit 4)
make release                  # six platforms + SHA256SUMS (runs verify-deps first)
make fuzz                     # fuzz the log parser for 60s
make bench                    # marker-scanner throughput
```

There is no Make target for a single test — use `go test` directly:

```sh
go test -run TestFullyMitigated ./internal/detect/config/
go test -race -run TestCompromisedHostEndToEnd ./internal/engine/
```

`TestCompiledBinaryDoesNotContainItsOwnMarkers` compiles a real binary and skips under `-short`.

## Invariants

These are the product. Each is mechanically enforced, so breaking one fails a build or a test rather
than silently degrading the tool — treat the guardrails as load-bearing, not decorative.

**No network, no third-party dependencies.** Do not import `net`, `net/http`, `crypto/tls`, or
`os/user`, and keep `go.sum` empty (`go.mod` has no require block on purpose). `make verify-deps`
greps `go list -deps` and fails the release otherwise. This is also why builds are `CGO_ENABLED=0`
and why `hostfs.Home` uses `os.UserHomeDir` rather than `os/user`.

**Read-only.** Every host file read goes through `hostfs.OpenRead` (`O_RDONLY`, no create, no
truncate). `hostfs` is the only package that touches the filesystem, and it has no function that
creates, writes, renames, chmods, or removes. `TestRepositoryIsNeverModified` snapshots `.git`
before and after a scan and demands byte-for-byte equality.

**`gitx` is the only package that executes a subprocess**, and its allowlist is `rev-list`,
`ls-tree`, `rev-parse`, `version`. `cat-file` is deliberately absent: with no way to read a blob,
"never prints secret values" is structural rather than a promise. Do not add it. The `grok` binary is
never executed — not even `grok --version`; its collector runs outside the permission system, so
launching it could itself start a session.

**`model.Evidence` has no field capable of holding file contents.** Adding an `Excerpt`, `Content`,
or `Match` field would break the guarantee that secret *locations* are reported and secret *values*
never are. Every field on it is a location, a hash, or tool-authored prose, and that is the test a
new field has to pass: `Source`/`SourceLine` cite the log file and line an event was read from,
because a line *number* is evidence — the line's *text* is the excerpt field this type refuses to
have. `SecretHit.Blob` is the same bargain from the other side: `rev-list` prints the object id
next to the path, so the report hands the user a pointer (`git cat-file -p <blob>`) that grokpatrol
itself cannot follow, because `cat-file` is not on the gitx allowlist. That is what makes the
strongest evidence in the report free to print.

**Markers are stored reversed and flipped at init** (`internal/scan/markers.go`). A scanner that
stores the indicator it hunts for contains that indicator and detects itself — and splitting the
literal is not enough, because the Go linker packs string constants contiguously in `.rodata` and the
fragments end up adjacent anyway. No *non-test* source file may contain a marker as a readable
literal; test files may (the test binary is not shipped, and the self-detect test builds only
`cmd/grokpatrol`).

**A degraded scan never reports CLEAN.** A material `ScanError` — one that could have hidden an
indicator — sets `Report.Degraded`, which forces INDETERMINATE over CLEAN. Immaterial errors are
reported but do not degrade the verdict; if they did, every Mac would be INDETERMINATE forever.

**Exit 1 is reserved for tool failure and is never used for findings**, so a caller can always tell
"grokpatrol broke" from "grokpatrol found something". 0 CLEAN, 2 INDETERMINATE, 3 EXPOSED,
4 COMPROMISED (`model.Verdict.ExitCode`).

## Architecture

`engine.Engine` runs detectors in **three ordered phases**, and the ordering is the design, not an
accident:

1. **Discover** (`detect/deepscan`) — walks the host, finds grok homes, upload queues, staged
   archives, and marker-carrying binaries. Fills `Env.Discovered`.
2. **Readers** (`detect/logs`, `queue`, `config`, `version`) — run **in parallel**; each is a handful
   of file reads over what phase 1 found. They cannot run first: a stray `.grok` under `~/work` has
   its own logs and config, and assuming `~/.grok` is the only grok home is a false negative.
3. **Triage** (`detect/secrets`) — runs last because it needs the repositories phases 1–2 implicated
   (`Env.SeedRepos`, seeded from log ledger rows and staged manifests).

Every detector satisfies `engine.Detector` and returns an `engine.Result`; errors are non-fatal by
construction. `Engine.runOne` recovers panics per-detector — a crash that produces no findings reads
exactly like a clean host, which is the worst failure this tool could have.

**The walk is not optional.** `--quick` used to skip phase 1, and a scan that never looks at the
disk cannot see a grok binary, a staged archive, or a stray `.grok` — yet it returned CLEAN with
the same confidence as one that did. The flag is gone and `Env` has no `DeepScan`.

**Every detector narrates itself.** It implements `engine.Describer` (what it is about to look
for) and sets `Result.Summary` (what it found), which `report.Progress` prints on **stderr** as the
scan runs — never stdout, because `--json | jq` must keep working. Two tests hold the line:
`TestEveryDetectorDescribesWhatItChecks`, and `TestDetectorsSummarizeEvenWhenTheyFindNothing`,
which exists because a blank progress line is indistinguishable from a detector that died. A
`Describe()` string must compose markers from `scan.Marker*` rather than spelling them out, or the
binary detects itself.

The verdict is derived in `engine.verdict`: COMPROMISED requires a finding tagged `exfil` (proof of
collection/upload), not merely a high severity. A High config finding is exposure, not exfiltration.

Package boundaries are capability boundaries — one package owns one dangerous power:

| Package | Role |
|---|---|
| `hostfs` | the only filesystem access; `walk.go` handles symlink/mount-crossing policy |
| `gitx` | the only subprocess execution; read-only allowlist, scrubbed env |
| `scan` | marker matching over candidate files (chunked, overlap-carried), magic-byte classification |
| `model` | findings, severities, verdicts, exit codes — the shared vocabulary |
| `report` | `human.go` (terminal), `json.go` (fleet collection), `display.go` (home-relative paths) |

There is no `redact` package any more. `--redact` hashed repo paths and session IDs so a report
could be pasted into a vendor ticket; the report is an incident document about the user's own
machine and stays on it, so the hashing bought a sharing story nobody wanted and charged the
reader the one thing the report exists to tell them — which file, in which repo, to rotate.
`report.Display` is what survived: the home-relative path normalization that had been riding
along inside the redactor. Every path-bearing field in the report must be listed in its walk.

The core insight of `detect/secrets`: the uploaded set was every git object reachable from HEAD
(`git rev-list --objects HEAD`). Subtracting the working tree (`git ls-tree HEAD`) yields files
**deleted from the checkout but still alive in history** — the deleted `.env`, the rotated-out
`.pem`. Those sort first in the report because they are what the user cannot find by looking at their
own repo.

## Conventions

- **Config mitigation is two independent settings**, `telemetry.trace_upload = false` **and**
  `harness.disable_codebase_upload = true`. A host with only one is EXPOSED, not mitigated — see
  `TestPartialMitigationIsNotMitigated`. The config parser fails closed.
- **A file that merely mentions the bucket is not an install.** `engine.BinaryHit.IsInstall` gates on
  executable magic or `BundleMinBytes` (512 KB, since Grok may ship as a Bun/Node bundle with no
  magic). Reporting an IoC list or another detection tool as an install trains people to ignore this
  one.
- Test fixtures carrying live IoC strings trip corporate EDR, so the compromised-host fixture is
  **generated, never committed**: `./testdata/make_fakehome.sh /tmp/fakehome`.
- Comments here explain *why* a constraint exists, often citing the failure that motivated it. When
  you touch a guarded path, preserve that reasoning rather than trimming it.
