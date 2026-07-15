# grokpatrol

Detects, on your machine, whether the **Grok Build CLI** collected and queued your
git repositories for upload to xAI — and tells you **which secrets went with them**.

The Grok Build CLI was found to silently upload entire git repositories to the Google Cloud Storage. The upload was performed by a background collector that ran **outside the tool-call permission system**, so it fired even in sessions where the model was denied file access. What it shipped:

- every tracked file at git HEAD,
- every git object reachable from HEAD,
- **files deleted from the checkout but still reachable in git history** — which is
  exactly where secrets tend to hide.

Confirmed affected: `0.2.93`. Reported still present in versions through at least `0.2.99`.
The tool is version `0.1.0` and can detect versions `0.1.212` through the latest observed.

Most published indicators were network-based — you had to be watching the wire while it
happened. `grokpatrol` answers the question you can still ask afterwards: **what evidence
is left on this disk, which repos were taken, and what do I have to rotate?**

## Install

### 1. One-liner

```sh
curl -fsSL https://raw.githubusercontent.com/optimuslabs-io/grokpatrol/main/install.sh | sh
```

Detects your OS and architecture, downloads the matching release binary, **verifies it
against SHA256SUMS before installing** (aborting on any mismatch), and installs to
`~/.local/bin` if that is on your PATH, else `/usr/local/bin`.

macOS and Linux only; Windows is not currently built or supported.

### 2. Build from source through the Go module proxy

```sh
go install github.com/optimuslabs-io/grokpatrol/cmd/grokpatrol@latest
```

### 3. Download and verify

Grab the binary for your platform plus `SHA256SUMS` from the
[releases page](https://github.com/optimuslabs-io/grokpatrol/releases), then:

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS      # sha256sum on Linux

# Prove the binary was built by this repo's release workflow (sigstore):
gh attestation verify grokpatrol_v0.1.0_darwin_arm64 -R optimuslabs-io/grokpatrol

chmod +x grokpatrol_v0.1.0_darwin_arm64 && mv grokpatrol_v0.1.0_darwin_arm64 /usr/local/bin/grokpatrol
```

The checksum proves the download arrived intact. The attestation proves something
stronger: the binary was built from this repository's source by its release workflow,
recorded in a transparency log that a compromise of this repo could not rewrite.

## Use

```sh
grokpatrol                    # scan this machine (summarized output)
grokpatrol --verbose          # scan this machine (full archive & secret list)
grokpatrol --json             # machine-readable, for fleet collection (all details)
```

The default report is a transparent **summary**: it names totals (archive counts, secret counts),
tells you which ones matter most (secrets deleted from your checkout), and points you to `--verbose`
and `--json` for the complete receipt. The summary is not a redaction — it's an admission of
what it is, with pointers to everything it withholds.

`--verbose` lists every `gs://` destination, every secret file by name and blob id, and all evidence rows.
`--json` is the complete forensic record for fleet collection or automated tools.

### Watch it work

The report itself goes to stdout, so `grokpatrol --json | jq` still works while you
watch. `--quiet` silences it.

```
grokpatrol 0.1.0 scanning /Users/you

  → deepscan  walking the filesystem for grok homes, upload queues, staged archives, and executables carrying the bucket name
    ✓ deepscan  1 executable carrying the bucket name, 1 upload queue, 2 staged archives (28ms)
  → logs      reading Grok's logs (incl. rotated and gzipped) for repo_state.upload.start / .enqueued events
  → queue     listing the upload_queue: staged codebase archives, and manifests naming the destination bucket
  → config    checking config.toml for BOTH upload mitigations: harness.disable_codebase_upload and telemetry.trace_upload
  → version   inferring the Grok version from install manifests, package metadata and binary strings
    ✓ logs      2 repositories with 3 archives QUEUED FOR UPLOAD, 1 repository collected, upload unconfirmed
    ✓ queue     2 codebase archives staged (371.2 KB), 1 manifest naming the bucket
    ✓ config    NEITHER mitigation set: uploads are not blocked
    ✓ version   0.1.212, 0.2.39, 0.2.51, 0.2.56 -- REPORTED AFFECTED
  → secrets   git rev-list --objects HEAD minus the working tree, per implicated repository
    ✓ secrets   3 secret files, 2 DELETED FROM THE CHECKOUT but still in history

VERDICT: EXPOSED
  2 repositories collected and 3 archives built and queued for upload to gs://grok-code-session-traces/.

LIKELY EXPOSED SECRETS
  3 secret files, 2 deleted from the checkout but still in history
  3 secret files found. --verbose lists them by name and blob id; --json has the full record.
```

A detector that finds nothing says so out loud, rather than printing nothing: a silent line is
indistinguishable from a detector that crashed, and a crash that produces no findings reads
exactly like a clean host.

Exit codes, for scripting:

| Code | Verdict | Meaning |
|---|---|---|
| `0` | CLEAN | No Grok artifacts, and the scan was not degraded |
| `1` | — | The tool itself failed (bad flags, internal error). **Never used for findings.** |
| `2` | INDETERMINATE | Nothing found, but parts of the host could not be read |
| `3` | EXPOSED | Grok is present and unmitigated, and/or repositories were collected, queued or staged on your system — but no evidence the bytes were uploaded |
| `4` | COMPROMISED | Evidence of upload — a delivery to xAI was confirmed (or an upload event the tool cannot classify, read as one) |

## What it looks at

| Indicator | Where |
|---|---|
| `repo_state.upload.start` / `.enqueued` events | `~/.grok/logs/unified*.jsonl` (incl. rotated + gzipped) |
| Staged archives awaiting upload | `~/.grok/upload_queue/` |
| Manifests naming the destination bucket | staged `metadata.json` → `gs://grok-code-session-traces/` |
| The bucket name embedded in the binary | any executable on disk |
| Both missing mitigations | `~/.grok/config.toml` → see below |
| Affected version | install manifests, package metadata, binary strings |
| **Secrets in the uploaded object set** | `git rev-list --objects HEAD` minus the working tree |

### Secrets

The secrets section is the one that matters most. The exfiltrated set was *"every git object
reachable from HEAD"*, which is precisely what `git rev-list --objects HEAD` enumerates.
Subtracting the current checkout from it yields the files that are **gone from your working
tree but still alive in history** — the deleted `.env`, the rotated-out `.pem`. 

**In default mode**, the report shows you the count of secrets and specifically flags how many are
deleted from your checkout (the ones you cannot find by looking) — because those are the priority:
they're off your disk but alive in git history, and they went out first.

**With `--verbose`**, each secret is reported with its **full path and git object id**, which `rev-list`
prints on the same line as the path. That is the one claim in this report you can check for yourself:

```sh
git -C ~/work/payments-api cat-file -p d6da7879bc89     # the .env you deleted, still in history
```

grokpatrol will never run that command. `cat-file` is not on its git allowlist, so it hands
you a pointer to a file it is structurally incapable of reading — which is exactly why it can
afford to hand it to you at all.

## Guarantees

These are enforced mechanically:

- **No network. Ever.** Proven by the linker: `make verify-deps` asserts that `net`,
  `net/http` and `crypto/tls` do not appear in `go list -deps`, and that `go.sum` is empty.
  A binary with no networking packages linked in cannot phone home. There is no remote
  check, no telemetry, no update ping.
- **Zero dependencies.** Stdlib only. A tool that hunts for unaudited code should not
  ship any.
- **Read-only.** Every file open goes through one function, with `O_RDONLY`. There is no
  `--out` flag, no cache, no state directory. A test snapshots `.git` before and after a
  scan and demands byte-for-byte equality.
- **The `grok` binary is never executed** — not even `grok --version`. It carries a
  collector that runs outside the permission system; launching it to ask a question could
  itself start a session. Version is inferred passively.
- **Secret *values* are never read; secret *locations* always are.** The report prints the
  full path and git object id of every exposed credential file, because a rotation checklist
  you cannot locate is useless. It never reads their contents: `git cat-file` is excluded from
  the allowlist, so no code path exists that could read a blob. `model.Evidence` has no field
  capable of holding file contents, which makes this structural rather than a promise — a line
  *number* is evidence, a line's *text* never is. `~/.grok/auth.json` is checked for existence
  and never opened.
- **Every positive finding cites something you can go and look at.** A queued archive is
  reported with its `gs://` destination and the log file and line Grok wrote when it queued it;
  a staged archive with its SHA-256; an exposed secret with its blob id. A verdict you have to
  take on faith is not a forensic result.
- **Your archives are never unpacked.** A `*codebase.tar.gz` in the upload queue is your
  own source code. It is recorded by name, size and SHA-256. `archive/tar` is not imported.
- **A degraded scan never reports CLEAN.** If macOS TCC blocked `~/Documents`, the verdict
  is INDETERMINATE, and the report says which directories it could not see.


## Two things worth knowing

**Absence of evidence is not evidence of absence.** A drained upload queue means the
archives went *out*, not that they never existed. Rotated-away logs leave no trace. The
report's "WHAT THIS SCAN COULD NOT SEE" section prints on every run, including clean ones,
for exactly this reason.

**A file that mentions the bucket is not an install.** grokpatrol distinguishes an
executable that *contains* the collector from a text file that merely *names* the
indicators — your own notes, an IoC list, another detection tool, or this repo's test
fixtures. Executables and packed bundles (≥512 KB, since Grok may ship as a Bun/Node
bundle with no executable magic) are reported as an install; small text files are listed
for completeness and do not affect the verdict.

## Development

`make` on its own lists every target.

| Target | What it does |
|---|---|
| `make build` | build `./dist/grokpatrol` for this machine |
| `make run` | build, then scan this machine (`ARGS="--json"` to pass flags) |
| `make demo` | build a synthetic compromised host and scan it — expect COMPROMISED |
| `make check` | what CI runs: deps + fmt + vet + race tests + cross-compile smoke |
| `make verify-deps` | prove the binary is stdlib-only, with no network and no cgo |
| `make test` / `fuzz` / `bench` | race tests, fuzz the log parser, benchmark the scanner |
| `make fmt` / `vet` | gofmt in place, go vet |
| `make release` | all four platforms, trimmed, CGO-free, with `SHA256SUMS` |
| `make clean` / `distclean` | remove build output; also caches and the demo fixture |

`make demo` is the one worth running. There is no real Grok install to test against, so
the compromised case is constructed: every host-side indicator planted, including a repo
whose secrets were committed and then deleted. It should print `VERDICT: COMPROMISED` and
flag `.env.production` and `certs/prod.pem` as *deleted from checkout, still in history*.

The fixture is generated rather than committed: files carrying a live IoC string trip
corporate EDR, which is a real problem for anyone who clones this.
