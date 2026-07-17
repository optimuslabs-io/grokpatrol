# AGENTS.md

Machine-readable contract for AI agents installing, running, and interpreting **grokpatrol**.
Humans: see [README.md](README.md).

grokpatrol is a single-binary, offline, read-only forensic scanner. It answers one question for
the host it runs on: did the **Grok Build CLI** collect, queue, and/or upload this machine's git
repositories to xAI, and which secrets went with them.

## Install (ranked for non-interactive use)

1. **Go toolchain present — preferred, hermetic (stdlib-only, zero dependencies):**
   ```sh
   go install github.com/optimuslabs-io/grokpatrol/cmd/grokpatrol@latest
   ```
   Installs to `$GOBIN` (or `$(go env GOPATH)/bin` if `GOBIN` is unset). No third-party modules are fetched (`go.sum` is absent).

2. **No Go toolchain — verified binary download.** Release assets follow a constructable scheme;
   no HTML scraping or API calls are required:
   ```
   https://github.com/optimuslabs-io/grokpatrol/releases/download/<tag>/grokpatrol_<tag>_<os>_<arch>
   https://github.com/optimuslabs-io/grokpatrol/releases/download/<tag>/SHA256SUMS
   ```
   `<os>` ∈ {`darwin`, `linux`}, `<arch>` ∈ {`amd64`, `arm64`}. `<tag>` looks like `v0.1.0`.
   Resolve the latest tag without the API by following the `releases/latest` redirect:
   ```sh
   tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/optimuslabs-io/grokpatrol/releases/latest)"
   tag="${tag##*/}"
   ```
   Then download the matching asset **and** `SHA256SUMS`, set `os` and `arch` to your platform
   (e.g. `os=linux arch=amd64`), verify, and only install on match:
   ```sh
   grep "  grokpatrol_${tag}_${os}_${arch}" SHA256SUMS | sha256sum -c   # shasum -a 256 -c on macOS
   ```

3. **Install script** (non-interactive, no `sudo`, verifies the checksum before installing):
   ```sh
   curl -fsSL https://raw.githubusercontent.com/optimuslabs-io/grokpatrol/main/install.sh | sh
   ```
   Override the version with `GROKPATROL_VERSION=v0.1.0`. It exits non-zero on any download or
   checksum failure and never installs an unverified binary.

**Provenance (recommended before executing on a sensitive host).** Release binaries carry sigstore
attestation — proof the binary was built by this repository's release workflow, in a transparency
log a repo compromise could not rewrite:
```sh
gh attestation verify <binary> -R optimuslabs-io/grokpatrol
```

Platforms: macOS and Linux, amd64 and arm64. Windows is not built.

## Run

```sh
grokpatrol --json        # complete machine-readable forensic record on stdout (use this)
grokpatrol               # human summary on stdout
grokpatrol --quiet       # print only the verdict
grokpatrol --version     # print version and exit
```

- The report is on **stdout**; progress narration is on **stderr**. `grokpatrol --json | jq` is
  safe — stdout stays pure JSON.
- No arguments are required. It scans the current user's machine. Useful flags: `--home <dir>`,
  `--grok-home <dir>`, `--scan-root <dir>` (repeatable), `--no-git`, `--timeout <dur>`,
  `--color never`. Full list: `grokpatrol --help`.
- It runs entirely offline and makes no network calls. Do not expect or require network egress.

## Interpret the result

**Exit code answers only "did grokpatrol run", never "what did it find".** Do not branch on the
exit code to decide whether the host is affected.

| Exit code | Meaning |
|---|---|
| `0` | The scan ran and printed a report — any verdict. Read the verdict from the report body. |
| `1` | Tool failure (bad flags, internal error). Never used for a finding. |

Read the finding from the report. For agents, parse `--json` and read the top-level `verdict`
string:

```sh
grokpatrol --json | jq -r .verdict
```

**Verdict taxonomy** (checked in this order):

| Verdict | Meaning | Agent action |
|---|---|---|
| `COMPROMISED` | Proof the code left the machine (a confirmed or unclassifiable upload). | Escalate. Advise rotating credentials from the full git history of every touched repo. |
| `EXPOSED` | Grok present and unmitigated, and/or repositories collected/queued/staged — but no proof of upload. | Advise rotate + set both config mitigations. Queued ≠ safe. |
| `INDETERMINATE` | No upload and nothing high-severity, but part of the scan was degraded (unreadable dir/log). Not a clean bill of health. | Report the blind spots; recommend re-running with access. |
| `CLEAN` | None of the above. | No action; note the standing blind-spots caveat. |

A collected-and-queued host is `EXPOSED`, not `CLEAN` — its credentials must still be rotated. A
degraded scan never reports `CLEAN`.

## Safety guarantees (assertions you can relay to a user)

These are mechanically enforced in the codebase, not aspirational:

- **No network, ever.** `net`, `net/http`, `crypto/tls` are not linked in (`make verify-deps`);
  `go.sum` is absent (no third-party dependencies). The binary cannot phone home, and there is no telemetry or update ping.
- **Read-only.** Every file open is `O_RDONLY` through one function; no write/create/rename/remove.
  A test proves `.git` is byte-for-byte identical after a scan.
- **Never executes the `grok` binary** — not even `--version`. Version is inferred passively.
- **Never prints secret values.** It reports secret *locations* (path, git object id, rule id)
  only; the evidence model has no field for file contents. A default run never reads file
  contents at all; `--full-secrets-search` matches contents in memory (gitleaks rule set) and
  still reports only locations — leak tests grep every output channel for planted values.
- **A degraded scan never reports CLEAN**, so a blocked directory cannot be mistaken for a clean host.

## Do not

- Do not auto-run grokpatrol as a side effect of an unrelated task. It is an incident-response
  action; run it when a user is investigating a possible Grok exfiltration, and surface the verdict.
- Do not pipe the human report (stdout without `--json`) into a parser — use `--json`.
- Do not treat exit code `0` as "clean" — read the verdict.
