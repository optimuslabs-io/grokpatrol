# Contributing to grokpatrol

Thanks for helping. grokpatrol is a forensic tool that runs on possibly-compromised
hosts, so it holds itself to a few hard rules that ordinary projects don't. Most of
contributing here is understanding *why* those rules exist and not breaking them.

## The invariants (each is mechanically enforced — a failed build/test, not a code-review nit)

Before you write code, know these. They are the product:

- **No network, no third-party dependencies.** Don't import `net`, `net/http`,
  `crypto/tls`, or `os/user`; keep `go.sum` absent. `make verify-deps` enforces this
  via `go list -deps`. A tool that hunts for unaudited code ships none of its own.
- **Read-only.** All host file reads go through `hostfs.OpenRead` (`O_RDONLY`).
  `hostfs` is the only package that touches the filesystem, and it never
  creates/writes/renames/removes. A test snapshots `.git` and demands it is
  byte-for-byte unchanged after a scan.
- **`gitx` is the only package that runs a subprocess**, against a read-only
  allowlist (`rev-list`, `ls-tree`, `rev-parse`, `version`). No `cat-file` — that is
  what makes "never prints secret values" structural. The `grok` binary is never
  executed.
- **`model.Evidence` has no field that can hold file contents.** Secret *locations*
  are reported; secret *values* never are.
- **A degraded scan never reports CLEAN.** A material `ScanError` forces
  INDETERMINATE over CLEAN.

If your change needs to bend one of these, that is a design discussion first — open
an issue before the PR. See `CLAUDE.md` for the full architecture and the reasoning
behind each rule.

## Development

```sh
make build     # ./dist/grokpatrol
make check     # what CI runs: verify-deps + gofmt + vet + race tests + cross-compile
make test      # go test -race ./...
make demo      # build a synthetic compromised host and scan it (expect COMPROMISED)
```

`make` with no target lists them all. There is no target for a single test — use
`go test -run <Name> ./internal/<pkg>/`.

> **Note:** `make demo` generates a fixture containing live indicator strings that
> can trip corporate EDR. Run it in a throwaway VM or container, not on a managed
> work machine. The fixture is generated, never committed, for this reason.

## Before you open a PR

1. `make check` passes locally. CI runs exactly this, so there are no surprises.
2. `gofmt` is clean (`make fmt`).
3. New behavior has a test. This codebase tests its invariants, not just its happy
   paths — match that.
4. Comments explain **why** a constraint exists, not what the code does. When you
   touch a guarded path, preserve its reasoning.

## Commit and PR style

- Keep PRs focused; one concern per PR.
- Write commit messages that explain the reasoning, not just the diff.
- The PR template asks which invariants your change touches — answer it honestly.

## Reporting bugs and detection gaps

- Security issues: **do not** use public issues — see [SECURITY.md](SECURITY.md).
- A missed detection or a false alarm: use the **False positive / false negative**
  issue template. Detection accuracy is the product; these reports are valued.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license of this project.
