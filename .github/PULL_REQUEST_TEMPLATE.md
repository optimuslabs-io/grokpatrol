<!--
Thanks for contributing. Keep the PR focused on one concern.
See CONTRIBUTING.md for the invariants this project enforces.
-->

## What & why

<!-- What does this change, and what problem does it solve? Explain the reasoning,
     not just the diff. -->

## Invariants touched

<!-- These are enforced by make check; confirm your change keeps them. -->

- [ ] No new import of `net`, `net/http`, `crypto/tls`, `os/user`; `go.sum` stays absent.
- [ ] Stays read-only — no file create/write/rename/remove; host reads go through `hostfs`.
- [ ] `gitx` subprocess allowlist unchanged (no `cat-file`); the `grok` binary is not executed.
- [ ] No new field on `model.Evidence` that could hold file contents; secret values are never read or printed.
- [ ] A degraded scan still cannot report CLEAN.

<!-- If your change deliberately touches one of these, explain why here. -->

## Checklist

- [ ] `make check` passes locally (verify-deps + gofmt + vet + race tests + cross-compile).
- [ ] New behavior has a test (this codebase tests its invariants, not just happy paths).
- [ ] Comments explain *why* where a constraint is involved.
