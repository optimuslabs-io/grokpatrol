# Security Policy

grokpatrol is a forensic tool people run on hosts they are worried about. Its
whole value is trust, so we treat security reports seriously and hold the tool to
the guarantees the README makes.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Public disclosure before a
fix puts every user at risk.

Instead, report privately through GitHub's
[private vulnerability reporting](https://github.com/optimuslabs-io/grokpatrol/security/advisories/new)
("Report a vulnerability" on the Security tab). If that is unavailable to you,
email **security@optimuslabs.io** with:

- a description of the issue and its impact,
- the version (`grokpatrol --version`) and platform,
- steps to reproduce, and
- any suggested remediation.

We aim to acknowledge a report within **3 business days** and to ship a fix or a
mitigation plan within **30 days**, coordinating disclosure with you.

## What we especially want to hear about

Because of what this tool claims, these classes are the highest priority:

- **Any write to the host.** grokpatrol is read-only; a code path that creates,
  modifies, renames, or deletes a file is a serious bug.
- **Any network egress.** The binary must make no network calls. A linked
  networking package or an outbound connection breaks the core promise.
- **Reading or emitting secret *values*.** The tool reports secret *locations*
  only; anything that reads or prints a secret's contents is a vulnerability.
- **Executing the `grok` binary**, directly or indirectly.
- **A false CLEAN on a degraded scan** — a blocked or unreadable area that is not
  reflected as INDETERMINATE.
- **Supply-chain integrity** — anything that would let a released binary differ
  from the tagged source (the release carries sigstore provenance for this reason).

False positives and false negatives in *detection* are important too, but they are
not security-sensitive — please file those as regular issues using the
"False positive / false negative" template.

## Supported versions

grokpatrol is pre-1.0 and releases roll forward. Security fixes land on the latest
release; please reproduce on the newest version before reporting.

## Verifying what you run

Every release binary carries sigstore build provenance. Before trusting one:

```sh
gh attestation verify <binary> -R optimuslabs-io/grokpatrol
```

This proves the binary was built by this repository's release workflow from the
tagged commit, recorded in a public transparency log.
