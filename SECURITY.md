# Security Policy

This project implements identity and authorization logic. Handle vulnerabilities
with care.

## Supported versions

The project is pre-1.0 and follows a latest-release support model. Security fixes
are developed on `main` and shipped in the most recent release; only the latest
release receives security updates. Publishing a new release ends security support
for the previous one. There is no long-term-support branch, and pre-1.0 versions
carry no extended-support or backward-compatibility guarantee.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's private vulnerability reporting (the "Report a
vulnerability" button under the repository's Security tab). If that is unavailable,
contact the maintainer directly at the address listed on the project website.

Please include: a description of the issue, steps to reproduce, the affected version
or commit, and the impact as you see it.

## What to expect

- Acknowledgment of your report, normally within a week.
- A coordinated fix: the maintainer will work on a remedy and agree on a disclosure
  timeline with you before any public disclosure.
- Credit for the report, if you'd like it.
- Public disclosure once a fix is available: resolved vulnerabilities are published
  as GitHub Security Advisories (GHSA) on this repository, so downstream users can
  see what was found, which versions were affected, and how it was fixed.

## A note for deployers

This is a reference implementation, not a turnkey security product. If you deploy
it, you are responsible for reviewing it against your own threat model, choosing
your trusted issuers and policy, and operating key material safely. The spec's
threat-model section is a starting point, not a guarantee.

## Secrets and credentials

The project holds no long-lived secrets. Release artifacts are signed keylessly
with Sigstore using the release workflow's GitHub Actions OIDC identity, so there
is no signing key to store or rotate. CI uses only the automatically-scoped,
ephemeral `GITHUB_TOKEN`. If the project ever needs a credential, it will live
only in GitHub Actions encrypted secrets, never in the repository, be scoped to
least privilege, and be rotated immediately on any suspected exposure.

## Dependency vulnerabilities (SCA)

Dependencies are scanned with `pip-audit` in CI on every push and pull request,
and the check gates merges. Remediation threshold: a known vulnerability in any
dependency blocks merge and release. A finding that is not exploitable in this
project's usage, or for which no fix is yet available, may be suppressed only with
`pip-audit --ignore-vuln <ID>` and a written justification recorded as a VEX entry
in this file. License threshold: every dependency must carry an OSI-approved
license compatible with Apache-2.0; an incompatible or unknown license blocks
release until resolved. All SCA findings are resolved or explicitly suppressed as
non-exploitable before any release.

No dependency vulnerabilities are outstanding at this time, so there are no active
VEX entries.

## Static analysis (SAST)

Source is scanned with `bandit` in CI on every push and pull request, and the
check gates merges. Remediation threshold: any finding at Medium severity or above
must be fixed before merge, or suppressed inline with `# nosec` and a written
reason when it is a verified false positive. Low-severity findings are addressed at
the maintainer's discretion.
