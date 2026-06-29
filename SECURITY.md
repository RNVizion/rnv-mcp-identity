# Security Policy

This project implements identity and authorization logic. Handle vulnerabilities
with care.

## Supported versions

The project is pre-1.0. Security fixes target `main` and the latest release. There
is no long-term-support branch yet.

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
