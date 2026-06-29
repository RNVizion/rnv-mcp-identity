# Governance

rnv-mcp-identity is an open-source project released under Apache-2.0. This
document describes how decisions are made and how responsibility is shared. It
describes the project as it actually is today, and the path by which that changes.

## Current state: single maintainer

The project currently has one maintainer, listed in OWNERS.md. Being honest about
this matters: there is no committee yet, and pretending otherwise would help no
one. The maintainer sets technical direction, reviews and merges contributions,
and is accountable for releases and security response.

This is a starting point, not the intended end state. The explicit goal is to grow
into shared, merit-based maintainership across more than one person and, in time,
more than one organization.

## Roles

- **Contributor:** anyone who opens an issue or a pull request. No prior standing
  required.
- **Committer:** a contributor trusted with the commit bit, listed in OWNERS.md.
  Committers review and merge contributions.
- **Maintainer:** a committer who also sets direction and has final say on
  unresolved disputes. Today there is one.

## How decisions are made

Most decisions are made in the open on pull requests and issues, by lazy
consensus: a change merges when CI passes and no committer objects within a
reasonable review window. Substantive disagreements are resolved by discussion; if
consensus can't be reached, the maintainer decides and records why.

Changes to the wire format or the spec's normative behavior require explicit
maintainer approval and a versioned update to SPEC.md in the same change. See
CONTRIBUTING.md for the spec-change process.

## Becoming a committer

Committers are recognized for sustained, high-quality contribution, code, review,
docs, or triage, not for a single large pull request. The path:

1. Contribute consistently and well over time.
2. Get nominated by an existing committer or the maintainer.
3. Be approved by the existing committers and the maintainer.

New committers are added to OWNERS.md. As the number of committers grows beyond one
maintainer, decision-making moves from "the maintainer decides" to "committers
decide by consensus," and this document will be updated to match.

## Changing this document

Governance changes by pull request to this file, approved by the maintainer (and,
once there is more than one, by committer consensus). The intended direction is
toward multi-person and multi-organization maintainership.

## License and intellectual property

The project is licensed under Apache-2.0. Contributions are accepted under the same
license via Developer Certificate of Origin sign-off (see CONTRIBUTING.md).

Forward note, stated honestly: this project aspires to become a foundation-hosted
project (see AAIF-READINESS.md). If it is ever accepted into a foundation such as
the AAIF, that foundation's technical charter and IP policy would govern, and this
document would be superseded by the chartered governance at that time. Until then,
this is the governance in force.

## Code of conduct

The project follows the Contributor Covenant. Be respectful; assume good faith;
keep it about the work.
