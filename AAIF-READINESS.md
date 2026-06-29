# rnv-mcp-identity: AAIF Readiness Dossier

*Working draft. Not yet submitted. This document maps the project to the Agentic
AI Foundation's published intake requirements and Project Lifecycle Policy
(effective March 18, 2026), records honestly what is true today, and names the
gaps that must close before a submission is warranted.*

The discipline that runs through the code runs through this document too: state
what resolves, refuse to claim what doesn't, and never guess. Where a requirement
is not yet met, it says so.

---

## Readiness verdict (read this first)

**Current status: pre-submission.** The project does not yet meet the Growth
Stage acceptance criteria, and submitting now would be premature.

Three criteria are unmet today:

1. **Production adoption at scale.** The Growth bar asks a project to document
   successful production use at wide scale. rnv-mcp-identity was published
   recently as a reference implementation and has no production adopters yet.
2. **Maintainer diversity and contribution flow.** The project is solo-built.
   There is one maintainer and no external merged contributions yet.
3. **A Technical Committee sponsor.** None identified. Growth Stage requires a TC
   sponsor to champion and mentor the project.

Everything else, license, public repo, automated validation and release, a
public contribution process, an issue tracker, a documented spec, named
dependencies, is either in place or is a governance file this dossier's checklist
schedules. **Target stage when ready: Growth.** The growth plan below addresses
the three gaps directly.

---

## What this project is

rnv-mcp-identity is an open-source reference implementation of an identity and
authorization layer for MCP servers. It answers one question on every tool call:
is this caller who it claims to be, and is this specific action within what it's
allowed to do? The answer is exactly one of three outcomes, **allow**, **deny**,
or **unknown**, and an unknown caller never acts. That is the project's thesis:
*resolve or refuse, never guess.*

It implements three trust layers that a single deployment can resolve on its own:

- **L1, identity provenance:** who is calling, and from which recognized authority.
- **L2, verification:** cryptographic proof the caller holds the key its identity
  commits to (holder-of-key, not bearer), within a valid window, for this server.
- **L3, authorization:** whether the verified caller's declared capabilities cover
  the specific action, under a declarative, deny-by-default policy.

It composes on existing standards rather than reinventing them: the MCP
authorization model, WIMSE-style workload identity, RFC 7800 key confirmation,
RFC 7638 thumbprints, and EAT-style attestation. The project's own contribution
is the composition, the per-tool capability model, and the resolve/refuse/unknown
semantics, expressed as MCP middleware.

This project is the reference-implementation arm of a broader initiative, AIII (the Artificial Intelligence Identification Initiative).
Layers L4 and L5, structural enforcement and cross-organization behavioral trust,
are deliberately **out of scope** for this codebase: they cannot be resolved by a
single operator. That boundary is precisely why a neutral foundation matters, and
it's the honest reason this work belongs in an AAIF conversation rather than a
single vendor's repo.

---

## Proposal fields (mapped to AAIF's intake requirements)

The Project Lifecycle Policy enumerates the information a submission must provide.
Each is answered here as it stands today.

| Required field | Current answer |
|---|---|
| **Project name** | rnv-mcp-identity (confirmed; the public repository name) |
| **Description: what it does** | An L1–L3 identity and authorization layer for MCP servers; resolve, refuse, or mark unknown on every tool call |
| **Description: why valuable** | A large share of deployed MCP servers accept tool calls without verifying caller identity. This is the missing, reusable safety pattern: holder-of-key agent identity plus deny-by-default per-tool authorization |
| **Origin and history** | Built under the RNVizion banner as a reference implementation composing IETF/WIMSE/OAuth building blocks; spec-first, then implementation, then a runnable demo |
| **Alignment with AAIF mission** | See "Alignment" below |
| **Relation to existing AAIF projects** | See "Relation to MCP" below |
| **Example use cases + evidence of adoption** | Use cases below are concrete; **adoption evidence is nascent and stated honestly as a gap** |
| **TC sponsor (if identified)** | None yet. Securing one is a growth-plan milestone |
| **OSI-approved permissive license** | Apache-2.0 |
| **Public repository** | github.com/RNVizion/rnv-mcp-identity |
| **Automated validation and delivery** | GitHub Actions: a test matrix (Linux + Windows, Python 3.10–3.12) plus a separate FastMCP demo job; the suite includes named eval gates for correct resolution, correct refusal, and no false refusal |
| **Release methodology** | SemVer with tagged releases; pre-1.0 while the wire format stabilizes (documented in the spec) |
| **Public contribution process for specs** | SPEC.md is versioned in-repo; changes proceed by pull request with rationale. Formalized in CONTRIBUTING.md (scheduled) |
| **Public issue tracker** | GitHub Issues |
| **External dependencies (and licenses)** | Core runtime: **zero dependencies.** Optional extras: PyJWT (MIT), cryptography (Apache-2.0 / BSD), FastMCP (Apache-2.0). Dev-only: pytest (MIT), Hypothesis (MPL-2.0). *Licenses to be re-verified at submission time.* |
| **Core maintainers** | Christian Smith (sole maintainer) |
| **Leadership and decision-making** | Currently single-maintainer; governance defines the path to shared, merit-based maintainership (scheduled in GOVERNANCE.md) |
| **Documented governance (GOVERNANCE.md)** | Scheduled (see checklist) |
| **Official communication channels** | GitHub Issues and Discussions to start; no chat channel yet |
| **Project website** | Live at rnvizion.dev/aiii |
| **Social accounts** | RNVizion presence on dev.to and LinkedIn (optional field) |
| **Existing financial sponsorship** | None |
| **Infrastructure needs** | None from the foundation at this stage; CI runs on GitHub-hosted runners |
| **Desired stage (optional)** | Growth, once the three unmet criteria are addressed |

---

## Alignment with the AAIF mission

AAIF is aimed at agent standards and orchestration, including shared safety
patterns and interoperability. Agent identity and per-action authorization is one
of those shared safety patterns: every framework that lets an agent call a tool
faces the same question, and today most answer it ad hoc or not at all.

rnv-mcp-identity offers that pattern as a small, model-agnostic, reusable layer
with one stated rule, an unverified caller does not act. It is interoperable by
construction: it composes on already-published standards and rides MCP's existing
transport, so adopting it does not fork the protocol.

## Relation to MCP (a founding AAIF project)

MCP, donated to AAIF by Anthropic, standardizes how agents reach tools and
includes an OAuth-based authorization model. It intentionally leaves the
identity-and-policy details to deployments. This project sits exactly in that gap:
it does not replace MCP's authorization model, it composes with it and adds the
agent-identity provenance, holder-of-key verification, and declarative per-tool
policy that a deployment needs to actually decide a call. The relationship is
additive and dependent, MCP is the substrate, this is a layer on top.

## Example use cases

- **Guarding an MCP server:** refuse tool calls from agents that can't prove a
  recognized identity, while allowing those that can and are in scope.
- **Least-privilege tool access:** grant `tool:read_*` to a reporting agent and
  nothing else, deny-by-default, with the refusal reason machine-readable.
- **Stolen-token resistance:** a leaked identity token alone can't act; the caller
  must also hold the key the token commits to.
- **Auditability:** every allowed call is bound to a verified identity for the
  record.

**Adoption evidence, stated honestly:** the use cases are demonstrated by a
runnable demo and a gate-checked test suite, not yet by third-party production
deployments. Closing that gap is the heart of the growth plan.

---

## Readiness against Growth Stage acceptance criteria

| Criterion | Status | Note |
|---|---|---|
| TC sponsor to champion and mentor | **Not met** | None identified; outreach is a milestone |
| Growth plan demonstrating diverse maintainership | Partial | Plan exists (below); maintainer diversity is the goal, not the current state |
| Documented successful production use at wide scale | **Not met** | No production adopters yet |
| Ongoing flow of commits and merged contributions | Partial | Active commits by one maintainer; no external merges yet |
| Community participation sufficient for the plan | **Not met** | Community not yet formed |
| Apache-2.0 / OSI-approved permissive license | On track | Apache-2.0 (LICENSE scheduled) |
| Automated validation and release | **Met** | CI matrix + demo job + eval gates |
| Public spec, issue tracker, contribution process | Partial | Spec and tracker exist; CONTRIBUTING.md scheduled |

The pattern is clear: the engineering substrate is in good shape; the
community-and-adoption substrate does not yet exist. That is the normal state of a
new project, and it's exactly what the growth plan is for.

---

## Growth plan

The plan targets the three unmet criteria in order of leverage.

1. **Earn a credible adoption story.** Stand up a public, live demo deployment and
   publish the build narrative so others can adopt the pattern. Pursue at least a
   handful of real integrations into MCP servers and report them honestly,
   counts, not adjectives.
2. **Open the project to contributors.** Ship GOVERNANCE.md, CONTRIBUTING.md, and
   OWNERS.md that define how someone earns the commit bit, then label
   good-first-issues and review external PRs promptly. Diverse maintainership is
   earned by making contribution easy and review fast.
3. **Find a Technical Committee sponsor.** Engage the AAIF community (Discord,
   office hours, MCP Dev Summit) and the MCP maintainers, since this layer sits
   directly on MCP, to find a sponsor willing to mentor toward Growth.
4. **Keep the cadence visible.** Maintain a regular commit and release rhythm and
   a public roadmap, so "ongoing flow of contributions" is demonstrable rather
   than asserted.

## Readiness checklist (drives the work; submit only when the musts are green)

Governance and licensing (done this pass):
- [x] LICENSE (Apache-2.0) at repo root
- [x] Apache license headers on source files
- [x] GOVERNANCE.md: decision-making and the path to shared maintainership
- [x] CONTRIBUTING.md: how to contribute code and propose spec changes
- [x] OWNERS.md: current (and future emeritus) committers
- [x] SECURITY.md: how to report vulnerabilities
- [x] README points at the spec and the runnable in-repo demo (a live public deployment remains an adoption item below)

Adoption and community (must, takes time):
- [ ] A live, public demo deployment
- [ ] Documented real-world integrations, reported by count
- [ ] First external merged contribution
- [ ] At least one committer from a second organization (Impact-stage signal)

Process polish (should):
- [ ] Tagged SemVer release
- [ ] Published roadmap
- [ ] OpenSSF Best Practices badge
- [ ] Re-verify all dependency licenses

When the governance musts are green and the adoption musts show real, honest
progress, and a TC sponsor is in hand, the proposal moves from this dossier into
the AAIF issue form. Not before. If a future submission is judged "Too Early,"
the project addresses the stated gaps and reapplies after the three-month window,
exactly as the policy provides.

---

*Honesty note: this dossier claims no adoption it doesn't have and no governance
it hasn't written. Its value is in being accurate about where the project stands
and specific about what closing the distance requires.*
