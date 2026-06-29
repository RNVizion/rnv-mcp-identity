# AIII Build Roadmap

*AIII is the Artificial Intelligence Identification Initiative; rnv-mcp-identity is its reference implementation.*

From a draft proposal to a working MCP identity layer, submitted where MCP already lives.

**End goal:** an open-source L1–L3 identity-and-authorization reference implementation for MCP servers that resolves what it can prove and refuses the rest, credible enough to propose to the Agentic AI Foundation (AAIF).

This is a living plan. Phases and tasks change as the work teaches us.

---

## P0: Stand up the front door

*Goal: the proposal is live and linkable, and the build has a home.*

**Done when:** the AIII page is live off the blog feed, and this repo exists with a README and license.

- [ ] Publish the AIII page at its own path (e.g. `/aiii`), outside `blog/**`, with its OG image
- [ ] Add the resume bottom-line link to the live AIII page
- [ ] Confirm the page is excluded from the RSS feed and the Ask the Corpus ingest
- [ ] Create the implementation repo (working name: `rnv-mcp-identity`)
- [ ] Write README v0: thesis, scope (L1–L3), explicit non-goals (L4–L5)
- [ ] Add LICENSE: Apache-2.0, to match MCP and AAIF norms
- [ ] Drop this roadmap into the repo as `ROADMAP.md`

## P1: Resolve before building

*Goal: know exactly what to build, and what to refuse, grounded in prior art.*

**Done when:** a written spec exists that maps to existing standards and defines the resolve / refuse semantics plus eval gates.

- [ ] Read the active IETF agent-identity drafts; one-line summary of each and the layer it covers
- [ ] Map MCP's current auth spec and the ~2,000-servers gap: what exists vs what's missing
- [ ] Decide reuse vs build: pin to OAuth 2.0 / WIMSE / HTTP Message Signatures (RFC 9421); no new crypto
- [ ] Write `SPEC.md`: the identity data model, the L1 / L2 / L3 operations, the refusal and unknown states
- [ ] Define three eval gates: correct-resolution, correct-refusal, false-refusal
- [ ] Write the threat model: identity spoofing, scope escalation, audit evasion
- [ ] Mark the L4 boundary explicitly in the spec

## P2: Identity that resolves

*Goal: running code that issues and verifies an agent identity for an MCP server.*

**Done when:** a demo server verifies a valid identity and refuses an invalid one, under CI.

- [ ] Scaffold a FastMCP-based middleware skeleton (Codespaces, mobile-friendly)
- [ ] Implement L1: attach a verifiable agent identity (who controls this agent)
- [ ] Implement L2: verify the identity claim (signature / credential check)
- [ ] Refusal path: unknown or invalid identity returns an explicit deny, never a guess
- [ ] pytest + hypothesis tests; wire GitHub Actions CI
- [ ] Pass the correct-resolution and correct-refusal gates

## P3: Authorization that refuses

*Goal: scope what an agent may do, enforce it per call, refuse out of scope.*

**Done when:** out-of-scope calls are denied, valid calls pass, and the false-refusal gate stays green.

- [ ] Define the capability / scope model (what the agent is cleared to do)
- [ ] Enforce authorization on every tool call
- [ ] Implement explicit allow / deny / unknown outcomes: resolve or refuse, never guess
- [ ] Add the false-refusal gate: valid identities and scopes must not be wrongly denied
- [ ] Document in code exactly where L4 (cross-system enforcement) would begin
- [ ] Tag a `v0.1` release

## P4: Make it provable

*Goal: anyone can see it resolve and refuse in minutes.*

**Done when:** a public quickstart or demo runs, and the docs read clean to an outside engineer.

- [ ] Build a runnable demo (Hugging Face Space or a one-command quickstart)
- [ ] Record a short walkthrough: resolve, then refuse
- [ ] Polish README, SPEC, and threat model for an external reader
- [ ] Add the "what this does NOT do" section (L4–L5), stated plainly
- [ ] Cross-link the AIII page and the repo both ways

## P5: Earn the submission

*Goal: turn the build into a credible AAIF project proposal.*

**Done when:** the proposal is submitted through the AAIF process.

- [ ] Check against AAIF criteria: OSI license, open governance, contribution guidelines, adoption signal
- [ ] Add `CONTRIBUTING.md` and a lightweight governance note
- [ ] Share for prior-art feedback (MCP community, relevant W3C / IETF group); log responses
- [ ] Write the AAIF project proposal: problem, scope, why neutral, why now
- [ ] Submit via the AAIF GitHub proposal process
- [ ] Capture the journey as a build post: the spoke graduates into an essay
