# Specification: rnv-mcp-identity

*Working draft. This revision pins the scope, the dependency map, and the refusal semantics; the data model, wire format, and per-operation detail are stubbed for the next pass. Grounded in [docs/PRIOR-ART.md](docs/PRIOR-ART.md).*

## The rule

Resolve or refuse, never guess. Every decision this layer makes resolves to one of three outcomes: allow, deny, or unknown. There is no implicit allow. Absence of a credential is unknown, not permitted. A false yes is the single failure mode this layer exists to never produce.

## 1. Scope

This layer covers the parts of agent identity that a single MCP deployment can actually resolve:

- **L1, identity provenance:** who issued this agent, and who controls it.
- **L2, verification:** is the identity claim cryptographically real.
- **L3, authorization:** what the agent is scoped to do, enforced on every tool call.

It explicitly does **not** cover:

- **L4, structural enforcement:** holding an agent to its scope across systems.
- **L5, cross-organizational behavioral trust:** trusting an agent beyond the deployment that made it.

L4 and L5 are out of scope on purpose. No single deployment can operate cross-organizational trust, so this layer marks the boundary and stops (see section 7). Closing it is the AIII argument, not this code.

## 2. Position in the MCP stack

This is not a replacement for MCP's authorization spec; it sits alongside it. MCP's OAuth 2.1 resource-server model answers "did a user delegate this access." This layer answers the question OAuth leaves open: "who is the non-human caller, and what is it cleared to do." The two compose: a request can carry both a user-delegated OAuth token and a verified agent identity, and both must hold for an allow.

## 3. Dependency map

The build rule is visible at a glance: most concerns are reused, and the small set we build is the MCP-specific composition, the capability model, and the refusal path.

| Concern | Layer | Approach | Source |
|---|---|---|---|
| Agent identifier | L1 | Reuse | WIMSE Workload Identifier (SPIFFE-compatible) |
| Who controls the agent | L1 | Reuse pattern | Dual-Identity Credential (`draft-ni-wimse-ai-agent-identity`) |
| Identity token / credential | L1 / L2 | Reuse | WIMSE Workload Identity Token + Workload Credentials |
| Proof of possession | L2 | Reuse | WIMSE Workload Proof Token |
| Agent attestation | L2 | Reuse | EAT profile for autonomous agents (`draft-messous-eat-ai`) |
| Wire verification | L2 | Reuse | HTTP Message Signatures (RFC 9421) |
| User delegation | adjacent | Reuse | MCP OAuth 2.1 RS model (PRM 9728, Resource Indicators 8707, PKCE) |
| Capability / scope model | L3 | **Build** | Declarable per-tool capabilities with a defined naming convention |
| Refusal semantics | L1–L3 | **Build** | Explicit allow / deny / unknown on every call |
| MCP composition | L1–L3 | **Build** | Middleware wiring the above onto an MCP server |
| Multi-hop / cross-domain delegation | L4 | Out of scope | See `draft-ietf-oauth-identity-chaining`, transaction-tokens |

No new cryptography. Where a draft already specifies a primitive, this layer adopts it rather than competing, conforming to the stance of `draft-klrc-aiagent-auth`.

## 4. Resolve / refuse / unknown

Every tool call passes through one decision with exactly three possible outcomes:

- **allow:** the identity resolved (L1), verified (L2), and the requested action is within the agent's authorized capabilities (L3). The call proceeds, bound to the verified identity for audit.
- **deny:** the identity resolved and verified, but the action is outside its capabilities; or an identity was presented and verification failed. The call is refused, with a machine-readable reason.
- **unknown:** the identity could not be resolved or verified at all (absent, malformed, unverifiable). The call is refused. The layer does not assume a default identity and does not infer a permission.

The invariant: `unknown` is never silently upgraded to `allow`. An unverified caller does not act. This is the rule from section 0 made operational.

## 5. Eval gates

Correctness is measured in CI, not asserted. Three gates, mirroring the retrieval project's harness:

- **correct-resolution:** a valid, verifiable identity making an in-scope call is allowed.
- **correct-refusal:** an invalid or unverifiable identity, or an authenticated-but-unauthorized call, is denied or marked unknown; never allowed.
- **false-refusal:** a valid identity making an authorized call is never wrongly denied or marked unknown.

The third gate is load-bearing. Without it, a layer that refuses everything would pass `correct-refusal` trivially; `false-refusal` is what keeps the system honest as the rules grow.

## 6. Threat model (stub, to expand with the data model)

- **Identity spoofing:** a caller claims an identity it doesn't hold. Mitigated by proof-of-possession (WPT), attestation (EAT), and signature verification (RFC 9421).
- **Scope escalation:** an authenticated agent attempts actions beyond its capabilities. Mitigated by a per-call capability check that denies by default.
- **Audit evasion:** actions taken without an attributable identity. Mitigated by the section 4 invariant: no `unknown` caller is allowed to act, so every allowed call binds to a verified identity.

## 7. The L4 boundary

The boundary is the first multi-hop: when an agent must act on a second system on behalf of the first, or delegate attenuated authority across a trust domain. That needs holder-attenuable delegation and cross-protocol binding, which the field has no unified answer for yet (AIMS's authorization section reads "TODO Security"; the AIP survey finds no single draft that unifies it). This layer stops at the single-deployment edge and marks that edge explicitly in code, so the gap is visible rather than papered over.

## 8. To fill (next pass)

- The identity data model: concrete claim set for the agent identity and the owner binding.
- The L1 / L2 / L3 operations: the exact sequence for resolve, verify, and authorize.
- The capability naming convention for L3 scopes.
- The wire format for carrying identity and proof alongside an MCP request.
- The machine-readable `deny` and `unknown` reason vocabulary.
