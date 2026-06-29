# Prior Art

*A survey of what already exists, so the spec builds on it and claims only the gap. Snapshot: June 2026. These are Internet-Drafts; they expire and revise on a roughly six-month cycle, so re-check before the AAIF proposal.*

This document grounds the scope and dependency choices in [SPEC.md](../SPEC.md). The short version: nearly everything below our gap already has a home at the IETF, in the WIMSE working group. We cite far more than we build.

## What MCP already provides

MCP has an authorization specification. A protected server acts as an OAuth 2.1 resource server, a client acts as the OAuth client, and a user delegates access through an authorization server (often an existing IdP). The mandatory pieces are PKCE, Protected Resource Metadata (RFC 9728) for discovery, and Resource Indicators (RFC 8707) to bind a token to its intended server. The 2026 revisions added role-based tool access and aligned more closely with OAuth and OpenID Connect.

So delegated authorization is solved and standardized. We compose on top of it; we do not rebuild it.

## What MCP leaves open

Two gaps, both named by the spec's own analysts:

1. **Caller identity.** OAuth authorizes a user's delegation, but PKCE protects the token exchange without authenticating the caller itself. Strong identity for a non-human client depends on infrastructure-asserted identity. That is L1 and L2: who is this agent, who controls it, and is the claim real.
2. **Scope semantics.** MCP does not define a scope convention, so implementers each invent their own. That is L3 with no shared shape.

The gap is real at scale: as of 2026, only about 8.5% of MCP servers implement the mandatory OAuth 2.1, while the public registry has grown past 9,400 servers.

## The IETF landscape (WIMSE)

The relevant working group is WIMSE (Workload Identity in Multi-System Environments). It produces the workload-identity primitives and is actively extending them to AI agents.

### WIMSE core primitives — reuse for L1 and L2

| Draft | What it gives us | Layer |
|---|---|---|
| `draft-ietf-wimse-arch` | The multi-system workload-identity architecture everything sits in | foundation |
| `draft-ietf-wimse-identifier` | How to name a workload or agent; SPIFFE-ID compatible | L1 |
| `draft-ietf-wimse-workload-creds` | The credential a workload presents | L1 / L2 |
| `draft-ietf-wimse-wpt` | Workload Proof Token: proves possession of the key behind a Workload Identity Token | L2 |
| `draft-ietf-wimse-http-signature` | Workload-to-workload auth via HTTP Message Signatures (RFC 9421) | L2 |
| `draft-ietf-wimse-workload-identity-practices` | How workloads get identities without managing long-lived secrets | L1 (practice) |

### Agent-specific drafts — align and reuse concepts

| Draft | What it gives us | Layer |
|---|---|---|
| `draft-ni-wimse-ai-agent-identity` | Applies WIMSE to agents; a Dual-Identity Credential binds agent identity to owner identity | L1 (who controls it) |
| `draft-messous-eat-ai` | An Entity Attestation Token profile for autonomous AI agents | L2 (attestation) |
| `draft-klrc-aiagent-auth` | Agent authn/authz best practices built on WIMSE and OAuth, deliberately not inventing new protocols | L1–L3 umbrella |
| `draft-rosenberg-cheq` | A human-in-the-loop confirmation protocol for agent decisions | L4-adjacent |

Agentic JWT adds agent claims to JWTs but can't attenuate authority without minting a new token that breaks the chain; SCIM-for-agents covers provisioning lifecycle, not runtime authorization. Both are adjacent, not core.

### OAuth delegation drafts — the L3 to L4 edge

| Draft | What it gives us | Layer |
|---|---|---|
| `draft-ietf-oauth-identity-chaining` | Identity and authorization chaining across domains | L4 edge |
| `draft-ietf-oauth-transaction-tokens` | Short-lived tokens across a call chain inside a trust domain | L3 / L4 |

## The confirmed gap

The frontier is the cross-domain, multi-hop layer, and the drafts say so plainly. AIMS composes WIMSE, SPIFFE, and OAuth, but its authorization section reads "TODO Security." A survey of the field (the AIP preprint) finds that no single draft yet provides holder-attenuable delegation, cross-protocol bindings, and provenance in one protocol.

That frontier is L4 and L5. It's exactly where our scope stops, and where the larger AIII (Artificial Intelligence Identification Initiative) argument lives.

## What this means for the build

- **Reuse:** WIMSE identifier and Workload Identity Token (L1), Workload Proof Token and the EAT attestation profile (L2), HTTP Message Signatures / RFC 9421 (verification), the Dual-Identity Credential pattern (owner binding), and MCP's OAuth 2.1 resource-server model (user delegation).
- **Build:** the concrete MCP middleware that composes these, maps identity to a declarable per-tool capability model, and wires explicit resolve / refuse / unknown into the call path. No surveyed draft targets MCP, and none wires the refusal semantics in.
- **Conform:** to `draft-klrc-aiagent-auth`, which shares our stance of using existing standards and naming gaps rather than inventing protocols.

## References

All drafts are at the IETF Datatracker under `https://datatracker.ietf.org/doc/<name>/`:

- WIMSE: `draft-ietf-wimse-arch`, `draft-ietf-wimse-identifier`, `draft-ietf-wimse-workload-creds`, `draft-ietf-wimse-wpt`, `draft-ietf-wimse-http-signature`, `draft-ietf-wimse-workload-identity-practices`
- Agents: `draft-ni-wimse-ai-agent-identity`, `draft-messous-eat-ai`, `draft-klrc-aiagent-auth`, `draft-rosenberg-cheq`
- OAuth delegation: `draft-ietf-oauth-identity-chaining`, `draft-ietf-oauth-transaction-tokens`
- MCP authorization: `https://modelcontextprotocol.io/specification` (Authorization section)
- AIP / AIMS / Agentic JWT / SCIM-for-agents: drawn from the AIP preprint survey of agent-identity proposals
