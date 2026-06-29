# Specification: rnv-mcp-identity

*Working draft. This revision pins the scope, the dependency map, the refusal semantics, the identity data model, and the decision sequence; the capability naming, policy format, and wire format are stubbed for the next pass. Grounded in [docs/PRIOR-ART.md](docs/PRIOR-ART.md).*

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

L4 and L5 are out of scope on purpose. No single deployment can operate cross-organizational trust, so this layer marks the boundary and stops (see section 9). Closing it is the AIII argument, not this code.

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

## 4. Identity data model

The identity is a signed token the agent presents with a request. It reuses registered JWT and EAT claims for the envelope, and adds the minimum agent-specific claims the gap requires. It asserts *who*, not *what the agent may do*: authorization (L3) is resolved separately, so capabilities can change without re-minting identity. This avoids the immutability trap that limits agent-claims-in-JWT approaches, where a delegatee can't attenuate authority without breaking the cryptographic chain.

### 4.1 The agent identity token

Envelope, reusing registered claims:

| Claim | Meaning | Source |
|---|---|---|
| `iss` | the identity authority that minted this identity (the control plane) | JWT |
| `sub` | the agent's stable identifier, as a WIMSE workload identifier (SPIFFE-compatible URI) | WIMSE identifier |
| `aud` | the MCP server(s) this identity is for; aligns with Resource Indicators | RFC 8707 |
| `iat` / `nbf` / `exp` | issued-at, not-before, expiry; identities are short-lived | JWT |
| `jti` | unique token id, for replay defense and audit | JWT |
| `cnf` | the proof-of-possession key the agent must prove it holds; binds L1 to L2 | RFC 7800 |

Agent-specific, the minimal addition:

| Claim | Meaning |
|---|---|
| `controller` | the verifiable identifier of the principal that operates this agent (the owner binding; see 4.2) |
| `agent_kind` | optional, coarse descriptor of the agent runtime; informational, never a trust input |

Capabilities are deliberately absent from the token. What the agent may do is resolved at decision time from policy keyed on `(sub, controller, aud)`. Identity says who; authorization says what, and the two move on different clocks.

### 4.2 The owner binding (Dual-Identity Credential)

L1 has two halves: who the agent is, and who controls it. The `controller` claim carries the second. Its trust comes from the issuer: by signing a token that names both `sub` and `controller`, the issuer (which has authority over both) vouches that this agent is operated by this principal. This is the Dual-Identity Credential pattern, reduced to its minimal viable form.

- **v0, issuer-asserted:** the issuer states the `controller` in the signed identity token. Trust derives from the issuer's authority; enough to attribute every action to a controlling principal.
- **Later, chained or co-signed:** the agent credential chains to, or is co-signed by, the controller's own credential, so the binding holds even where the issuer isn't trusted for that relationship. A strengthening, not required for v0.

The invariant that makes this useful: an allowed call is always attributable to a `(sub, controller)` pair. There is no anonymous agent action, which ties directly to the audit-evasion mitigation in section 8.

### 4.3 Verification inputs (how L2 consumes this)

The data model is shaped so L2 can verify without inventing anything:

- **Issuer signature:** verify the token signature against the issuer's published keys (JWKS). Establishes the token is authentic and unaltered.
- **Proof of possession:** the agent proves it holds the `cnf` key, via a WIMSE Workload Proof Token or an HTTP Message Signature (RFC 9421) over the request. Turns a stealable bearer token into a held credential.
- **Attestation, optional:** an EAT profile for the agent runtime, where a deployment wants assurance the agent is a genuine, un-tampered runtime and not merely a holder of keys.

### 4.4 Worked example (illustrative, non-normative)

```
// Agent identity token, decoded claims
{
  "iss":  "https://control-plane.example",
  "sub":  "wimse://example/agent/report-bot",
  "aud":  "https://mcp.example/finance",
  "controller": "https://example/principal/acme-ops",
  "agent_kind": "scheduled-report-runner",
  "cnf":  { "jkt": "NzbLsXh8u..." },   // thumbprint of the proof key
  "iat":  1751130000,
  "nbf":  1751130000,
  "exp":  1751130900,                  // 15-minute lifetime
  "jti":  "9f2c...e1"
}
```

The agent presents this token plus a proof: a signature over the request using the key whose thumbprint is in `cnf`. The layer verifies the issuer signature, checks `aud` matches this server, checks the proof against `cnf`, then resolves capabilities for `(sub, controller, aud)` from policy. Any failure resolves to `deny` or `unknown` per section 5; nothing defaults to allow.

## 5. Resolve / refuse / unknown

Every tool call passes through one decision with exactly three possible outcomes:

- **allow:** the identity resolved (L1), verified (L2), and the requested action is within the agent's authorized capabilities (L3). The call proceeds, bound to the verified identity for audit.
- **deny:** the identity resolved and verified, but the action is outside its capabilities; or an identity was presented and verification failed. The call is refused, with a machine-readable reason.
- **unknown:** the identity could not be resolved or verified at all (absent, malformed, unverifiable). The call is refused. The layer does not assume a default identity and does not infer a permission.

The invariant: `unknown` is never silently upgraded to `allow`. An unverified caller does not act. This is the opening rule made operational.

## 6. The decision sequence

One ordered pipeline runs on every tool call. The order is deliberate: resolve before verify before authorize, cheapest and most fundamental refusals first, and the authorize step is never reached without a verified identity. `unknown` can only be produced at the resolve stage, where nothing could be established; once a claim has been made and fails, the outcome is `deny`.

**Step 0, intake.** Extract the agent identity token and the request proof from the call (carriage is defined in section 10). If either is absent or unparseable, resolve to `unknown` (`identity_absent`, `identity_malformed`) and stop.

**Step 1, resolve (L1).** Decode the token without trusting it. If its issuer (`iss`) is not a recognized identity authority for this deployment, resolve to `unknown` (`issuer_unknown`) and stop. Otherwise read `sub` and `controller`; these stay claims until step 2 verifies them.

**Step 2, verify (L2).** In order, any failure resolving to `deny` and stopping:

- issuer signature invalid against the issuer's JWKS: `signature_invalid`
- outside the token's validity window (`nbf`..`exp`): `token_expired` / `token_not_yet_valid`
- `aud` does not match this server's canonical URI: `audience_mismatch`
- the request proof does not verify against the `cnf` key: `proof_invalid`
- `jti` already seen within its window, where replay defense is enabled: `replay_detected`

After step 2 the identity is verified: `sub` and `controller` are now trusted.

**Step 3, authorize (L3).** Map the tool call to the capability it requires. Resolve the agent's granted capabilities from policy, keyed on `(sub, controller, aud)`. If no policy resolves for the pair, deny by default (`no_policy`). If the required capability is not in the granted set, `deny` (`capability_denied`). Otherwise, `allow`.

**Step 4, bind.** On `allow`, bind `(sub, controller, jti)` to the execution context and the audit record before the tool runs, so every effect is attributable to a controlling principal.

### Outcome reference

| Reason | Outcome | Stage |
|---|---|---|
| `identity_absent`, `identity_malformed` | unknown | intake |
| `issuer_unknown` | unknown | resolve |
| `signature_invalid` | deny | verify |
| `token_expired`, `token_not_yet_valid` | deny | verify |
| `audience_mismatch` | deny | verify |
| `proof_invalid` | deny | verify |
| `replay_detected` | deny | verify |
| `no_policy`, `capability_denied` | deny | authorize |
| (all checks pass) | allow | authorize |

The split is the spec's spine: `unknown` means the layer couldn't establish who is calling; `deny` means it could, and a check failed. Neither ever becomes `allow` by default.

### Capability and policy model (L3)

The required capability for a tool call follows one convention in v0: `tool:<tool_name>`. The argument map is available to the resolver but is not part of the v0 capability; argument-scoped capabilities are a later extension.

A grant is either an exact capability or a single trailing-`*` prefix: `tool:read_report` (exact), `tool:read_*` (prefix), `tool:*` (the whole `tool` namespace), `*` (everything; discouraged, never implicit). Matching is exact-or-prefix only, with no other glob features, so a grant's reach is obvious on inspection.

Policy is a declarative document of rules. Each rule carries an optional `sub`, `controller`, and `audience` selector and a set of capability grants. A rule selects a request when every present selector equals the request's value; an absent selector matches any. A rule with all three is agent-specific; a rule with only `controller` and `audience` grants every agent under that controller. The capabilities granted to a principal are the union over all selecting rules. If no rule selects the principal, the outcome is `no_policy` (deny by default); if rules select but none covers the required capability, the outcome is `capability_denied`. Authority is only ever added by an explicit rule.

## 7. Eval gates

Correctness is measured in CI, not asserted. Three gates, mirroring the retrieval project's harness:

- **correct-resolution:** a valid, verifiable identity making an in-scope call is allowed.
- **correct-refusal:** an invalid or unverifiable identity, or an authenticated-but-unauthorized call, is denied or marked unknown; never allowed.
- **false-refusal:** a valid identity making an authorized call is never wrongly denied or marked unknown.

The third gate is load-bearing. Without it, a layer that refuses everything would pass `correct-refusal` trivially; `false-refusal` is what keeps the system honest as the rules grow.

## 8. Threat model

- **Identity spoofing:** a caller claims an identity it doesn't hold. Mitigated by proof-of-possession (WPT), attestation (EAT), and signature verification (RFC 9421) in step 2.
- **Token theft / replay:** a stolen token is reused. Mitigated by proof-of-possession (a bearer token alone is insufficient), short `exp` lifetimes, `aud` binding, and optional `jti` replay tracking.
- **Scope escalation:** an authenticated agent attempts actions beyond its capabilities. Mitigated by the step 3 capability check that denies by default.
- **Audit evasion:** actions taken without an attributable identity. Mitigated by the section 4.2 invariant: no `unknown` caller is allowed to act, so every allowed call binds to a `(sub, controller)` pair.

## 9. The L4 boundary

The boundary is the first multi-hop: when an agent must act on a second system on behalf of the first, or delegate attenuated authority across a trust domain. That needs holder-attenuable delegation and cross-protocol binding, which the field has no unified answer for yet (AIMS's authorization section reads "TODO Security"; the AIP survey finds no single draft that unifies it). This layer stops at the single-deployment edge and marks that edge explicitly in code, so the gap is visible rather than papered over.

## 10. To fill (next pass)

- The wire format: the exact header carriage for the identity token and its proof, and how the proof binds to the request (the RFC 9421 signature base). The capability and policy model is pinned in section 6.
