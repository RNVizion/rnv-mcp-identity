# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/). Pre-1.0 the wire format and API may
change between minor versions; those changes are called out here.

## [0.1.0] - 2026-06-29

First tagged release: a working L1–L3 identity and authorization layer for MCP
servers, built on one rule, resolve or refuse, never guess.

### Added
- Decision engine (`decide`) implementing the ordered sequence in SPEC section 6:
  intake, resolve (L1), verify (L2), authorize (L3), bind. Exactly three outcomes
  (allow, deny, unknown); no implicit allow, and unknown is never upgraded.
- `JwtVerifier`: issuer-signature verification against a JWKS, validity-window
  checks, audience binding, holder-of-key proof-of-possession (RFC 7800 `cnf` plus
  RFC 7638 thumbprint), and replay detection.
- Declarative authorization (`DocumentPolicy`) with a bounded capability matcher
  (exact, or a single trailing-`*` prefix), deny-by-default, and an honest
  `no_policy` versus `capability_denied` distinction.
- A FastMCP middleware adapter that guards real tool calls and refuses with a
  machine-readable reason.
- A runnable demo: a guarded FastMCP server, an in-process test, and an HTTP
  client that mints a valid identity-plus-proof. The v0 wire format is pinned in
  SPEC section 10.
- 46 tests, including Hypothesis property tests and three named eval gates
  (correct-resolution, correct-refusal, no-false-refusal). CI runs a matrix on
  Linux and Windows across Python 3.10 to 3.12, plus a FastMCP demo job.
- Project documentation (SPEC, ROADMAP, PRIOR-ART, an AAIF readiness dossier) and
  a governance set (GOVERNANCE, CONTRIBUTING, OWNERS, SECURITY) under Apache-2.0.

### Known limits
- Pre-1.0: the wire format is v0. RFC 9421 request-signature binding (binding the
  proof to the HTTP method, path, and body, not only the identity token) is
  planned.
- L4 (structural enforcement) and L5 (cross-organizational trust) are out of scope
  by design; this release marks where L4 begins.

[0.1.0]: https://github.com/RNVizion/rnv-mcp-identity/releases/tag/v0.1.0
