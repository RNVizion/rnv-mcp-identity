# rnv-mcp-identity

An identity and authorization layer for MCP servers. On every tool call it asks one
question, is this caller who it claims to be, and is this action within what it's
allowed to do?, and answers with exactly one of three outcomes:

- **allow:** identity resolved, verified, and the action is in scope.
- **deny:** verified, but out of scope; or an identity was presented and failed
  verification.
- **unknown:** identity could not be established at all. The call is refused.

An unknown caller never acts. That rule is the whole project: *resolve or refuse,
never guess.*

> Status: reference implementation, pre-1.0, Apache-2.0. This is the
> reference-implementation arm of AIII, the [Artificial Intelligence Identification Initiative](https://rnvizion.dev/aiii/). It composes on existing
> standards (the MCP authorization model, WIMSE workload identity, RFC 7800 key
> confirmation, RFC 7638 thumbprints, EAT attestation) rather than replacing them.

## What's here

- **`src/rnv_mcp_identity/`** — the library: a framework-agnostic decision engine
  (L1 identity, L2 verification, L3 authorization) plus a FastMCP middleware
  adapter. The core has no runtime dependencies.
- **`examples/`** — a runnable FastMCP server guarded by the layer, an in-process
  test, and an HTTP client. Start here to watch it allow one call and refuse three.
- **`SPEC.md`** — the normative spec: the decision sequence, the capability and
  policy model, the threat model, and the v0 wire format.
- **`AAIF-READINESS.md`** — an honest dossier on whether this belongs in a
  foundation, and what's missing before it would.

## Quickstart

```
pip install -e ".[dev,verify,fastmcp]"
python -m pytest -q                                # the full suite
python -m pytest -q tests/test_demo_inprocess.py   # just the guarded-server demo
```

Run the demo over real HTTP:

```
python examples/demo_server.py        # terminal 1
python examples/demo_client_http.py   # terminal 2
```

## The wire format (v0)

The identity token rides in the `mcp-agent-identity` header and a holder-of-key
proof in `mcp-agent-proof`. The proof binds to the exact token, so a stolen token
alone can't act. The reference client in `examples/` is the normative example; see
SPEC.md section 10.

## Docs

- `SPEC.md` — the specification
- `ROADMAP.md` — where this is going
- `PRIOR-ART.md` — what it builds on, and the gap it fills
- `GOVERNANCE.md` — how decisions are made
- `CONTRIBUTING.md` — how to help
- `SECURITY.md` — how to report vulnerabilities
- `AAIF-READINESS.md` — foundation-readiness assessment

## License

Apache-2.0. See `LICENSE`.

## A note on affiliation

This project *aspires* to become a foundation-hosted project and is not affiliated
with, endorsed by, or accepted into the AAIF or the Linux Foundation. See
AAIF-READINESS.md for an honest account of where it stands.
