# Demo: an MCP server that resolves or refuses

This wires `IdentityMiddleware` onto a real FastMCP server with two tools and
shows the layer allowing one call and refusing three, each for its own reason.

## What it proves

The server grants the demo agent `tool:read_*` and nothing else. So:

| call | identity | result |
|---|---|---|
| `read_report` | valid token + proof, in scope | **allow** |
| `delete_report` | valid token + proof, out of scope | refuse: `capability_denied` |
| `read_report` | no identity headers | refuse: `identity_absent` |
| `read_report` | valid token, tampered proof | refuse: `proof_invalid` |

Nothing reaches a tool body without a verified, authorized identity.

## Run it in-process (no network)

```
pip install -e ".[dev,verify,fastmcp]"
python -m pytest -q tests/test_demo_inprocess.py
```

The in-process test injects the headers directly (the in-memory transport has no
HTTP layer) and drives the server through the FastMCP client.

## Run it over HTTP (the real wire path)

```
python examples/demo_server.py        # terminal 1
python examples/demo_client_http.py   # terminal 2
```

## The wire format (v0)

`identity_kit.headers_for` is the spec: the identity token rides in the
`mcp-agent-identity` header and the proof in `mcp-agent-proof`. The proof is a
WPT-style JWS whose protected header carries the holder's public JWK and whose
`ath` claim is `base64url(sha256(identity_token))`, binding the proof to that
exact token. A stolen token alone cannot act: the caller must also hold the key
the token's `cnf` commits to.
