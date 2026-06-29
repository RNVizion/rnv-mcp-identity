"""Demo identity kit: deterministic keys and token/proof minting shared by the
server, the HTTP client, and the in-process test. DEMO ONLY; the private keys
are derived from fixed, public seeds and are not secret.

This module is also the de facto v0 wire spec: `headers_for` shows exactly which
headers carry the identity token and its proof, and `mint_proof` shows the `ath`
binding.
"""
from __future__ import annotations

import base64
import hashlib
import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rnv_mcp_identity import jwk_thumbprint
from rnv_mcp_identity.adapters.fastmcp_middleware import IDENTITY_HEADER, PROOF_HEADER

ISS = "https://issuer.demo.rnvizion.dev"
AUD = "https://mcp.demo.rnvizion.dev"
SUB = "wimse://demo/agent/report-bot"
CTRL = "https://demo/principal/acme-ops"

# Fixed, public seeds -> deterministic keys shared across processes. DEMO ONLY.
ISSUER_PRIV = Ed25519PrivateKey.from_private_bytes(bytes(range(0, 32)))
HOLDER_PRIV = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
ISSUER_PUBLIC = ISSUER_PRIV.public_key()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def holder_jwk() -> dict:
    raw = HOLDER_PRIV.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "alg": "EdDSA"}


def mint_identity(*, jti: str = "demo-1", exp_delta: int = 300) -> str:
    now = int(time.time())
    payload = {
        "iss": ISS, "sub": SUB, "controller": CTRL, "aud": AUD,
        "iat": now, "exp": now + exp_delta, "jti": jti,
        "cnf": {"jkt": jwk_thumbprint(holder_jwk())},
    }
    return jwt.encode(payload, ISSUER_PRIV, algorithm="EdDSA", headers={"kid": "demo-iss"})


def mint_proof(identity_token: str) -> str:
    now = int(time.time())
    ath = _b64url(hashlib.sha256(identity_token.encode()).digest())
    payload = {"ath": ath, "iat": now, "exp": now + 120, "jti": "proof-demo"}
    return jwt.encode(payload, HOLDER_PRIV, algorithm="EdDSA",
                      headers={"jwk": holder_jwk(), "typ": "wpt+jwt"})


def headers_for(identity_token: str, proof: str) -> dict:
    """The v0 wire format: token and proof ride in two request headers."""
    return {IDENTITY_HEADER: identity_token, PROOF_HEADER: proof}
