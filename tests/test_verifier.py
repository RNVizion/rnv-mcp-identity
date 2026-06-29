# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""Real-key L2 tests (SPEC section 6, step 2). Needs the `verify` extra."""
from __future__ import annotations

import base64
import hashlib
import time

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rnv_mcp_identity.verifier import (
    JwtVerifier,
    StaticJwks,
    InMemoryReplayCache,
    jwk_thumbprint,
)
from rnv_mcp_identity.outcomes import Outcome, Reason
from rnv_mcp_identity.engine import decide
from rnv_mcp_identity.identity import IdentityRequest
from rnv_mcp_identity.policy import IssuerRegistry, StaticPolicy

ISS = "https://control-plane.example"
AUD = "https://mcp.example/finance"
SUB = "wimse://example/agent/report-bot"
CTRL = "https://example/principal/acme-ops"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ed() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def pub_jwk(priv: Ed25519PrivateKey) -> dict:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "alg": "EdDSA"}


def mint_id(issuer_priv, holder_jwk, *, aud=AUD, exp_delta=300, nbf=None, jti="id-1"):
    now = int(time.time())
    payload = {
        "iss": ISS, "sub": SUB, "controller": CTRL, "aud": aud,
        "iat": now, "exp": now + exp_delta, "jti": jti,
        "cnf": {"jkt": jwk_thumbprint(holder_jwk)},
    }
    if nbf is not None:
        payload["nbf"] = nbf
    return jwt.encode(payload, issuer_priv, algorithm="EdDSA", headers={"kid": "iss-1"})


def mint_proof(holder_priv, holder_jwk, token, *, ath=None):
    now = int(time.time())
    a = ath if ath is not None else _b64url(hashlib.sha256(token.encode()).digest())
    payload = {"ath": a, "iat": now, "exp": now + 120, "jti": "proof-1"}
    return jwt.encode(payload, holder_priv, algorithm="EdDSA",
                      headers={"jwk": holder_jwk, "typ": "wpt+jwt"})


def verifier(issuer_priv, **kw) -> JwtVerifier:
    return JwtVerifier(jwks=StaticJwks({ISS: issuer_priv.public_key()}), **kw)


def unverified(token) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


# --- the good path ---

def test_valid_token_and_proof_succeeds():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.ok


# --- step 1: signature ---

def test_tampered_signature_is_signature_invalid():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    bad = tok[:-3] + ("aaa" if not tok.endswith("aaa") else "bbb")
    r = verifier(ik).verify(token=bad, proof=pf, claims=unverified(tok), audience=AUD)
    assert (r.ok, r.reason) == (False, Reason.SIGNATURE_INVALID)


def test_wrong_issuer_key_is_signature_invalid():
    ik, other, hk = ed(), ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    r = verifier(other).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.SIGNATURE_INVALID


# --- step 2: temporal ---

def test_expired_token():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj, exp_delta=-10); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.TOKEN_EXPIRED


def test_not_yet_valid_token():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj, nbf=int(time.time()) + 3600); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.TOKEN_NOT_YET_VALID


# --- step 3: audience ---

def test_wrong_audience():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj, aud="https://mcp.example/other"); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.AUDIENCE_MISMATCH


# --- step 4: proof of possession ---

def test_missing_proof_is_proof_invalid():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)
    r = verifier(ik).verify(token=tok, proof=None, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.PROOF_INVALID


def test_proof_with_unbound_key_is_proof_invalid():
    ik, hk, wrong = ed(), ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)                      # cnf binds to hk
    pf = mint_proof(wrong, pub_jwk(wrong), tok)  # but proof signed by a different key
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.PROOF_INVALID


def test_proof_bound_to_other_token_is_proof_invalid():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)
    other = mint_id(ik, hj, jti="id-2")
    pf = mint_proof(hk, hj, other)            # ath binds to a different token
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.PROOF_INVALID


def test_proof_not_required_allows_without_proof():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)
    r = verifier(ik, require_proof=False).verify(
        token=tok, proof=None, claims=unverified(tok), audience=AUD)
    assert r.ok


# --- step 5: replay ---

def test_replay_detected_on_second_use():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    v = verifier(ik, replay_cache=InMemoryReplayCache())
    first = v.verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    second = v.verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert first.ok
    assert second.reason is Reason.REPLAY_DETECTED


# --- end to end through the engine ---

def test_engine_allows_valid_with_real_verifier():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    req = IdentityRequest("read_report", {}, AUD, identity_token=tok, proof=pf)
    d = decide(
        req,
        issuers=IssuerRegistry([ISS]),
        verifier=verifier(ik),
        policy=StaticPolicy({(SUB, CTRL, AUD): {"tool:read_report"}}),
    )
    assert d.outcome is Outcome.ALLOW
    assert d.identity.sub == SUB


def test_engine_denies_bad_proof_with_real_verifier():
    ik, hk, wrong = ed(), ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(wrong, pub_jwk(wrong), tok)
    req = IdentityRequest("read_report", {}, AUD, identity_token=tok, proof=pf)
    d = decide(
        req,
        issuers=IssuerRegistry([ISS]),
        verifier=verifier(ik),
        policy=StaticPolicy({(SUB, CTRL, AUD): {"tool:read_report"}}),
    )
    assert d.outcome is Outcome.DENY
    assert d.reason is Reason.PROOF_INVALID
