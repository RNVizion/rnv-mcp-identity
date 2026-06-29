# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""Decision-engine tests. Seed the three eval gates (SPEC section 7)."""
from __future__ import annotations

import base64
import json

from rnv_mcp_identity.engine import decide
from rnv_mcp_identity.identity import IdentityRequest
from rnv_mcp_identity.outcomes import Outcome, Reason
from rnv_mcp_identity.policy import IssuerRegistry, StaticPolicy
from rnv_mcp_identity.verifier import VerifyResult

AUD = "https://mcp.example/finance"
ISS = "https://control-plane.example"
SUB = "wimse://example/agent/report-bot"
CTRL = "https://example/principal/acme-ops"


def make_token(**overrides) -> str:
    claims = {"iss": ISS, "sub": SUB, "controller": CTRL, "aud": AUD, "jti": "abc"}
    claims.update(overrides)

    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'none'})}.{seg(claims)}.{seg({})}"


class FakeVerifier:
    """Stands in for JwtVerifier so the engine is testable before P2-2."""

    def __init__(self, result: VerifyResult) -> None:
        self._result = result

    def verify(self, *, token, proof, claims, audience) -> VerifyResult:
        return self._result


def deps(verifier, policy=None, issuers=None):
    return dict(
        issuers=issuers or IssuerRegistry([ISS]),
        verifier=verifier,
        policy=policy or StaticPolicy({(SUB, CTRL, AUD): {"tool:read_report"}}),
    )


def call(tool="read_report", token="__default__", proof="proof"):
    tok = make_token() if token == "__default__" else token
    return IdentityRequest(
        tool_name=tool, arguments={}, audience=AUD, identity_token=tok, proof=proof
    )


# correct-resolution + false-refusal: the good path is allowed
def test_valid_identity_in_scope_is_allowed():
    d = decide(call(), **deps(FakeVerifier(VerifyResult.success())))
    assert d.outcome is Outcome.ALLOW
    assert d.identity.sub == SUB
    assert d.jti == "abc"


# correct-refusal: no token -> unknown / absent
def test_no_token_is_unknown_absent():
    r = IdentityRequest("read_report", {}, AUD, identity_token=None, proof=None)
    d = decide(r, **deps(FakeVerifier(VerifyResult.success())))
    assert d.outcome is Outcome.UNKNOWN
    assert d.reason is Reason.IDENTITY_ABSENT


def test_malformed_token_is_unknown():
    d = decide(call(token="not-a-jwt"), **deps(FakeVerifier(VerifyResult.success())))
    assert d.outcome is Outcome.UNKNOWN
    assert d.reason is Reason.IDENTITY_MALFORMED


def test_unknown_issuer_is_unknown():
    d = decide(call(), **deps(FakeVerifier(VerifyResult.success()), issuers=IssuerRegistry(["https://other"])))
    assert d.outcome is Outcome.UNKNOWN
    assert d.reason is Reason.ISSUER_UNKNOWN


# correct-refusal: verification failure -> deny (not unknown)
def test_failed_verification_is_deny():
    d = decide(call(), **deps(FakeVerifier(VerifyResult.failure(Reason.SIGNATURE_INVALID))))
    assert d.outcome is Outcome.DENY
    assert d.reason is Reason.SIGNATURE_INVALID


def test_proof_failure_is_deny():
    d = decide(call(), **deps(FakeVerifier(VerifyResult.failure(Reason.PROOF_INVALID))))
    assert d.outcome is Outcome.DENY
    assert d.reason is Reason.PROOF_INVALID


# correct-refusal: authenticated but out of scope -> deny
def test_out_of_scope_capability_is_deny():
    d = decide(call(tool="delete_everything"), **deps(FakeVerifier(VerifyResult.success())))
    assert d.outcome is Outcome.DENY
    assert d.reason is Reason.CAPABILITY_DENIED


def test_missing_policy_denies_by_default():
    d = decide(call(), **deps(FakeVerifier(VerifyResult.success()), policy=StaticPolicy({})))
    assert d.outcome is Outcome.DENY
    assert d.reason is Reason.NO_POLICY


# invariant: nothing short of the full chain ever yields allow
def test_unknown_and_deny_never_carry_allow():
    failing = [
        decide(IdentityRequest("t", {}, AUD, None, None), **deps(FakeVerifier(VerifyResult.success()))),
        decide(call(token="bad"), **deps(FakeVerifier(VerifyResult.success()))),
        decide(call(), **deps(FakeVerifier(VerifyResult.failure(Reason.PROOF_INVALID)))),
        decide(call(tool="nope"), **deps(FakeVerifier(VerifyResult.success()))),
    ]
    assert all(d.outcome is not Outcome.ALLOW for d in failing)
