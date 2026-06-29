# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""Property-based invariants over the decision engine, and the three eval
gates (SPEC section 7) named and machine-checked. Needs hypothesis."""
from __future__ import annotations

import base64
import json

import pytest

pytest.importorskip("hypothesis")
from hypothesis import given, settings, strategies as st

from rnv_mcp_identity.engine import decide
from rnv_mcp_identity.identity import IdentityRequest, decode_unverified
from rnv_mcp_identity.outcomes import Outcome, Reason
from rnv_mcp_identity.policy import IssuerRegistry, StaticPolicy
from rnv_mcp_identity.verifier import VerifyResult

settings.register_profile("rnv", deadline=None)
settings.load_profile("rnv")

ISS = "iss://authority"
AUD = "aud://server"
SUB = "sub://agent"
CTRL = "ctrl://owner"
GOOD = {"iss": ISS, "sub": SUB, "controller": CTRL, "aud": AUD, "jti": "j1"}

TOOLS = ["alpha", "beta", "gamma", "delta"]
CAPS = [f"tool:{t}" for t in TOOLS]

VERIFY_REASONS = [
    Reason.SIGNATURE_INVALID, Reason.TOKEN_EXPIRED, Reason.TOKEN_NOT_YET_VALID,
    Reason.AUDIENCE_MISMATCH, Reason.PROOF_INVALID, Reason.REPLAY_DETECTED,
]
UNKNOWN_REASONS = {Reason.IDENTITY_ABSENT, Reason.IDENTITY_MALFORMED, Reason.ISSUER_UNKNOWN}
DENY_REASONS = set(VERIFY_REASONS) | {Reason.NO_POLICY, Reason.CAPABILITY_DENIED}


def tok(claims) -> str:
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'none'})}.{seg(claims)}.{seg({})}"


class ConfigurableVerifier:
    def __init__(self, result: VerifyResult) -> None:
        self._result = result

    def verify(self, **_) -> VerifyResult:
        return self._result


def run(token, tool, vres, grants, has_policy):
    policy = StaticPolicy({(SUB, CTRL, AUD): grants}) if has_policy else StaticPolicy({})
    return decide(
        IdentityRequest(tool, {}, AUD, identity_token=token, proof="p"),
        issuers=IssuerRegistry([ISS]),
        verifier=ConfigurableVerifier(vres),
        policy=policy,
    )


tokens = st.sampled_from([None, "not-a-jwt", tok(GOOD), tok({**GOOD, "iss": "iss://stranger"})])
verifiers = st.sampled_from([VerifyResult.success()] + [VerifyResult.failure(r) for r in VERIFY_REASONS])
grant_sets = st.sets(st.sampled_from(CAPS)).map(frozenset)
tools = st.sampled_from(TOOLS)


# --- invariants over the whole input space ---

@given(token=tokens, tool=tools, vres=verifiers, grants=grant_sets, has_policy=st.booleans())
def test_outcome_is_total(token, tool, vres, grants, has_policy):
    d = run(token, tool, vres, grants, has_policy)
    assert d.outcome in (Outcome.ALLOW, Outcome.DENY, Outcome.UNKNOWN)
    assert d.reason is not None
    assert (d.outcome is Outcome.ALLOW) == (d.reason is Reason.OK)


@given(token=tokens, tool=tools, vres=verifiers, grants=grant_sets, has_policy=st.booleans())
def test_reason_partitions_by_outcome(token, tool, vres, grants, has_policy):
    d = run(token, tool, vres, grants, has_policy)
    if d.outcome is Outcome.UNKNOWN:
        assert d.reason in UNKNOWN_REASONS
    elif d.outcome is Outcome.DENY:
        assert d.reason in DENY_REASONS


@given(token=tokens, tool=tools, vres=verifiers, grants=grant_sets, has_policy=st.booleans())
def test_no_implicit_allow(token, tool, vres, grants, has_policy):
    d = run(token, tool, vres, grants, has_policy)
    if d.outcome is Outcome.ALLOW:
        # ALLOW is reachable only when every precondition held.
        assert token is not None
        claims = decode_unverified(token)
        assert claims is not None and claims.get("iss") == ISS
        assert vres.ok
        assert has_policy and f"tool:{tool}" in grants


@given(token=tokens, tool=tools, vres=verifiers, grants=grant_sets, has_policy=st.booleans())
def test_decision_is_deterministic(token, tool, vres, grants, has_policy):
    a = run(token, tool, vres, grants, has_policy)
    b = run(token, tool, vres, grants, has_policy)
    assert (a.outcome, a.reason) == (b.outcome, b.reason)


# --- the three eval gates (SPEC section 7) ---

@given(tool=tools, extra=grant_sets)
def test_gate_correct_resolution(tool, extra):
    """A valid, verified, in-scope call is allowed."""
    grants = frozenset(extra | {f"tool:{tool}"})
    d = run(tok(GOOD), tool, VerifyResult.success(), grants, True)
    assert d.outcome is Outcome.ALLOW


@given(tool=tools, vres=st.sampled_from([VerifyResult.failure(r) for r in VERIFY_REASONS]))
def test_gate_correct_refusal_failed_verification(tool, vres):
    """An identity that fails verification is denied, never allowed."""
    d = run(tok(GOOD), tool, vres, frozenset({f"tool:{tool}"}), True)
    assert d.outcome is Outcome.DENY and d.reason is vres.reason


@given(tool=tools)
def test_gate_correct_refusal_unknown_issuer(tool):
    """An unresolvable issuer is unknown, never allowed."""
    d = run(tok({**GOOD, "iss": "iss://stranger"}), tool, VerifyResult.success(),
            frozenset({f"tool:{tool}"}), True)
    assert d.outcome is Outcome.UNKNOWN and d.reason is Reason.ISSUER_UNKNOWN


@given(tool=tools)
def test_gate_correct_refusal_unauthorized(tool):
    """An authenticated but out-of-scope call is denied."""
    grants = frozenset(c for c in CAPS if c != f"tool:{tool}")
    d = run(tok(GOOD), tool, VerifyResult.success(), grants, True)
    assert d.outcome is Outcome.DENY and d.reason is Reason.CAPABILITY_DENIED


@given(tool=tools, extra=grant_sets)
def test_gate_no_false_refusal(tool, extra):
    """The load-bearing gate: a valid, authorized call is never wrongly refused,
    no matter what else is in the grant set."""
    grants = frozenset(extra | {f"tool:{tool}"})
    d = run(tok(GOOD), tool, VerifyResult.success(), grants, True)
    assert d.outcome is Outcome.ALLOW and d.reason is Reason.OK
