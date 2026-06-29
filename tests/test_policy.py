# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""L3 authorization tests: the capability matcher and the declarative policy."""
from __future__ import annotations

import base64
import json

import pytest

from rnv_mcp_identity.policy import (
    StaticPolicy,
    DocumentPolicy,
    capability_granted,
    default_capability_for,
)
from rnv_mcp_identity.engine import decide
from rnv_mcp_identity.identity import IdentityRequest
from rnv_mcp_identity.outcomes import Outcome, Reason
from rnv_mcp_identity.policy import IssuerRegistry
from rnv_mcp_identity.verifier import VerifyResult

ISS = "iss://authority"
AUD = "aud://server"
SUB = "sub://agent"
CTRL = "ctrl://owner"
GOOD = {"iss": ISS, "sub": SUB, "controller": CTRL, "aud": AUD, "jti": "j1"}


def tok(claims) -> str:
    seg = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'none'})}.{seg(claims)}.{seg({})}"


class OkVerifier:
    def verify(self, **_) -> VerifyResult:
        return VerifyResult.success()


# --- the capability matcher ---

def test_exact_grant_matches():
    assert capability_granted({"tool:read"}, "tool:read")


def test_unrelated_capability_does_not_match():
    assert not capability_granted({"tool:read"}, "tool:write")


def test_namespace_wildcard_covers_any_tool():
    assert capability_granted({"tool:*"}, "tool:anything")


def test_prefix_wildcard_is_bounded():
    assert capability_granted({"tool:read_*"}, "tool:read_report")
    assert not capability_granted({"tool:read_*"}, "tool:write_report")


def test_global_wildcard_covers_all():
    assert capability_granted({"*"}, "tool:x")


def test_naming_convention_is_pinned():
    assert default_capability_for("read_report", {}) == "tool:read_report"


# --- the declarative policy ---

DOC = {
    "version": 1,
    "grants": [
        {"sub": SUB, "controller": CTRL, "audience": AUD, "capabilities": ["tool:read_*"]},
        {"controller": CTRL, "audience": AUD, "capabilities": ["tool:ping"]},
    ],
}


def test_agent_specific_and_controller_rules_union():
    g = DocumentPolicy.from_dict(DOC).granted_capabilities(sub=SUB, controller=CTRL, audience=AUD)
    assert capability_granted(g, "tool:read_report")  # agent-specific prefix
    assert capability_granted(g, "tool:ping")          # inherited from controller rule
    assert not capability_granted(g, "tool:write_report")


def test_controller_rule_applies_to_other_agents():
    g = DocumentPolicy.from_dict(DOC).granted_capabilities(
        sub="sub://someone-else", controller=CTRL, audience=AUD)
    assert g is not None
    assert capability_granted(g, "tool:ping")
    assert not capability_granted(g, "tool:read_report")  # agent-specific rule didn't select


def test_unselected_principal_has_no_policy():
    g = DocumentPolicy.from_dict(DOC).granted_capabilities(
        sub=SUB, controller="ctrl://stranger", audience=AUD)
    assert g is None


def test_bad_version_is_rejected():
    with pytest.raises(ValueError):
        DocumentPolicy.from_dict({"version": 2, "grants": []})


# --- through the engine ---

def run(policy, tool):
    return decide(
        IdentityRequest(tool, {}, AUD, identity_token=tok(GOOD), proof="p"),
        issuers=IssuerRegistry([ISS]),
        verifier=OkVerifier(),
        policy=policy,
    )


def test_engine_allows_via_document_policy():
    assert run(DocumentPolicy.from_dict(DOC), "read_report").outcome is Outcome.ALLOW


def test_engine_denies_uncovered_capability():
    d = run(DocumentPolicy.from_dict(DOC), "write_report")
    assert d.outcome is Outcome.DENY and d.reason is Reason.CAPABILITY_DENIED


def test_engine_no_policy_for_unselected_principal():
    doc = {"version": 1, "grants": [{"sub": "sub://nobody", "audience": AUD, "capabilities": ["tool:*"]}]}
    d = run(DocumentPolicy.from_dict(doc), "read_report")
    assert d.outcome is Outcome.DENY and d.reason is Reason.NO_POLICY


def test_static_policy_supports_wildcards_too():
    p = StaticPolicy({(SUB, CTRL, AUD): {"tool:*"}})
    assert run(p, "anything").outcome is Outcome.ALLOW
