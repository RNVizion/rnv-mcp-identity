# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""The agent identity data model (SPEC section 4)."""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class AgentIdentity:
    """Who is calling. Trusted only after L2 verification (SPEC section 4.1)."""
    sub: str
    controller: Optional[str] = None
    agent_kind: Optional[str] = None
    claims: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_claims(cls, claims: Mapping[str, Any]) -> "AgentIdentity":
        controller = claims.get("controller")
        agent_kind = claims.get("agent_kind")
        return cls(
            sub=str(claims.get("sub", "")),
            controller=str(controller) if controller else None,
            agent_kind=str(agent_kind) if agent_kind else None,
            claims=dict(claims),
        )


@dataclass(frozen=True)
class IdentityRequest:
    """A framework-agnostic view of an incoming tool call. Adapters build this."""
    tool_name: str
    arguments: Mapping[str, Any]
    audience: str
    identity_token: Optional[str] = None
    proof: Optional[str] = None


def decode_unverified(token: str) -> Optional[dict]:
    """Read JWT payload claims WITHOUT verifying anything.

    For routing only (SPEC section 6, step 1). Signature, expiry, audience, and
    proof are all checked later by the Verifier (step 2). Returns None if the
    token is not a parseable JWT.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        padding = "=" * (-len(payload) % 4)
        raw = base64.urlsafe_b64decode(payload + padding)
        claims = json.loads(raw)
        return claims if isinstance(claims, dict) else None
    except (ValueError, binascii.Error, json.JSONDecodeError):
        return None
