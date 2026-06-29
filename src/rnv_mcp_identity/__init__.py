# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""rnv-mcp-identity: an identity-and-authorization layer for MCP servers.

Resolve or refuse, never guess. The decision engine is framework-agnostic;
the FastMCP binding lives in `rnv_mcp_identity.adapters.fastmcp_middleware`
and is only imported when the `fastmcp` extra is installed.
"""
from .outcomes import Outcome, Reason, Decision
from .identity import AgentIdentity, IdentityRequest, decode_unverified
from .verifier import (
    Verifier,
    VerifyResult,
    JwtVerifier,
    JwksResolver,
    StaticJwks,
    InMemoryReplayCache,
    jwk_thumbprint,
)
from .policy import (
    IssuerRegistry,
    Policy,
    StaticPolicy,
    DocumentPolicy,
    capability_granted,
    default_capability_for,
)
from .engine import decide

__all__ = [
    "Outcome", "Reason", "Decision",
    "AgentIdentity", "IdentityRequest", "decode_unverified",
    "Verifier", "VerifyResult", "JwtVerifier", "JwksResolver",
    "StaticJwks", "InMemoryReplayCache", "jwk_thumbprint",
    "IssuerRegistry", "Policy", "StaticPolicy", "DocumentPolicy",
    "capability_granted", "default_capability_for",
    "decide",
]
