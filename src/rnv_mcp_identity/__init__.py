"""rnv-mcp-identity: an identity-and-authorization layer for MCP servers.

Resolve or refuse, never guess. The decision engine is framework-agnostic;
the FastMCP binding lives in `rnv_mcp_identity.adapters.fastmcp_middleware`
and is only imported when the `fastmcp` extra is installed.
"""
from .outcomes import Outcome, Reason, Decision
from .identity import AgentIdentity, IdentityRequest, decode_unverified
from .verifier import Verifier, VerifyResult, JwtVerifier
from .policy import IssuerRegistry, Policy, StaticPolicy, default_capability_for
from .engine import decide

__all__ = [
    "Outcome", "Reason", "Decision",
    "AgentIdentity", "IdentityRequest", "decode_unverified",
    "Verifier", "VerifyResult", "JwtVerifier",
    "IssuerRegistry", "Policy", "StaticPolicy", "default_capability_for",
    "decide",
]
