# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""FastMCP adapter. The only module that imports FastMCP.

Wraps every tool call in the decision sequence (SPEC section 6). Requires the
`fastmcp` extra:  pip install "rnv-mcp-identity[fastmcp]"
"""
from __future__ import annotations

from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers
from fastmcp.exceptions import ToolError

from ..engine import decide
from ..identity import IdentityRequest
from ..policy import default_capability_for

# v0 wire format (SPEC section 10): identity token and proof ride in headers.
# These names are the v0 choice; confirm before the AAIF proposal.
IDENTITY_HEADER = "mcp-agent-identity"
PROOF_HEADER = "mcp-agent-proof"


class IdentityMiddleware(Middleware):
    """Runs resolve -> verify -> authorize before any tool executes."""

    def __init__(
        self,
        *,
        issuers,
        verifier,
        policy,
        audience: str,
        capability_for=default_capability_for,
    ) -> None:
        self._issuers = issuers
        self._verifier = verifier
        self._policy = policy
        self._audience = audience
        self._capability_for = capability_for

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        headers = get_http_headers() or {}
        request = IdentityRequest(
            tool_name=getattr(context.message, "name", ""),
            arguments=getattr(context.message, "arguments", {}) or {},
            audience=self._audience,
            identity_token=headers.get(IDENTITY_HEADER),
            proof=headers.get(PROOF_HEADER),
        )

        decision = decide(
            request,
            issuers=self._issuers,
            verifier=self._verifier,
            policy=self._policy,
            capability_for=self._capability_for,
        )

        if not decision.allowed:
            # Refuse with a stable reason code, no detail that aids probing.
            raise ToolError(f"identity refused: {decision.reason.value}")

        # Bind the verified identity to the call for downstream audit (step 4).
        ctx = context.fastmcp_context
        if ctx is not None and decision.identity is not None:
            ctx.set_state("agent_sub", decision.identity.sub)
            ctx.set_state("agent_controller", decision.identity.controller)
            ctx.set_state("agent_jti", decision.jti)

        return await call_next(context)
