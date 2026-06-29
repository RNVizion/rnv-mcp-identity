# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""A runnable FastMCP server guarded by IdentityMiddleware.

In-process:  imported by tests/test_demo_inprocess.py via build_server().
Over HTTP:   `python examples/demo_server.py`  then run demo_client_http.py.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from fastmcp import FastMCP

from rnv_mcp_identity.adapters.fastmcp_middleware import IdentityMiddleware
from rnv_mcp_identity.policy import DocumentPolicy, IssuerRegistry
from rnv_mcp_identity.verifier import JwtVerifier, StaticJwks

import identity_kit as kit

POLICY = {
    "version": 1,
    "grants": [
        # The demo agent may read, but not delete.
        {"sub": kit.SUB, "controller": kit.CTRL, "audience": kit.AUD,
         "capabilities": ["tool:read_*"]},
    ],
}


def build_server() -> FastMCP:
    mcp = FastMCP("rnv-identity-demo")
    mcp.add_middleware(IdentityMiddleware(
        issuers=IssuerRegistry([kit.ISS]),
        verifier=JwtVerifier(jwks=StaticJwks({kit.ISS: kit.ISSUER_PUBLIC})),
        policy=DocumentPolicy.from_dict(POLICY),
        audience=kit.AUD,
    ))

    @mcp.tool
    def read_report() -> str:
        """Read the quarterly report (granted to the demo agent)."""
        return "Q2 revenue up 12 percent."

    @mcp.tool
    def delete_report() -> str:
        """Delete the report (privileged; NOT granted to the demo agent)."""
        return "report deleted"

    return mcp


if __name__ == "__main__":
    build_server().run(transport="http", host="127.0.0.1", port=8000)
