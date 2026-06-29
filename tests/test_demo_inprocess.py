# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""In-process demo: drive the guarded FastMCP server through the in-memory
client and confirm one allow and three refusals. Needs fastmcp + verify."""
from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("fastmcp")
pytest.importorskip("jwt")
pytest.importorskip("cryptography")

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

from fastmcp import Client

import rnv_mcp_identity.adapters.fastmcp_middleware as adapter
from demo_server import build_server
import identity_kit as kit


def test_demo_allows_then_refuses(monkeypatch):
    state = {"headers": {}}
    # The in-memory transport carries no HTTP headers; inject them at the source.
    monkeypatch.setattr(adapter, "get_http_headers", lambda: dict(state["headers"]))

    mcp = build_server()
    tok = kit.mint_identity()
    proof = kit.mint_proof(tok)

    async def run():
        async with Client(mcp) as client:
            # 1. valid + in scope -> allowed
            state["headers"] = kit.headers_for(tok, proof)
            result = await client.call_tool("read_report", {})
            assert result is not None

            # 2. valid + out of scope -> capability_denied
            with pytest.raises(Exception) as denied:
                await client.call_tool("delete_report", {})
            assert "capability_denied" in str(denied.value)

            # 3. no identity -> identity_absent
            state["headers"] = {}
            with pytest.raises(Exception) as absent:
                await client.call_tool("read_report", {})
            assert "identity_absent" in str(absent.value)

            # 4. tampered proof -> proof_invalid
            state["headers"] = kit.headers_for(tok, proof[:-4] + "AAAA")
            with pytest.raises(Exception) as badproof:
                await client.call_tool("read_report", {})
            assert "proof_invalid" in str(badproof.value)

    asyncio.run(run())
