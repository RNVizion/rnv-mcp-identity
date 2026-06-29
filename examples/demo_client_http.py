"""HTTP client that exercises the guarded server over the real header wire path.

Start the server first:  python examples/demo_server.py
Then in another shell:    python examples/demo_client_http.py
"""
from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

import identity_kit as kit

URL = "http://127.0.0.1:8000/mcp/"


async def call(label, headers, tool):
    try:
        async with Client(StreamableHttpTransport(URL, headers=headers)) as c:
            result = await c.call_tool(tool, {})
        print(f"[allow]  {label}: {tool} -> {getattr(result, 'data', result)}")
    except Exception as e:  # ToolError carries the refusal reason
        print(f"[refuse] {label}: {tool} -> {e}")


async def main():
    tok = kit.mint_identity()
    proof = kit.mint_proof(tok)
    good = kit.headers_for(tok, proof)

    await call("valid, in scope", good, "read_report")
    await call("valid, out of scope", good, "delete_report")
    await call("no identity", {}, "read_report")
    await call("tampered proof", kit.headers_for(tok, proof[:-4] + "AAAA"), "read_report")


if __name__ == "__main__":
    asyncio.run(main())
