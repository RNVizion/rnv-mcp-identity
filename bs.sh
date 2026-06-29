#!/usr/bin/env bash
# Bootstrap the rnv-mcp-identity repository. Run from an empty repo root.
set -euo pipefail

mkdir -p '.github/workflows'
mkdir -p 'examples'
mkdir -p 'src/rnv_mcp_identity'
mkdir -p 'src/rnv_mcp_identity/adapters'
mkdir -p 'tests'

cat > 'pyproject.toml' <<'RNV_FILE_EOF'
[project]
name = "rnv-mcp-identity"
version = "0.0.1"
description = "An identity-and-authorization layer for MCP servers: resolve or refuse, never guess."
readme = "README.md"
requires-python = ">=3.10"
license = { text = "Apache-2.0" }
dependencies = []

[project.optional-dependencies]
fastmcp = ["fastmcp>=2.9"]
verify = ["pyjwt>=2.8", "cryptography>=42"]
dev = ["pytest>=8", "hypothesis>=6"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/rnv_mcp_identity"]

[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/__init__.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/adapters/__init__.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""Framework adapters. Importing a submodule here pulls its framework dependency."""
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/adapters/fastmcp_middleware.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/engine.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""The decision sequence (SPEC section 6). Pure, framework-agnostic."""
from __future__ import annotations

from typing import Any, Callable, Mapping

from .identity import AgentIdentity, IdentityRequest, decode_unverified
from .outcomes import Decision, Reason
from .policy import IssuerRegistry, Policy, capability_granted, default_capability_for
from .verifier import Verifier

CapabilityFor = Callable[[str, Mapping[str, Any]], str]


def decide(
    request: IdentityRequest,
    *,
    issuers: IssuerRegistry,
    verifier: Verifier,
    policy: Policy,
    capability_for: CapabilityFor = default_capability_for,
) -> Decision:
    """Run the decision sequence for one tool call.

    Returns a Decision whose outcome is exactly one of allow / deny / unknown.
    There is no implicit allow: unknown is never upgraded, verification failure
    denies, and missing policy denies by default.
    """
    # Step 0: intake
    if request.identity_token is None:
        return Decision.unknown(Reason.IDENTITY_ABSENT)
    claims = decode_unverified(request.identity_token)
    if claims is None:
        return Decision.unknown(Reason.IDENTITY_MALFORMED)

    # Step 1: resolve (L1). Claims stay untrusted until step 2.
    if not issuers.is_recognized(claims.get("iss")):
        return Decision.unknown(Reason.ISSUER_UNKNOWN)
    identity = AgentIdentity.from_claims(claims)

    # Step 2: verify (L2).
    result = verifier.verify(
        token=request.identity_token,
        proof=request.proof,
        claims=claims,
        audience=request.audience,
    )
    if not result.ok:
        return Decision.deny(result.reason or Reason.SIGNATURE_INVALID, identity=identity)
    # identity is now trusted

    # Step 3: authorize (L3).
    required = capability_for(request.tool_name, request.arguments)
    granted = policy.granted_capabilities(
        sub=identity.sub, controller=identity.controller, audience=request.audience
    )
    if granted is None:
        return Decision.deny(Reason.NO_POLICY, identity=identity)
    if not capability_granted(granted, required):
        return Decision.deny(Reason.CAPABILITY_DENIED, identity=identity)

    # Step 4: bind + allow.
    return Decision.allow(identity=identity, jti=claims.get("jti"))
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/identity.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/outcomes.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""Outcomes and reasons (SPEC sections 5 and 6)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .identity import AgentIdentity


class Outcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


class Reason(str, Enum):
    # intake / resolve -> unknown
    IDENTITY_ABSENT = "identity_absent"
    IDENTITY_MALFORMED = "identity_malformed"
    ISSUER_UNKNOWN = "issuer_unknown"
    # verify -> deny
    SIGNATURE_INVALID = "signature_invalid"
    TOKEN_EXPIRED = "token_expired"
    TOKEN_NOT_YET_VALID = "token_not_yet_valid"
    AUDIENCE_MISMATCH = "audience_mismatch"
    PROOF_INVALID = "proof_invalid"
    REPLAY_DETECTED = "replay_detected"
    # authorize -> deny
    NO_POLICY = "no_policy"
    CAPABILITY_DENIED = "capability_denied"
    # allow
    OK = "ok"


@dataclass(frozen=True)
class Decision:
    """The single result of the decision sequence. Exactly one outcome."""
    outcome: Outcome
    reason: Reason
    identity: "Optional[AgentIdentity]" = None
    jti: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.outcome is Outcome.ALLOW

    @classmethod
    def allow(cls, *, identity, jti=None) -> "Decision":
        return cls(Outcome.ALLOW, Reason.OK, identity=identity, jti=jti)

    @classmethod
    def deny(cls, reason: Reason, *, identity=None) -> "Decision":
        return cls(Outcome.DENY, reason, identity=identity)

    @classmethod
    def unknown(cls, reason: Reason) -> "Decision":
        return cls(Outcome.UNKNOWN, reason)
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/policy.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""L1 issuer registry and L3 authorization (SPEC section 6, steps 1 and 3).

The capability model is deliberately small so a grant's reach is obvious on
inspection: a capability is `tool:<tool_name>` in v0, and a grant is either an
exact capability or a single trailing-`*` prefix. No other glob features.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional, Protocol, Tuple, runtime_checkable


class IssuerRegistry:
    """The identity authorities this deployment recognizes (L1, step 1)."""

    def __init__(self, issuers: Iterable[str] = ()) -> None:
        self._issuers = set(issuers)

    def is_recognized(self, issuer: Optional[str]) -> bool:
        return issuer is not None and issuer in self._issuers

    def add(self, issuer: str) -> None:
        self._issuers.add(issuer)


# --- the capability model (SPEC section 6, L3) ---

def default_capability_for(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """v0 capability naming convention: `tool:<tool_name>`.

    The argument map is available but not part of the v0 capability; argument-
    scoped capabilities are a later extension.
    """
    return f"tool:{tool_name}"


def _grant_covers(grant: str, required: str) -> bool:
    """A grant covers a required capability by exact match, or by a single
    trailing-`*` prefix. `tool:*` covers the tool namespace; `*` covers all."""
    if grant == required:
        return True
    if grant.endswith("*"):
        return required.startswith(grant[:-1])
    return False


def capability_granted(grants: Iterable[str], required: str) -> bool:
    """True when any grant covers the required capability. Total and obvious:
    exact-or-prefix only, so authority is never inferred beyond what's written."""
    return any(_grant_covers(g, required) for g in grants)


@runtime_checkable
class Policy(Protocol):
    """Resolves the capability grants that apply to (agent, controller) for a
    server. Returns None when no policy applies to the principal: the engine
    denies by default (SPEC section 6, step 3), never allows on missing policy.
    """

    def granted_capabilities(
        self, *, sub: str, controller: Optional[str], audience: str
    ) -> Optional[frozenset]: ...


class StaticPolicy:
    """A simple, real policy: an in-memory table keyed on (sub, controller, audience).
    Grants may be exact capabilities or trailing-`*` prefixes."""

    def __init__(self, grants: Optional[Mapping[Tuple, Iterable[str]]] = None) -> None:
        self._grants: dict = {}
        for key, caps in (grants or {}).items():
            self._grants[self._norm(key)] = frozenset(caps)

    @staticmethod
    def _norm(key: Tuple) -> Tuple:
        if len(key) == 3:
            return key
        if len(key) == 2:
            return (key[0], None, key[1])
        raise ValueError("grant key must be (sub, controller, audience) or (sub, audience)")

    def grant(self, *, sub, controller, audience, capabilities) -> None:
        self._grants[(sub, controller, audience)] = frozenset(capabilities)

    def granted_capabilities(self, *, sub, controller, audience):
        if (sub, controller, audience) in self._grants:
            return self._grants[(sub, controller, audience)]
        if (sub, None, audience) in self._grants:
            return self._grants[(sub, None, audience)]
        return None


@dataclass(frozen=True)
class _Rule:
    sub: Optional[str]
    controller: Optional[str]
    audience: Optional[str]
    capabilities: frozenset

    def selects(self, sub, controller, audience) -> bool:
        # An absent selector matches any value; a present one must match exactly.
        return (
            (self.sub is None or self.sub == sub)
            and (self.controller is None or self.controller == controller)
            and (self.audience is None or self.audience == audience)
        )


class DocumentPolicy:
    """A declarative L3 policy. Each rule has optional sub / controller / audience
    selectors and a set of capability grants. A rule with all three is agent-
    specific; a rule with only controller and audience grants every agent under
    that controller. Authority is only ever added by an explicit rule.

    Document shape:
        {
          "version": 1,
          "grants": [
            {"sub": "...", "controller": "...", "audience": "...",
             "capabilities": ["tool:read_*"]},
            {"controller": "...", "audience": "...",
             "capabilities": ["tool:ping"]}
          ]
        }
    """

    def __init__(self, rules: Iterable[_Rule]) -> None:
        self._rules = list(rules)

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> "DocumentPolicy":
        if doc.get("version") != 1:
            raise ValueError("unsupported policy version (expected 1)")
        rules = [
            _Rule(
                sub=raw.get("sub"),
                controller=raw.get("controller"),
                audience=raw.get("audience"),
                capabilities=frozenset(raw.get("capabilities", ())),
            )
            for raw in doc.get("grants", ())
        ]
        return cls(rules)

    def granted_capabilities(self, *, sub, controller, audience):
        matched = [r for r in self._rules if r.selects(sub, controller, audience)]
        if not matched:
            return None  # no applicable policy -> NO_POLICY (deny by default)
        out: set = set()
        for r in matched:
            out |= r.capabilities
        return frozenset(out)
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/verifier.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""L2 verification (SPEC section 6, step 2): the crypto.

The Verifier owns every deny-reason in step 2. The engine never inspects a
signature itself; it asks the Verifier and maps the result. `JwtVerifier` is
the real implementation; it needs the `verify` extra:

    pip install "rnv-mcp-identity[verify]"
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol, runtime_checkable

from .outcomes import Reason

try:  # the core install stays dependency-free; crypto is opt-in
    import jwt
except ImportError:  # pragma: no cover
    jwt = None  # type: ignore

DEFAULT_ALGORITHMS = ("EdDSA", "ES256", "RS256")


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    reason: Optional[Reason] = None

    @classmethod
    def success(cls) -> "VerifyResult":
        return cls(True, None)

    @classmethod
    def failure(cls, reason: Reason) -> "VerifyResult":
        return cls(False, reason)


@runtime_checkable
class Verifier(Protocol):
    """Verifies a presented identity token and its proof of possession."""

    def verify(
        self,
        *,
        token: str,
        proof: Optional[str],
        claims: Mapping[str, Any],
        audience: str,
    ) -> VerifyResult: ...


@runtime_checkable
class JwksResolver(Protocol):
    """Resolves an issuer's public verifying key."""

    def public_key_for(self, *, issuer: Optional[str], kid: Optional[str]) -> Optional[Any]: ...


class StaticJwks:
    """In-memory issuer -> public key map. A real JWKS-over-HTTP resolver is a
    later drop-in behind the same Protocol."""

    def __init__(self, keys: Optional[Mapping[str, Any]] = None) -> None:
        self._by_issuer = dict(keys or {})

    def public_key_for(self, *, issuer: Optional[str], kid: Optional[str] = None) -> Optional[Any]:
        return self._by_issuer.get(issuer) if issuer else None

    def add(self, issuer: str, key: Any) -> None:
        self._by_issuer[issuer] = key


class InMemoryReplayCache:
    """Tracks seen identity `jti` values. Process-local; a shared store is a
    later drop-in. v0 does not evict on expiry."""

    def __init__(self) -> None:
        self._seen: set = set()

    def seen(self, jti: str, exp: Optional[int] = None) -> bool:
        if jti in self._seen:
            return True
        self._seen.add(jti)
        return False


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 JWK thumbprint over the canonical required members."""
    kty = jwk["kty"]
    if kty == "OKP":
        members = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    elif kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise ValueError(f"unsupported kty: {kty}")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return _b64url(hashlib.sha256(canonical).digest())


class JwtVerifier:
    """Holder-of-key JWT verifier implementing SPEC section 6, step 2.

    Order, each failure short-circuiting:
      1. issuer signature against the resolved key  -> SIGNATURE_INVALID
      2. nbf / exp window                           -> TOKEN_NOT_YET_VALID / TOKEN_EXPIRED
      3. aud == audience                            -> AUDIENCE_MISMATCH
      4. proof of possession against cnf            -> PROOF_INVALID
      5. jti replay, when a cache is configured     -> REPLAY_DETECTED

    No new crypto: signature and proof are JWS (pyjwt); the proof is a WPT-style
    token whose public JWK must thumbprint-match the token's `cnf.jkt` (RFC 7638)
    and which binds to this exact identity token via `ath` (RFC 9449 style).
    """

    def __init__(
        self,
        *,
        jwks: JwksResolver,
        algorithms: tuple = DEFAULT_ALGORITHMS,
        require_proof: bool = True,
        replay_cache: Optional[InMemoryReplayCache] = None,
    ) -> None:
        if jwt is None:  # pragma: no cover
            raise RuntimeError(
                "JwtVerifier needs the 'verify' extra: pip install \"rnv-mcp-identity[verify]\""
            )
        self._jwks = jwks
        self._algorithms = tuple(algorithms)
        self._require_proof = require_proof
        self._replay_cache = replay_cache

    def verify(self, *, token, proof, claims, audience) -> VerifyResult:
        # Resolve the issuer's key (issuer recognition already happened at L1).
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return VerifyResult.failure(Reason.SIGNATURE_INVALID)
        key = self._jwks.public_key_for(issuer=claims.get("iss"), kid=header.get("kid"))
        if key is None:
            # Recognized issuer but no usable key: cannot establish authenticity.
            return VerifyResult.failure(Reason.SIGNATURE_INVALID)

        # 1 + 2 + 3: signature, then temporal, then audience.
        try:
            verified = jwt.decode(
                token,
                key,
                algorithms=list(self._algorithms),
                audience=audience,
                options={"require": ["exp", "iat", "aud"], "verify_aud": True},
            )
        except jwt.ExpiredSignatureError:
            return VerifyResult.failure(Reason.TOKEN_EXPIRED)
        except jwt.ImmatureSignatureError:
            return VerifyResult.failure(Reason.TOKEN_NOT_YET_VALID)
        except jwt.InvalidAudienceError:
            return VerifyResult.failure(Reason.AUDIENCE_MISMATCH)
        except jwt.InvalidTokenError:
            return VerifyResult.failure(Reason.SIGNATURE_INVALID)

        # 4: proof of possession.
        if self._require_proof:
            failed = self._verify_proof(token=token, proof=proof, verified=verified)
            if failed is not None:
                return failed

        # 5: replay.
        if self._replay_cache is not None:
            jti = verified.get("jti")
            if jti is None or self._replay_cache.seen(jti, verified.get("exp")):
                return VerifyResult.failure(Reason.REPLAY_DETECTED)

        return VerifyResult.success()

    def _verify_proof(self, *, token, proof, verified) -> Optional[VerifyResult]:
        cnf = verified.get("cnf") or {}
        jkt = cnf.get("jkt")
        if not jkt or not proof:
            return VerifyResult.failure(Reason.PROOF_INVALID)
        try:
            jwk = jwt.get_unverified_header(proof).get("jwk")
            if not jwk or jwk_thumbprint(jwk) != jkt:
                return VerifyResult.failure(Reason.PROOF_INVALID)
            pop_key = jwt.PyJWK.from_dict(jwk).key
            proof_claims = jwt.decode(
                proof,
                pop_key,
                algorithms=list(self._algorithms),
                options={"require": ["ath"], "verify_aud": False},
            )
        except Exception:
            return VerifyResult.failure(Reason.PROOF_INVALID)
        expected_ath = _b64url(hashlib.sha256(token.encode("utf-8")).digest())
        if proof_claims.get("ath") != expected_ath:
            return VerifyResult.failure(Reason.PROOF_INVALID)
        return None
RNV_FILE_EOF

cat > 'tests/test_demo_inprocess.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'tests/test_engine.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'tests/test_policy.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'tests/test_properties.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'tests/test_verifier.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""Real-key L2 tests (SPEC section 6, step 2). Needs the `verify` extra."""
from __future__ import annotations

import base64
import hashlib
import time

import pytest

jwt = pytest.importorskip("jwt")
pytest.importorskip("cryptography")
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rnv_mcp_identity.verifier import (
    JwtVerifier,
    StaticJwks,
    InMemoryReplayCache,
    jwk_thumbprint,
)
from rnv_mcp_identity.outcomes import Outcome, Reason
from rnv_mcp_identity.engine import decide
from rnv_mcp_identity.identity import IdentityRequest
from rnv_mcp_identity.policy import IssuerRegistry, StaticPolicy

ISS = "https://control-plane.example"
AUD = "https://mcp.example/finance"
SUB = "wimse://example/agent/report-bot"
CTRL = "https://example/principal/acme-ops"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def ed() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def pub_jwk(priv: Ed25519PrivateKey) -> dict:
    raw = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "alg": "EdDSA"}


def mint_id(issuer_priv, holder_jwk, *, aud=AUD, exp_delta=300, nbf=None, jti="id-1"):
    now = int(time.time())
    payload = {
        "iss": ISS, "sub": SUB, "controller": CTRL, "aud": aud,
        "iat": now, "exp": now + exp_delta, "jti": jti,
        "cnf": {"jkt": jwk_thumbprint(holder_jwk)},
    }
    if nbf is not None:
        payload["nbf"] = nbf
    return jwt.encode(payload, issuer_priv, algorithm="EdDSA", headers={"kid": "iss-1"})


def mint_proof(holder_priv, holder_jwk, token, *, ath=None):
    now = int(time.time())
    a = ath if ath is not None else _b64url(hashlib.sha256(token.encode()).digest())
    payload = {"ath": a, "iat": now, "exp": now + 120, "jti": "proof-1"}
    return jwt.encode(payload, holder_priv, algorithm="EdDSA",
                      headers={"jwk": holder_jwk, "typ": "wpt+jwt"})


def verifier(issuer_priv, **kw) -> JwtVerifier:
    return JwtVerifier(jwks=StaticJwks({ISS: issuer_priv.public_key()}), **kw)


def unverified(token) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


# --- the good path ---

def test_valid_token_and_proof_succeeds():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.ok


# --- step 1: signature ---

def test_tampered_signature_is_signature_invalid():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    bad = tok[:-3] + ("aaa" if not tok.endswith("aaa") else "bbb")
    r = verifier(ik).verify(token=bad, proof=pf, claims=unverified(tok), audience=AUD)
    assert (r.ok, r.reason) == (False, Reason.SIGNATURE_INVALID)


def test_wrong_issuer_key_is_signature_invalid():
    ik, other, hk = ed(), ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    r = verifier(other).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.SIGNATURE_INVALID


# --- step 2: temporal ---

def test_expired_token():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj, exp_delta=-10); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.TOKEN_EXPIRED


def test_not_yet_valid_token():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj, nbf=int(time.time()) + 3600); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.TOKEN_NOT_YET_VALID


# --- step 3: audience ---

def test_wrong_audience():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj, aud="https://mcp.example/other"); pf = mint_proof(hk, hj, tok)
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.AUDIENCE_MISMATCH


# --- step 4: proof of possession ---

def test_missing_proof_is_proof_invalid():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)
    r = verifier(ik).verify(token=tok, proof=None, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.PROOF_INVALID


def test_proof_with_unbound_key_is_proof_invalid():
    ik, hk, wrong = ed(), ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)                      # cnf binds to hk
    pf = mint_proof(wrong, pub_jwk(wrong), tok)  # but proof signed by a different key
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.PROOF_INVALID


def test_proof_bound_to_other_token_is_proof_invalid():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)
    other = mint_id(ik, hj, jti="id-2")
    pf = mint_proof(hk, hj, other)            # ath binds to a different token
    r = verifier(ik).verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert r.reason is Reason.PROOF_INVALID


def test_proof_not_required_allows_without_proof():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj)
    r = verifier(ik, require_proof=False).verify(
        token=tok, proof=None, claims=unverified(tok), audience=AUD)
    assert r.ok


# --- step 5: replay ---

def test_replay_detected_on_second_use():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    v = verifier(ik, replay_cache=InMemoryReplayCache())
    first = v.verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    second = v.verify(token=tok, proof=pf, claims=unverified(tok), audience=AUD)
    assert first.ok
    assert second.reason is Reason.REPLAY_DETECTED


# --- end to end through the engine ---

def test_engine_allows_valid_with_real_verifier():
    ik, hk = ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(hk, hj, tok)
    req = IdentityRequest("read_report", {}, AUD, identity_token=tok, proof=pf)
    d = decide(
        req,
        issuers=IssuerRegistry([ISS]),
        verifier=verifier(ik),
        policy=StaticPolicy({(SUB, CTRL, AUD): {"tool:read_report"}}),
    )
    assert d.outcome is Outcome.ALLOW
    assert d.identity.sub == SUB


def test_engine_denies_bad_proof_with_real_verifier():
    ik, hk, wrong = ed(), ed(), ed(); hj = pub_jwk(hk)
    tok = mint_id(ik, hj); pf = mint_proof(wrong, pub_jwk(wrong), tok)
    req = IdentityRequest("read_report", {}, AUD, identity_token=tok, proof=pf)
    d = decide(
        req,
        issuers=IssuerRegistry([ISS]),
        verifier=verifier(ik),
        policy=StaticPolicy({(SUB, CTRL, AUD): {"tool:read_report"}}),
    )
    assert d.outcome is Outcome.DENY
    assert d.reason is Reason.PROOF_INVALID
RNV_FILE_EOF

cat > 'examples/README.md' <<'RNV_FILE_EOF'
# Demo: an MCP server that resolves or refuses

This wires `IdentityMiddleware` onto a real FastMCP server with two tools and
shows the layer allowing one call and refusing three, each for its own reason.

## What it proves

The server grants the demo agent `tool:read_*` and nothing else. So:

| call | identity | result |
|---|---|---|
| `read_report` | valid token + proof, in scope | **allow** |
| `delete_report` | valid token + proof, out of scope | refuse: `capability_denied` |
| `read_report` | no identity headers | refuse: `identity_absent` |
| `read_report` | valid token, tampered proof | refuse: `proof_invalid` |

Nothing reaches a tool body without a verified, authorized identity.

## Run it in-process (no network)

```
pip install -e ".[dev,verify,fastmcp]"
python -m pytest -q tests/test_demo_inprocess.py
```

The in-process test injects the headers directly (the in-memory transport has no
HTTP layer) and drives the server through the FastMCP client.

## Run it over HTTP (the real wire path)

```
python examples/demo_server.py        # terminal 1
python examples/demo_client_http.py   # terminal 2
```

## The wire format (v0)

`identity_kit.headers_for` is the spec: the identity token rides in the
`mcp-agent-identity` header and the proof in `mcp-agent-proof`. The proof is a
WPT-style JWS whose protected header carries the holder's public JWK and whose
`ath` claim is `base64url(sha256(identity_token))`, binding the proof to that
exact token. A stolen token alone cannot act: the caller must also hold the key
the token's `cnf` commits to.
RNV_FILE_EOF

cat > 'examples/demo_client_http.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
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
RNV_FILE_EOF

cat > 'examples/demo_server.py' <<'RNV_FILE_EOF'
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
RNV_FILE_EOF

cat > 'examples/identity_kit.py' <<'RNV_FILE_EOF'
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Christian Smith (RNVizion)
"""Demo identity kit: deterministic keys and token/proof minting shared by the
server, the HTTP client, and the in-process test. DEMO ONLY; the private keys
are derived from fixed, public seeds and are not secret.

This module is also the de facto v0 wire spec: `headers_for` shows exactly which
headers carry the identity token and its proof, and `mint_proof` shows the `ath`
binding.
"""
from __future__ import annotations

import base64
import hashlib
import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from rnv_mcp_identity import jwk_thumbprint
from rnv_mcp_identity.adapters.fastmcp_middleware import IDENTITY_HEADER, PROOF_HEADER

ISS = "https://issuer.demo.rnvizion.dev"
AUD = "https://mcp.demo.rnvizion.dev"
SUB = "wimse://demo/agent/report-bot"
CTRL = "https://demo/principal/acme-ops"

# Fixed, public seeds -> deterministic keys shared across processes. DEMO ONLY.
ISSUER_PRIV = Ed25519PrivateKey.from_private_bytes(bytes(range(0, 32)))
HOLDER_PRIV = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
ISSUER_PUBLIC = ISSUER_PRIV.public_key()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def holder_jwk() -> dict:
    raw = HOLDER_PRIV.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw), "alg": "EdDSA"}


def mint_identity(*, jti: str = "demo-1", exp_delta: int = 300) -> str:
    now = int(time.time())
    payload = {
        "iss": ISS, "sub": SUB, "controller": CTRL, "aud": AUD,
        "iat": now, "exp": now + exp_delta, "jti": jti,
        "cnf": {"jkt": jwk_thumbprint(holder_jwk())},
    }
    return jwt.encode(payload, ISSUER_PRIV, algorithm="EdDSA", headers={"kid": "demo-iss"})


def mint_proof(identity_token: str) -> str:
    now = int(time.time())
    ath = _b64url(hashlib.sha256(identity_token.encode()).digest())
    payload = {"ath": ath, "iat": now, "exp": now + 120, "jti": "proof-demo"}
    return jwt.encode(payload, HOLDER_PRIV, algorithm="EdDSA",
                      headers={"jwk": holder_jwk(), "typ": "wpt+jwt"})


def headers_for(identity_token: str, proof: str) -> dict:
    """The v0 wire format: token and proof ride in two request headers."""
    return {IDENTITY_HEADER: identity_token, PROOF_HEADER: proof}
RNV_FILE_EOF

cat > '.github/workflows/ci.yml' <<'RNV_FILE_EOF'
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    name: ${{ matrix.os }} py${{ matrix.python-version }}
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        python-version: ["3.10", "3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install (crypto and test extras)
        run: pip install -e ".[dev,verify]"
      - name: Run the suite
        run: python -m pytest -q

  demo:
    name: demo (in-process)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install (with FastMCP)
        run: pip install -e ".[dev,verify,fastmcp]"
      - name: Run the demo test
        run: python -m pytest -q tests/test_demo_inprocess.py
RNV_FILE_EOF

cat > 'AAIF-READINESS.md' <<'RNV_FILE_EOF'
# rnv-mcp-identity: AAIF Readiness Dossier

*Working draft. Not yet submitted. This document maps the project to the Agentic
AI Foundation's published intake requirements and Project Lifecycle Policy
(effective March 18, 2026), records honestly what is true today, and names the
gaps that must close before a submission is warranted.*

The discipline that runs through the code runs through this document too: state
what resolves, refuse to claim what doesn't, and never guess. Where a requirement
is not yet met, it says so.

---

## Readiness verdict (read this first)

**Current status: pre-submission.** The project does not yet meet the Growth
Stage acceptance criteria, and submitting now would be premature.

Three criteria are unmet today:

1. **Production adoption at scale.** The Growth bar asks a project to document
   successful production use at wide scale. rnv-mcp-identity was published
   recently as a reference implementation and has no production adopters yet.
2. **Maintainer diversity and contribution flow.** The project is solo-built.
   There is one maintainer and no external merged contributions yet.
3. **A Technical Committee sponsor.** None identified. Growth Stage requires a TC
   sponsor to champion and mentor the project.

Everything else, license, public repo, automated validation and release, a
public contribution process, an issue tracker, a documented spec, named
dependencies, is either in place or is a governance file this dossier's checklist
schedules. **Target stage when ready: Growth.** The growth plan below addresses
the three gaps directly.

---

## What this project is

rnv-mcp-identity is an open-source reference implementation of an identity and
authorization layer for MCP servers. It answers one question on every tool call:
is this caller who it claims to be, and is this specific action within what it's
allowed to do? The answer is exactly one of three outcomes, **allow**, **deny**,
or **unknown**, and an unknown caller never acts. That is the project's thesis:
*resolve or refuse, never guess.*

It implements three trust layers that a single deployment can resolve on its own:

- **L1, identity provenance:** who is calling, and from which recognized authority.
- **L2, verification:** cryptographic proof the caller holds the key its identity
  commits to (holder-of-key, not bearer), within a valid window, for this server.
- **L3, authorization:** whether the verified caller's declared capabilities cover
  the specific action, under a declarative, deny-by-default policy.

It composes on existing standards rather than reinventing them: the MCP
authorization model, WIMSE-style workload identity, RFC 7800 key confirmation,
RFC 7638 thumbprints, and EAT-style attestation. The project's own contribution
is the composition, the per-tool capability model, and the resolve/refuse/unknown
semantics, expressed as MCP middleware.

This project is the reference-implementation arm of a broader initiative (AIII).
Layers L4 and L5, structural enforcement and cross-organization behavioral trust,
are deliberately **out of scope** for this codebase: they cannot be resolved by a
single operator. That boundary is precisely why a neutral foundation matters, and
it's the honest reason this work belongs in an AAIF conversation rather than a
single vendor's repo.

---

## Proposal fields (mapped to AAIF's intake requirements)

The Project Lifecycle Policy enumerates the information a submission must provide.
Each is answered here as it stands today.

| Required field | Current answer |
|---|---|
| **Project name** | rnv-mcp-identity (working name; may be renamed before submission) |
| **Description: what it does** | An L1–L3 identity and authorization layer for MCP servers; resolve, refuse, or mark unknown on every tool call |
| **Description: why valuable** | A large share of deployed MCP servers accept tool calls without verifying caller identity. This is the missing, reusable safety pattern: holder-of-key agent identity plus deny-by-default per-tool authorization |
| **Origin and history** | Built under the RNVizion banner as a reference implementation composing IETF/WIMSE/OAuth building blocks; spec-first, then implementation, then a runnable demo |
| **Alignment with AAIF mission** | See "Alignment" below |
| **Relation to existing AAIF projects** | See "Relation to MCP" below |
| **Example use cases + evidence of adoption** | Use cases below are concrete; **adoption evidence is nascent and stated honestly as a gap** |
| **TC sponsor (if identified)** | None yet. Securing one is a growth-plan milestone |
| **OSI-approved permissive license** | Apache-2.0 |
| **Public repository** | github.com/RNVizion/rnv-mcp-identity (to confirm/finalize) |
| **Automated validation and delivery** | GitHub Actions: a test matrix (Linux + Windows, Python 3.10–3.12) plus a separate FastMCP demo job; the suite includes named eval gates for correct resolution, correct refusal, and no false refusal |
| **Release methodology** | SemVer with tagged releases; pre-1.0 while the wire format stabilizes (documented in the spec) |
| **Public contribution process for specs** | SPEC.md is versioned in-repo; changes proceed by pull request with rationale. Formalized in CONTRIBUTING.md (scheduled) |
| **Public issue tracker** | GitHub Issues |
| **External dependencies (and licenses)** | Core runtime: **zero dependencies.** Optional extras: PyJWT (MIT), cryptography (Apache-2.0 / BSD), FastMCP (Apache-2.0). Dev-only: pytest (MIT), Hypothesis (MPL-2.0). *Licenses to be re-verified at submission time.* |
| **Core maintainers** | Christian Smith (sole maintainer) |
| **Leadership and decision-making** | Currently single-maintainer; governance defines the path to shared, merit-based maintainership (scheduled in GOVERNANCE.md) |
| **Documented governance (GOVERNANCE.md)** | Scheduled (see checklist) |
| **Official communication channels** | GitHub Issues and Discussions to start; no chat channel yet |
| **Project website** | Planned at rnvizion.dev/aiii (not yet live) |
| **Social accounts** | RNVizion presence on dev.to and LinkedIn (optional field) |
| **Existing financial sponsorship** | None |
| **Infrastructure needs** | None from the foundation at this stage; CI runs on GitHub-hosted runners |
| **Desired stage (optional)** | Growth, once the three unmet criteria are addressed |

---

## Alignment with the AAIF mission

AAIF is aimed at agent standards and orchestration, including shared safety
patterns and interoperability. Agent identity and per-action authorization is one
of those shared safety patterns: every framework that lets an agent call a tool
faces the same question, and today most answer it ad hoc or not at all.

rnv-mcp-identity offers that pattern as a small, model-agnostic, reusable layer
with one stated rule, an unverified caller does not act. It is interoperable by
construction: it composes on already-published standards and rides MCP's existing
transport, so adopting it does not fork the protocol.

## Relation to MCP (a founding AAIF project)

MCP, donated to AAIF by Anthropic, standardizes how agents reach tools and
includes an OAuth-based authorization model. It intentionally leaves the
identity-and-policy details to deployments. This project sits exactly in that gap:
it does not replace MCP's authorization model, it composes with it and adds the
agent-identity provenance, holder-of-key verification, and declarative per-tool
policy that a deployment needs to actually decide a call. The relationship is
additive and dependent, MCP is the substrate, this is a layer on top.

## Example use cases

- **Guarding an MCP server:** refuse tool calls from agents that can't prove a
  recognized identity, while allowing those that can and are in scope.
- **Least-privilege tool access:** grant `tool:read_*` to a reporting agent and
  nothing else, deny-by-default, with the refusal reason machine-readable.
- **Stolen-token resistance:** a leaked identity token alone can't act; the caller
  must also hold the key the token commits to.
- **Auditability:** every allowed call is bound to a verified identity for the
  record.

**Adoption evidence, stated honestly:** the use cases are demonstrated by a
runnable demo and a gate-checked test suite, not yet by third-party production
deployments. Closing that gap is the heart of the growth plan.

---

## Readiness against Growth Stage acceptance criteria

| Criterion | Status | Note |
|---|---|---|
| TC sponsor to champion and mentor | **Not met** | None identified; outreach is a milestone |
| Growth plan demonstrating diverse maintainership | Partial | Plan exists (below); maintainer diversity is the goal, not the current state |
| Documented successful production use at wide scale | **Not met** | No production adopters yet |
| Ongoing flow of commits and merged contributions | Partial | Active commits by one maintainer; no external merges yet |
| Community participation sufficient for the plan | **Not met** | Community not yet formed |
| Apache-2.0 / OSI-approved permissive license | On track | Apache-2.0 (LICENSE scheduled) |
| Automated validation and release | **Met** | CI matrix + demo job + eval gates |
| Public spec, issue tracker, contribution process | Partial | Spec and tracker exist; CONTRIBUTING.md scheduled |

The pattern is clear: the engineering substrate is in good shape; the
community-and-adoption substrate does not yet exist. That is the normal state of a
new project, and it's exactly what the growth plan is for.

---

## Growth plan

The plan targets the three unmet criteria in order of leverage.

1. **Earn a credible adoption story.** Stand up a public, live demo deployment and
   publish the build narrative so others can adopt the pattern. Pursue at least a
   handful of real integrations into MCP servers and report them honestly,
   counts, not adjectives.
2. **Open the project to contributors.** Ship GOVERNANCE.md, CONTRIBUTING.md, and
   OWNERS.md that define how someone earns the commit bit, then label
   good-first-issues and review external PRs promptly. Diverse maintainership is
   earned by making contribution easy and review fast.
3. **Find a Technical Committee sponsor.** Engage the AAIF community (Discord,
   office hours, MCP Dev Summit) and the MCP maintainers, since this layer sits
   directly on MCP, to find a sponsor willing to mentor toward Growth.
4. **Keep the cadence visible.** Maintain a regular commit and release rhythm and
   a public roadmap, so "ongoing flow of contributions" is demonstrable rather
   than asserted.

## Readiness checklist (drives the work; submit only when the musts are green)

Governance and licensing (done this pass):
- [x] LICENSE (Apache-2.0) at repo root
- [x] Apache license headers on source files
- [x] GOVERNANCE.md: decision-making and the path to shared maintainership
- [x] CONTRIBUTING.md: how to contribute code and propose spec changes
- [x] OWNERS.md: current (and future emeritus) committers
- [x] SECURITY.md: how to report vulnerabilities
- [x] README points at the spec and the runnable in-repo demo (a live public deployment remains an adoption item below)

Adoption and community (must, takes time):
- [ ] A live, public demo deployment
- [ ] Documented real-world integrations, reported by count
- [ ] First external merged contribution
- [ ] At least one committer from a second organization (Impact-stage signal)

Process polish (should):
- [ ] Tagged SemVer release
- [ ] Published roadmap
- [ ] OpenSSF Best Practices badge
- [ ] Re-verify all dependency licenses

When the governance musts are green and the adoption musts show real, honest
progress, and a TC sponsor is in hand, the proposal moves from this dossier into
the AAIF issue form. Not before. If a future submission is judged "Too Early,"
the project addresses the stated gaps and reapplies after the three-month window,
exactly as the policy provides.

---

*Honesty note: this dossier claims no adoption it doesn't have and no governance
it hasn't written. Its value is in being accurate about where the project stands
and specific about what closing the distance requires.*
RNV_FILE_EOF

cat > 'CONTRIBUTING.md' <<'RNV_FILE_EOF'
# Contributing

Thanks for considering a contribution. This project values correctness and honesty
over speed: the whole point of the codebase is a system that resolves or refuses
rather than guessing, and contributions are held to that same bar.

## Development setup

The core library has no runtime dependencies. For development, install the extras:

```
pip install -e ".[dev,verify,fastmcp]"
```

Run the full suite:

```
python -m pytest -q
```

The suite runs on Linux and Windows across Python 3.10 through 3.12 in CI, plus a
separate FastMCP demo job.

## What a good contribution looks like

- **New behavior ships with tests.** Every decision path, especially refusal paths,
  needs coverage. The suite includes named eval gates for correct resolution,
  correct refusal, and the absence of false refusals; a change that touches decision
  logic should keep those green and add cases where relevant.
- **Refusals stay honest.** If the engine can't establish something, the outcome is
  `deny` or `unknown` with a machine-readable reason, never a silent allow. Don't
  add a path that guesses.
- **Keep the core dependency-free.** Runtime dependencies belong behind optional
  extras (`verify`, `fastmcp`), not in the core decision engine.

## Proposing a spec change

SPEC.md is versioned in the repository. If your change alters normative behavior or
the wire format:

1. Update SPEC.md in the same pull request as the implementation.
2. For wire-format changes, bump the version noted in the spec and update the
   reference example in `examples/`.
3. Explain the rationale in the pull request description.

Spec-affecting changes require maintainer approval (see GOVERNANCE.md).

## Pull request process

1. Fork and branch from `main`.
2. Make the change with tests; run the suite locally.
3. Sign your commits (Developer Certificate of Origin): `git commit -s`. This
   certifies you have the right to submit the work under the project's license.
4. Open a pull request. CI must pass. A committer reviews; lazy consensus governs
   merging (see GOVERNANCE.md).

## Reporting bugs and security issues

Functional bugs go in the public issue tracker. Security vulnerabilities do **not**;
see SECURITY.md for private reporting.
RNV_FILE_EOF

cat > 'GOVERNANCE.md' <<'RNV_FILE_EOF'
# Governance

rnv-mcp-identity is an open-source project released under Apache-2.0. This
document describes how decisions are made and how responsibility is shared. It
describes the project as it actually is today, and the path by which that changes.

## Current state: single maintainer

The project currently has one maintainer, listed in OWNERS.md. Being honest about
this matters: there is no committee yet, and pretending otherwise would help no
one. The maintainer sets technical direction, reviews and merges contributions,
and is accountable for releases and security response.

This is a starting point, not the intended end state. The explicit goal is to grow
into shared, merit-based maintainership across more than one person and, in time,
more than one organization.

## Roles

- **Contributor:** anyone who opens an issue or a pull request. No prior standing
  required.
- **Committer:** a contributor trusted with the commit bit, listed in OWNERS.md.
  Committers review and merge contributions.
- **Maintainer:** a committer who also sets direction and has final say on
  unresolved disputes. Today there is one.

## How decisions are made

Most decisions are made in the open on pull requests and issues, by lazy
consensus: a change merges when CI passes and no committer objects within a
reasonable review window. Substantive disagreements are resolved by discussion; if
consensus can't be reached, the maintainer decides and records why.

Changes to the wire format or the spec's normative behavior require explicit
maintainer approval and a versioned update to SPEC.md in the same change. See
CONTRIBUTING.md for the spec-change process.

## Becoming a committer

Committers are recognized for sustained, high-quality contribution, code, review,
docs, or triage, not for a single large pull request. The path:

1. Contribute consistently and well over time.
2. Get nominated by an existing committer or the maintainer.
3. Be approved by the existing committers and the maintainer.

New committers are added to OWNERS.md. As the number of committers grows beyond one
maintainer, decision-making moves from "the maintainer decides" to "committers
decide by consensus," and this document will be updated to match.

## Changing this document

Governance changes by pull request to this file, approved by the maintainer (and,
once there is more than one, by committer consensus). The intended direction is
toward multi-person and multi-organization maintainership.

## License and intellectual property

The project is licensed under Apache-2.0. Contributions are accepted under the same
license via Developer Certificate of Origin sign-off (see CONTRIBUTING.md).

Forward note, stated honestly: this project aspires to become a foundation-hosted
project (see AAIF-READINESS.md). If it is ever accepted into a foundation such as
the AAIF, that foundation's technical charter and IP policy would govern, and this
document would be superseded by the chartered governance at that time. Until then,
this is the governance in force.

## Code of conduct

The project follows the Contributor Covenant. Be respectful; assume good faith;
keep it about the work.
RNV_FILE_EOF

cat > 'OWNERS.md' <<'RNV_FILE_EOF'
# Owners

Current committers and maintainers of rnv-mcp-identity. See GOVERNANCE.md for what
these roles mean and how one becomes a committer.

## Maintainers

- Christian Smith (@RNVizion)

## Committers

- Christian Smith (@RNVizion)

## Emeritus

- None yet.

*The project currently has a single maintainer. Growing this list across people and
organizations is an explicit goal; see AAIF-READINESS.md.*
RNV_FILE_EOF

cat > 'PRIOR-ART.md' <<'RNV_FILE_EOF'
# Prior Art

*A survey of what already exists, so the spec builds on it and claims only the gap. Snapshot: June 2026. These are Internet-Drafts; they expire and revise on a roughly six-month cycle, so re-check before the AAIF proposal.*

This document grounds the scope and dependency choices in [SPEC.md](../SPEC.md). The short version: nearly everything below our gap already has a home at the IETF, in the WIMSE working group. We cite far more than we build.

## What MCP already provides

MCP has an authorization specification. A protected server acts as an OAuth 2.1 resource server, a client acts as the OAuth client, and a user delegates access through an authorization server (often an existing IdP). The mandatory pieces are PKCE, Protected Resource Metadata (RFC 9728) for discovery, and Resource Indicators (RFC 8707) to bind a token to its intended server. The 2026 revisions added role-based tool access and aligned more closely with OAuth and OpenID Connect.

So delegated authorization is solved and standardized. We compose on top of it; we do not rebuild it.

## What MCP leaves open

Two gaps, both named by the spec's own analysts:

1. **Caller identity.** OAuth authorizes a user's delegation, but PKCE protects the token exchange without authenticating the caller itself. Strong identity for a non-human client depends on infrastructure-asserted identity. That is L1 and L2: who is this agent, who controls it, and is the claim real.
2. **Scope semantics.** MCP does not define a scope convention, so implementers each invent their own. That is L3 with no shared shape.

The gap is real at scale: as of 2026, only about 8.5% of MCP servers implement the mandatory OAuth 2.1, while the public registry has grown past 9,400 servers.

## The IETF landscape (WIMSE)

The relevant working group is WIMSE (Workload Identity in Multi-System Environments). It produces the workload-identity primitives and is actively extending them to AI agents.

### WIMSE core primitives — reuse for L1 and L2

| Draft | What it gives us | Layer |
|---|---|---|
| `draft-ietf-wimse-arch` | The multi-system workload-identity architecture everything sits in | foundation |
| `draft-ietf-wimse-identifier` | How to name a workload or agent; SPIFFE-ID compatible | L1 |
| `draft-ietf-wimse-workload-creds` | The credential a workload presents | L1 / L2 |
| `draft-ietf-wimse-wpt` | Workload Proof Token: proves possession of the key behind a Workload Identity Token | L2 |
| `draft-ietf-wimse-http-signature` | Workload-to-workload auth via HTTP Message Signatures (RFC 9421) | L2 |
| `draft-ietf-wimse-workload-identity-practices` | How workloads get identities without managing long-lived secrets | L1 (practice) |

### Agent-specific drafts — align and reuse concepts

| Draft | What it gives us | Layer |
|---|---|---|
| `draft-ni-wimse-ai-agent-identity` | Applies WIMSE to agents; a Dual-Identity Credential binds agent identity to owner identity | L1 (who controls it) |
| `draft-messous-eat-ai` | An Entity Attestation Token profile for autonomous AI agents | L2 (attestation) |
| `draft-klrc-aiagent-auth` | Agent authn/authz best practices built on WIMSE and OAuth, deliberately not inventing new protocols | L1–L3 umbrella |
| `draft-rosenberg-cheq` | A human-in-the-loop confirmation protocol for agent decisions | L4-adjacent |

Agentic JWT adds agent claims to JWTs but can't attenuate authority without minting a new token that breaks the chain; SCIM-for-agents covers provisioning lifecycle, not runtime authorization. Both are adjacent, not core.

### OAuth delegation drafts — the L3 to L4 edge

| Draft | What it gives us | Layer |
|---|---|---|
| `draft-ietf-oauth-identity-chaining` | Identity and authorization chaining across domains | L4 edge |
| `draft-ietf-oauth-transaction-tokens` | Short-lived tokens across a call chain inside a trust domain | L3 / L4 |

## The confirmed gap

The frontier is the cross-domain, multi-hop layer, and the drafts say so plainly. AIMS composes WIMSE, SPIFFE, and OAuth, but its authorization section reads "TODO Security." A survey of the field (the AIP preprint) finds that no single draft yet provides holder-attenuable delegation, cross-protocol bindings, and provenance in one protocol.

That frontier is L4 and L5. It's exactly where our scope stops, and where the larger AIII argument lives.

## What this means for the build

- **Reuse:** WIMSE identifier and Workload Identity Token (L1), Workload Proof Token and the EAT attestation profile (L2), HTTP Message Signatures / RFC 9421 (verification), the Dual-Identity Credential pattern (owner binding), and MCP's OAuth 2.1 resource-server model (user delegation).
- **Build:** the concrete MCP middleware that composes these, maps identity to a declarable per-tool capability model, and wires explicit resolve / refuse / unknown into the call path. No surveyed draft targets MCP, and none wires the refusal semantics in.
- **Conform:** to `draft-klrc-aiagent-auth`, which shares our stance of using existing standards and naming gaps rather than inventing protocols.

## References

All drafts are at the IETF Datatracker under `https://datatracker.ietf.org/doc/<name>/`:

- WIMSE: `draft-ietf-wimse-arch`, `draft-ietf-wimse-identifier`, `draft-ietf-wimse-workload-creds`, `draft-ietf-wimse-wpt`, `draft-ietf-wimse-http-signature`, `draft-ietf-wimse-workload-identity-practices`
- Agents: `draft-ni-wimse-ai-agent-identity`, `draft-messous-eat-ai`, `draft-klrc-aiagent-auth`, `draft-rosenberg-cheq`
- OAuth delegation: `draft-ietf-oauth-identity-chaining`, `draft-ietf-oauth-transaction-tokens`
- MCP authorization: `https://modelcontextprotocol.io/specification` (Authorization section)
- AIP / AIMS / Agentic JWT / SCIM-for-agents: drawn from the AIP preprint survey of agent-identity proposals
RNV_FILE_EOF

cat > 'README.md' <<'RNV_FILE_EOF'
# rnv-mcp-identity

An identity and authorization layer for MCP servers. On every tool call it asks one
question, is this caller who it claims to be, and is this action within what it's
allowed to do?, and answers with exactly one of three outcomes:

- **allow:** identity resolved, verified, and the action is in scope.
- **deny:** verified, but out of scope; or an identity was presented and failed
  verification.
- **unknown:** identity could not be established at all. The call is refused.

An unknown caller never acts. That rule is the whole project: *resolve or refuse,
never guess.*

> Status: reference implementation, pre-1.0, Apache-2.0. This is the
> reference-implementation arm of the AIII initiative. It composes on existing
> standards (the MCP authorization model, WIMSE workload identity, RFC 7800 key
> confirmation, RFC 7638 thumbprints, EAT attestation) rather than replacing them.

## What's here

- **`src/rnv_mcp_identity/`** — the library: a framework-agnostic decision engine
  (L1 identity, L2 verification, L3 authorization) plus a FastMCP middleware
  adapter. The core has no runtime dependencies.
- **`examples/`** — a runnable FastMCP server guarded by the layer, an in-process
  test, and an HTTP client. Start here to watch it allow one call and refuse three.
- **`SPEC.md`** — the normative spec: the decision sequence, the capability and
  policy model, the threat model, and the v0 wire format.
- **`AAIF-READINESS.md`** — an honest dossier on whether this belongs in a
  foundation, and what's missing before it would.

## Quickstart

```
pip install -e ".[dev,verify,fastmcp]"
python -m pytest -q                                # the full suite
python -m pytest -q tests/test_demo_inprocess.py   # just the guarded-server demo
```

Run the demo over real HTTP:

```
python examples/demo_server.py        # terminal 1
python examples/demo_client_http.py   # terminal 2
```

## The wire format (v0)

The identity token rides in the `mcp-agent-identity` header and a holder-of-key
proof in `mcp-agent-proof`. The proof binds to the exact token, so a stolen token
alone can't act. The reference client in `examples/` is the normative example; see
SPEC.md section 10.

## Docs

- `SPEC.md` — the specification
- `ROADMAP.md` — where this is going
- `PRIOR-ART.md` — what it builds on, and the gap it fills
- `GOVERNANCE.md` — how decisions are made
- `CONTRIBUTING.md` — how to help
- `SECURITY.md` — how to report vulnerabilities
- `AAIF-READINESS.md` — foundation-readiness assessment

## License

Apache-2.0. See `LICENSE`.

## A note on affiliation

This project *aspires* to become a foundation-hosted project and is not affiliated
with, endorsed by, or accepted into the AAIF or the Linux Foundation. See
AAIF-READINESS.md for an honest account of where it stands.
RNV_FILE_EOF

cat > 'ROADMAP.md' <<'RNV_FILE_EOF'
# AIII — Build Roadmap

From a draft proposal to a working MCP identity layer, submitted where MCP already lives.

**End goal:** an open-source L1–L3 identity-and-authorization reference implementation for MCP servers that resolves what it can prove and refuses the rest, credible enough to propose to the Agentic AI Foundation (AAIF).

This is a living plan. Phases and tasks change as the work teaches us.

---

## P0: Stand up the front door

*Goal: the proposal is live and linkable, and the build has a home.*

**Done when:** the AIII page is live off the blog feed, and this repo exists with a README and license.

- [ ] Publish the AIII page at its own path (e.g. `/aiii`), outside `blog/**`, with its OG image
- [ ] Add the resume bottom-line link to the live AIII page
- [ ] Confirm the page is excluded from the RSS feed and the Ask the Corpus ingest
- [ ] Create the implementation repo (working name: `rnv-mcp-identity`)
- [ ] Write README v0: thesis, scope (L1–L3), explicit non-goals (L4–L5)
- [ ] Add LICENSE: Apache-2.0, to match MCP and AAIF norms
- [ ] Drop this roadmap into the repo as `ROADMAP.md`

## P1: Resolve before building

*Goal: know exactly what to build, and what to refuse, grounded in prior art.*

**Done when:** a written spec exists that maps to existing standards and defines the resolve / refuse semantics plus eval gates.

- [ ] Read the active IETF agent-identity drafts; one-line summary of each and the layer it covers
- [ ] Map MCP's current auth spec and the ~2,000-servers gap: what exists vs what's missing
- [ ] Decide reuse vs build: pin to OAuth 2.0 / WIMSE / HTTP Message Signatures (RFC 9421); no new crypto
- [ ] Write `SPEC.md`: the identity data model, the L1 / L2 / L3 operations, the refusal and unknown states
- [ ] Define three eval gates: correct-resolution, correct-refusal, false-refusal
- [ ] Write the threat model: identity spoofing, scope escalation, audit evasion
- [ ] Mark the L4 boundary explicitly in the spec

## P2: Identity that resolves

*Goal: running code that issues and verifies an agent identity for an MCP server.*

**Done when:** a demo server verifies a valid identity and refuses an invalid one, under CI.

- [ ] Scaffold a FastMCP-based middleware skeleton (Codespaces, mobile-friendly)
- [ ] Implement L1: attach a verifiable agent identity (who controls this agent)
- [ ] Implement L2: verify the identity claim (signature / credential check)
- [ ] Refusal path: unknown or invalid identity returns an explicit deny, never a guess
- [ ] pytest + hypothesis tests; wire GitHub Actions CI
- [ ] Pass the correct-resolution and correct-refusal gates

## P3: Authorization that refuses

*Goal: scope what an agent may do, enforce it per call, refuse out of scope.*

**Done when:** out-of-scope calls are denied, valid calls pass, and the false-refusal gate stays green.

- [ ] Define the capability / scope model (what the agent is cleared to do)
- [ ] Enforce authorization on every tool call
- [ ] Implement explicit allow / deny / unknown outcomes: resolve or refuse, never guess
- [ ] Add the false-refusal gate: valid identities and scopes must not be wrongly denied
- [ ] Document in code exactly where L4 (cross-system enforcement) would begin
- [ ] Tag a `v0.1` release

## P4: Make it provable

*Goal: anyone can see it resolve and refuse in minutes.*

**Done when:** a public quickstart or demo runs, and the docs read clean to an outside engineer.

- [ ] Build a runnable demo (Hugging Face Space or a one-command quickstart)
- [ ] Record a short walkthrough: resolve, then refuse
- [ ] Polish README, SPEC, and threat model for an external reader
- [ ] Add the "what this does NOT do" section (L4–L5), stated plainly
- [ ] Cross-link the AIII page and the repo both ways

## P5: Earn the submission

*Goal: turn the build into a credible AAIF project proposal.*

**Done when:** the proposal is submitted through the AAIF process.

- [ ] Check against AAIF criteria: OSI license, open governance, contribution guidelines, adoption signal
- [ ] Add `CONTRIBUTING.md` and a lightweight governance note
- [ ] Share for prior-art feedback (MCP community, relevant W3C / IETF group); log responses
- [ ] Write the AAIF project proposal: problem, scope, why neutral, why now
- [ ] Submit via the AAIF GitHub proposal process
- [ ] Capture the journey as a build post: the spoke graduates into an essay
RNV_FILE_EOF

cat > 'SECURITY.md' <<'RNV_FILE_EOF'
# Security Policy

This project implements identity and authorization logic. Handle vulnerabilities
with care.

## Supported versions

The project is pre-1.0. Security fixes target `main` and the latest release. There
is no long-term-support branch yet.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.**

Report privately through GitHub's private vulnerability reporting (the "Report a
vulnerability" button under the repository's Security tab). If that is unavailable,
contact the maintainer directly at the address listed on the project website.

Please include: a description of the issue, steps to reproduce, the affected version
or commit, and the impact as you see it.

## What to expect

- Acknowledgment of your report, normally within a week.
- A coordinated fix: the maintainer will work on a remedy and agree on a disclosure
  timeline with you before any public disclosure.
- Credit for the report, if you'd like it.

## A note for deployers

This is a reference implementation, not a turnkey security product. If you deploy
it, you are responsible for reviewing it against your own threat model, choosing
your trusted issuers and policy, and operating key material safely. The spec's
threat-model section is a starting point, not a guarantee.
RNV_FILE_EOF

cat > 'SPEC.md' <<'RNV_FILE_EOF'
# Specification: rnv-mcp-identity

*Working draft. This revision pins the scope, the dependency map, the refusal semantics, the identity data model, and the decision sequence; the capability naming, policy format, and wire format are stubbed for the next pass. Grounded in [docs/PRIOR-ART.md](docs/PRIOR-ART.md).*

## The rule

Resolve or refuse, never guess. Every decision this layer makes resolves to one of three outcomes: allow, deny, or unknown. There is no implicit allow. Absence of a credential is unknown, not permitted. A false yes is the single failure mode this layer exists to never produce.

## 1. Scope

This layer covers the parts of agent identity that a single MCP deployment can actually resolve:

- **L1, identity provenance:** who issued this agent, and who controls it.
- **L2, verification:** is the identity claim cryptographically real.
- **L3, authorization:** what the agent is scoped to do, enforced on every tool call.

It explicitly does **not** cover:

- **L4, structural enforcement:** holding an agent to its scope across systems.
- **L5, cross-organizational behavioral trust:** trusting an agent beyond the deployment that made it.

L4 and L5 are out of scope on purpose. No single deployment can operate cross-organizational trust, so this layer marks the boundary and stops (see section 9). Closing it is the AIII argument, not this code.

## 2. Position in the MCP stack

This is not a replacement for MCP's authorization spec; it sits alongside it. MCP's OAuth 2.1 resource-server model answers "did a user delegate this access." This layer answers the question OAuth leaves open: "who is the non-human caller, and what is it cleared to do." The two compose: a request can carry both a user-delegated OAuth token and a verified agent identity, and both must hold for an allow.

## 3. Dependency map

The build rule is visible at a glance: most concerns are reused, and the small set we build is the MCP-specific composition, the capability model, and the refusal path.

| Concern | Layer | Approach | Source |
|---|---|---|---|
| Agent identifier | L1 | Reuse | WIMSE Workload Identifier (SPIFFE-compatible) |
| Who controls the agent | L1 | Reuse pattern | Dual-Identity Credential (`draft-ni-wimse-ai-agent-identity`) |
| Identity token / credential | L1 / L2 | Reuse | WIMSE Workload Identity Token + Workload Credentials |
| Proof of possession | L2 | Reuse | WIMSE Workload Proof Token |
| Agent attestation | L2 | Reuse | EAT profile for autonomous agents (`draft-messous-eat-ai`) |
| Wire verification | L2 | Reuse | HTTP Message Signatures (RFC 9421) |
| User delegation | adjacent | Reuse | MCP OAuth 2.1 RS model (PRM 9728, Resource Indicators 8707, PKCE) |
| Capability / scope model | L3 | **Build** | Declarable per-tool capabilities with a defined naming convention |
| Refusal semantics | L1–L3 | **Build** | Explicit allow / deny / unknown on every call |
| MCP composition | L1–L3 | **Build** | Middleware wiring the above onto an MCP server |
| Multi-hop / cross-domain delegation | L4 | Out of scope | See `draft-ietf-oauth-identity-chaining`, transaction-tokens |

No new cryptography. Where a draft already specifies a primitive, this layer adopts it rather than competing, conforming to the stance of `draft-klrc-aiagent-auth`.

## 4. Identity data model

The identity is a signed token the agent presents with a request. It reuses registered JWT and EAT claims for the envelope, and adds the minimum agent-specific claims the gap requires. It asserts *who*, not *what the agent may do*: authorization (L3) is resolved separately, so capabilities can change without re-minting identity. This avoids the immutability trap that limits agent-claims-in-JWT approaches, where a delegatee can't attenuate authority without breaking the cryptographic chain.

### 4.1 The agent identity token

Envelope, reusing registered claims:

| Claim | Meaning | Source |
|---|---|---|
| `iss` | the identity authority that minted this identity (the control plane) | JWT |
| `sub` | the agent's stable identifier, as a WIMSE workload identifier (SPIFFE-compatible URI) | WIMSE identifier |
| `aud` | the MCP server(s) this identity is for; aligns with Resource Indicators | RFC 8707 |
| `iat` / `nbf` / `exp` | issued-at, not-before, expiry; identities are short-lived | JWT |
| `jti` | unique token id, for replay defense and audit | JWT |
| `cnf` | the proof-of-possession key the agent must prove it holds; binds L1 to L2 | RFC 7800 |

Agent-specific, the minimal addition:

| Claim | Meaning |
|---|---|
| `controller` | the verifiable identifier of the principal that operates this agent (the owner binding; see 4.2) |
| `agent_kind` | optional, coarse descriptor of the agent runtime; informational, never a trust input |

Capabilities are deliberately absent from the token. What the agent may do is resolved at decision time from policy keyed on `(sub, controller, aud)`. Identity says who; authorization says what, and the two move on different clocks.

### 4.2 The owner binding (Dual-Identity Credential)

L1 has two halves: who the agent is, and who controls it. The `controller` claim carries the second. Its trust comes from the issuer: by signing a token that names both `sub` and `controller`, the issuer (which has authority over both) vouches that this agent is operated by this principal. This is the Dual-Identity Credential pattern, reduced to its minimal viable form.

- **v0, issuer-asserted:** the issuer states the `controller` in the signed identity token. Trust derives from the issuer's authority; enough to attribute every action to a controlling principal.
- **Later, chained or co-signed:** the agent credential chains to, or is co-signed by, the controller's own credential, so the binding holds even where the issuer isn't trusted for that relationship. A strengthening, not required for v0.

The invariant that makes this useful: an allowed call is always attributable to a `(sub, controller)` pair. There is no anonymous agent action, which ties directly to the audit-evasion mitigation in section 8.

### 4.3 Verification inputs (how L2 consumes this)

The data model is shaped so L2 can verify without inventing anything:

- **Issuer signature:** verify the token signature against the issuer's published keys (JWKS). Establishes the token is authentic and unaltered.
- **Proof of possession:** the agent proves it holds the `cnf` key, via a WIMSE Workload Proof Token or an HTTP Message Signature (RFC 9421) over the request. Turns a stealable bearer token into a held credential.
- **Attestation, optional:** an EAT profile for the agent runtime, where a deployment wants assurance the agent is a genuine, un-tampered runtime and not merely a holder of keys.

### 4.4 Worked example (illustrative, non-normative)

```
// Agent identity token, decoded claims
{
  "iss":  "https://control-plane.example",
  "sub":  "wimse://example/agent/report-bot",
  "aud":  "https://mcp.example/finance",
  "controller": "https://example/principal/acme-ops",
  "agent_kind": "scheduled-report-runner",
  "cnf":  { "jkt": "NzbLsXh8u..." },   // thumbprint of the proof key
  "iat":  1751130000,
  "nbf":  1751130000,
  "exp":  1751130900,                  // 15-minute lifetime
  "jti":  "9f2c...e1"
}
```

The agent presents this token plus a proof: a signature over the request using the key whose thumbprint is in `cnf`. The layer verifies the issuer signature, checks `aud` matches this server, checks the proof against `cnf`, then resolves capabilities for `(sub, controller, aud)` from policy. Any failure resolves to `deny` or `unknown` per section 5; nothing defaults to allow.

## 5. Resolve / refuse / unknown

Every tool call passes through one decision with exactly three possible outcomes:

- **allow:** the identity resolved (L1), verified (L2), and the requested action is within the agent's authorized capabilities (L3). The call proceeds, bound to the verified identity for audit.
- **deny:** the identity resolved and verified, but the action is outside its capabilities; or an identity was presented and verification failed. The call is refused, with a machine-readable reason.
- **unknown:** the identity could not be resolved or verified at all (absent, malformed, unverifiable). The call is refused. The layer does not assume a default identity and does not infer a permission.

The invariant: `unknown` is never silently upgraded to `allow`. An unverified caller does not act. This is the opening rule made operational.

## 6. The decision sequence

One ordered pipeline runs on every tool call. The order is deliberate: resolve before verify before authorize, cheapest and most fundamental refusals first, and the authorize step is never reached without a verified identity. `unknown` can only be produced at the resolve stage, where nothing could be established; once a claim has been made and fails, the outcome is `deny`.

**Step 0, intake.** Extract the agent identity token and the request proof from the call (carriage is defined in section 10). If either is absent or unparseable, resolve to `unknown` (`identity_absent`, `identity_malformed`) and stop.

**Step 1, resolve (L1).** Decode the token without trusting it. If its issuer (`iss`) is not a recognized identity authority for this deployment, resolve to `unknown` (`issuer_unknown`) and stop. Otherwise read `sub` and `controller`; these stay claims until step 2 verifies them.

**Step 2, verify (L2).** In order, any failure resolving to `deny` and stopping:

- issuer signature invalid against the issuer's JWKS: `signature_invalid`
- outside the token's validity window (`nbf`..`exp`): `token_expired` / `token_not_yet_valid`
- `aud` does not match this server's canonical URI: `audience_mismatch`
- the request proof does not verify against the `cnf` key: `proof_invalid`
- `jti` already seen within its window, where replay defense is enabled: `replay_detected`

After step 2 the identity is verified: `sub` and `controller` are now trusted.

**Step 3, authorize (L3).** Map the tool call to the capability it requires. Resolve the agent's granted capabilities from policy, keyed on `(sub, controller, aud)`. If no policy resolves for the pair, deny by default (`no_policy`). If the required capability is not in the granted set, `deny` (`capability_denied`). Otherwise, `allow`.

**Step 4, bind.** On `allow`, bind `(sub, controller, jti)` to the execution context and the audit record before the tool runs, so every effect is attributable to a controlling principal.

### Outcome reference

| Reason | Outcome | Stage |
|---|---|---|
| `identity_absent`, `identity_malformed` | unknown | intake |
| `issuer_unknown` | unknown | resolve |
| `signature_invalid` | deny | verify |
| `token_expired`, `token_not_yet_valid` | deny | verify |
| `audience_mismatch` | deny | verify |
| `proof_invalid` | deny | verify |
| `replay_detected` | deny | verify |
| `no_policy`, `capability_denied` | deny | authorize |
| (all checks pass) | allow | authorize |

The split is the spec's spine: `unknown` means the layer couldn't establish who is calling; `deny` means it could, and a check failed. Neither ever becomes `allow` by default.

### Capability and policy model (L3)

The required capability for a tool call follows one convention in v0: `tool:<tool_name>`. The argument map is available to the resolver but is not part of the v0 capability; argument-scoped capabilities are a later extension.

A grant is either an exact capability or a single trailing-`*` prefix: `tool:read_report` (exact), `tool:read_*` (prefix), `tool:*` (the whole `tool` namespace), `*` (everything; discouraged, never implicit). Matching is exact-or-prefix only, with no other glob features, so a grant's reach is obvious on inspection.

Policy is a declarative document of rules. Each rule carries an optional `sub`, `controller`, and `audience` selector and a set of capability grants. A rule selects a request when every present selector equals the request's value; an absent selector matches any. A rule with all three is agent-specific; a rule with only `controller` and `audience` grants every agent under that controller. The capabilities granted to a principal are the union over all selecting rules. If no rule selects the principal, the outcome is `no_policy` (deny by default); if rules select but none covers the required capability, the outcome is `capability_denied`. Authority is only ever added by an explicit rule.

## 7. Eval gates

Correctness is measured in CI, not asserted. Three gates, mirroring the retrieval project's harness:

- **correct-resolution:** a valid, verifiable identity making an in-scope call is allowed.
- **correct-refusal:** an invalid or unverifiable identity, or an authenticated-but-unauthorized call, is denied or marked unknown; never allowed.
- **false-refusal:** a valid identity making an authorized call is never wrongly denied or marked unknown.

The third gate is load-bearing. Without it, a layer that refuses everything would pass `correct-refusal` trivially; `false-refusal` is what keeps the system honest as the rules grow.

## 8. Threat model

- **Identity spoofing:** a caller claims an identity it doesn't hold. Mitigated by proof-of-possession (WPT), attestation (EAT), and signature verification (RFC 9421) in step 2.
- **Token theft / replay:** a stolen token is reused. Mitigated by proof-of-possession (a bearer token alone is insufficient), short `exp` lifetimes, `aud` binding, and optional `jti` replay tracking.
- **Scope escalation:** an authenticated agent attempts actions beyond its capabilities. Mitigated by the step 3 capability check that denies by default.
- **Audit evasion:** actions taken without an attributable identity. Mitigated by the section 4.2 invariant: no `unknown` caller is allowed to act, so every allowed call binds to a `(sub, controller)` pair.

## 9. The L4 boundary

The boundary is the first multi-hop: when an agent must act on a second system on behalf of the first, or delegate attenuated authority across a trust domain. That needs holder-attenuable delegation and cross-protocol binding, which the field has no unified answer for yet (AIMS's authorization section reads "TODO Security"; the AIP survey finds no single draft that unifies it). This layer stops at the single-deployment edge and marks that edge explicitly in code, so the gap is visible rather than papered over.

## 10. Wire format (v0)

The carriage is pinned by the reference demo in `examples/`. The identity token rides in the `mcp-agent-identity` request header and the proof in `mcp-agent-proof`. The proof is a WPT-style JWS whose protected header carries the holder's public JWK and whose `ath` claim is `base64url(sha256(identity_token))`, binding the proof to that exact token; the proof verifies only when its JWK thumbprints to the token's `cnf.jkt`. The capability and policy model is pinned in section 6.

The planned hardening is RFC 9421 request binding: signing the HTTP method, path, and body into the proof so it attests to the specific request, not only the identity token. That tightens the L2/L4 seam and is the natural next revision.
RNV_FILE_EOF

cat > 'LICENSE' <<'RNV_FILE_EOF'
                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or Derivative
          Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work, excluding
          those notices that do not pertain to any part of the Derivative
          Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and do
          not modify the License. You may add Your own attribution notices
          within Derivative Works that You distribute, alongside or as an
          addendum to the NOTICE text from the Work, provided that such
          additional attribution notices cannot be construed as modifying
          the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions for
      use, reproduction, or distribution of Your modifications, or for any
      such Derivative Works as a whole, provided Your use, reproduction,
      and distribution of the Work otherwise complies with the conditions
      stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright 2026 Christian Smith (RNVizion)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
RNV_FILE_EOF

echo "repo written. next:  pip install -e \".[dev,verify,fastmcp]\" && python -m pytest -q"
