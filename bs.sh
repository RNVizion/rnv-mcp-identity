#!/usr/bin/env bash
# Bootstrap the rnv-mcp-identity scaffold. Run from an empty repo root.
set -euo pipefail

mkdir -p '.github/workflows'
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
"""Framework adapters. Importing a submodule here pulls its framework dependency."""
RNV_FILE_EOF

cat > 'src/rnv_mcp_identity/adapters/fastmcp_middleware.py' <<'RNV_FILE_EOF'
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

cat > 'tests/test_engine.py' <<'RNV_FILE_EOF'
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
      - name: Install (with crypto and test extras)
        run: pip install -e ".[dev,verify]"
      - name: Run the suite
        run: python -m pytest -q
RNV_FILE_EOF

echo "scaffold written. next:  pip install -e \".[dev,verify]\" && python -m pytest -q"
