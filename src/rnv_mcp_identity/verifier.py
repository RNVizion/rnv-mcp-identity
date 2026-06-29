"""L2 verification (SPEC section 6, step 2). The crypto seam.

The Verifier owns every deny-reason in step 2. The engine never inspects a
signature itself; it asks the Verifier and maps the result. This keeps the
crypto in one swappable place and the engine pure.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol, runtime_checkable

from .outcomes import Reason


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


class JwtVerifier:
    """Skeleton JWKS + proof-of-possession verifier.

    TODO(P2-2): implement, in order, each failure short-circuiting:
      1. issuer signature against JWKS   -> SIGNATURE_INVALID
      2. nbf / exp window                -> TOKEN_NOT_YET_VALID / TOKEN_EXPIRED
      3. aud == audience                 -> AUDIENCE_MISMATCH
      4. proof against cnf key (RFC 9421)-> PROOF_INVALID
      5. jti replay, if enabled          -> REPLAY_DETECTED
    Reuses WIMSE WPT / EAT / RFC 9421; no new crypto (SPEC section 3).
    """

    def __init__(self, *, jwks_resolver=None, replay_cache=None) -> None:
        self._jwks_resolver = jwks_resolver
        self._replay_cache = replay_cache

    def verify(self, *, token, proof, claims, audience) -> VerifyResult:
        raise NotImplementedError("JwtVerifier is implemented in P2-2")
