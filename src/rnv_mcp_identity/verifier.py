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
