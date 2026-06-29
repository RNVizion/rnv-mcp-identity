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
