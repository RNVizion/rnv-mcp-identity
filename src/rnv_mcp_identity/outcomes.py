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
