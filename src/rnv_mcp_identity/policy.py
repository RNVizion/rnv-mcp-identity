"""L1 issuer registry and L3 policy (SPEC section 6, steps 1 and 3)."""
from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional, Protocol, Tuple, runtime_checkable


class IssuerRegistry:
    """The identity authorities this deployment recognizes (L1, step 1)."""

    def __init__(self, issuers: Iterable[str] = ()) -> None:
        self._issuers = set(issuers)

    def is_recognized(self, issuer: Optional[str]) -> bool:
        return issuer is not None and issuer in self._issuers

    def add(self, issuer: str) -> None:
        self._issuers.add(issuer)


@runtime_checkable
class Policy(Protocol):
    """Resolves the capability set granted to (agent, controller) for a server.

    Returns None when no policy exists for the pair: the engine denies by
    default (SPEC section 6, step 3), never allows on missing policy.
    """

    def granted_capabilities(
        self, *, sub: str, controller: Optional[str], audience: str
    ) -> Optional[frozenset]: ...


class StaticPolicy:
    """A simple, real policy: an in-memory table keyed on (sub, controller, audience).

    Enough for tests and small deployments. Dynamic or external policy is a
    later drop-in behind the same Protocol.
    """

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


def default_capability_for(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """v0 capability naming convention: `tool:<tool_name>` (SPEC section 10)."""
    return f"tool:{tool_name}"
