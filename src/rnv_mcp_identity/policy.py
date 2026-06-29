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
