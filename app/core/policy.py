"""Scope model and scope-attenuation rules.

Scopes are explicit capabilities (`calendar.read`, `payments.transfer`).
Wildcards are deliberately unsupported so that containment is decidable by
simple set logic: a child delegation may only carry scopes that its parent
effectively conveys. This makes attenuation a pure function — deterministic
and exhaustively testable.
"""

from __future__ import annotations

from app.core.models import Scope


class ScopeSet:
    """An immutable set of scopes with deterministic ordering.

    Wraps `frozenset` but always iterates in sorted order so that any
    user-visible representation (logs, API responses, canonical forms) is
    stable and comparable.
    """

    __slots__ = ("_scopes",)

    def __init__(self, scopes: list[Scope] | set[Scope] | frozenset[Scope]) -> None:
        self._scopes: frozenset[Scope] = frozenset(scopes)

    @classmethod
    def from_strings(cls, raw: list[str] | tuple[str, ...]) -> ScopeSet:
        return cls({Scope.parse(s) for s in raw})

    def __contains__(self, scope: Scope) -> bool:
        return scope in self._scopes

    def __iter__(self):
        return iter(sorted(self._scopes, key=lambda s: (s.namespace, s.action)))

    def __len__(self) -> int:
        return len(self._scopes)

    def is_subset_of(self, other: ScopeSet) -> bool:
        """True if every scope in `self` is also in `other` (attenuation rule)."""
        return self._scopes <= other._scopes

    def difference(self, other: ScopeSet) -> ScopeSet:
        return ScopeSet(self._scopes - other._scopes)

    def union(self, other: ScopeSet) -> ScopeSet:
        return ScopeSet(self._scopes | other._scopes)

    def to_strings(self) -> list[str]:
        return [str(s) for s in self]

    def __repr__(self) -> str:
        return f"ScopeSet({self.to_strings()!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ScopeSet):
            return NotImplemented
        return self._scopes == other._scopes

    def __hash__(self) -> int:
        return hash(self._scopes)


class TrustAnchor:
    """The root of the delegation hierarchy: the human (or local operator).

    The anchor holds no delegation credential — its authority is inherent.
    Delegations signed with the anchor's key are root delegations and are
    the only place where scopes may be minted from nothing.
    """

    __slots__ = ("_identity",)

    def __init__(self, identity) -> None:  # AgentIdentity; typed loosely to avoid import cycle
        self._identity = identity

    @property
    def agent_id(self) -> str:
        return self._identity.agent_id

    @property
    def public_identity(self):
        return self._identity.public_identity

    def sign(self, data: bytes) -> str:
        return self._identity.sign(data)

    def __repr__(self) -> str:
        return f"TrustAnchor(agent_id={self._identity.agent_id!r})"


def check_scope_attenuation(
    child_scopes: ScopeSet,
    parent_effective_scopes: ScopeSet,
) -> list[Scope]:
    """Return the scopes in `child_scopes` that the parent does NOT convey.

    Empty list means attenuation holds. Pure function, no side effects.
    """
    return sorted(
        child_scopes.difference(parent_effective_scopes),
        key=lambda s: (s.namespace, s.action),
    )


__all__ = [
    "ScopeSet",
    "TrustAnchor",
    "check_scope_attenuation",
]
