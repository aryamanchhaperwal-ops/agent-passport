"""Delegation credential issuance, signing, and the revocation registry.

A `Delegation` is a signed statement: issuer grants subject the listed
scopes for a bounded time, optionally attenuating a parent delegation.

Trust model in one paragraph: every chain starts at a `TrustAnchor` (the
human). A root delegation is signed by the anchor and has
`parent_delegation_id=None`; every non-root delegation must reference a
parent that is present in the presented chain (or resolvable through the
`ParentResolver` registry) and itself valid. This means an attacker cannot
splice a valid-looking orphan into a chain and cannot present a chain whose
root they signed themselves — root signatures must verify against the
configured anchor key.

Signing covers the canonical JSON of ALL credential fields with
`signature: None`, so any modification of any field — including the
delegation_id, timestamps, and scopes — invalidates the signature.
"""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Protocol

from pydantic import ValidationError

from app.core.errors import DenyReason, VerificationError
from app.core.identity import AgentIdentity, verify_signature_with_public_key
from app.core.models import AgentRef, Delegation, Scope, utc_now
from app.core.policy import ScopeSet, TrustAnchor

_DELEGATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class RevocationRegistry(Protocol):
    """Interface for revocation checking so a persistent store can be swapped
    in later without touching the verifier."""

    def is_revoked(self, delegation_id: str) -> bool: ...

    def revoke(self, delegation_id: str) -> None: ...


class InMemoryRevocationRegistry:
    """Simple in-memory revocation set for the local testbed."""

    def __init__(self) -> None:
        self._revoked: set[str] = set()

    def is_revoked(self, delegation_id: str) -> bool:
        return delegation_id in self._revoked

    def revoke(self, delegation_id: str) -> None:
        self._revoked.add(delegation_id)


class ParentResolver(Protocol):
    """Interface for resolving parent delegations not included in the chain."""

    def resolve(self, delegation_id: str) -> Delegation | None: ...


class InMemoryParentResolver:
    """Holds previously verified delegations so chains can be presented as
    a single hop plus a reference to an earlier-verified parent."""

    def __init__(self) -> None:
        self._delegations: dict[str, Delegation] = {}

    def store(self, delegation: Delegation) -> None:
        self._delegations[delegation.delegation_id] = delegation

    def resolve(self, delegation_id: str) -> Delegation | None:
        return self._delegations.get(delegation_id)


def new_delegation_id() -> str:
    """Return a fresh unguessable delegation id (`dlg_` + 24 urlsafe chars)."""
    return f"dlg_{secrets.token_urlsafe(18)}"


def _agent_ref(identity: AgentIdentity) -> AgentRef:
    return AgentRef(
        agent_id=identity.agent_id,
        public_key_hex=identity.public_identity.public_key_hex,
    )


class DelegationBuilder:
    """Issues (creates + signs) delegation credentials.

    For root delegations, pass the `TrustAnchor` as the issuer. For child
    delegations, the issuer must be an `AgentIdentity` holding a delegation
    that confers the scopes being granted — the *verifier* enforces this;
    the builder only refuses structurally impossible requests (e.g. no
    scopes, non-positive lifetime) so that mistakes fail fast at issuance.
    """

    def __init__(
        self,
        anchor: TrustAnchor,
        max_lifetime: timedelta = timedelta(days=30),
    ) -> None:
        self._anchor = anchor
        self._max_lifetime = max_lifetime

    def issue_root(
        self,
        subject: AgentIdentity,
        scopes: list[Scope] | list[str],
        *,
        issued_at: datetime | None = None,
        ttl: timedelta = timedelta(hours=1),
        delegation_id: str | None = None,
    ) -> Delegation:
        """The anchor grants scopes directly to `subject`."""
        return self._issue(
            issuer_identity=self._anchor,
            subject=subject,
            scopes=scopes,
            parent=None,
            issued_at=issued_at,
            ttl=ttl,
            delegation_id=delegation_id,
        )

    def issue_child(
        self,
        issuer: AgentIdentity,
        subject: AgentIdentity,
        scopes: list[Scope] | list[str],
        parent: Delegation,
        *,
        issued_at: datetime | None = None,
        ttl: timedelta = timedelta(hours=1),
        delegation_id: str | None = None,
    ) -> Delegation:
        """`issuer` re-delegates a subset of `parent.scopes` to `subject`.

        Validity inheritance: the child's `expires_at` is CLAMPED to the
        parent's remaining validity (`expires_at <= parent.expires_at`), so
        an honestly issued child can never outlive its parent even if the
        caller requests a longer ttl. The verifier independently rejects
        any over-long child (EXCEEDS_PARENT_VALIDITY), so a malicious issuer
        cannot circumvent this by hand-crafting the credential.
        """
        return self._issue(
            issuer_identity=issuer,
            subject=subject,
            scopes=scopes,
            parent=parent,
            issued_at=issued_at,
            ttl=ttl,
            delegation_id=delegation_id,
        )

    def _issue(
        self,
        issuer_identity: AgentIdentity | TrustAnchor,
        subject: AgentIdentity,
        scopes: list[Scope] | list[str],
        parent: Delegation | None,
        issued_at: datetime | None,
        ttl: timedelta,
        delegation_id: str | None,
    ) -> Delegation:
        now = issued_at if issued_at is not None else utc_now()
        if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
            raise VerificationError(
                DenyReason.INVALID_REQUEST, "issued_at must be timezone-aware"
            )
        now = now.astimezone(UTC)

        if ttl <= timedelta(0):
            raise VerificationError(DenyReason.INVALID_REQUEST, "ttl must be positive")
        requested_expires_at = now + ttl
        if requested_expires_at - now > self._max_lifetime:
            raise VerificationError(
                DenyReason.INVALID_REQUEST,
                f"delegation lifetime exceeds maximum of {self._max_lifetime}",
            )

        # Validity inheritance: a child may never outlive its parent.
        if parent is not None:
            if parent.expires_at <= now:
                raise VerificationError(
                    DenyReason.INVALID_REQUEST,
                    f"parent delegation {parent.delegation_id} is already expired",
                )
            expires_at = min(requested_expires_at, parent.expires_at)
        else:
            expires_at = requested_expires_at
        parent_id = parent.delegation_id if parent is not None else None

        normalized: list[Scope] = []
        for s in scopes:
            if isinstance(s, str):
                s = Scope.parse(s)
            elif not isinstance(s, Scope):
                raise VerificationError(
                    DenyReason.INVALID_REQUEST, f"unsupported scope value {s!r}"
                )
            normalized.append(s)
        if not normalized:
            raise VerificationError(DenyReason.INVALID_REQUEST, "at least one scope required")

        did = delegation_id or new_delegation_id()
        if not _DELEGATION_ID_PATTERN.match(did):
            raise VerificationError(
                DenyReason.MALFORMED_CREDENTIAL,
                f"delegation_id {did!r} does not match {_DELEGATION_ID_PATTERN.pattern}",
            )

        delegation = Delegation(
            delegation_id=did,
            issuer=_agent_ref(_identity_of(issuer_identity)),
            subject=_agent_ref(subject),
            scopes=normalized,
            issued_at=now,
            expires_at=expires_at,
            parent_delegation_id=parent_id,
            signature=None,
        )
        signature = _identity_of(issuer_identity).sign(delegation.canonical_bytes())
        return delegation.model_copy(update={"signature": signature})


def _identity_of(issuer: AgentIdentity | TrustAnchor) -> AgentIdentity:
    return issuer._identity if isinstance(issuer, TrustAnchor) else issuer


def effective_scopes_of(delegation: Delegation) -> ScopeSet:
    """Return the delegation's scopes as a ScopeSet."""
    return ScopeSet(delegation.scopes)


def sign_delegation(delegation: Delegation, signer: AgentIdentity) -> Delegation:
    """(Re-)sign a delegation, replacing any existing signature.

    Only the anchor or the issuer should ever call this.
    """
    signature = signer.sign(delegation.model_copy(update={"signature": None}).canonical_bytes())
    return delegation.model_copy(update={"signature": signature})


def verify_delegation_signature(delegation: Delegation) -> bool:
    """Check a delegation's signature against its embedded issuer public key.

    Returns False rather than raising on any malformed input.
    """
    if delegation.signature is None:
        return False
    unsigned = delegation.model_copy(update={"signature": None})
    return verify_signature_with_public_key(
        delegation.issuer.public_key_hex,
        unsigned.canonical_bytes(),
        delegation.signature,
    )


__all__ = [
    "DelegationBuilder",
    "InMemoryParentResolver",
    "InMemoryRevocationRegistry",
    "ParentResolver",
    "RevocationRegistry",
    "effective_scopes_of",
    "new_delegation_id",
    "sign_delegation",
    "verify_delegation_signature",
]
