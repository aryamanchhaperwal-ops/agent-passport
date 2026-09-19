"""Deterministic verification of delegation chains.

The verifier is the security core. It takes a proposed action
(`requesting_agent_id` + `requested_scope`) and the delegation chain the
requester presents, and returns a structured ALLOW/DENY — never a bare
bool, never an exception-based decision, and never anything an LLM could
talk its way past: every branch below is a fixed, ordered, pure check.

Validation order per chain (all must pass for ALLOW):
  1. Structural validation of every credential (MALFORMED_CREDENTIAL).
  2. Chain ordering: root must be a root (parent None), each following
     credential must reference the previous one (INVALID_CHAIN /
     PARENT_NOT_FOUND / SUBJECT_MISMATCH).
  3. Signature verification of every credential, from root to leaf
     (INVALID_SIGNATURE). Root signatures must verify against the trusted
     anchor key; a chain rooted at an attacker key is rejected as
     INVALID_CHAIN before any signature check.
  4. Revocation of every credential in the chain (REVOKED_DELEGATION).
  5. Expiration and future-issuance (clock skew) of every credential
     (EXPIRED_DELEGATION / NOT_YET_VALID).
  6. Validity inheritance: every child's expires_at must not exceed its
     parent's remaining validity (EXCEEDS_PARENT_VALIDITY), so effective
     authority is monotonically non-increasing along the chain.
  7. Scope attenuation across every hop (SCOPE_ESCALATION).
  8. The requesting agent must be the leaf subject, and the requested
     scope must be in the leaf's effective scopes (UNAUTHORIZED_SCOPE).

Depth is bounded (DELEGATION_DEPTH_EXCEEDED) to keep verification O(n)
and to stop pathological chains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from pydantic import ValidationError

from app.core.delegation import (
    Delegation,
    RevocationRegistry,
    effective_scopes_of,
    verify_delegation_signature,
)
from app.core.errors import DenyReason, VerificationError
from app.core.models import DEFAULT_MAX_CLOCK_SKEW, Scope, VerifyRequest, utc_now
from app.core.policy import ScopeSet, TrustAnchor, check_scope_attenuation

# A root delegation is signed by the anchor; anything else must reference a
# parent. Chains longer than this are rejected outright.
DEFAULT_MAX_CHAIN_DEPTH = 8


@dataclass(frozen=True)
class VerificationOutcome:
    """Structured result of a verification attempt.

    `decision` is always "ALLOW" or "DENY". On DENY, `reason` carries a
    machine-readable DenyReason and `detail` a human-readable explanation.
    On ALLOW, `effective_scopes` lists what the requesting agent may do.
    """

    decision: str
    reason: str | None
    detail: str | None
    agent: str | None
    requested_scope: str | None
    effective_scopes: list[str] = field(default_factory=list)

    @classmethod
    def allow(cls, agent: str, scope: Scope, effective: ScopeSet) -> "VerificationOutcome":
        return cls(
            decision="ALLOW",
            reason="AUTHORIZED",
            detail=None,
            agent=agent,
            requested_scope=str(scope),
            effective_scopes=effective.to_strings(),
        )

    @classmethod
    def deny(
        cls,
        reason: DenyReason,
        detail: str,
        *,
        agent: str | None = None,
        requested_scope: str | None = None,
    ) -> "VerificationOutcome":
        return cls(
            decision="DENY",
            reason=reason.value,
            detail=detail,
            agent=agent,
            requested_scope=requested_scope,
            effective_scopes=[],
        )


def verify_chain(
    anchor: TrustAnchor,
    chain: list[Delegation],
    requested_scope: Scope | str,
    requesting_agent_id: str,
    *,
    revocation_registry: RevocationRegistry | None = None,
    now: datetime | None = None,
    max_clock_skew: timedelta = DEFAULT_MAX_CLOCK_SKEW,
    max_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
) -> VerificationOutcome:
    """Verify a complete delegation chain for a proposed action.

    Returns ALLOW with the effective scopes, or DENY with a machine-readable
    reason. Inputs too malformed to evaluate are caught here and become
    DENY(MALFORMED_CREDENTIAL / INVALID_REQUEST); only the *caller's* misuse
    (wrong argument types entirely) raises.
    """
    agent_id: str | None = None
    scope_str = str(requested_scope) if not isinstance(requested_scope, str) else requested_scope

    try:
        # ---- Step 0: normalize and structurally validate the request ----
        if now is not None:
            if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
                return VerificationOutcome.deny(
                    DenyReason.INVALID_REQUEST, "now must be timezone-aware",
                    agent=None, requested_scope=scope_str,
                )
            now_dt = now.astimezone(UTC)
        else:
            now_dt = utc_now()
        if not isinstance(requesting_agent_id, str) or not requesting_agent_id:
            return VerificationOutcome.deny(
                DenyReason.INVALID_REQUEST, "requesting_agent_id must be a non-empty string",
                agent=None, requested_scope=scope_str,
            )
        agent_id = requesting_agent_id

        if not isinstance(chain, list) or not chain:
            return VerificationOutcome.deny(
                DenyReason.INVALID_REQUEST, "chain must be a non-empty list of delegations",
                agent=agent_id, requested_scope=scope_str,
            )
        if len(chain) > max_depth:
            return VerificationOutcome.deny(
                DenyReason.DELEGATION_DEPTH_EXCEEDED,
                f"chain of {len(chain)} delegations exceeds maximum depth {max_depth}",
                agent=agent_id, requested_scope=scope_str,
            )

        try:
            scope_obj = (
                requested_scope if isinstance(requested_scope, Scope)
                else Scope.parse(requested_scope)
            )
        except (ValueError, ValidationError) as exc:
            return VerificationOutcome.deny(
                DenyReason.INVALID_REQUEST, f"unparseable requested_scope: {exc}",
                agent=agent_id, requested_scope=scope_str,
            )

        # Re-validate every presented credential through the strict model so
        # that fields we never signed or wrong-typed data cannot sneak in.
        try:
            validated: list[Delegation] = [Delegation.model_validate(d) for d in chain]
        except ValidationError as exc:
            return VerificationOutcome.deny(
                DenyReason.MALFORMED_CREDENTIAL, f"credential failed validation: {exc}",
                agent=agent_id, requested_scope=scope_str,
            )

        root = validated[0]

        # ---- Step 1: chain structure and parent linking ----
        if root.parent_delegation_id is not None:
            return VerificationOutcome.deny(
                DenyReason.INVALID_CHAIN,
                "root of chain must be a root delegation (parent_delegation_id is None)",
                agent=agent_id, requested_scope=scope_str,
            )

        for i, cred in enumerate(validated):
            if i == 0:
                continue
            parent = validated[i - 1]
            if cred.parent_delegation_id != parent.delegation_id:
                if cred.parent_delegation_id is None:
                    return VerificationOutcome.deny(
                        DenyReason.PARENT_NOT_FOUND,
                        f"credential {i} ({cred.delegation_id}) has no parent reference "
                        f"but is not the root",
                        agent=agent_id, requested_scope=scope_str,
                    )
                return VerificationOutcome.deny(
                    DenyReason.PARENT_NOT_FOUND,
                    f"credential {i} ({cred.delegation_id}) references parent "
                    f"{cred.parent_delegation_id!r} but previous credential is "
                    f"{parent.delegation_id!r}",
                    agent=agent_id, requested_scope=scope_str,
                )
            if cred.issuer != parent.subject:
                return VerificationOutcome.deny(
                    DenyReason.SUBJECT_MISMATCH,
                    f"credential {i} issuer {cred.issuer.agent_id!r} is not the subject "
                    f"of its parent {parent.subject.agent_id!r}",
                    agent=agent_id, requested_scope=scope_str,
                )

        # ---- Step 2: signatures, root against the trusted anchor key ----
        if root.issuer.public_key_hex != anchor.public_identity.public_key_hex:
            return VerificationOutcome.deny(
                DenyReason.INVALID_CHAIN,
                "root delegation issuer key does not match the trusted anchor",
                agent=agent_id, requested_scope=scope_str,
            )
        if root.issuer.agent_id != anchor.agent_id:
            return VerificationOutcome.deny(
                DenyReason.UNKNOWN_ISSUER,
                "root delegation issuer id does not match the trusted anchor",
                agent=agent_id, requested_scope=scope_str,
            )

        for i, cred in enumerate(validated):
            if not verify_delegation_signature(cred):
                return VerificationOutcome.deny(
                    DenyReason.INVALID_SIGNATURE,
                    f"signature check failed for credential {i} ({cred.delegation_id})",
                    agent=agent_id, requested_scope=scope_str,
                )

        # ---- Step 3: revocation (checked for every credential) ----
        if revocation_registry is not None:
            for cred in validated:
                if revocation_registry.is_revoked(cred.delegation_id):
                    return VerificationOutcome.deny(
                        DenyReason.REVOKED_DELEGATION,
                        f"delegation {cred.delegation_id} has been revoked",
                        agent=agent_id, requested_scope=scope_str,
                    )

        # ---- Step 4: time validity of every credential (expiry, clock skew) ----
        for cred in validated:
            if now_dt >= cred.expires_at:
                return VerificationOutcome.deny(
                    DenyReason.EXPIRED_DELEGATION,
                    f"delegation {cred.delegation_id} expired at {cred.expires_at.isoformat()}",
                    agent=agent_id, requested_scope=scope_str,
                )
            if cred.issued_at > now_dt + max_clock_skew:
                return VerificationOutcome.deny(
                    DenyReason.NOT_YET_VALID,
                    f"delegation {cred.delegation_id} issued_at "
                    f"{cred.issued_at.isoformat()} is further than {max_clock_skew} "
                    f"in the future",
                    agent=agent_id, requested_scope=scope_str,
                )

        # ---- Step 5: validity inheritance along the chain ----
        # Effective authority must remain bounded by EVERY ancestor's
        # expiration: effective expiry is monotonically non-increasing from
        # root to leaf. A child outliving its parent (hand-crafted and
        # re-signed — honest issuance clamps in the builder) is rejected.
        effective_expires_at = validated[0].expires_at
        for cred in validated[1:]:
            if cred.expires_at > effective_expires_at:
                return VerificationOutcome.deny(
                    DenyReason.EXCEEDS_PARENT_VALIDITY,
                    f"delegation {cred.delegation_id} expires at "
                    f"{cred.expires_at.isoformat()}, after its parent's effective "
                    f"expiry {effective_expires_at.isoformat()}",
                    agent=agent_id, requested_scope=scope_str,
                )
            effective_expires_at = min(effective_expires_at, cred.expires_at)

        # ---- Step 6: scope attenuation across every hop ----
        parent_effective = ScopeSet(validated[0].scopes)
        for cred in validated[1:]:
            child_set = ScopeSet(cred.scopes)
            missing = check_scope_attenuation(child_set, parent_effective)
            if missing:
                escalation = ", ".join(str(s) for s in missing)
                return VerificationOutcome.deny(
                    DenyReason.SCOPE_ESCALATION,
                    f"delegation {cred.delegation_id} grants {escalation} not conveyed "
                    f"by parent {parent.delegation_id}",
                    agent=agent_id, requested_scope=scope_str,
                )
            parent_effective = child_set

        # ---- Step 7: the requester and the requested scope ----
        leaf = validated[-1]
        if leaf.subject.agent_id != agent_id:
            return VerificationOutcome.deny(
                DenyReason.SUBJECT_MISMATCH,
                f"chain leaf subject {leaf.subject.agent_id!r} is not the requesting "
                f"agent {agent_id!r}",
                agent=agent_id, requested_scope=scope_str,
            )
        effective = effective_scopes_of(leaf)
        if scope_obj not in effective:
            return VerificationOutcome.deny(
                DenyReason.UNAUTHORIZED_SCOPE,
                f"requested scope {scope_str!r} is not in the effective scopes "
                f"of the chain",
                agent=agent_id, requested_scope=scope_str,
            )

        return VerificationOutcome.allow(agent_id, scope_obj, effective)

    except VerificationError as exc:
        return VerificationOutcome.deny(
            exc.reason, exc.message, agent=agent_id, requested_scope=scope_str
        )
    except Exception as exc:  # noqa: BLE001 — the verifier must never crash open
        return VerificationOutcome.deny(
            DenyReason.MALFORMED_CREDENTIAL,
            f"unexpected error during verification: {exc}",
            agent=agent_id, requested_scope=scope_str,
        )


def verify_request(
    anchor: TrustAnchor,
    request: VerifyRequest,
    *,
    revocation_registry: RevocationRegistry | None = None,
    max_clock_skew: timedelta = DEFAULT_MAX_CLOCK_SKEW,
    max_depth: int = DEFAULT_MAX_CHAIN_DEPTH,
) -> VerificationOutcome:
    """Convenience wrapper for pre-validated `VerifyRequest` objects."""
    return verify_chain(
        anchor=anchor,
        chain=request.chain,
        requested_scope=request.requested_scope,
        requesting_agent_id=request.requesting_agent_id,
        revocation_registry=revocation_registry,
        now=request.now,
        max_clock_skew=max_clock_skew,
        max_depth=max_depth,
    )


__all__ = [
    "DEFAULT_MAX_CHAIN_DEPTH",
    "VerificationOutcome",
    "verify_chain",
    "verify_request",
]
