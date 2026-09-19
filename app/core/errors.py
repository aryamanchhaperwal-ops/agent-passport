"""Error taxonomy for the AgentPassport security core.

Every denial carries a machine-readable `DenyReason` so that callers (and
eventually LLM-facing tool wrappers) can react deterministically without
parsing human text. The LLM never interprets these reasons to *make* a
decision — it may only observe them.
"""

from __future__ import annotations

from enum import Enum


class DenyReason(str, Enum):
    """Explicit, machine-readable reasons for denying a requested action.

    These are part of the verifier's public contract. Do not remove or
    renumber values; add new ones only when a new failure class appears.
    """

    # The request itself is unusable (bad shape, unknown fields, bad types).
    INVALID_REQUEST = "INVALID_REQUEST"
    # A credential's bytes do not match its signature.
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    # The issuer of a delegation is not an identity we can bind to keys.
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"
    # The chain structure itself is unusable (e.g. missing root anchor).
    INVALID_CHAIN = "INVALID_CHAIN"
    # A child references a parent delegation that is not present/valid.
    PARENT_NOT_FOUND = "PARENT_NOT_FOUND"
    # A delegation's subject does not match the child's issuer.
    SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
    # A credential is outside its validity window.
    EXPIRED_DELEGATION = "EXPIRED_DELEGATION"
    # A child credential outlives the parent it extends.
    EXCEEDS_PARENT_VALIDITY = "EXCEEDS_PARENT_VALIDITY"
    # A credential claims validity starting too far in the future (clock skew).
    NOT_YET_VALID = "NOT_YET_VALID"
    # A child delegation grants scopes its parent chain does not convey.
    SCOPE_ESCALATION = "SCOPE_ESCALATION"
    # The requested scope is not within the effective scopes of the chain.
    UNAUTHORIZED_SCOPE = "UNAUTHORIZED_SCOPE"
    # The credential is structurally broken (bad types, missing fields).
    MALFORMED_CREDENTIAL = "MALFORMED_CREDENTIAL"
    # The delegation has been explicitly revoked.
    REVOKED_DELEGATION = "REVOKED_DELEGATION"
    # Chain exceeds the configured maximum depth.
    DELEGATION_DEPTH_EXCEEDED = "DELEGATION_DEPTH_EXCEEDED"


class VerificationError(Exception):
    """Raised when a credential or request cannot even be evaluated.

    This is distinct from a DENY outcome: DENY is a *deterministic decision*
    produced by the verifier, while VerificationError signals that inputs
    were too broken to evaluate (the verifier catches these internally and
    converts them to DENY with the appropriate reason).
    """

    def __init__(self, reason: DenyReason, message: str) -> None:
        super().__init__(f"{reason.value}: {message}")
        self.reason = reason
        self.message = message
