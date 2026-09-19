"""Security core: identity, delegation, authorization.

No tool execution lives here. This layer only ever returns ALLOW / DENY
decisions; callers are responsible for enforcing the decision.
"""

from app.core.delegation import (
    Delegation,
    DelegationBuilder,
    InMemoryParentResolver,
    InMemoryRevocationRegistry,
    ParentResolver,
    RevocationRegistry,
    TrustAnchor,
    effective_scopes_of,
    new_delegation_id,
    sign_delegation,
    verify_delegation_signature,
)
from app.core.errors import DenyReason, VerificationError
from app.core.identity import AgentIdentity, PublicAgentIdentity
from app.core.models import CanonicalModel, utc_now
from app.core.policy import Scope, ScopeSet, TrustAnchor
from app.core.verifier import VerificationOutcome, verify_chain

__all__ = [
    "AgentIdentity",
    "CanonicalModel",
    "Delegation",
    "DelegationBuilder",
    "DenyReason",
    "InMemoryParentResolver",
    "InMemoryRevocationRegistry",
    "ParentResolver",
    "PublicAgentIdentity",
    "RevocationRegistry",
    "Scope",
    "ScopeSet",
    "TrustAnchor",
    "VerificationError",
    "VerificationOutcome",
    "effective_scopes_of",
    "new_delegation_id",
    "sign_delegation",
    "utc_now",
    "verify_chain",
    "verify_delegation_signature",
]
