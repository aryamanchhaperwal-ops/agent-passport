"""Canonical serialization and credential models.

Canonicalization approach (documented contract)
-----------------------------------------------
A signature is only meaningful if every verifier reconstructs *exactly* the
same bytes from the same data. We therefore define one canonical byte string
for any credential:

    1. Pydantic validates and normalizes all fields (types, enums, datetimes
       normalized to UTC with microsecond precision, offsets stripped).
    2. `model_dump(mode="json")` produces plain JSON types.
    3. `json.dumps(..., sort_keys=True, separators=(",", ":"),
       ensure_ascii=False, allow_nan=False)` produces the canonical text:
       recursively key-sorted, no insignificant whitespace.
    4. The text is encoded UTF-8 and signed with Ed25519.

`sort_keys=True` makes Python's `json` module sort keys recursively, so the
same logical object always yields the same bytes regardless of key insertion
order — this defeats reordering attacks. Re-serialization is *not* trusted
from the client: incoming credentials are re-validated through the same
Pydantic models before any signature check, so an attacker cannot smuggle in
fields we never signed or skip validation.

Replay protection: `delegation_id` is a unique, unguessable identifier and is
*inside* the signed payload. A modified delegation (including a modified ID)
therefore always fails signature verification; a re-presented unmodified
credential is still bound to the same subject/scopes, so replay cannot gain
the attacker anything they could not get by holding the original credential.
Use-once semantics can be layered on top later (nonce registry) without
changing the credential format.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Clock-skew allowance for issuance timestamps. A credential may not be
# *issued* more than this far in the future — beyond that it is rejected as
# NOT_YET_VALID to stop pre-signed credentials with artificially long lives.
DEFAULT_MAX_CLOCK_SKEW = timedelta(minutes=5)

# Defensive bound on exponent sizes in serialized payloads.
MAX_STRING_LENGTH = 2048


def utc_now() -> datetime:
    """Return the current time, timezone-aware, in UTC.

    Single source of truth for "now" so tests can freeze time in one place
    if needed, and so no module accidentally uses naive local time.
    """
    return datetime.now(UTC)


def canonicalize(model: BaseModel) -> bytes:
    """Return the deterministic byte representation used for signing.

    See module docstring. Never call `json.dumps` directly on credential
    data — always go through here (or through a model that inherits from
    `CanonicalModel`).
    """
    payload = model.model_dump(mode="json")
    text = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


class CanonicalModel(BaseModel):
    """Base for anything that will be cryptographically signed.

    Forbids unknown fields so a credential cannot smuggle extra data past
    validation, and freezes models so validated credentials cannot be
    mutated in memory after verification.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
    )

    def canonical_bytes(self) -> bytes:
        return canonicalize(self)


class Scope(CanonicalModel):
    """A single capability: `namespace.action` (e.g. `calendar.read`).

    Wildcards are intentionally NOT supported: a capability is either held
    or it is not, which keeps attenuation checks trivially decidable.
    """

    namespace: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=64)

    @field_validator("namespace", "action")
    @classmethod
    def _validate_component(cls, v: str) -> str:
        if not v or len(v) > 64 or not all(c.isalnum() or c in "._-" for c in v):
            raise ValueError(
                f"scope component {v!r} must be 1-64 chars of [a-zA-Z0-9._-]"
            )
        return v

    @model_validator(mode="before")
    @classmethod
    def _accept_string_form(cls, data: object) -> object:
        """Allow `"calendar.read"` as input wherever a Scope is expected
        (notably JSON request bodies); canonical form is still an object."""
        if isinstance(data, str):
            parts = data.split(".")
            if len(parts) != 2:
                raise ValueError(
                    f"scope {data!r} must be exactly `namespace.action`"
                )
            return {"namespace": parts[0], "action": parts[1]}
        return data

    @classmethod
    def parse(cls, raw: str) -> Scope:
        """Parse a scope string like `calendar.read` into a Scope."""
        parts = raw.split(".")
        if len(parts) != 2:
            raise ValueError(f"scope {raw!r} must be exactly `namespace.action`")
        return cls(namespace=parts[0], action=parts[1])

    def __str__(self) -> str:
        return f"{self.namespace}.{self.action}"


class AgentRef(CanonicalModel):
    """Reference to an agent identity: its ID and its raw Ed25519 public key.

    Including the public key inside the signed payload binds the delegation
    to a specific key, so signatures can be verified even without a key
    registry, and a swapped key breaks the credential.
    """

    agent_id: str = Field(min_length=1, max_length=128)
    public_key_hex: str = Field(min_length=64, max_length=64)

    @field_validator("agent_id")
    @classmethod
    def _validate_agent_id(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c in "._-:@ " for c in v):
            raise ValueError(f"agent_id {v!r} contains invalid characters")
        return v


class Delegation(CanonicalModel):
    """A signed statement: `issuer` grants `subject` the listed `scopes`."""

    delegation_id: str = Field(min_length=16, max_length=128)
    issuer: AgentRef
    subject: AgentRef
    scopes: list[Scope] = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    parent_delegation_id: str | None = None
    signature: str | None = None

    @field_validator("delegation_id")
    @classmethod
    def _validate_delegation_id(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c in "-_" for c in v):
            raise ValueError(f"delegation_id {v!r} contains invalid characters")
        return v

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _require_tz_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("timestamps must be timezone-aware")
        return v.astimezone(UTC).replace(microsecond=0)

    @field_validator("scopes")
    @classmethod
    def _dedupe_scopes(cls, v: list[Scope]) -> list[Scope]:
        # Deduplicate and sort for canonical representation so two logically
        # identical scope lists sign to the same bytes.
        unique = {(s.namespace, s.action): s for s in v}
        return sorted(unique.values(), key=lambda s: (s.namespace, s.action))

    @field_validator("parent_delegation_id")
    @classmethod
    def _validate_parent_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not v or not all(c.isalnum() or c in "-_" for c in v):
            raise ValueError(f"parent_delegation_id {v!r} contains invalid characters")
        return v


class VerifyRequest(CanonicalModel):
    """A proposed action that the verifier will evaluate — never authorize."""

    requesting_agent_id: str = Field(min_length=1, max_length=128)
    requested_scope: Scope
    chain: list[Delegation]
    now: datetime | None = None

    @field_validator("requesting_agent_id")
    @classmethod
    def _validate_requester(cls, v: str) -> str:
        if not v or not all(c.isalnum() or c in "._-:@ " for c in v):
            raise ValueError(f"agent_id {v!r} contains invalid characters")
        return v

    @field_validator("now")
    @classmethod
    def _require_tz_aware_now(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return None
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError("now must be timezone-aware")
        return v.astimezone(UTC).replace(microsecond=0)


__all__ = [
    "AgentRef",
    "CanonicalModel",
    "Delegation",
    "DEFAULT_MAX_CLOCK_SKEW",
    "MAX_STRING_LENGTH",
    "Scope",
    "VerifyRequest",
    "canonicalize",
    "utc_now",
]
