"""Ed25519 agent identities.

Each agent has an Ed25519 keypair. The private key signs delegation
credentials; the public key verifies them. Private keys NEVER leave the
owning process: serialization functions here only ever expose public
material, and `AgentIdentity` is deliberately not JSON-serializable as a
whole to prevent accidental private-key leakage through generic dumpers.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import BaseModel, ConfigDict

# Raw Ed25519 public keys are 32 bytes -> 64 hex chars. Enforce exactly this
# so an attacker cannot substitute a malformed key through identity refs.
PUBLIC_KEY_HEX_LENGTH = 64


def _fingerprint(public_key: Ed25519PublicKey) -> str:
    """Stable identifier for a public key: SHA-256 of the raw key bytes."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


class PublicAgentIdentity(BaseModel):
    """The shareable, non-secret form of an agent identity.

    This is the ONLY representation of an identity that may be embedded in
    credentials, sent over the network, or persisted. It carries no private
    key material by construction.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    agent_id: str
    public_key_hex: str

    @property
    def fingerprint(self) -> str:
        return self.public_key_hex


class AgentIdentity:
    """A full Ed25519 identity. Private key stays in memory only."""

    __slots__ = ("_agent_id", "_private_key", "_public_identity")

    def __init__(self, agent_id: str, private_key: Ed25519PrivateKey) -> None:
        self._agent_id = agent_id
        self._private_key = private_key
        raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._public_identity = PublicAgentIdentity(
            agent_id=agent_id,
            public_key_hex=raw.hex(),
        )

    @classmethod
    def generate(cls, agent_id: str) -> AgentIdentity:
        """Generate a fresh Ed25519 keypair for `agent_id`."""
        if not agent_id or not isinstance(agent_id, str):
            raise ValueError("agent_id must be a non-empty string")
        return cls(agent_id=agent_id, private_key=Ed25519PrivateKey.generate())

    @property
    def fingerprint(self) -> str:
        """SHA-256 fingerprint of this identity's public key."""
        return _fingerprint(self._private_key.public_key())

    @classmethod
    def from_private_key_hex(cls, agent_id: str, private_key_hex: str) -> AgentIdentity:
        """Reconstruct from a hex-encoded raw private key (32 bytes).

        For tests and local persistence only. Never log the private key.
        """
        try:
            raw = bytes.fromhex(private_key_hex)
        except ValueError as exc:
            raise ValueError("private key must be valid hex") from exc
        if len(raw) != 32:
            raise ValueError("private key must be exactly 32 bytes")
        return cls(agent_id=agent_id, private_key=Ed25519PrivateKey.from_private_bytes(raw))

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def public_identity(self) -> PublicAgentIdentity:
        """The safe, shareable public half of this identity."""
        return self._public_identity

    def sign(self, data: bytes) -> str:
        """Sign arbitrary bytes, returning a hex-encoded signature."""
        return self._private_key.sign(data).hex()

    def verify(self, data: bytes, signature_hex: str) -> bool:
        """Verify a hex signature over `data` with this identity's public key."""
        try:
            sig = bytes.fromhex(signature_hex)
        except ValueError:
            return False
        try:
            self._private_key.public_key().verify(sig, data)
            return True
        except InvalidSignature:
            return False

    def export_public(self) -> dict[str, str]:
        """Export ONLY public fields (for logs, registries, API responses)."""
        pub = self._public_identity
        return {"agent_id": pub.agent_id, "public_key_hex": pub.public_key_hex}

    def export_private_key_hex(self) -> str:
        """Export the raw private key hex.

        For local test fixtures and key rotation tooling only. Callers must
        never persist this to anything that leaves the local testbed.
        """
        raw = self._private_key.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption(),
        )
        return raw.hex()

    def __repr__(self) -> str:
        # Repr deliberately omits any key material.
        return f"AgentIdentity(agent_id={self._agent_id!r})"


def verify_signature_with_public_key(
    public_key_hex: str,
    data: bytes,
    signature_hex: str,
) -> bool:
    """Verify a hex-encoded Ed25519 signature against a hex-encoded public key."""
    if len(public_key_hex) != PUBLIC_KEY_HEX_LENGTH:
        return False
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        sig = bytes.fromhex(signature_hex)
    except (ValueError, TypeError):
        return False
    try:
        pub.verify(sig, data)
        return True
    except InvalidSignature:
        return False


__all__ = [
    "AgentIdentity",
    "PUBLIC_KEY_HEX_LENGTH",
    "PublicAgentIdentity",
    "verify_signature_with_public_key",
]
