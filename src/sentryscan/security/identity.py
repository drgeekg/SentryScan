"""Per-agent cryptographic Ed25519 identity management."""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


class AgentIdentity:
    """Cryptographic identity holding an Ed25519 keypair for an agent.

    Security Boundary:
    Private keys are retained strictly in memory and are never written to disk,
    logs, serialized outputs, or environment dumps.
    """

    def __init__(self, agent_id: str, private_key: Ed25519PrivateKey) -> None:
        self.agent_id = agent_id
        self._private_key = private_key
        self._public_key = private_key.public_key()

    @classmethod
    def generate(cls, agent_id: str) -> AgentIdentity:
        """Generate a fresh throwaway Ed25519 keypair for the given agent."""
        private_key = Ed25519PrivateKey.generate()
        return cls(agent_id=agent_id, private_key=private_key)

    @classmethod
    def from_seed(cls, agent_id: str, seed: bytes) -> AgentIdentity:
        """Derive an Ed25519 identity deterministically from a 32-byte seed."""
        if len(seed) != 32:
            raise ValueError("Ed25519 private seed must be exactly 32 bytes.")
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        return cls(agent_id=agent_id, private_key=private_key)

    @property
    def public_key(self) -> Ed25519PublicKey:
        """Return the public key object."""
        return self._public_key

    @property
    def public_key_bytes(self) -> bytes:
        """Return raw 32-byte public key."""
        return self._public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    @property
    def public_key_hex(self) -> str:
        """Return 64-character lowercase hex string of public key."""
        return self.public_key_bytes.hex()

    def sign_bytes(self, data: bytes) -> bytes:
        """Sign binary data with Ed25519 private key, returning 64-byte signature."""
        return self._private_key.sign(data)

    def sign_hex(self, data: bytes) -> str:
        """Sign binary data with Ed25519 private key, returning 128-character hex string."""
        return self.sign_bytes(data).hex()

    def sign_message(self, message: Any) -> Any:
        """Sign a Message envelope with this identity's Ed25519 private key."""
        from sentryscan.security.canonical import sign_envelope

        return sign_envelope(message, self)

    def __repr__(self) -> str:
        """Safe representation suppressing private key bytes."""
        pk_prefix = self.public_key_hex[:16]
        return f"AgentIdentity(agent_id={self.agent_id!r}, public_key={pk_prefix}...)"
