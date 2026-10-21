"""Canonical serialization and signing utilities for Message envelopes."""

from __future__ import annotations

import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sentryscan.contracts.message import Message
from sentryscan.security.identity import AgentIdentity

logger = logging.getLogger(__name__)


def sign_envelope(message: Message, identity: AgentIdentity) -> Message:
    """Compute payload digest and Ed25519 signature over canonical envelope bytes."""
    if message.sender != identity.agent_id:
        raise ValueError(
            f"Signer agent_id mismatch: message.sender={message.sender!r} vs "
            f"identity.agent_id={identity.agent_id!r}"
        )

    # 1. Compute and attach payload digest
    message.payload_sha256 = message.compute_payload_sha256()

    # 2. Derive canonical bytes covering envelope fields (excluding signature)
    canonical_bytes = message.canonical_envelope_bytes()

    # 3. Compute Ed25519 signature
    message.signature = identity.sign_hex(canonical_bytes)

    return message


def verify_payload_digest(message: Message) -> bool:
    """Verify that message.payload_sha256 matches current payload hash."""
    if not message.payload_sha256:
        return False
    computed = message.compute_payload_sha256()
    return computed == message.payload_sha256


def verify_envelope_signature(message: Message, public_key: Ed25519PublicKey) -> bool:
    """Verify Ed25519 signature over message canonical envelope bytes."""
    if not message.signature:
        return False

    try:
        sig_bytes = bytes.fromhex(message.signature)
    except ValueError:
        logger.warning("Invalid hex signature format in message %s", message.message_id)
        return False

    canonical_bytes = message.canonical_envelope_bytes()
    try:
        public_key.verify(sig_bytes, canonical_bytes)
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        logger.error("Signature verification error for message %s: %s", message.message_id, e)
        return False
