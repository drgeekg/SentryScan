"""Unit tests for Canonical Signing, Receiver Binding, and Digest Verification."""

import pytest

from sentryscan.contracts.message import Message, Performative
from sentryscan.security.canonical import (
    sign_envelope,
    verify_envelope_signature,
    verify_payload_digest,
)
from sentryscan.security.identity import AgentIdentity


def test_sign_envelope_valid() -> None:
    """Verify standard signing and successful signature verification."""
    identity = AgentIdentity.generate("supervisor-agent-01")

    msg = Message(
        message_id="msg-sign-01",
        run_id="run-sec-01",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T10:00:00Z",
        nonce="nonce-sign-01",
        payload={"finding_id": "fnd-01", "severity": "CRITICAL"},
    )

    assert msg.signature is None
    assert msg.payload_sha256 is None

    signed_msg = sign_envelope(msg, identity)
    assert signed_msg.signature is not None
    assert signed_msg.payload_sha256 is not None
    assert len(signed_msg.signature) == 128

    # Verification passes
    assert verify_payload_digest(signed_msg) is True
    assert verify_envelope_signature(signed_msg, identity.public_key) is True


def test_receiver_binding_prevents_redirection() -> None:
    """Verify that tampering with receiver invalidates signature."""
    identity = AgentIdentity.generate("supervisor-agent-01")

    msg = Message(
        message_id="msg-sign-02",
        run_id="run-sec-01",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T10:00:00Z",
        nonce="nonce-sign-02",
        payload={"finding_id": "fnd-02"},
    )
    sign_envelope(msg, identity)
    assert verify_envelope_signature(msg, identity.public_key) is True

    # Attacker alters receiver to scout-agent-01
    msg.receiver = "scout-agent-01"
    assert verify_envelope_signature(msg, identity.public_key) is False


def test_payload_tampering_detection() -> None:
    """Verify that tampering with payload is detected via digest mismatch."""
    identity = AgentIdentity.generate("supervisor-agent-01")

    msg = Message(
        message_id="msg-sign-03",
        run_id="run-sec-01",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T10:00:00Z",
        nonce="nonce-sign-03",
        payload={"severity": "LOW"},
    )
    sign_envelope(msg, identity)
    assert verify_payload_digest(msg) is True

    # Attacker mutates payload
    msg.payload["severity"] = "CRITICAL"
    assert verify_payload_digest(msg) is False


def test_signer_identity_mismatch_raises_error() -> None:
    """Ensure agent cannot sign messages claiming to be from another sender."""
    identity = AgentIdentity.generate("imposter-agent")

    msg = Message(
        message_id="msg-sign-04",
        run_id="run-sec-01",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T10:00:00Z",
        nonce="nonce-sign-04",
    )

    with pytest.raises(ValueError, match="Signer agent_id mismatch"):
        sign_envelope(msg, identity)
