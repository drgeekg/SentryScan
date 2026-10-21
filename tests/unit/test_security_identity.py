"""Unit tests for Ed25519 Agent Identity and Trusted Registry."""

from pathlib import Path

from sentryscan.security.identity import AgentIdentity
from sentryscan.security.registry import TrustedAgentRegistry


def test_agent_identity_generation_and_signing() -> None:
    """Verify Ed25519 identity generation, public key formats, and signing."""
    identity = AgentIdentity.generate("agent-test-01")
    assert identity.agent_id == "agent-test-01"
    assert len(identity.public_key_bytes) == 32
    assert len(identity.public_key_hex) == 64

    # Sign data
    data = b"sentryscan-test-payload-bytes"
    sig_hex = identity.sign_hex(data)
    assert len(sig_hex) == 128

    # Verify signature
    sig_bytes = bytes.fromhex(sig_hex)
    identity.public_key.verify(sig_bytes, data)


def test_agent_identity_deterministic_from_seed() -> None:
    """Verify reproducible key generation from a 32-byte seed."""
    seed = b"\x01" * 32
    id1 = AgentIdentity.from_seed("agent-seeded", seed)
    id2 = AgentIdentity.from_seed("agent-seeded", seed)
    assert id1.public_key_hex == id2.public_key_hex


def test_agent_identity_repr_safety() -> None:
    """Ensure private key material never appears in repr output."""
    identity = AgentIdentity.generate("agent-secret")
    repr_str = repr(identity)
    assert "private" not in repr_str.lower()
    assert "AgentIdentity" in repr_str


def test_trusted_agent_registry_lifecycle(tmp_path: Path) -> None:
    """Verify registration, lookup, revocation, and persistence."""
    reg = TrustedAgentRegistry()
    id1 = AgentIdentity.generate("scout-agent")

    assert reg.is_trusted("scout-agent") is False

    reg.register("scout-agent", id1.public_key_hex, status="ACTIVE")
    assert reg.is_trusted("scout-agent") is True

    pub = reg.get_public_key("scout-agent")
    assert pub is not None

    # Test file persistence
    save_file = tmp_path / "trusted.json"
    reg.save_to_file(save_file)

    loaded_reg = TrustedAgentRegistry.load_from_file(save_file)
    assert loaded_reg.is_trusted("scout-agent") is True

    # Test revocation
    loaded_reg.revoke("scout-agent")
    assert loaded_reg.is_trusted("scout-agent") is False
    assert loaded_reg.get_public_key("scout-agent") is None
