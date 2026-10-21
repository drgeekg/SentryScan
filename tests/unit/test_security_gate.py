"""Comprehensive unit and breach tests for Security Gate, Nonce Cache, and Reason Codes."""

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.common.clock import FakeClock
from sentryscan.contracts.message import Message, Performative
from sentryscan.security.canonical import sign_envelope
from sentryscan.security.gate import SecurityGate, SecurityReasonCode
from sentryscan.security.identity import AgentIdentity
from sentryscan.security.nonce_cache import NonceCache
from sentryscan.security.registry import TrustedAgentRegistry


def setup_security_fixture(initial_iso: str = "2026-10-21T12:00:00Z") -> tuple[
    SecurityGate,
    AgentIdentity,
    AgentIdentity,
    FakeClock,
]:
    """Helper setting up clock, identities, registry, and security gate."""
    clock = FakeClock(initial_iso)
    supervisor_ident = AgentIdentity.generate("supervisor-agent-01")
    analyst_ident = AgentIdentity.generate("analyst-agent-01")

    registry = TrustedAgentRegistry()
    registry.register("supervisor-agent-01", supervisor_ident.public_key_hex, "ACTIVE")
    registry.register("analyst-agent-01", analyst_ident.public_key_hex, "ACTIVE")

    gate = SecurityGate(
        agent_id="analyst-agent-01",
        registry=registry,
        clock=clock,
        freshness_window_seconds=30.0,
    )

    return gate, supervisor_ident, analyst_ident, clock


def test_valid_signed_message_accepted() -> None:
    """Vector 0: Valid authentic message with fresh timestamp passes security check."""
    gate, supervisor, _, clock = setup_security_fixture()

    msg = Message(
        message_id="msg-ok-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-ok-01",
        payload={"finding_id": "fnd-01", "severity": "HIGH"},
    )
    sign_envelope(msg, supervisor)

    verdict = gate.validate(msg)
    assert verdict.valid is True
    assert verdict.reason_code == SecurityReasonCode.OK
    assert gate.stats()["accepted"] == 1


def test_reject_forged_signature() -> None:
    """Vector 1: Message signed by wrong key triggers BAD_SIGNATURE rejection."""
    gate, _, _, clock = setup_security_fixture()
    attacker = AgentIdentity.generate("rogue-key-attacker")

    msg = Message(
        message_id="msg-forged-01",
        run_id="run-sec",
        sender="supervisor-agent-01",  # Claiming to be supervisor
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-forged-01",
        payload={"finding_id": "fnd-forged"},
    )
    # Signed with rogue key instead of supervisor's registered key
    # Bypass sign_envelope sender check to simulate forged signature
    msg.payload_sha256 = msg.compute_payload_sha256()
    msg.signature = attacker.sign_hex(msg.canonical_envelope_bytes())

    verdict = gate.validate(msg)
    assert verdict.valid is False
    assert verdict.reason_code == SecurityReasonCode.BAD_SIGNATURE


def test_reject_unknown_and_revoked_sender() -> None:
    """Vector 2: Message from unregistered or revoked agent triggers UNKNOWN_SENDER."""
    gate, _, _, clock = setup_security_fixture()
    stranger = AgentIdentity.generate("unknown-agent-99")

    msg = Message(
        message_id="msg-stranger-01",
        run_id="run-sec",
        sender="unknown-agent-99",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-stranger-01",
        payload={"finding_id": "fnd-stranger"},
    )
    sign_envelope(msg, stranger)

    verdict = gate.validate(msg)
    assert verdict.valid is False
    assert verdict.reason_code == SecurityReasonCode.UNKNOWN_SENDER

    # Test revoked sender
    gate.registry.revoke("supervisor-agent-01")
    supervisor = AgentIdentity.generate("supervisor-agent-01")
    msg2 = Message(
        message_id="msg-revoked-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-revoked-01",
    )
    sign_envelope(msg2, supervisor)
    verdict2 = gate.validate(msg2)
    assert verdict2.valid is False
    assert verdict2.reason_code == SecurityReasonCode.UNKNOWN_SENDER


def test_reject_wrong_recipient_redirection() -> None:
    """Vector 3: Valid message redirected to wrong recipient triggers WRONG_RECIPIENT."""
    gate, supervisor, _, clock = setup_security_fixture()

    msg = Message(
        message_id="msg-redirect-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="scout-agent-01",  # Intended for scout, but delivered to analyst gate
        performative=Performative.TASK_REQUEST,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-redirect-01",
        payload={"task_id": "task-01"},
    )
    sign_envelope(msg, supervisor)

    verdict = gate.validate(msg)
    assert verdict.valid is False
    assert verdict.reason_code == SecurityReasonCode.WRONG_RECIPIENT


def test_reject_tampered_payload() -> None:
    """Vector 4: In-transit payload manipulation triggers PAYLOAD_TAMPERED."""
    gate, supervisor, _, clock = setup_security_fixture()

    msg = Message(
        message_id="msg-tamper-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-tamper-01",
        payload={"severity": "LOW"},
    )
    sign_envelope(msg, supervisor)

    # In-transit attacker alters payload
    msg.payload["severity"] = "CRITICAL"

    verdict = gate.validate(msg)
    assert verdict.valid is False
    assert verdict.reason_code == SecurityReasonCode.PAYLOAD_TAMPERED


def test_reject_stale_timestamp() -> None:
    """Vector 5: Message with clock skew exceeding ±30s triggers STALE_TIMESTAMP."""
    gate, supervisor, _, clock = setup_security_fixture("2026-10-21T12:00:00Z")

    # Message from 45 seconds in the past
    msg_past = Message(
        message_id="msg-past-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T11:59:15Z",
        nonce="nonce-past-01",
        payload={"finding_id": "fnd-past"},
    )
    sign_envelope(msg_past, supervisor)

    verdict_past = gate.validate(msg_past)
    assert verdict_past.valid is False
    assert verdict_past.reason_code == SecurityReasonCode.STALE_TIMESTAMP

    # Message from 40 seconds in the future
    msg_future = Message(
        message_id="msg-future-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T12:00:40Z",
        nonce="nonce-future-01",
        payload={"finding_id": "fnd-future"},
    )
    sign_envelope(msg_future, supervisor)

    verdict_future = gate.validate(msg_future)
    assert verdict_future.valid is False
    assert verdict_future.reason_code == SecurityReasonCode.STALE_TIMESTAMP


def test_reject_replayed_nonce() -> None:
    """Vector 6: Replay of an identical (sender, nonce) triggers REPLAYED_NONCE."""
    gate, supervisor, _, clock = setup_security_fixture()

    msg = Message(
        message_id="msg-replay-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-replay-unique-01",
        payload={"finding_id": "fnd-replay"},
    )
    sign_envelope(msg, supervisor)

    # First attempt: Accepted
    verdict1 = gate.validate(msg)
    assert verdict1.valid is True
    assert verdict1.reason_code == SecurityReasonCode.OK

    # Replay attempt: Rejected
    verdict2 = gate.validate(msg)
    assert verdict2.valid is False
    assert verdict2.reason_code == SecurityReasonCode.REPLAYED_NONCE


def test_fail_closed_nonce_cache_at_capacity() -> None:
    """Vector 7: Nonce cache exceeding capacity fails closed with NONCE_CACHE_FULL."""
    clock = FakeClock("2026-10-21T12:00:00Z")
    small_cache = NonceCache(clock=clock, ttl_seconds=60.0, max_size=2)
    supervisor = AgentIdentity.generate("supervisor-agent-01")

    registry = TrustedAgentRegistry()
    registry.register("supervisor-agent-01", supervisor.public_key_hex, "ACTIVE")

    gate = SecurityGate(
        agent_id="analyst-agent-01",
        registry=registry,
        clock=clock,
        nonce_cache=small_cache,
    )

    # Add 2 messages to fill small_cache
    for i in range(1, 3):
        msg = Message(
            message_id=f"msg-fill-{i}",
            run_id="run-sec",
            sender="supervisor-agent-01",
            receiver="analyst-agent-01",
            performative=Performative.ALERT,
            timestamp_utc=clock.now_iso(),
            nonce=f"nonce-fill-{i}",
        )
        sign_envelope(msg, supervisor)
        v = gate.validate(msg)
        assert v.valid is True

    # Third message: Cache is full -> Fails closed
    msg3 = Message(
        message_id="msg-fill-3",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-fill-3",
    )
    sign_envelope(msg3, supervisor)

    v3 = gate.validate(msg3)
    assert v3.valid is False
    assert v3.reason_code == SecurityReasonCode.NONCE_CACHE_FULL


def test_analyst_agent_shielded_by_gate() -> None:
    """Verify AnalystAgent rejects unauthenticated or replayed message with ERROR message."""
    gate, supervisor, _, clock = setup_security_fixture()
    analyst = AnalystAgent(
        agent_id="analyst-agent-01",
        clock=clock,
        security_gate=gate,
    )

    # Attacker sends replayed message
    msg = Message(
        message_id="msg-analyst-shield-01",
        run_id="run-sec",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-shield-01",
        payload={"finding_id": "fnd-shield", "severity": "CRITICAL"},
    )
    sign_envelope(msg, supervisor)

    # First call: Accepted and responded with PARAMS_UPDATE
    reply1 = analyst.process_message(msg)
    assert reply1 is not None
    assert reply1.performative == Performative.PARAMS_UPDATE

    # Second call (Replay): Rejected by gate and responded with ERROR performative
    reply2 = analyst.process_message(msg)
    assert reply2 is not None
    assert reply2.performative == Performative.ERROR
    assert reply2.payload["reason_code"] == "REPLAYED_NONCE"
