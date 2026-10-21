"""Unit tests for the canonical agent Message envelope and performatives."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from sentryscan.contracts.message import Message, Performative


def test_performative_enum_values():
    assert Performative.ALERT == "ALERT"
    assert Performative.PARAMS_UPDATE == "PARAMS_UPDATE"
    assert Performative.TASK_REQUEST == "TASK_REQUEST"
    assert Performative.TASK_RESULT == "TASK_RESULT"
    assert Performative.CFP == "CFP"
    assert Performative.PROPOSE == "PROPOSE"
    assert Performative.COUNTERPROPOSE == "COUNTERPROPOSE"
    assert Performative.ACCEPT == "ACCEPT"
    assert Performative.REJECT == "REJECT"
    assert Performative.CONFIRM == "CONFIRM"
    assert Performative.EVENT == "EVENT"
    assert Performative.ERROR == "ERROR"


def test_message_creation_and_roundtrip():
    msg = Message(
        message_id="msg-001",
        run_id="run-test-01",
        sender="supervisor-agent",
        receiver="analyst-agent",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T06:00:00Z",
        nonce="nonce-abc-123",
        payload={"finding_id": "f-001", "severity": "HIGH", "target": "192.0.2.10"},
        task_id="task-01",
    )

    json_str = msg.to_json()
    rehydrated = Message.from_json(json_str)

    assert rehydrated.message_id == "msg-001"
    assert rehydrated.sender == "supervisor-agent"
    assert rehydrated.receiver == "analyst-agent"
    assert rehydrated.performative == Performative.ALERT
    assert rehydrated.payload["severity"] == "HIGH"
    assert rehydrated.task_id == "task-01"


def test_canonical_payload_and_envelope_bytes():
    msg1 = Message(
        message_id="msg-002",
        run_id="run-02",
        sender="agent-a",
        receiver="agent-b",
        performative=Performative.PARAMS_UPDATE,
        timestamp_utc="2026-10-21T06:05:00Z",
        nonce="nonce-999",
        payload={"z": 1, "a": 2},
    )
    msg2 = Message(
        message_id="msg-002",
        run_id="run-02",
        sender="agent-a",
        receiver="agent-b",
        performative=Performative.PARAMS_UPDATE,
        timestamp_utc="2026-10-21T06:05:00Z",
        nonce="nonce-999",
        payload={"a": 2, "z": 1},
    )

    # Key order in payload dictionary should not change canonical bytes
    assert msg1.canonical_payload_bytes() == msg2.canonical_payload_bytes()
    assert msg1.compute_payload_sha256() == msg2.compute_payload_sha256()
    assert msg1.canonical_envelope_bytes() == msg2.canonical_envelope_bytes()

    # Verify canonical envelope bytes include domain prefix and expected fields
    envelope_data = json.loads(msg1.canonical_envelope_bytes().decode("utf-8"))
    assert envelope_data["domain_prefix"] == "sentryscan/v1/envelope"
    assert envelope_data["performative"] == "PARAMS_UPDATE"
    assert envelope_data["payload_sha256"] == msg1.compute_payload_sha256()


def test_message_validation_failure():
    with pytest.raises(ValidationError):
        # Missing required fields like sender, receiver, nonce
        Message(
            message_id="bad-msg",
            run_id="run-01",
            performative=Performative.ALERT,  # type: ignore[call-arg]
        )
