"""Unit tests for the AnalystAgent autonomous reasoning and parameter tuning."""

from __future__ import annotations

import threading

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Message, Performative
from sentryscan.transport.in_process import InProcessTransport


def _build_analyst():
    clock = FakeClock("2026-10-21T06:30:00Z")
    id_gen = IdGenerator(seed=123)
    return AnalystAgent(agent_id="analyst-agent-01", clock=clock, id_gen=id_gen)


def test_analyst_alert_critical_severity():
    analyst = _build_analyst()
    alert_msg = Message(
        message_id="msg-alert-01",
        run_id="run-01",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T06:30:00Z",
        nonce="nonce-001",
        task_id="task-eval-01",
        payload={
            "target_host": "192.0.2.10",
            "finding_id": "fnd-0001",
            "rule_id": "RULE-01-VULN-BANNER",
            "severity": "CRITICAL",
        },
    )

    reply = analyst.process_message(alert_msg)
    assert reply is not None
    assert reply.performative == Performative.PARAMS_UPDATE
    assert reply.sender == "analyst-agent-01"
    assert reply.receiver == "supervisor-agent"
    assert reply.payload["target_host"] == "192.0.2.10"
    assert reply.payload["action"] == "DEEP_INSPECTION"
    assert reply.payload["scan_interval_ms"] == 50
    assert reply.payload["quarantine_flag"] is True
    assert 22 in reply.payload["priority_ports"]
    assert "quarantine" in reply.payload["rationale"].lower()

    # Beliefs store should have updated
    assert "192.0.2.10" in analyst.beliefs
    assert analyst.beliefs["192.0.2.10"]["severity"] == "CRITICAL"


def test_analyst_alert_high_severity():
    analyst = _build_analyst()
    alert_msg = Message(
        message_id="msg-alert-02",
        run_id="run-01",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T06:30:00Z",
        nonce="nonce-002",
        payload={
            "target_host": "192.0.2.11",
            "finding_id": "fnd-0002",
            "severity": "HIGH",
        },
    )

    reply = analyst.process_message(alert_msg)
    assert reply is not None
    assert reply.performative == Performative.PARAMS_UPDATE
    assert reply.payload["action"] == "DEEP_INSPECTION"
    assert reply.payload["scan_interval_ms"] == 100
    assert reply.payload["quarantine_flag"] is False


def test_analyst_alert_medium_and_low_severity():
    analyst = _build_analyst()
    # Medium
    med_msg = Message(
        message_id="msg-alert-03",
        run_id="run-01",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T06:30:00Z",
        nonce="nonce-003",
        payload={"target_host": "192.0.2.12", "severity": "MEDIUM"},
    )
    reply_med = analyst.process_message(med_msg)
    assert reply_med is not None
    assert reply_med.payload["action"] == "NOMINAL_MONITORING"
    assert reply_med.payload["scan_interval_ms"] == 250

    # Low
    low_msg = Message(
        message_id="msg-alert-04",
        run_id="run-01",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T06:30:00Z",
        nonce="nonce-004",
        payload={"target_host": "192.0.2.13", "severity": "LOW"},
    )
    reply_low = analyst.process_message(low_msg)
    assert reply_low is not None
    assert reply_low.payload["action"] == "NOMINAL_MONITORING"
    assert reply_low.payload["scan_interval_ms"] == 500


def test_analyst_state_sync_and_event():
    analyst = _build_analyst()
    sync_msg = Message(
        message_id="msg-sync-01",
        run_id="run-01",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.STATE_SYNC,
        timestamp_utc="2026-10-21T06:30:00Z",
        nonce="nonce-005",
        payload={"phase": "ACTIVE_MONITORING"},
    )
    reply_sync = analyst.process_message(sync_msg)
    assert reply_sync is not None
    assert reply_sync.performative == Performative.CONFIRM

    event_msg = Message(
        message_id="msg-evt-01",
        run_id="run-01",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.EVENT,
        timestamp_utc="2026-10-21T06:30:00Z",
        nonce="nonce-006",
        payload={"metric": "heartbeat"},
    )
    assert analyst.process_message(event_msg) is None


def test_analyst_unsupported_performative():
    analyst = _build_analyst()
    cfp_msg = Message(
        message_id="msg-cfp-01",
        run_id="run-01",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.CFP,
        timestamp_utc="2026-10-21T06:30:00Z",
        nonce="nonce-007",
        payload={},
    )
    reply = analyst.process_message(cfp_msg)
    assert reply is not None
    assert reply.performative == Performative.ERROR


def test_analyst_in_process_transport_loop():
    analyst = _build_analyst()
    trans_analyst, trans_supervisor = InProcessTransport.create_pair()

    stop_event = threading.Event()

    def run_analyst():
        analyst.listen_and_respond(trans_analyst, stop_event=stop_event, timeout=0.05)

    thread = threading.Thread(target=run_analyst, daemon=True)
    thread.start()

    try:
        # Supervisor sends alert over transport
        trans_supervisor.send(
            Message(
                message_id="msg-pipe-01",
                run_id="run-pipe",
                sender="supervisor-agent",
                receiver="analyst-agent-01",
                performative=Performative.ALERT,
                timestamp_utc="2026-10-21T06:30:00Z",
                nonce="nonce-pipe-01",
                payload={"target_host": "192.0.2.99", "severity": "CRITICAL"},
            )
        )

        reply = trans_supervisor.receive(timeout=1.0)
        assert reply is not None
        assert reply.performative == Performative.PARAMS_UPDATE
        assert reply.payload["action"] == "DEEP_INSPECTION"
    finally:
        stop_event.set()
        thread.join(timeout=1.0)
        trans_analyst.close()
        trans_supervisor.close()
