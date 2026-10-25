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


def test_l3_human_approval_gate_and_rejection():
    from sentryscan.contracts.finding import Finding, Severity
    from sentryscan.storage.store import SQLiteRunStore

    clock = FakeClock("2026-10-21T06:30:00Z")
    id_gen = IdGenerator(seed=99)
    l3 = AnalystAgent(agent_id="analyst-l3-containment", tier="L3", clock=clock, id_gen=id_gen)

    # Low-confidence (< 0.95) CRITICAL finding must wait for human approval
    low_conf_msg = Message(
        message_id="msg-l3-low",
        run_id="run-gate-01",
        sender="analyst-l2-incident",
        receiver="analyst-l3-containment",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-l3-low",
        payload={
            "target_host": "sim-host-low",
            "finding_id": "fnd-low-01",
            "rule_id": "RULE-004",
            "severity": "CRITICAL",
            "confidence": 0.80,
            "remote_exploitable": True,
        },
    )
    reply_low = l3.process_message(low_conf_msg)
    assert reply_low is not None
    assert reply_low.payload["action"] == "PENDING_QUARANTINE"
    assert reply_low.payload["quarantine_flag"] is False
    assert reply_low.payload["pending_quarantine"] is True
    assert l3.belief_base.get_or_create_host("sim-host-low").quarantined is False

    # Store pending record and reject it via SQLiteRunStore
    store = SQLiteRunStore(":memory:")
    store.save_run("run-gate-01", created_at=clock.now_iso())
    store.save_finding(
        Finding(
            finding_id="fnd-low-01",
            run_id="run-gate-01",
            record_id="rec-01",
            host_id="sim-host-low",
            rule_id="RULE-004",
            severity=Severity.CRITICAL,
            confidence=0.80,
            title="Default creds",
            description="Test",
            evidence={},
            created_at=clock.now_iso(),
        ),
        quarantined=False,
    )
    store.save_pending_quarantine(
        quarantine_id="pq-001",
        run_id="run-gate-01",
        host_id="sim-host-low",
        finding_id="fnd-low-01",
        rule_id="RULE-004",
        confidence=0.80,
        remote_exploitable=True,
        status="PENDING",
        created_at=clock.now_iso(),
    )
    decided = store.decide_pending_quarantine(
        quarantine_id="pq-001",
        decision="REJECTED",
        decided_by="soc-lead",
        decided_at=clock.now_iso(),
    )
    assert decided["status"] == "REJECTED"
    findings = store.get_findings("run-gate-01")
    assert findings[0]["quarantined"] is False
    events = store.get_events("run-gate-01")
    assert any(
        e["reason_code"] == "QUARANTINE_REJECTED"
        and e["details"]["who"] == "soc-lead"
        and e["details"]["what"] == "REJECTED"
        for e in events
    )

    # High-confidence (>= 0.95) + remote_exploitable=True auto-approves
    high_conf_msg = Message(
        message_id="msg-l3-high",
        run_id="run-gate-01",
        sender="analyst-l2-incident",
        receiver="analyst-l3-containment",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-l3-high",
        payload={
            "target_host": "sim-host-high",
            "finding_id": "fnd-high-01",
            "rule_id": "RULE-005",
            "severity": "CRITICAL",
            "confidence": 0.95,
            "remote_exploitable": True,
        },
    )
    reply_high = l3.process_message(high_conf_msg)
    assert reply_high is not None
    assert reply_high.payload["action"] == "QUARANTINE_HOST"
    assert reply_high.payload["quarantine_flag"] is True
    assert reply_high.payload["auto_approved"] is True
    assert l3.belief_base.get_or_create_host("sim-host-high").quarantined is True
    store.close()


def test_l2_scan_cadence_step_decay_after_clean_cycles(tmp_path):
    from sentryscan.contracts.events import EventType
    from sentryscan.observability.recorder import EventRecorder
    from sentryscan.storage.store import SQLiteRunStore

    clock = FakeClock("2026-10-21T06:30:00Z")
    id_gen = IdGenerator(seed=55)
    store = SQLiteRunStore(":memory:")
    store.save_run("run-decay-01", created_at=clock.now_iso())
    recorder = EventRecorder(
        run_id="run-decay-01",
        output_path=tmp_path / "trace.jsonl",
        clock=clock,
        sqlite_store=store,
    )

    l2 = AnalystAgent(
        agent_id="analyst-l2-incident",
        tier="L2",
        clock=clock,
        id_gen=id_gen,
        clean_cycles_for_decay=10,
        decay_step_ms=100,
    )
    assert l2.current_cadence_ms == 500

    # Tighten cadence to 100ms via HIGH alert
    alert = Message(
        message_id="msg-tight-01",
        run_id="run-decay-01",
        sender="analyst-l1-triage",
        receiver="analyst-l2-incident",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="nonce-tight-01",
        payload={"target_host": "sim-host-01", "finding_id": "f-01", "severity": "HIGH"},
    )
    reply = l2.process_message(alert)
    assert reply is not None
    assert l2.current_cadence_ms == 100

    # First 9 clean cycles: no decay yet
    for _ in range(9):
        assert l2.record_cycle_outcome(has_threats=False, run_id="run-decay-01", recorder=recorder) is None
    assert l2.current_cadence_ms == 100

    # Clean cycles 10..13 step cadence 100 -> 200 -> 300 -> 400 -> 500
    expected_steps = [200, 300, 400, 500]
    for exp_ms in expected_steps:
        msg = l2.record_cycle_outcome(has_threats=False, run_id="run-decay-01", recorder=recorder)
        assert msg is not None
        assert msg.performative == Performative.PARAMS_UPDATE
        assert msg.payload["scan_interval_ms"] == exp_ms
        assert l2.current_cadence_ms == exp_ms

    # Once at 500ms, further clean cycles do not emit redundant updates
    assert l2.record_cycle_outcome(has_threats=False, run_id="run-decay-01", recorder=recorder) is None

    recorder.close()
    events = store.get_events("run-decay-01")
    param_events = [e for e in events if e["event_type"] == EventType.PARAMS_UPDATE.value]
    assert len(param_events) == 4
    assert [e["details"]["scan_interval_ms"] for e in param_events] == [200, 300, 400, 500]
    store.close()


def test_dry_run_remediator_generates_rules_with_no_subprocess_or_socket():
    from unittest.mock import patch

    from sentryscan.agents.remediator import RemediatorAgent
    from sentryscan.contracts.finding import Finding, Severity
    from sentryscan.storage.store import SQLiteRunStore

    clock = FakeClock("2026-10-21T06:30:00Z")
    id_gen = IdGenerator(seed=77)
    store = SQLiteRunStore(":memory:")
    store.save_run("run-remed-01", created_at=clock.now_iso())

    f1 = Finding(
        finding_id="fnd-rem-01",
        run_id="run-remed-01",
        record_id="rec-rem-01",
        host_id="sim-host-q1",
        rule_id="RULE-004",
        severity=Severity.CRITICAL,
        confidence=1.0,
        title="Default creds on Telnet",
        description="Test",
        evidence={"port": 23, "ip": "192.0.2.55"},
        created_at=clock.now_iso(),
    )
    store.save_finding(f1, quarantined=False)
    store.save_pending_quarantine(
        quarantine_id="pq-rem-01",
        run_id="run-remed-01",
        host_id="sim-host-q1",
        finding_id="fnd-rem-01",
        rule_id="RULE-004",
        confidence=0.85,
        remote_exploitable=True,
        status="PENDING",
        created_at=clock.now_iso(),
    )

    with (
        patch("subprocess.Popen", side_effect=AssertionError("subprocess.Popen called")) as m_popen,
        patch("subprocess.run", side_effect=AssertionError("subprocess.run called")) as m_run,
        patch("subprocess.call", side_effect=AssertionError("subprocess.call called")) as m_call,
        patch("os.system", side_effect=AssertionError("os.system called")) as m_sys,
        patch("socket.socket", side_effect=AssertionError("socket.socket called")) as m_sock,
    ):
        # 1. Human approval triggers RemediatorAgent and writes report
        decided = store.decide_pending_quarantine(
            quarantine_id="pq-rem-01",
            decision="APPROVED",
            decided_by="soc-lead",
            decided_at=clock.now_iso(),
        )
        assert decided is not None
        assert decided["status"] == "APPROVED"

        # 2. Direct RemediatorAgent invocation on auto-approved host
        remediator = RemediatorAgent(clock=clock, id_gen=id_gen)
        plan = remediator.remediate_and_store(
            store=store,
            run_id="run-remed-01",
            host_id="sim-host-q2",
            findings=[f1.model_copy(update={"host_id": "sim-host-q2", "finding_id": "fnd-rem-02"})],
        )
        assert "iptables -A INPUT" in plan["data"]["iptables"]
        assert "table inet sentryscan_quarantine" in plan["data"]["nftables"]
        assert m_popen.call_count == 0
        assert m_run.call_count == 0
        assert m_call.call_count == 0
        assert m_sys.call_count == 0
        assert m_sock.call_count == 0

    reports = store.get_reports("run-remed-01")
    assert len(reports) == 2
    for rep in reports:
        assert rep["data"]["type"] == "remediation_plan"
        assert rep["data"]["dry_run"] is True
        assert "iptables" in rep["data"]["iptables"]
        assert "table inet" in rep["data"]["nftables"]
        assert rep["data"]["rationale"]
    store.close()


def test_bidder_feedback_loop_and_5_run_eval_comparison(tmp_path):
    from sentryscan.agents.scout import ScoutAgent
    from sentryscan.agents.triage import TriageAgent
    from sentryscan.capstone import run_eval
    from sentryscan.storage.store import SQLiteRunStore

    # 1. Verify bounded step updates and SQLite persistence
    triage = TriageAgent()
    scout = ScoutAgent()
    old_p, new_p = triage.update_port_weight(23, confirmed=True)
    assert new_p > old_p
    for _ in range(50):
        triage.update_port_weight(23, confirmed=True)
        scout.update_coverage_weight(confirmed=True)
    assert triage.port_weights[23] == TriageAgent.MAX_WEIGHT
    assert scout.coverage_weight == ScoutAgent.MAX_COVERAGE_WEIGHT

    for _ in range(50):
        triage.update_port_weight(23, confirmed=False)
        scout.update_coverage_weight(confirmed=False)
    assert triage.port_weights[23] == TriageAgent.MIN_WEIGHT
    assert scout.coverage_weight == ScoutAgent.MIN_COVERAGE_WEIGHT

    store = SQLiteRunStore(":memory:")
    store.save_bidder_weights({**triage.export_weights(), **scout.export_weights()})
    loaded = store.get_bidder_weights()
    assert loaded["triage_port_23"] == TriageAgent.MIN_WEIGHT
    assert loaded["scout_coverage_weight"] == ScoutAgent.MIN_COVERAGE_WEIGHT
    store.close()

    # 2. 5-run comparison: adaptive feedback vs fixed weights
    seeds = [11, 22, 33, 44, 55]
    for s in seeds:
        res_fixed = run_eval(
            seed=s, cycles=4, output_dir=tmp_path / f"fixed_{s}", adaptive_weights=False
        )
        res_adapt = run_eval(
            seed=s, cycles=4, output_dir=tmp_path / f"adapt_{s}", adaptive_weights=True
        )
        assert res_fixed["parity_passed"] is True
        assert res_adapt["parity_passed"] is True
        assert (
            res_adapt["eval_metrics"]["detection_precision"]
            >= res_fixed["eval_metrics"]["detection_precision"]
        )
        assert len(res_adapt["bidder_weights"]) > 0
