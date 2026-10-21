"""Integration test proving autonomous BDI intention preemption upon critical belief updates."""

from __future__ import annotations

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.bdi.desires import DesireType
from sentryscan.bdi.intentions import IntentionState
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Message, Performative
from sentryscan.transport.in_process import InProcessTransport


def test_bdi_intention_changes_after_critical_belief_injection() -> None:
    """Prove that an injected critical finding triggers BDI intention preemption.

    Scenario:
    1. Analyst initializes with clean beliefs and adopts nominal fleet audit intention.
    2. Routine low-severity percept arrives: intention is preserved.
    3. Critical finding is injected on sim-host-007: triggers reconsideration.
    4. Previous intention is abandoned with an explicit logged rationale.
    5. New emergency intention (CONTAIN_COMPROMISED_HOSTS) is adopted and steps are executed.
    """
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=777)
    analyst = AnalystAgent(agent_id="analyst-agent-01", clock=clock, id_gen=id_gen)

    # Step 1: Initial alert with nominal severity
    msg_low = Message(
        message_id="msg-001",
        run_id="run-bdi-proof",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T07:00:00Z",
        nonce="nonce-001",
        payload={
            "target_host": "sim-host-001",
            "finding_id": "fnd-info-001",
            "severity": "INFO",
            "rule_id": "RULE-05-BANNER",
        },
    )
    reply_low = analyst.process_message(msg_low)
    assert reply_low is not None
    assert reply_low.performative == Performative.PARAMS_UPDATE

    # Verify initial intention state
    initial_intention = analyst.active_intention
    assert initial_intention is not None
    assert initial_intention.desire_type == DesireType.AUDIT_ASSIGNED_HOSTS
    assert initial_intention.state == IntentionState.ACTIVE
    initial_intention_id = initial_intention.intention_id

    # Step 2: Critical finding arrives while initial intention is actively in-progress
    critical_host = "sim-host-007"
    critical_finding_id = "fnd-crit-rce-007"
    msg_critical = Message(
        message_id="msg-002",
        run_id="run-bdi-proof",
        sender="supervisor-agent",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T07:01:00Z",
        nonce="nonce-002",
        payload={
            "target_host": critical_host,
            "finding_id": critical_finding_id,
            "rule_id": "RULE-01-CRITICAL-EXPLOIT",
            "severity": "CRITICAL",
            "priority_ports": [80, 443, 22, 8080],
        },
    )

    reply_critical = analyst.process_message(msg_critical)
    assert reply_critical is not None
    assert reply_critical.performative == Performative.PARAMS_UPDATE
    assert reply_critical.payload["target_host"] == critical_host
    assert reply_critical.payload["action"] == "DEEP_INSPECTION"
    assert reply_critical.payload["quarantine_flag"] is True
    assert reply_critical.payload["scan_interval_ms"] == 50

    # Step 3: Prove that intention changed and previous was preempted mid-stream
    reconsidered_intention = analyst.active_intention
    assert reconsidered_intention is not None
    assert reconsidered_intention.intention_id != initial_intention_id
    assert reconsidered_intention.desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS
    assert reconsidered_intention.target_host == critical_host

    # Step 4: Verify auditable ReconsiderationRecord
    history = analyst.reconsideration_history
    assert len(history) == 2

    # Initial record
    assert history[0].trigger == "INITIAL_DELIBERATION"
    assert history[0].new_desire_type == DesireType.AUDIT_ASSIGNED_HOSTS.value

    # The latest record documents the preemption
    replan_record = history[-1]
    assert replan_record.reconsidered is True
    assert replan_record.trigger == "MATERIAL_BELIEF_UPDATE"
    assert replan_record.material_change is True
    assert replan_record.previous_intention_id == initial_intention_id
    assert replan_record.previous_desire_type == DesireType.AUDIT_ASSIGNED_HOSTS.value
    assert replan_record.new_intention_id == reconsidered_intention.intention_id
    assert replan_record.new_desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS.value
    assert "Material severity escalation to CRITICAL on sim-host-007" in replan_record.replan_reason

    # Verify belief state reflects quarantine and compromised status
    host_belief = analyst.belief_base.hosts[critical_host]
    assert host_belief.quarantined is True
    assert host_belief.highest_severity == "CRITICAL"
    assert critical_host in analyst.belief_base.fleet.quarantined_hosts


def test_bdi_transport_roundtrip_reconsideration() -> None:
    """Verify BDI intention transition over InProcessTransport simulating inter-agent channel."""
    clock = FakeClock("2026-10-21T07:10:00Z")
    id_gen = IdGenerator(seed=888)
    analyst = AnalystAgent(agent_id="analyst-agent-01", clock=clock, id_gen=id_gen)

    t_sup, t_ana = InProcessTransport.create_pair()

    # Send CRITICAL alert over transport
    alert = Message(
        message_id="msg-t-01",
        run_id="run-t-01",
        sender="supervisor",
        receiver="analyst",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T07:10:00Z",
        nonce="nonce-t-01",
        payload={
            "target_host": "sim-host-009",
            "finding_id": "fnd-t-crit",
            "severity": "CRITICAL",
        },
    )
    t_sup.send(alert)

    # Analyst receives and responds
    inbound = t_ana.receive(timeout=1.0)
    assert inbound is not None
    reply = analyst.process_message(inbound)
    assert reply is not None
    t_ana.send(reply)

    # Supervisor receives response
    resp = t_sup.receive(timeout=1.0)
    assert resp is not None
    assert resp.performative == Performative.PARAMS_UPDATE
    assert resp.payload["quarantine_flag"] is True

    # Assert BDI intention state
    assert analyst.active_intention.desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS
    assert analyst.active_intention.target_host == "sim-host-009"
