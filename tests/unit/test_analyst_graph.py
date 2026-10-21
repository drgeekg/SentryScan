"""Unit tests for the deliberative Analyst LangGraph workflow."""

from sentryscan.bdi.beliefs import BeliefBase
from sentryscan.bdi.desires import DesireType
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.graphs.analyst_graph import build_analyst_graph
from sentryscan.graphs.analyst_state import AnalystGraphState


def test_analyst_graph_initial_invocation() -> None:
    """Test initial invocation compiles graph and adopts baseline intention."""
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=101)
    graph = build_analyst_graph(clock=clock, id_gen=id_gen)

    state: AnalystGraphState = {
        "beliefs": BeliefBase(),
        "active_intention": None,
        "reconsideration_history": [],
        "incoming_percept": {
            "target_host": "192.0.2.50",
            "finding_id": "fnd-info-01",
            "severity": "INFO",
        },
    }

    result = graph.invoke(state)
    assert result["status"] == "STEP_EXECUTED"
    assert result["active_intention"] is not None
    assert result["active_intention"].desire_type == DesireType.AUDIT_ASSIGNED_HOSTS
    assert len(result["reconsideration_history"]) == 1
    assert result["reconsideration_history"][0].trigger == "INITIAL_DELIBERATION"
    assert result["generated_action"] is not None
    assert result["generated_action"]["action"] == "NOMINAL_MONITORING"


def test_analyst_graph_critical_finding_triggers_reconsideration() -> None:
    """Test that a critical percept triggers material reconsideration and preemption."""
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=102)
    graph = build_analyst_graph(clock=clock, id_gen=id_gen)

    # First run: establish nominal intention
    s1: AnalystGraphState = {
        "beliefs": BeliefBase(),
        "active_intention": None,
        "reconsideration_history": [],
        "incoming_percept": {"target_host": "192.0.2.10", "severity": "LOW"},
    }
    r1 = graph.invoke(s1)
    init_plan = r1["active_intention"]
    assert init_plan.desire_type == DesireType.AUDIT_ASSIGNED_HOSTS

    # Second run: Inject CRITICAL finding on sim-host-007
    s2: AnalystGraphState = {
        "beliefs": r1["beliefs"],
        "active_intention": init_plan,
        "reconsideration_history": r1["reconsideration_history"],
        "incoming_percept": {
            "target_host": "sim-host-007",
            "finding_id": "fnd-sqli-99",
            "severity": "CRITICAL",
        },
    }
    r2 = graph.invoke(s2)

    # Intention should be preempted and replaced with containment plan
    new_plan = r2["active_intention"]
    assert new_plan.intention_id != init_plan.intention_id
    assert new_plan.desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS
    assert new_plan.target_host == "sim-host-007"

    # Reconsideration history should contain 2 records
    history = r2["reconsideration_history"]
    assert len(history) == 2
    replan_record = history[-1]
    assert replan_record.reconsidered is True
    assert replan_record.trigger == "MATERIAL_BELIEF_UPDATE"
    assert replan_record.material_change is True
    assert replan_record.previous_intention_id == init_plan.intention_id
    assert replan_record.previous_desire_type == DesireType.AUDIT_ASSIGNED_HOSTS.value
    assert replan_record.new_intention_id == new_plan.intention_id
    assert replan_record.new_desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS.value
    assert "Material severity escalation" in replan_record.replan_reason

    # Generated action should be quarantine deep inspection
    action = r2["generated_action"]
    assert action["quarantine_flag"] is True
    assert action["scan_interval_ms"] == 50
    assert r2["beliefs"].hosts["sim-host-007"].quarantined is True
