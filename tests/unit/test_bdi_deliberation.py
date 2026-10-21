"""Unit tests for BDI Deliberator option generation, ranking, and intention synthesis."""

from sentryscan.bdi import (
    BDIDeliberator,
    BeliefBase,
    DesireType,
    IntentionState,
)
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator


def test_deliberator_nominal_audit_selection() -> None:
    """When the fleet is clean and budget is ample, deliberator adopts AUDIT_ASSIGNED_HOSTS."""
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    deliberator = BDIDeliberator(clock=clock, id_gen=id_gen)
    beliefs = BeliefBase()

    winning_desire = deliberator.deliberate(beliefs)
    assert winning_desire is not None
    assert winning_desire.desire_type == DesireType.AUDIT_ASSIGNED_HOSTS
    assert winning_desire.priority == 60.0

    plan = deliberator.create_plan(winning_desire, beliefs)
    assert plan.desire_type == DesireType.AUDIT_ASSIGNED_HOSTS
    assert plan.state == IntentionState.ACTIVE
    assert len(plan.steps) == 2
    assert plan.steps[0].action == "SET_SCAN_CADENCE"
    assert plan.steps[0].parameters["cadence_ms"] == 250
    assert plan.steps[1].action == "SCHEDULE_FLEET_AUDIT"


def test_deliberator_critical_host_escalation() -> None:
    """When a critical uncontained host appears, deliberator preempts audit to CONTAIN."""
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    deliberator = BDIDeliberator(clock=clock, id_gen=id_gen)
    beliefs = BeliefBase()

    # Inject critical finding on sim-host-007
    beliefs.update_host_finding(
        host_id="sim-host-007",
        finding_id="find-sqli-01",
        severity="CRITICAL",
        open_ports=[80, 443, 22],
    )

    plan = deliberator.deliberate_and_plan(beliefs)
    assert plan is not None
    assert plan.desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS
    assert plan.target_host == "sim-host-007"
    assert len(plan.steps) == 4

    # Verify ordered emergency steps
    actions = [s.action for s in plan.steps]
    assert actions == [
        "QUARANTINE_HOST",
        "SET_SCAN_CADENCE",
        "SCHEDULE_PRIORITY_PORTS",
        "EMIT_CONTAINMENT_ALERT",
    ]
    assert plan.steps[1].parameters["cadence_ms"] == 50
    assert plan.steps[2].parameters["priority_ports"] == [80, 443, 22]


def test_deliberator_budget_conservation_preemption() -> None:
    """When budget drops critically low (< 10.0), CONSERVE_BUDGET takes priority over audit."""
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    deliberator = BDIDeliberator(clock=clock, id_gen=id_gen)
    beliefs = BeliefBase()
    beliefs.fleet.remaining_budget = 8.5  # Critical budget depletion

    winning_desire = deliberator.deliberate(beliefs)
    assert winning_desire is not None
    assert winning_desire.desire_type == DesireType.CONSERVE_BUDGET
    assert winning_desire.priority == 85.0

    plan = deliberator.create_plan(winning_desire, beliefs)
    assert plan.desire_type == DesireType.CONSERVE_BUDGET
    actions = [s.action for s in plan.steps]
    assert actions == [
        "SET_SCAN_CADENCE",
        "RESTRICT_SCAN_PORTS",
        "EMIT_BUDGET_WARNING",
    ]
    assert plan.steps[0].parameters["cadence_ms"] == 1000


def test_deliberator_quarantined_host_switches_to_triage() -> None:
    """After quarantine is applied, deliberation shifts to SURFACE_CRITICAL_FINDINGS."""
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    deliberator = BDIDeliberator(clock=clock, id_gen=id_gen)
    beliefs = BeliefBase()

    # Host is critical AND quarantined
    beliefs.update_host_finding("sim-host-007", "find-01", "CRITICAL")
    beliefs.quarantine_host("sim-host-007")

    plan = deliberator.deliberate_and_plan(beliefs)
    assert plan is not None
    assert plan.desire_type == DesireType.SURFACE_CRITICAL_FINDINGS
    assert plan.target_host == "sim-host-007"
    actions = [s.action for s in plan.steps]
    assert actions == [
        "SET_SCAN_CADENCE",
        "SCHEDULE_PRIORITY_PORTS",
        "COLLECT_FORENSIC_TRIAGE",
    ]
