"""Unit tests for BDI BeliefBase, Desire, and Intention foundational models."""

from sentryscan.bdi import (
    BeliefBase,
    Desire,
    DesireType,
    HostBelief,
    HostStatus,
    Intention,
    IntentionState,
    IntentionStep,
    IntentionStepStatus,
)


def test_host_belief_lifecycle() -> None:
    """Test HostBelief state mutations, severity updates, and quarantine requirements."""
    host = HostBelief(host_id="sim-host-001", ip_address="192.0.2.10")
    assert host.status == HostStatus.CLEAN
    assert not host.is_critical()
    assert not host.requires_quarantine()

    host.highest_severity = "CRITICAL"
    assert host.is_critical()
    assert host.requires_quarantine()

    host.quarantined = True
    assert not host.requires_quarantine()


def test_belief_base_mutations_and_material_escalation() -> None:
    """Test BeliefBase updates and detection of material belief escalations."""
    bb = BeliefBase()
    host_id = "sim-host-007"

    # Initial low finding: non-material
    mat1 = bb.update_host_finding(
        host_id=host_id,
        finding_id="find-01",
        severity="LOW",
        timestamp_iso="2026-10-21T07:00:00Z",
    )
    assert not mat1
    host = bb.hosts[host_id]
    assert host.highest_severity == "LOW"
    assert host.status == HostStatus.CLEAN

    # Medium finding: non-material
    mat2 = bb.update_host_finding(
        host_id=host_id,
        finding_id="find-02",
        severity="MEDIUM",
        timestamp_iso="2026-10-21T07:01:00Z",
    )
    assert not mat2
    assert host.highest_severity == "MEDIUM"

    # Escalation to CRITICAL: material belief change
    mat3 = bb.update_host_finding(
        host_id=host_id,
        finding_id="find-03",
        severity="CRITICAL",
        timestamp_iso="2026-10-21T07:02:00Z",
        open_ports=[22, 443],
    )
    assert mat3
    assert host.highest_severity == "CRITICAL"
    assert host.status == HostStatus.COMPROMISED
    assert 22 in host.open_ports
    assert bb.get_uncontained_critical_hosts() == [host]

    # Quarantine host
    quarantine_changed = bb.quarantine_host(host_id)
    assert quarantine_changed
    assert host.quarantined
    assert host.status == HostStatus.QUARANTINED
    assert host_id in bb.fleet.quarantined_hosts
    assert len(bb.get_uncontained_critical_hosts()) == 0


def test_belief_base_budget_and_scans() -> None:
    """Test fleet budget deduction and scan tracking."""
    bb = BeliefBase()
    assert bb.fleet.remaining_budget == 100.0

    ok = bb.deduct_budget(30.0)
    assert ok
    assert bb.fleet.remaining_budget == 70.0
    assert bb.fleet.allocated_scans == 1

    # Overdraft attempt
    failed = bb.deduct_budget(80.0)
    assert not failed
    assert bb.fleet.remaining_budget == 70.0

    bb.record_scan_completed("sim-host-001")
    bb.record_scan_completed("sim-host-002")
    unscanned = bb.get_unscanned_hosts(["sim-host-001", "sim-host-002", "sim-host-003"])
    assert unscanned == ["sim-host-003"]


def test_desire_eligibility_evaluation() -> None:
    """Test that desires correctly evaluate their eligibility against current beliefs."""
    bb = BeliefBase()

    # Budget conservation desire
    d_budget = Desire(
        desire_id="d-budget-01",
        desire_type=DesireType.CONSERVE_BUDGET,
        priority=40.0,
    )
    assert not d_budget.is_eligible(bb)  # Budget is 100.0 >= 25.0

    bb.fleet.remaining_budget = 15.0
    assert d_budget.is_eligible(bb)  # Now eligible

    # Quarantine desire without target
    d_contain = Desire(
        desire_id="d-contain-01",
        desire_type=DesireType.CONTAIN_COMPROMISED_HOSTS,
        priority=100.0,
    )
    assert not d_contain.is_eligible(bb)  # No compromised hosts yet

    bb.update_host_finding("sim-host-99", "find-99", "CRITICAL")
    assert d_contain.is_eligible(bb)  # Eligible because sim-host-99 is critical

    bb.quarantine_host("sim-host-99")
    assert not d_contain.is_eligible(bb)  # Not eligible once quarantined


def test_intention_lifecycle_and_step_execution() -> None:
    """Test Intention step advancement, completion, and abandonment."""
    steps = [
        IntentionStep(step_id="step-01", action="ISOLATE_NETWORK_INTERFACE"),
        IntentionStep(step_id="step-02", action="COLLECT_FORENSIC_TRIAGE"),
        IntentionStep(step_id="step-03", action="ALERT_SECURITY_OFFICER"),
    ]
    intention = Intention(
        intention_id="int-01",
        desire_id="d-contain-01",
        desire_type=DesireType.CONTAIN_COMPROMISED_HOSTS,
        target_host="sim-host-007",
        steps=steps,
    )

    assert intention.state == IntentionState.ACTIVE
    assert intention.current_step().step_id == "step-01"

    # Advance first step
    has_more = intention.advance_step(step_result={"quarantined": True})
    assert has_more
    assert steps[0].status == IntentionStepStatus.COMPLETED
    assert intention.current_step().step_id == "step-02"

    # Abandon during step 2
    intention.abandon("Preempted by emergency shutdown order")
    assert intention.state == IntentionState.ABANDONED
    assert intention.reconsideration_reason == "Preempted by emergency shutdown order"
    assert intention.is_finished()
    assert steps[1].status == IntentionStepStatus.FAILED
