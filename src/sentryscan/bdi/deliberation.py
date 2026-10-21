"""BDI Deliberation and Intention Selection engine for SentryScan."""

from __future__ import annotations

import logging

from sentryscan.bdi.beliefs import BeliefBase, HostBelief
from sentryscan.bdi.desires import Desire, DesireType
from sentryscan.bdi.intentions import (
    Intention,
    IntentionState,
    IntentionStep,
)
from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator

logger = logging.getLogger(__name__)


class BDIDeliberator:
    """Deliberative engine that evaluates beliefs, selects desires, and builds intentions."""

    def __init__(
        self,
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
    ) -> None:
        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator()

    def generate_options(self, beliefs: BeliefBase) -> list[Desire]:
        """Generate candidate desires (options) from current epistemic beliefs."""
        options: list[Desire] = []
        now_iso = self.clock.now_iso()

        # 1. Check for uncontained critical/compromised hosts
        uncontained = beliefs.get_uncontained_critical_hosts()
        for host in uncontained:
            options.append(
                Desire(
                    desire_id=self.id_gen.next_id("desire"),
                    desire_type=DesireType.CONTAIN_COMPROMISED_HOSTS,
                    priority=100.0,
                    target_host=host.host_id,
                    description=(
                        f"Contain critical compromised host {host.host_id} "
                        f"with active findings {host.finding_ids}"
                    ),
                    created_at_iso=now_iso,
                    parameters={"severity": host.highest_severity},
                )
            )

        # 2. Check for hosts needing critical finding escalation / deep inspection
        for host_id, host in beliefs.hosts.items():
            if host.is_critical() and host.quarantined:
                # Already quarantined, but needs ongoing triage/inspection
                options.append(
                    Desire(
                        desire_id=self.id_gen.next_id("desire"),
                        desire_type=DesireType.SURFACE_CRITICAL_FINDINGS,
                        priority=90.0,
                        target_host=host_id,
                        description=(
                            f"Surface forensic triage findings for "
                            f"quarantined host {host_id}"
                        ),
                        created_at_iso=now_iso,
                    )
                )
            elif host.highest_severity == "HIGH":
                options.append(
                    Desire(
                        desire_id=self.id_gen.next_id("desire"),
                        desire_type=DesireType.SURFACE_CRITICAL_FINDINGS,
                        priority=80.0,
                        target_host=host_id,
                        description=f"Triage high-severity exposure on {host_id}",
                        created_at_iso=now_iso,
                    )
                )

        # 3. Budget conservation desire if budget is tight
        if beliefs.fleet.remaining_budget < 25.0:
            urgency = 85.0 if beliefs.fleet.remaining_budget < 10.0 else 55.0
            options.append(
                Desire(
                    desire_id=self.id_gen.next_id("desire"),
                    desire_type=DesireType.CONSERVE_BUDGET,
                    priority=urgency,
                    description=(
                        f"Conserve remaining budget "
                        f"({beliefs.fleet.remaining_budget:.1f} left)"
                    ),
                    created_at_iso=now_iso,
                )
            )

        # 4. Fleet coverage desire
        if beliefs.fleet.remaining_budget >= 5.0:
            options.append(
                Desire(
                    desire_id=self.id_gen.next_id("desire"),
                    desire_type=DesireType.AUDIT_ASSIGNED_HOSTS,
                    priority=60.0,
                    description="Audit unscanned hosts across synthetic fleet",
                    created_at_iso=now_iso,
                )
            )

        # 5. Baseline audit trail preservation (always active)
        options.append(
            Desire(
                desire_id=self.id_gen.next_id("desire"),
                desire_type=DesireType.MAINTAIN_AUDIT_TRAIL,
                priority=20.0,
                description="Maintain comprehensive forensic audit trail",
                created_at_iso=now_iso,
            )
        )

        return options

    def filter_and_rank_desires(
        self,
        options: list[Desire],
        beliefs: BeliefBase,
    ) -> list[Desire]:
        """Filter desires by feasibility under beliefs, sorted descending by priority."""
        eligible = [d for d in options if d.is_eligible(beliefs)]
        # Deterministic sort: descending priority, then alphabetical desire_id
        return sorted(eligible, key=lambda d: (-d.priority, d.desire_id))

    def deliberate(self, beliefs: BeliefBase) -> Desire | None:
        """Select the highest-priority feasible desire from candidate options."""
        options = self.generate_options(beliefs)
        ranked = self.filter_and_rank_desires(options, beliefs)
        if ranked:
            return ranked[0]
        return None

    def create_plan(self, desire: Desire, beliefs: BeliefBase) -> Intention:
        """Synthesize a committed intention with an ordered sequence of action steps."""
        now_iso = self.clock.now_iso()
        steps: list[IntentionStep] = []
        target = desire.target_host

        if desire.desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS and target:
            host: HostBelief | None = beliefs.hosts.get(target)
            ports = host.open_ports if host else [80, 443, 22, 23, 3389, 8080]
            steps = [
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="QUARANTINE_HOST",
                    parameters={"target_host": target, "quarantine_flag": True},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="SET_SCAN_CADENCE",
                    parameters={"target_host": target, "cadence_ms": 50},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="SCHEDULE_PRIORITY_PORTS",
                    parameters={"target_host": target, "priority_ports": ports},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="EMIT_CONTAINMENT_ALERT",
                    parameters={"target_host": target, "severity": "CRITICAL"},
                ),
            ]
            rationale = (
                f"Emergency containment sequence adopted for {target} "
                "due to uncontained critical finding."
            )

        elif desire.desire_type == DesireType.SURFACE_CRITICAL_FINDINGS and target:
            steps = [
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="SET_SCAN_CADENCE",
                    parameters={"target_host": target, "cadence_ms": 100},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="SCHEDULE_PRIORITY_PORTS",
                    parameters={"target_host": target, "priority_ports": [80, 443, 22]},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="COLLECT_FORENSIC_TRIAGE",
                    parameters={"target_host": target},
                ),
            ]
            rationale = f"Deep inspection and triage sequence adopted for high-severity {target}."

        elif desire.desire_type == DesireType.CONSERVE_BUDGET:
            steps = [
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="SET_SCAN_CADENCE",
                    parameters={"cadence_ms": 1000},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="RESTRICT_SCAN_PORTS",
                    parameters={"priority_ports": [80, 443]},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="EMIT_BUDGET_WARNING",
                    parameters={"remaining_budget": beliefs.fleet.remaining_budget},
                ),
            ]
            rationale = (
                f"Resource conservation plan adopted: remaining budget is "
                f"{beliefs.fleet.remaining_budget:.1f}."
            )

        elif desire.desire_type == DesireType.AUDIT_ASSIGNED_HOSTS:
            steps = [
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="SET_SCAN_CADENCE",
                    parameters={"cadence_ms": 250},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="SCHEDULE_FLEET_AUDIT",
                    parameters={"batch_size": 5},
                ),
            ]
            rationale = "Nominal fleet sweep plan adopted to maximize coverage."

        else:  # MAINTAIN_AUDIT_TRAIL or default
            steps = [
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="FLUSH_AUDIT_RECORDS",
                    parameters={},
                ),
                IntentionStep(
                    step_id=self.id_gen.next_id("step"),
                    action="VERIFY_CHAIN_INTEGRITY",
                    parameters={},
                ),
            ]
            rationale = "Baseline audit verification plan adopted."

        return Intention(
            intention_id=self.id_gen.next_id("intention"),
            desire_id=desire.desire_id,
            desire_type=desire.desire_type,
            target_host=target,
            state=IntentionState.ACTIVE,
            steps=steps,
            current_step_index=0,
            adopted_at_iso=now_iso,
            rationale=rationale,
        )

    def deliberate_and_plan(self, beliefs: BeliefBase) -> Intention | None:
        """Execute full deliberation cycle: generate, rank, select, and instantiate intention."""
        winning_desire = self.deliberate(beliefs)
        if winning_desire is None:
            return None
        return self.create_plan(winning_desire, beliefs)
