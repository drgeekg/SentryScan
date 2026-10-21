"""Deliberative Analyst LangGraph workflow orchestrating BDI reasoning and replanning."""

from __future__ import annotations

import logging
from typing import Any

from langgraph.graph import END, START, StateGraph

from sentryscan.bdi.beliefs import BeliefBase
from sentryscan.bdi.deliberation import BDIDeliberator
from sentryscan.bdi.intentions import IntentionState
from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.graphs.analyst_state import AnalystGraphState, ReconsiderationRecord

logger = logging.getLogger(__name__)


def build_analyst_graph(
    clock: Clock | None = None,
    id_gen: IdGenerator | None = None,
):
    """Construct and compile the deliberative Analyst LangGraph workflow."""
    clk = clock if clock is not None else SystemClock()
    igen = id_gen if id_gen is not None else IdGenerator()
    deliberator = BDIDeliberator(clock=clk, id_gen=igen)

    # 1. Perception & Belief Revision Node
    def perceive_node(state: AnalystGraphState) -> dict[str, Any]:
        beliefs = state.get("beliefs")
        if beliefs is None:
            beliefs = BeliefBase()

        percept = state.get("incoming_percept") or {}
        target_host = percept.get("target_host") or percept.get("host_id")
        finding_id = percept.get("finding_id", "fnd-auto")
        severity = str(percept.get("severity", "INFO")).upper()
        ports = percept.get("priority_ports") or percept.get("open_ports")

        is_material = False
        replan_reason = ""
        if target_host:
            is_material = beliefs.update_host_finding(
                host_id=target_host,
                finding_id=finding_id,
                severity=severity,
                timestamp_iso=clk.now_iso(),
                open_ports=ports,
            )
            if is_material:
                replan_reason = (
                    f"Material severity escalation to {severity} on {target_host} "
                    f"from finding {finding_id}"
                )

        return {
            "beliefs": beliefs,
            "reconsideration_needed": is_material,
            "replan_reason": replan_reason,
        }

    # 2. Check Reconsideration Node
    def check_reconsideration_node(state: AnalystGraphState) -> dict[str, Any]:
        needs_replan = state.get("reconsideration_needed", False)
        replan_reason = state.get("replan_reason", "")
        active_plan = state.get("active_intention")
        beliefs = state.get("beliefs", BeliefBase())

        if active_plan is None:
            needs_replan = True
            replan_reason = "No active intention currently adopted"
        elif active_plan.is_finished():
            needs_replan = True
            replan_reason = f"Active intention {active_plan.intention_id} has terminated"
        elif not needs_replan:
            # Check if active intention's desire is no longer eligible under updated beliefs
            if active_plan.target_host:
                host = beliefs.hosts.get(active_plan.target_host)
                is_containment = active_plan.desire_type.value == "CONTAIN_COMPROMISED_HOSTS"
                if host and host.quarantined and is_containment:
                    needs_replan = True
                    replan_reason = (
                        f"Target host {active_plan.target_host} is now quarantined; "
                        "containment desire satisfied"
                    )

        return {
            "reconsideration_needed": needs_replan,
            "replan_reason": replan_reason,
        }

    # Conditional router
    def route_reconsideration(state: AnalystGraphState) -> str:
        if state.get("reconsideration_needed", False):
            return "deliberate_and_plan"
        return "execute_step"

    # 3. Deliberation & Plan Generation Node
    def deliberate_and_plan_node(state: AnalystGraphState) -> dict[str, Any]:
        beliefs = state.get("beliefs", BeliefBase())
        old_plan = state.get("active_intention")
        replan_reason = state.get("replan_reason", "Deliberation triggered")
        history = list(state.get("reconsideration_history", []))

        new_plan = deliberator.deliberate_and_plan(beliefs)

        now_iso = clk.now_iso()
        if old_plan is not None and not old_plan.is_finished():
            # Abandon old intention with explicit rationale
            old_plan.abandon(replan_reason)
            is_mat = "Material" in replan_reason
            record = ReconsiderationRecord(
                timestamp_utc=now_iso,
                trigger="MATERIAL_BELIEF_UPDATE" if is_mat else "PLAN_SUPERSEDED",
                material_change=is_mat,
                reconsidered=True,
                previous_intention_id=old_plan.intention_id,
                previous_desire_type=old_plan.desire_type.value,
                new_intention_id=new_plan.intention_id if new_plan else None,
                new_desire_type=new_plan.desire_type.value if new_plan else None,
                replan_reason=replan_reason,
            )
            history.append(record)
        elif old_plan is None and new_plan is not None:
            # Initial intention adoption
            record = ReconsiderationRecord(
                timestamp_utc=now_iso,
                trigger="INITIAL_DELIBERATION",
                material_change=False,
                reconsidered=False,
                previous_intention_id=None,
                previous_desire_type=None,
                new_intention_id=new_plan.intention_id,
                new_desire_type=new_plan.desire_type.value,
                replan_reason=replan_reason,
            )
            history.append(record)

        return {
            "active_intention": new_plan,
            "reconsideration_history": history,
            "reconsideration_needed": False,
        }

    # 4. Intention Step Execution Node
    def execute_step_node(state: AnalystGraphState) -> dict[str, Any]:
        beliefs = state.get("beliefs", BeliefBase())
        plan = state.get("active_intention")

        if plan is None:
            return {"generated_action": None, "status": "IDLE"}

        step = plan.current_step()
        if step is None:
            plan.state = IntentionState.COMPLETED
            return {
                "active_intention": plan,
                "generated_action": None,
                "status": "INTENTION_COMPLETED",
            }

        target = step.parameters.get("target_host") or plan.target_host or "unknown-host"
        action_name = step.action

        if action_name == "QUARANTINE_HOST":
            beliefs.quarantine_host(target)
            generated_action = {
                "target_host": target,
                "action": "DEEP_INSPECTION",
                "scan_interval_ms": 50,
                "priority_ports": [80, 443, 22, 23, 3389, 8080],
                "quarantine_flag": True,
                "rationale": (
                    f"Critical finding on {target}. "
                    "Escalating to immediate high-frequency deep inspection with host quarantine."
                ),
            }
            plan.advance_step(step_result={"quarantined": True})

        elif action_name == "SET_SCAN_CADENCE":
            cadence = int(step.parameters.get("cadence_ms", 250))
            is_deep = cadence <= 100
            ports = step.parameters.get("priority_ports", [80, 443, 22] if is_deep else [])
            generated_action = {
                "target_host": target,
                "action": "DEEP_INSPECTION" if is_deep else "NOMINAL_MONITORING",
                "scan_interval_ms": cadence,
                "priority_ports": ports,
                "quarantine_flag": False,
                "rationale": (
                    f"High-severity finding on {target}. Tightening sampling window "
                    "and monitoring core exposure ports."
                    if is_deep
                    else f"Applying standard observation cadence ({cadence}ms) on {target}."
                ),
            }
            plan.advance_step(step_result={"cadence_ms": cadence})

        elif action_name == "SCHEDULE_PRIORITY_PORTS":
            ports = list(step.parameters.get("priority_ports", [80, 443, 22]))
            generated_action = {
                "target_host": target,
                "action": "DEEP_INSPECTION",
                "scan_interval_ms": 100,
                "priority_ports": ports,
                "quarantine_flag": False,
                "rationale": f"Deep inspection targeting priority ports {ports} on {target}.",
            }
            plan.advance_step(step_result={"priority_ports": ports})

        else:
            generated_action = {
                "target_host": target,
                "action": "NOMINAL_MONITORING",
                "scan_interval_ms": 500,
                "priority_ports": [],
                "quarantine_flag": False,
                "rationale": f"Executing step {action_name} under desire {plan.desire_type.value}.",
            }
            plan.advance_step(step_result={"action": action_name, "status": "COMPLETED"})

        return {
            "beliefs": beliefs,
            "active_intention": plan,
            "generated_action": generated_action,
            "status": "STEP_EXECUTED",
        }

    # Build LangGraph workflow
    workflow = StateGraph(AnalystGraphState)
    workflow.add_node("perceive", perceive_node)
    workflow.add_node("check_reconsideration", check_reconsideration_node)
    workflow.add_node("deliberate_and_plan", deliberate_and_plan_node)
    workflow.add_node("execute_step", execute_step_node)

    workflow.add_edge(START, "perceive")
    workflow.add_edge("perceive", "check_reconsideration")
    workflow.add_conditional_edges(
        "check_reconsideration",
        route_reconsideration,
        {
            "deliberate_and_plan": "deliberate_and_plan",
            "execute_step": "execute_step",
        },
    )
    workflow.add_edge("deliberate_and_plan", "execute_step")
    workflow.add_edge("execute_step", END)

    return workflow.compile()
