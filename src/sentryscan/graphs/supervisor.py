"""LangGraph supervisor graph orchestrating multi-agent negotiation and worker fan-out."""



from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Sequence

if TYPE_CHECKING:
    from sentryscan.agents.analyst import AnalystAgent



from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from sentryscan.agents.scout import ScoutAgent
from sentryscan.agents.triage import TriageAgent
from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.finding import Finding
from sentryscan.contracts.message import Message, Performative
from sentryscan.contracts.telemetry import TelemetryRecord
from sentryscan.graphs.state import SupervisorState
from sentryscan.llm.interface import LLMProvider
from sentryscan.negotiation.protocol import ContractNetNegotiator
from sentryscan.rules.engine import RuleEngine, build_default_rules
from sentryscan.security.canonical import sign_envelope
from sentryscan.security.identity import AgentIdentity

logger = logging.getLogger(__name__)





def build_supervisor_graph(

    clock: Clock | None = None,

    id_gen: IdGenerator | None = None,

    llm_provider: LLMProvider | None = None,

    analyst_agent: AnalystAgent | None = None,

    supervisor_identity: AgentIdentity | None = None,

    max_rounds: int = 5,

):

    """Construct and compile the multi-agent LangGraph supervisor workflow."""

    clk = clock if clock is not None else SystemClock()

    igen = id_gen if id_gen is not None else IdGenerator()



    scout = ScoutAgent(llm_provider=llm_provider, id_gen=igen)

    triage = TriageAgent(llm_provider=llm_provider, id_gen=igen)

    negotiator = ContractNetNegotiator(

        supervisor_id="supervisor-agent",

        scout_agent=scout,

        triage_agent=triage,

        clock=clk,

        id_gen=igen,

        max_rounds=max_rounds,

    )

    rule_engine = RuleEngine(rules=build_default_rules())



    # 1. Negotiation Node

    def negotiate_node(state: SupervisorState) -> dict[str, Any]:

        task_id = state.get("task_id", igen.next_id("task"))

        run_id = state.get("run_id", igen.next_id("run"))

        batches = state.get("batches", {})

        constraints = state.get("constraints", {"max_cost": 100.0, "max_time": 1000.0})



        result = negotiator.run_negotiation(

            task_id=task_id,

            run_id=run_id,

            batches=batches,

            initial_constraints=constraints,

        )



        if result.status == "CONSENSUS_REACHED" and result.winning_proposal is not None:

            return {

                "phase": "AWARDED",

                "negotiation_round": result.rounds_completed,

                "winning_proposal": result.winning_proposal,

                "awarded_proposer": result.winning_proposer,

                "awarded_batch_ids": result.awarded_batch_ids,

                "messages": result.messages,

            }

        return {

            "phase": "UNRESOLVED",

            "negotiation_round": result.rounds_completed,

            "winning_proposal": None,

            "awarded_proposer": None,

            "awarded_batch_ids": [],

            "messages": result.messages,

        }



    # 2. Dynamic Routing / Dispatch using Send

    def route_after_negotiate(state: SupervisorState) -> Sequence[str | Send]:

        if state.get("phase") == "AWARDED" and state.get("awarded_batch_ids"):

            batches = state.get("batches", {})

            run_id = state.get("run_id", "run-default")

            task_id = state.get("task_id", "task-default")



            return [

                Send(

                    "scanner_worker",

                    {

                        "batch_id": bid,

                        "records": batches.get(bid, []),

                        "run_id": run_id,

                        "task_id": task_id,

                    },

                )

                for bid in state["awarded_batch_ids"]

            ]

        return ["handle_unresolved"]



    # 3. Scanner Worker Node (Executed per awarded batch via Send)

    def scanner_worker_node(worker_input: dict[str, Any]) -> dict[str, Any]:

        batch_id = worker_input.get("batch_id", "unknown-batch")

        raw_records = worker_input.get("records", [])

        run_id = worker_input.get("run_id", "run-default")

        task_id = worker_input.get("task_id", "task-default")



        worker_findings: list[Finding] = []

        for r_dict in raw_records:

            try:

                rec = TelemetryRecord.model_validate(r_dict)

                findings = rule_engine.evaluate_record(

                    record=rec,

                    run_id=run_id,

                    finding_id_generator=lambda: igen.next_id("finding"),

                    timestamp_iso=clk.now_iso(),

                )

                worker_findings.extend(findings)

            except Exception as err:

                logger.warning("Worker failed to evaluate record in batch %s: %s", batch_id, err)



        worker_msg = Message(

            message_id=igen.next_id("message"),

            run_id=run_id,

            sender=f"worker-{batch_id}",

            receiver="supervisor-agent",

            performative=Performative.TASK_RESULT,

            timestamp_utc=clk.now_iso(),

            nonce=igen.seeded_token(16),

            task_id=task_id,

            payload={

                "batch_id": batch_id,

                "records_evaluated": len(raw_records),

                "findings_count": len(worker_findings),

            },

        )



        return {

            "findings": worker_findings,

            "messages": [worker_msg],

        }



    # 4. Analyst Deliberation Node (Escalate findings to AnalystAgent)

    def analyst_triage_node(state: SupervisorState) -> dict[str, Any]:

        if analyst_agent is None:

            return {"analyst_replies": [], "quarantined_hosts": []}



        findings = state.get("findings", [])

        run_id = state.get("run_id", "run-default")

        task_id = state.get("task_id", "task-default")

        replies: list[Message] = []

        quarantined: list[str] = []



        for finding in findings:

            sev_val = (

                finding.severity.value

                if hasattr(finding.severity, "value")

                else str(finding.severity)

            )

            svc = finding.evidence.get("service") if finding.evidence else None

            banner = finding.evidence.get("banner") if finding.evidence else None



            alert_msg = Message(

                message_id=igen.next_id("message"),

                run_id=run_id,

                sender="supervisor-agent",

                receiver=analyst_agent.agent_id,

                performative=Performative.ALERT,

                timestamp_utc=clk.now_iso(),

                nonce=igen.seeded_token(16),

                task_id=task_id,

                payload={

                    "target_host": finding.host_id,

                    "host_id": finding.host_id,

                    "finding_id": finding.finding_id,

                    "rule_id": finding.rule_id,

                    "severity": sev_val,

                    "service": svc,

                    "banner": banner,

                },

            )

            if supervisor_identity is not None:

                alert_msg = sign_envelope(alert_msg, supervisor_identity)



            reply = analyst_agent.process_message(alert_msg)

            if reply is not None:

                replies.append(reply)

                if reply.payload.get("quarantine_flag"):

                    target = reply.payload.get("target_host") or finding.host_id

                    if target and target not in quarantined:

                        quarantined.append(target)



        return {

            "analyst_replies": replies,

            "quarantined_hosts": quarantined,

            "messages": replies,

        }



    # 5. Aggregation Node

    def aggregate_results_node(state: SupervisorState) -> dict[str, Any]:

        findings_count = len(state.get("findings", []))

        quarantined_hosts = state.get("quarantined_hosts", [])

        quarantined_count = len(quarantined_hosts)

        analyst_replies_count = len(state.get("analyst_replies", []))



        logger.info(

            "Multi-agent run completed. Awarded to %s, findings: %d, quarantined: %d",

            state.get("awarded_proposer"),

            findings_count,

            quarantined_count,

        )

        return {

            "phase": "COMPLETED",

            "metadata": {

                "total_findings": findings_count,

                "quarantined_hosts": quarantined_hosts,

                "quarantined_count": quarantined_count,

                "analyst_replies_count": analyst_replies_count,

            },

        }



    # 6. Unresolved Termination Node

    def handle_unresolved_node(state: SupervisorState) -> dict[str, Any]:

        logger.warning("Negotiation terminated without consensus after max rounds.")

        return {

            "phase": "UNRESOLVED",

            "errors": ["Negotiation failed to reach agreement under specified budget constraints."],

        }



    # Build StateGraph

    workflow = StateGraph(SupervisorState)

    workflow.add_node("negotiate", negotiate_node)

    workflow.add_node("scanner_worker", scanner_worker_node)

    workflow.add_node("analyst_triage", analyst_triage_node)

    workflow.add_node("aggregate_results", aggregate_results_node)

    workflow.add_node("handle_unresolved", handle_unresolved_node)



    workflow.add_edge(START, "negotiate")

    workflow.add_conditional_edges(

        "negotiate",

        route_after_negotiate,

        ["scanner_worker", "handle_unresolved"],

    )

    workflow.add_edge("scanner_worker", "analyst_triage")

    workflow.add_edge("analyst_triage", "aggregate_results")

    workflow.add_edge("aggregate_results", END)

    workflow.add_edge("handle_unresolved", END)



    return workflow.compile()

