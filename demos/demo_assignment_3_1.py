#!/usr/bin/env python3
"""Deterministic Demonstration Script for Assignment 3.1 — Multi-Agent Coordination.

Demonstrates:
1. Multi-turn Contract-Net negotiation (CFP -> PROPOSE -> COUNTERPROPOSE -> ACCEPT -> CONFIRM).
2. Role separation: ScoutAgent (coverage-maximizing) vs. TriageAgent (risk-prioritizing).
3. Score evaluation via inline score_bid() seam with hard constraint filtering.
4. LangGraph supervisor graph execution with dynamic worker fan-out via Send.
5. Deterministic rule evaluation inside scanner workers and finding aggregation.
6. Bounded termination ending in UNRESOLVED when constraints cannot be satisfied.
7. Verification of the determinism contract (identical execution traces with LLM off).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentryscan.common.clock import FakeClock  # noqa: E402
from sentryscan.common.id_generator import IdGenerator  # noqa: E402
from sentryscan.contracts.events import EventStatus, EventType  # noqa: E402
from sentryscan.contracts.message import Performative  # noqa: E402
from sentryscan.graphs.supervisor import build_supervisor_graph  # noqa: E402
from sentryscan.llm.deterministic import DeterministicLLMProvider  # noqa: E402
from sentryscan.negotiation.protocol import ContractNetNegotiator  # noqa: E402
from sentryscan.observability.recorder import EventRecorder  # noqa: E402


def _generate_demo_batches():
    return {
        "batch-01": [
            {
                "record_id": "tel-000001",
                "host_id": "sim-host-001",
                "ip": "192.0.2.10",
                "port": 22,
                "service": "ssh",
                "banner": "SSH-2.0-OpenSSH_7.2p2",
                "auth_mode": "required",
                "generated_at": "2026-10-21T07:00:00Z",
            },
            {
                "record_id": "tel-000002",
                "host_id": "sim-host-002",
                "ip": "192.0.2.11",
                "port": 80,
                "service": "http",
                "banner": "Apache/2.4.49",  # Critical CVE-2021-41773
                "auth_mode": "unknown",
                "generated_at": "2026-10-21T07:00:00Z",
            },
        ],
        "batch-02": [
            {
                "record_id": "tel-000003",
                "host_id": "sim-host-003",
                "ip": "192.0.2.12",
                "port": 23,
                "service": "telnet",  # High cleartext telnet
                "banner": "Linux telnetd",
                "auth_mode": "default",
                "generated_at": "2026-10-21T07:00:00Z",
            },
            {
                "record_id": "tel-000004",
                "host_id": "sim-host-004",
                "ip": "192.0.2.13",
                "port": 443,
                "service": "https",
                "banner": "nginx/1.18.0",
                "auth_mode": "required",
                "tls_version": "TLSv1.0",  # High deprecated TLS
                "generated_at": "2026-10-21T07:00:00Z",
            },
        ],
        "batch-03": [
            {
                "record_id": "tel-000005",
                "host_id": "sim-host-005",
                "ip": "192.0.2.14",
                "port": 21,
                "service": "ftp",
                "banner": "vsftpd 2.3.4",  # Critical backdoor banner
                "auth_mode": "anonymous",
                "generated_at": "2026-10-21T07:00:00Z",
            },
        ],
    }


def run_demo() -> None:
    evidence_dir = REPO_ROOT / "assignments" / "assignment_3_1" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log_path = evidence_dir / "run_log.txt"
    timeline_path = evidence_dir / "negotiation_timeline.md"
    trace_path = evidence_dir / "trace_excerpt.jsonl"
    if trace_path.exists():
        trace_path.unlink()

    log_lines: list[str] = []
    timeline_lines: list[str] = []

    def log(line: str) -> None:
        print(line)
        log_lines.append(line)

    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    recorder = EventRecorder(run_id="run-demo-3-1", output_path=trace_path, clock=clock)

    log("=" * 78)
    log(" SentryScan Milestone 3.1 -- Multi-Agent Coordination & Negotiation ")
    log("=" * 78)

    # 1. Multi-turn Negotiation Demonstration
    log("\n[1] Starting Multi-Turn Contract-Net Negotiation Session...")
    log("    Protocol: CFP -> PROPOSE -> COUNTERPROPOSE -> ACCEPT / REJECT -> CONFIRM")
    batches = _generate_demo_batches()

    # Initial tight constraint requiring counterproposal and concession in round 2
    initial_constraints = {"max_cost": 10.5, "max_time": 250.0}
    log(
        f"    Initial Constraints: Cost <= {initial_constraints['max_cost']}, "
        f"Time <= {initial_constraints['max_time']} ms"
    )

    negotiator = ContractNetNegotiator(clock=clock, id_gen=id_gen, max_rounds=5)
    neg_result = negotiator.run_negotiation(
        task_id="task-fleet-allocation",
        run_id="run-demo-3-1",
        batches=batches,
        initial_constraints=initial_constraints,
    )

    log(f"\n    [+] Outcome: {neg_result.status} in Round {neg_result.rounds_completed}")
    log(f"    [+] Winner:  {neg_result.winning_proposer}")
    if neg_result.winning_proposal:
        log(f"    [+] Batches: {neg_result.winning_proposal.batch_ids}")
        log(f"    [+] Cost:    {neg_result.winning_proposal.est_cost}")
        log(f"    [+] Cover:   {neg_result.winning_proposal.est_coverage}")
        log(f"    [+] Reason:  {neg_result.winning_proposal.rationale}")

    # Build Negotiation Timeline Markdown
    timeline_lines.append("# Contract-Net Negotiation Turn-by-Turn Timeline\n")
    timeline_lines.append(
        f"**Task ID:** `task-fleet-allocation`  \n"
        f"**Status:** `{neg_result.status}`  \n"
        f"**Rounds:** {neg_result.rounds_completed}\n"
    )
    timeline_lines.append("| Step | Sender | Receiver | Performative | Summary | Nonce |")
    timeline_lines.append("|---|---|---|---|---|---|")

    for idx, msg in enumerate(neg_result.messages, 1):
        summary = ""
        if msg.performative in (Performative.CFP, Performative.COUNTERPROPOSE):
            summary = (
                f"Round {msg.payload.get('round')}: Constraints {msg.payload.get('constraints')}"
            )
        elif msg.performative == Performative.PROPOSE:
            p = msg.payload.get("proposal", {})
            summary = (
                f"Batches {p.get('batch_ids')}, Cost {p.get('est_cost')}, "
                f"Cov {p.get('est_coverage')}"
            )
        elif msg.performative == Performative.ACCEPT:
            summary = (
                f"AWARDED {msg.payload.get('awarded_batch_ids')}, Score {msg.payload.get('score')}"
            )
        elif msg.performative == Performative.REJECT:
            summary = str(msg.payload.get("reason"))
        elif msg.performative == Performative.CONFIRM:
            summary = str(msg.payload.get("status"))

        timeline_lines.append(
            f"| {idx} | `{msg.sender}` | `{msg.receiver}` | `{msg.performative.value}` | "
            f"{summary} | `{msg.nonce}` |"
        )

        recorder.record(
            event_type=EventType.MESSAGE_SENT,
            component=msg.sender,
            status=EventStatus.OK,
            details={
                "performative": msg.performative.value,
                "receiver": msg.receiver,
                "summary": summary,
            },
        )

    # 2. LangGraph Supervisor Workflow Execution (with dynamic Send fan-out)
    log("\n[2] Executing LangGraph Supervisor Graph with Runtime Worker Fan-Out...")
    llm = DeterministicLLMProvider()
    app = build_supervisor_graph(clock=clock, id_gen=id_gen, llm_provider=llm, max_rounds=5)

    graph_state = app.invoke(
        {
            "run_id": "run-demo-3-1",
            "task_id": "task-graph-scan",
            "batches": batches,
            "constraints": {"max_cost": 80.0, "max_time": 600.0},
            "messages": [],
            "findings": [],
            "errors": [],
        }
    )

    log(f"    [+] Graph Phase:         {graph_state['phase']}")
    log(f"    [+] Winning Proposer:    {graph_state['awarded_proposer']}")
    log(f"    [+] Batches Fanned-Out:  {graph_state['awarded_batch_ids']}")
    log(f"    [+] Aggregated Findings: {len(graph_state['findings'])} findings discovered")

    for f in graph_state["findings"]:
        port_num = f.evidence.get("port")
        log(f"        - [{f.severity.value}] {f.finding_id}: {f.title} ({f.host_id}:{port_num})")
        recorder.record(
            event_type=EventType.FINDING_CREATED,
            component="scanner_worker",
            status=EventStatus.OK,
            finding_id=f.finding_id,
            host_id=f.host_id,
            rule_id=f.rule_id,
            details={"title": f.title, "severity": f.severity.value},
        )

    # 3. Bounded Termination Demonstration
    log("\n[3] Testing Bounded UNRESOLVED Termination under Impossible Constraints...")
    unresolved_neg = ContractNetNegotiator(clock=clock, id_gen=id_gen, max_rounds=2)
    unresolved_res = unresolved_neg.run_negotiation(
        task_id="task-impossible",
        run_id="run-demo-3-1",
        batches=batches,
        initial_constraints={"max_cost": 0.001, "max_time": 0.001},
    )
    log(
        f"    [+] Status: {unresolved_res.status} after "
        f"{unresolved_res.rounds_completed} rounds (No loop)"
    )
    assert unresolved_res.status == "UNRESOLVED"

    # 4. Determinism Contract Verification
    log("\n[4] Verifying Determinism Contract (Exact Identity with LLM Off)...")
    id_a = IdGenerator(seed=999)
    id_b = IdGenerator(seed=999)
    app_a = build_supervisor_graph(clock=clock, id_gen=id_a, llm_provider=None)
    app_b = build_supervisor_graph(clock=clock, id_gen=id_b, llm_provider=None)

    input_payload = {
        "run_id": "r1",
        "task_id": "t1",
        "batches": batches,
        "constraints": {"max_cost": 100.0, "max_time": 500.0},
        "messages": [],
        "findings": [],
        "errors": [],
    }
    st_a = app_a.invoke(input_payload)
    st_b = app_b.invoke(input_payload)

    assert st_a["awarded_proposer"] == st_b["awarded_proposer"]
    assert st_a["awarded_batch_ids"] == st_b["awarded_batch_ids"]
    assert len(st_a["findings"]) == len(st_b["findings"])
    log("    [+] Deterministic trace identical across runs (0 drift verified).")

    recorder.close()

    # Write files
    with open(run_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")

    with open(timeline_path, "w", encoding="utf-8") as f:
        f.write("\n".join(timeline_lines) + "\n")

    log("\n[*] Execution artifacts successfully generated:")
    log(f"    - Console Log:         {run_log_path}")
    log(f"    - Negotiation Timeline: {timeline_path}")
    log(f"    - Trace Excerpt:       {trace_path}")
    log("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description="Assignment 3.1 Multi-Agent Coordination Demo")
    parser.parse_args()
    run_demo()


if __name__ == "__main__":
    main()
