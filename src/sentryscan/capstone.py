"""Capstone multi-agent simulation coordinator for SentryScan."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

import uvicorn

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.common.clock import Clock, FakeClock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.events import AgentEvent, EventStatus, EventType
from sentryscan.dashboard_gateway.server import create_app
from sentryscan.graphs.supervisor import build_supervisor_graph
from sentryscan.integrity.checker import IntegrityChecker
from sentryscan.knowledge.enricher import KnowledgeEnricher
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase
from sentryscan.llm.deterministic import DeterministicLLMProvider
from sentryscan.observability.recorder import EventRecorder
from sentryscan.security.gate import SecurityGate
from sentryscan.security.identity import AgentIdentity
from sentryscan.security.registry import TrustedAgentRegistry
from sentryscan.simulation.fleet import DeviceFleetSimulator
from sentryscan.simulation.poisoning import (
    GroundTruthSidecar,
    InjectionOperator,
    PoisoningMutator,
)
from sentryscan.storage.store import SQLiteRunStore
from sentryscan.ui.rich_dashboard import RichCLIDashboard

logger = logging.getLogger(__name__)


def run_capstone(
    run_id: str | None = None,
    seed: int = 42,
    output_dir: str | Path = "data/runs/capstone_demo",
    port: int = 8000,
    launch_gateway: bool = True,
    clock: Clock | None = None,
    quiet: bool = False,
    serve_duration: float | None = None,
) -> dict[str, Any]:
    """Execute complete end-to-end multi-agent capstone simulation."""
    clk = clock if clock is not None else SystemClock()
    id_gen = IdGenerator(seed=seed)
    actual_run_id = run_id or f"run-capstone-{seed:04d}"

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    db_path = out_path / f"{actual_run_id}.db"
    trace_path = out_path / f"{actual_run_id}.jsonl"

    if trace_path.exists():
        trace_path.unlink()
    if db_path.exists():
        db_path.unlink()

    start_time = time.time()

    # 1. Initialize SQLite Run Store & Dual-Sink Event Recorder
    store = SQLiteRunStore(db_path)
    recorder = EventRecorder(
        run_id=actual_run_id,
        output_path=trace_path,
        clock=clk,
        sqlite_store=store,
    )

    manifest = {
        "version": "0.1.0",
        "seed": seed,
        "fleet_size": 4,
        "poison_ratio": 0.25,
        "llm_provider": "deterministic",
        "clock": type(clk).__name__,
        "parity_enforced": True,
    }
    store.save_run(
        run_id=actual_run_id,
        seed=seed,
        status="INITIALIZING",
        created_at=clk.now_iso(),
        manifest=manifest,
    )

    recorder.record(
        event_type=EventType.RUN_STARTED,
        component="supervisor",
        status=EventStatus.OK,
        details={"manifest": manifest},
    )

    # 2. Setup Cryptographic Registry and Identities
    supervisor_id = AgentIdentity.generate("supervisor-agent")
    analyst_id = AgentIdentity.generate("analyst-agent-01")
    scout_id = AgentIdentity.generate("scout-agent")
    triage_id = AgentIdentity.generate("triage-agent")

    registry = TrustedAgentRegistry()
    registry.register(
        supervisor_id.agent_id, supervisor_id.public_key_hex, description="Supervisor"
    )
    registry.register(analyst_id.agent_id, analyst_id.public_key_hex, description="Analyst")
    registry.register(scout_id.agent_id, scout_id.public_key_hex, description="Scout")
    registry.register(triage_id.agent_id, triage_id.public_key_hex, description="Triage")

    analyst_gate = SecurityGate(
        agent_id="analyst-agent-01",
        registry=registry,
        clock=clk,
        freshness_window_seconds=30.0,
    )

    ontology = VulnerabilityKnowledgeBase.load_from_file()
    enricher = KnowledgeEnricher(ontology=ontology, enable_online_nvd=False)
    analyst_agent = AnalystAgent(
        agent_id="analyst-agent-01",
        clock=clk,
        id_gen=id_gen,
        enricher=enricher,
        security_gate=analyst_gate,
    )

    # 3. Setup Fleet Simulator and Ingest Telemetry
    fleet_sim = DeviceFleetSimulator(device_count=4, clock=clk, id_gen=id_gen, seed=seed)
    sidecar = GroundTruthSidecar()
    mutator = PoisoningMutator(sidecar=sidecar, seed=seed)

    raw_records = []
    for dev in fleet_sim.devices:
        for idx in range(len(dev.services)):
            r, truth = fleet_sim.generate_record_with_truth(dev, service_index=idx)
            # Deterministically poison 1 record for telemetry anomaly testing
            if r.port == 23 and r.service == "telnet":
                is_p = True
                p_rec = mutator.mutate(
                    baseline=r,
                    operator=InjectionOperator.SERVICE_BANNER_MISMATCH,
                    new_record_id=id_gen.next_id("record"),
                )
                raw_records.append(p_rec)
                store.save_telemetry_record(p_rec, run_id=actual_run_id, is_poisoned=is_p)
                store.save_ground_truth(
                    record_id=p_rec.record_id,
                    run_id=actual_run_id,
                    host_id=p_rec.host_id,
                    cycle=1,
                    is_vulnerable=truth["is_vulnerable"],
                    expected_rules=truth["expected_rules"],
                    is_poisoned=True,
                    injection_type=InjectionOperator.SERVICE_BANNER_MISMATCH.value,
                )
            else:
                raw_records.append(r)
                store.save_telemetry_record(r, run_id=actual_run_id, is_poisoned=False)
                store.save_ground_truth(
                    record_id=r.record_id,
                    run_id=actual_run_id,
                    host_id=r.host_id,
                    cycle=1,
                    is_vulnerable=truth["is_vulnerable"],
                    expected_rules=truth["expected_rules"],
                    is_poisoned=False,
                    injection_type=None,
                )

    for rec in raw_records:
        recorder.record(
            event_type=EventType.RECORD_RECEIVED,
            component="fleet_sensor",
            status=EventStatus.OK,
            record_id=rec.record_id,
            host_id=rec.host_id,
            details={"service": rec.service, "port": rec.port},
        )

    # Partition records into batches for multi-agent allocation
    batch_01 = [r.model_dump() for r in raw_records[: len(raw_records) // 2]]
    batch_02 = [r.model_dump() for r in raw_records[len(raw_records) // 2 :]]
    batches = {"batch-alpha": batch_01, "batch-beta": batch_02}

    # 4. Launch FastAPI/WebSocket Dashboard Gateway in background
    app = create_app(store=store)
    server_thread: threading.Thread | None = None
    uv_server: uvicorn.Server | None = None
    if launch_gateway:
        config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="warning")
        uv_server = uvicorn.Server(config)
        server_thread = threading.Thread(target=uv_server.run, daemon=True)
        server_thread.start()
        time.sleep(0.3)  # Brief yield for server startup

    # 5. Compile and Execute Multi-Agent Supervisor Workflow
    llm = DeterministicLLMProvider()
    supervisor_graph = build_supervisor_graph(
        clock=clk,
        id_gen=id_gen,
        llm_provider=llm,
        analyst_agent=analyst_agent,
        supervisor_identity=supervisor_id,
        max_rounds=4,
    )

    initial_state = {
        "run_id": actual_run_id,
        "task_id": id_gen.next_id("task"),
        "batches": batches,
        "constraints": {"max_cost": 150.0, "max_time": 600.0},
        "messages": [],
        "findings": [],
        "analyst_replies": [],
        "quarantined_hosts": [],
        "errors": [],
    }

    final_state = supervisor_graph.invoke(initial_state)

    # 6. Persist Execution Findings and Messages
    findings = final_state.get("findings", [])
    quarantined_hosts = final_state.get("quarantined_hosts", [])
    pending_quarantines = final_state.get("pending_quarantines", [])
    messages = final_state.get("messages", [])

    for f in findings:
        is_q = f.host_id in quarantined_hosts
        cve = f.evidence.get("cve_id") if f.evidence else None
        store.save_finding(f, cve_id=cve, quarantined=is_q)
        recorder.record(
            event_type=EventType.FINDING_CREATED,
            component="scanner_worker",
            status=EventStatus.OK,
            host_id=f.host_id,
            finding_id=f.finding_id,
            rule_id=f.rule_id,
            details={"severity": f.severity.value, "quarantined": is_q},
        )

    for pq in pending_quarantines:
        store.save_pending_quarantine(**pq)
        recorder.record(
            event_type=EventType.STATE_TRANSITION,
            component="analyst-l3-containment",
            status=EventStatus.OK,
            host_id=pq["host_id"],
            finding_id=pq["finding_id"],
            rule_id=pq["rule_id"],
            reason_code=f"QUARANTINE_{pq['status']}",
            details={
                "quarantine_id": pq["quarantine_id"],
                "who": pq.get("decided_by") or "analyst-l3-containment",
                "what": pq["status"],
                "when": pq.get("decided_at") or pq["created_at"],
                "confidence": pq["confidence"],
                "remote_exploitable": pq["remote_exploitable"],
            },
        )

    from sentryscan.agents.remediator import RemediatorAgent
    remediator = RemediatorAgent(clock=clk, id_gen=id_gen)
    for q_host in quarantined_hosts:
        remediator.remediate_and_store(
            store=store,
            run_id=actual_run_id,
            host_id=q_host,
            findings=[f for f in findings if f.host_id == q_host],
            recorder=recorder,
        )

    for idx, msg in enumerate(messages, 1):
        store.save_message(msg, seq=idx)
        recorder.record(
            event_type=EventType.MESSAGE_SENT,
            component=msg.sender,
            status=EventStatus.OK,
            details={"receiver": msg.receiver, "performative": msg.performative.value},
        )

    # Save active BDI snapshot
    store.save_bdi_snapshot(
        snapshot_id=id_gen.next_id("snap"),
        run_id=actual_run_id,
        agent_id=analyst_agent.agent_id,
        timestamp_utc=clk.now_iso(),
        intention_type=(
            analyst_agent.active_intention.desire_type.value
            if analyst_agent.active_intention
            else "CONTAIN_COMPROMISED_HOSTS"
        ),
        desire_type="CONTAIN_COMPROMISED_HOSTS",
        target_host=quarantined_hosts[0] if quarantined_hosts else "none",
        reconsideration_count=len(analyst_agent.reconsideration_history),
        beliefs=analyst_agent.beliefs,
    )

    recorder.record(
        event_type=EventType.RUN_COMPLETED,
        component="supervisor",
        status=EventStatus.OK,
        details={
            "phase": final_state.get("phase"),
            "awarded_proposer": final_state.get("awarded_proposer"),
            "findings_count": len(findings),
            "quarantined_count": len(quarantined_hosts),
        },
    )

    # 7. Verify Event Parity (HLD §8.5)
    recorder.close()
    parity_report = store.verify_parity(run_id=actual_run_id, jsonl_path=trace_path)
    eval_metrics = store.compute_eval_metrics(run_id=actual_run_id)
    store.update_run_status(
        run_id=actual_run_id,
        status="COMPLETED",
        metadata={
            "findings_count": len(findings),
            "quarantined_count": len(quarantined_hosts),
            "parity_passed": parity_report["parity_passed"],
            "eval_metrics": eval_metrics,
        },
    )

    # 8. Render Rich CLI Dashboard
    dashboard = RichCLIDashboard()
    duration_s = time.time() - start_time
    sec_stats = {
        "accepted": analyst_gate.accepted_count,
        "rejected": analyst_gate.rejected_count,
    }

    if not quiet:
        all_evts = store.get_events(run_id=actual_run_id, from_seq=1, limit=50)
        # Convert dict events to AgentEvent objects for Rich layout
        typed_evts = [
            AgentEvent(
                event_id=e["event_id"],
                run_id=e["run_id"],
                seq=e["seq"],
                timestamp_utc=e["timestamp_utc"],
                event_type=EventType(e["event_type"]),
                component=e["component"],
                status=EventStatus(e["status"]),
                host_id=e.get("host_id"),
                rule_id=e.get("rule_id"),
                finding_id=e.get("finding_id"),
                reason_code=e.get("reason_code"),
                details=e.get("details", {}),
            )
            for e in all_evts
        ]
        dashboard.render_snapshot(
            run_id=actual_run_id,
            events=typed_evts,
            findings=findings,
            quarantined_hosts=quarantined_hosts,
            security_stats=sec_stats,
            active_intention=(
                analyst_agent.active_intention.desire_type.value
                if analyst_agent.active_intention
                else "CONTAIN_COMPROMISED_HOSTS"
            ),
            phase=final_state.get("phase", "COMPLETED"),
        )
        dashboard.render_summary_table(
            run_id=actual_run_id,
            total_events=parity_report["sqlite_event_count"],
            total_findings=len(findings),
            quarantined_count=len(quarantined_hosts),
            security_stats=sec_stats,
            duration_s=duration_s,
        )

    # If serve_duration is requested, keep the gateway live
    if serve_duration is not None and serve_duration > 0 and uv_server is not None:
        time.sleep(serve_duration)
        uv_server.should_exit = True

    return {
        "run_id": actual_run_id,
        "phase": final_state.get("phase"),
        "awarded_proposer": final_state.get("awarded_proposer"),
        "total_findings": len(findings),
        "quarantined_hosts": quarantined_hosts,
        "parity_passed": parity_report["parity_passed"],
        "sqlite_event_count": parity_report["sqlite_event_count"],
        "jsonl_event_count": parity_report["jsonl_event_count"],
        "eval_metrics": eval_metrics,
        "gateway_url": f"http://127.0.0.1:{port}" if launch_gateway else None,
        "db_path": str(db_path),
        "trace_path": str(trace_path),
    }


def run_eval(
    seed: int = 42,
    cycles: int = 5,
    device_count: int = 10,
    poison_ratio: float = 0.2,
    output_dir: str | Path = "data/runs/eval",
    adaptive_weights: bool = True,
) -> dict[str, Any]:
    """Execute deterministic multi-cycle ground-truth evaluation harness."""
    import random as _random

    clk = FakeClock("2026-10-21T10:00:00Z")
    id_gen = IdGenerator(seed=seed)
    rng = _random.Random(seed)
    actual_run_id = f"run-eval-s{seed}-c{cycles}"

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    db_path = out_path / f"{actual_run_id}.db"
    trace_path = out_path / f"{actual_run_id}.jsonl"

    if trace_path.exists():
        trace_path.unlink()
    if db_path.exists():
        db_path.unlink()

    store = SQLiteRunStore(db_path)
    recorder = EventRecorder(
        run_id=actual_run_id,
        output_path=trace_path,
        clock=clk,
        sqlite_store=store,
    )
    manifest = {
        "version": "0.1.0",
        "seed": seed,
        "cycles": cycles,
        "fleet_size": device_count,
        "poison_ratio": poison_ratio,
        "llm_provider": "deterministic",
        "clock": "FakeClock",
        "mode": "eval",
    }
    store.save_run(
        run_id=actual_run_id,
        seed=seed,
        status="IN_PROGRESS",
        created_at=clk.now_iso(),
        manifest=manifest,
    )
    recorder.record(
        event_type=EventType.RUN_STARTED,
        component="supervisor",
        status=EventStatus.OK,
        details={"manifest": manifest},
    )

    agent_names = (
        "supervisor-agent",
        "scout-agent",
        "triage-agent",
        "analyst-l1-triage",
        "analyst-l2-incident",
        "analyst-l3-containment",
    )
    ids = {n: AgentIdentity.generate(n) for n in agent_names}
    registry = TrustedAgentRegistry()
    for i in ids.values():
        registry.register(i.agent_id, i.public_key_hex, description=i.agent_id)

    kb = VulnerabilityKnowledgeBase.load_from_file()
    analyst_tiers = {
        tier: AnalystAgent(
            agent_id=aid,
            tier=tier,
            clock=clk,
            id_gen=id_gen,
            enricher=KnowledgeEnricher(ontology=kb, enable_online_nvd=False),
            security_gate=SecurityGate(
                agent_id=aid, registry=registry, clock=clk, freshness_window_seconds=300.0
            ),
        )
        for tier, aid in (
            ("L1", "analyst-l1-triage"),
            ("L2", "analyst-l2-incident"),
            ("L3", "analyst-l3-containment"),
        )
    }
    graph = build_supervisor_graph(
        clock=clk,
        id_gen=id_gen,
        llm_provider=DeterministicLLMProvider(),
        analyst_tiers=analyst_tiers,
        analyst_identities=ids,
        supervisor_identity=ids["supervisor-agent"],
        max_rounds=4,
        enable_bidder_feedback=adaptive_weights,
    )

    fleet = DeviceFleetSimulator(device_count=device_count, clock=clk, id_gen=id_gen, seed=seed)
    mutator = PoisoningMutator(sidecar=GroundTruthSidecar(), seed=seed)
    checker = IntegrityChecker(clock=clk, freshness_window_seconds=300.0)
    ops = [o for o in InjectionOperator if o != InjectionOperator.REPLAYED_RECORD]

    msg_seq = 0
    quarantined_all: set[str] = set()

    for cycle in range(1, cycles + 1):
        clk.advance(1.0)
        clean_records = []
        for dev in fleet.devices:
            svc_idx = (cycle - 1) % len(dev.services)
            rec, truth = fleet.generate_record_with_truth(dev, service_index=svc_idx)
            is_poisoned = False
            inj_type: str | None = None
            if rng.random() < poison_ratio:
                op = rng.choice(ops)
                rec = mutator.mutate(
                    baseline=rec,
                    operator=op,
                    new_record_id=id_gen.next_id("record"),
                )
                is_poisoned = True
                inj_type = op.value

            store.save_ground_truth(
                record_id=rec.record_id,
                run_id=actual_run_id,
                host_id=rec.host_id,
                cycle=cycle,
                is_vulnerable=truth["is_vulnerable"],
                expected_rules=truth["expected_rules"],
                is_poisoned=is_poisoned,
                injection_type=inj_type,
            )
            recorder.record(
                event_type=EventType.RECORD_RECEIVED,
                component="fleet_sensor",
                status=EventStatus.OK,
                record_id=rec.record_id,
                host_id=rec.host_id,
                details={"service": rec.service, "port": rec.port, "cycle": cycle},
            )
            flags = checker.check_record(rec)
            if flags:
                store.save_telemetry_record(rec, run_id=actual_run_id, is_poisoned=True)
                recorder.record(
                    event_type=EventType.RECORD_REJECTED,
                    component="integrity_checker",
                    status=EventStatus.REJECTED,
                    record_id=rec.record_id,
                    host_id=rec.host_id,
                    reason_code=flags[0].reason_code.value,
                    details={"flags": len(flags), "cycle": cycle},
                )
            else:
                store.save_telemetry_record(rec, run_id=actual_run_id, is_poisoned=False)
                clean_records.append(rec)

        if not clean_records:
            continue

        half = max(1, len(clean_records) // 2)
        batches = {
            "batch-alpha": [r.model_dump() for r in clean_records[:half]],
            "batch-beta": [r.model_dump() for r in clean_records[half:]],
        }
        if not batches["batch-beta"]:
            del batches["batch-beta"]

        state = graph.invoke(
            {
                "run_id": actual_run_id,
                "task_id": id_gen.next_id("task"),
                "batches": batches,
                "constraints": {"max_cost": 150.0, "max_time": 600.0},
                "messages": [],
                "findings": [],
                "analyst_replies": [],
                "quarantined_hosts": [],
                "errors": [],
            }
        )

        q_cycle = set(state.get("quarantined_hosts", []))
        quarantined_all |= q_cycle

        for f in state.get("findings", []):
            f.evidence["cycle"] = cycle
            is_q = f.host_id in q_cycle
            cve = f.evidence.get("cve_id") if f.evidence else None
            store.save_finding(f, cve_id=cve, quarantined=is_q)
            recorder.record(
                event_type=EventType.FINDING_CREATED,
                component="scanner_worker",
                status=EventStatus.OK,
                host_id=f.host_id,
                finding_id=f.finding_id,
                rule_id=f.rule_id,
                details={"severity": f.severity.value, "quarantined": is_q, "cycle": cycle},
            )

        for pq in state.get("pending_quarantines", []):
            store.save_pending_quarantine(**pq)
            recorder.record(
                event_type=EventType.STATE_TRANSITION,
                component="analyst-l3-containment",
                status=EventStatus.OK,
                host_id=pq["host_id"],
                finding_id=pq["finding_id"],
                rule_id=pq["rule_id"],
                reason_code=f"QUARANTINE_{pq['status']}",
                details={
                    "quarantine_id": pq["quarantine_id"],
                    "who": pq.get("decided_by") or "analyst-l3-containment",
                    "what": pq["status"],
                    "when": pq.get("decided_at") or pq["created_at"],
                    "confidence": pq["confidence"],
                    "remote_exploitable": pq["remote_exploitable"],
                    "cycle": cycle,
                },
            )

        from sentryscan.agents.remediator import RemediatorAgent
        remediator = RemediatorAgent(clock=clk, id_gen=id_gen)
        for q_host in sorted(q_cycle):
            remediator.remediate_and_store(
                store=store,
                run_id=actual_run_id,
                host_id=q_host,
                findings=[f for f in state.get("findings", []) if f.host_id == q_host],
                recorder=recorder,
            )

        for wu in state.get("weight_updates", []):
            store.save_bidder_weights(wu["weights_snapshot"], updated_at=wu["timestamp_utc"])
            recorder.record(
                event_type=EventType.PARAMS_UPDATE,
                component=wu["decided_by"],
                status=EventStatus.OK,
                host_id=wu["host_id"],
                finding_id=wu["finding_id"],
                rule_id=wu["rule_id"],
                reason_code="BIDDER_WEIGHT_UPDATE",
                details={
                    "port": wu["port"],
                    "confirmed": wu["confirmed"],
                    "triage_port_old": wu["triage_port_old"],
                    "triage_port_new": wu["triage_port_new"],
                    "scout_coverage_old": wu["scout_coverage_old"],
                    "scout_coverage_new": wu["scout_coverage_new"],
                    "cycle": cycle,
                },
            )

        for msg in state.get("messages", []):
            msg_seq += 1
            store.save_message(msg, seq=msg_seq)
            recorder.record(
                event_type=EventType.MESSAGE_SENT,
                component=msg.sender,
                status=EventStatus.OK,
                details={
                    "receiver": msg.receiver,
                    "performative": msg.performative.value,
                    "cycle": cycle,
                },
            )

        has_threats = any(
            f.severity.value in ("HIGH", "CRITICAL") for f in state.get("findings", [])
        ) or bool(q_cycle)
        decay_msg = analyst_tiers["L2"].record_cycle_outcome(
            has_threats=has_threats,
            run_id=actual_run_id,
            recorder=recorder,
        )
        if decay_msg is not None:
            decay_msg = ids["analyst-l2-incident"].sign_message(decay_msg)
            msg_seq += 1
            store.save_message(decay_msg, seq=msg_seq)
            recorder.record(
                event_type=EventType.MESSAGE_SENT,
                component=decay_msg.sender,
                status=EventStatus.OK,
                details={
                    "receiver": decay_msg.receiver,
                    "performative": decay_msg.performative.value,
                    "cycle": cycle,
                },
            )

    recorder.record(
        event_type=EventType.RUN_COMPLETED,
        component="supervisor",
        status=EventStatus.OK,
        details={
            "cycles": cycles,
            "quarantined_hosts": sorted(quarantined_all),
            "quarantined_count": len(quarantined_all),
        },
    )
    recorder.close()

    parity_report = store.verify_parity(run_id=actual_run_id, jsonl_path=trace_path)
    eval_metrics = store.compute_eval_metrics(run_id=actual_run_id)
    bidder_weights = store.get_bidder_weights()
    store.update_run_status(
        run_id=actual_run_id,
        status="COMPLETED",
        metadata={
            "cycles": cycles,
            "parity_passed": parity_report["parity_passed"],
            "eval_metrics": eval_metrics,
            "bidder_weights": bidder_weights,
        },
    )
    store.close()

    return {
        "run_id": actual_run_id,
        "seed": seed,
        "cycles": cycles,
        "parity_passed": parity_report["parity_passed"],
        "eval_metrics": eval_metrics,
        "bidder_weights": bidder_weights,
        "db_path": str(db_path),
        "trace_path": str(trace_path),
    }
