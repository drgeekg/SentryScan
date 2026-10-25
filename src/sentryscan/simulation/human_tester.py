"""Automated high-frequency human workstation test harness across Windows and Linux devices."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.agents.remediator import RemediatorAgent
from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.events import EventStatus, EventType
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
from sentryscan.simulation.human_traffic import HumanTrafficGenerator
from sentryscan.storage.store import SQLiteRunStore

logger = logging.getLogger(__name__)


def run_human_workstation_test(
    seed: int = 42,
    cycles: int = 5,
    device_count: int = 4,
    output_dir: str | Path = "data/runs/human_test",
    clock: Clock | None = None,
    poison_ratio: float = 0.25,
    fleet_spec: str | None = None,
) -> dict[str, Any]:
    """Execute high-frequency human workstation test across Windows & Linux machines.

    Validates multi-agent SOC performance under realistic human interaction burst frequencies,
    verifying throughput, integrity checking, negotiation, BDI deliberation, and dual-sink parity.
    """
    clk = clock if clock is not None else SystemClock()
    id_gen = IdGenerator(seed=seed)
    run_id = f"run-human-test-{seed:04d}"

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    db_path = out_path / f"{run_id}.db"
    trace_path = out_path / f"{run_id}.jsonl"

    if trace_path.exists():
        trace_path.unlink()
    if db_path.exists():
        db_path.unlink()

    store = SQLiteRunStore(db_path)
    recorder = EventRecorder(
        run_id=run_id,
        output_path=trace_path,
        clock=clk,
        sqlite_store=store,
    )

    manifest = {
        "version": "0.1.0",
        "seed": seed,
        "fleet_size": device_count,
        "poison_ratio": poison_ratio,
        "profile": "human_workstations",
        "mode": "test_human",
    }
    store.save_run(
        run_id=run_id,
        seed=seed,
        status="RUNNING",
        created_at=clk.now_iso(),
        manifest=manifest,
    )
    recorder.record(
        event_type=EventType.RUN_STARTED,
        component="supervisor",
        status=EventStatus.OK,
        details={"manifest": manifest},
    )

    # Setup Agent Identities & Registry
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
                agent_id=aid,
                registry=registry,
                clock=clk,
                freshness_window_seconds=30.0,
            ),
            clean_cycles_for_decay=10,
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
    )

    templates = None
    if fleet_spec is not None:
        from sentryscan.simulation.asset_types import build_templates, resolve_fleet
        templates = build_templates(resolve_fleet(fleet_spec, device_count, seed))
        device_count = len(templates)
    human_gen = HumanTrafficGenerator(
        templates=templates,
        device_count=device_count,
        seed=seed,
        clock=clk,
        id_gen=id_gen,
        poison_ratio=poison_ratio,
    )
    fleet = DeviceFleetSimulator(
        device_count=device_count,
        seed=seed,
        clock=clk,
        id_gen=id_gen,
        profile="human_workstations",
        templates=templates,
    )
    checker = IntegrityChecker(clock=clk)
    remediator = RemediatorAgent(clock=clk, id_gen=id_gen)

    if templates is not None:
        from sentryscan.platform import core as platform_core
        platform_core.bootstrap(store, run_id, templates, seed=seed)

    # Initial baseline registration
    for rec in fleet.generate_fleet_cycle():
        store.save_telemetry_record(rec, run_id=run_id, is_poisoned=False)
        checker.check_record(rec)

    total_records = 0
    total_bursts = 0
    total_anomalies_rejected = 0
    total_clean_records = 0
    quarantined_hosts: set[str] = set()
    burst_actions: dict[str, int] = {}
    host_record_counts: dict[str, int] = {}
    start_time = time.perf_counter()

    for cycle in range(1, cycles + 1):
        active_hosts = [d.host_id for d in fleet.devices if d.host_id not in quarantined_hosts]
        if not active_hosts:
            active_hosts = [d.host_id for d in fleet.devices]

        # Plan human interactive burst
        burst = human_gen.plan_next_human_burst(active_host_ids=active_hosts)
        ws_info = human_gen.workstation_map[burst.host_id]
        total_bursts += 1
        burst_actions[burst.action.value] = burst_actions.get(burst.action.value, 0) + 1

        recorder.record(
            event_type=EventType.STATE_TRANSITION,
            component="fleet_sensor",
            host_id=burst.host_id,
            details={
                "cycle": cycle,
                "user_action": burst.action.value,
                "burst_size": burst.record_count,
                "intra_delay_ms": round(burst.intra_event_delay_ms, 1),
                "is_anomaly": burst.is_anomaly,
                "os_family": ws_info.os_family,
                "persona": ws_info.persona,
                "host_label": ws_info.label,
            },
        )

        burst_records = human_gen.generate_burst_records(burst)
        clean_batch = []

        for rec, truth, is_p, inj_type in burst_records:
            total_records += 1
            host_record_counts[rec.host_id] = host_record_counts.get(rec.host_id, 0) + 1

            store.save_ground_truth(
                record_id=rec.record_id,
                run_id=run_id,
                host_id=rec.host_id,
                cycle=cycle,
                is_vulnerable=truth["is_vulnerable"],
                expected_rules=truth["expected_rules"],
                is_poisoned=is_p,
                injection_type=inj_type,
            )
            recorder.record(
                event_type=EventType.RECORD_RECEIVED,
                component="fleet_sensor",
                status=EventStatus.OK,
                record_id=rec.record_id,
                host_id=rec.host_id,
                details={
                    "service": rec.service,
                    "port": rec.port,
                    "is_vulnerable": truth["is_vulnerable"],
                    "is_poisoned": is_p,
                    "user_action": burst.action.value,
                    "os_family": ws_info.os_family,
                },
            )

            flags = checker.check_record(rec)
            if flags:
                total_anomalies_rejected += 1
                store.save_telemetry_record(rec, run_id=run_id, is_poisoned=True)
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
                total_clean_records += 1
                store.save_telemetry_record(rec, run_id=run_id, is_poisoned=False)
                clean_batch.append(rec)

        if len(clean_batch) < 2:
            continue

        half = len(clean_batch) // 2
        state = graph.invoke(
            {
                "run_id": run_id,
                "task_id": id_gen.next_id("task"),
                "batches": {
                    "batch-alpha": [r.model_dump() for r in clean_batch[:half]],
                    "batch-beta": [r.model_dump() for r in clean_batch[half:]],
                },
                "constraints": {"max_cost": 150.0, "max_time": 600.0},
                "messages": [],
                "findings": [],
                "analyst_replies": [],
                "quarantined_hosts": [],
                "errors": [],
            }
        )

        for msg in state.get("messages", []):
            store.save_message(msg)
            recorder.record(
                event_type=EventType.MESSAGE_SENT,
                component=msg.sender,
                details={
                    "receiver": msg.receiver,
                    "performative": msg.performative.value,
                    "message_id": msg.message_id,
                    "payload": msg.payload,
                },
            )

        q_now = set(state.get("quarantined_hosts", []))
        for f in state.get("findings", []):
            is_q = f.host_id in q_now
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

        for q_host in sorted(q_now - quarantined_hosts):
            remediator.remediate_and_store(
                store=store,
                run_id=run_id,
                host_id=q_host,
                findings=[f for f in state.get("findings", []) if f.host_id == q_host],
                recorder=recorder,
            )

        quarantined_hosts |= q_now

    elapsed = time.perf_counter() - start_time
    recorder.record(
        event_type=EventType.RUN_COMPLETED,
        component="supervisor",
        status=EventStatus.OK,
        details={
            "cycles": cycles,
            "total_records": total_records,
            "total_bursts": total_bursts,
            "elapsed_seconds": round(elapsed, 4),
        },
    )

    # Parity check: compare SQLite events to JSONL events
    sqlite_count = store.get_event_count(run_id)
    with open(trace_path, "r", encoding="utf-8") as f:
        jsonl_count = sum(1 for line in f if line.strip())
    parity_passed = (sqlite_count == jsonl_count)

    findings = store.get_findings(run_id)
    try:
        eval_metrics = store.compute_eval_metrics(run_id)
    except Exception:  # metrics are best-effort for ad-hoc scenarios
        eval_metrics = {}

    metrics = {
        "run_id": run_id,
        "seed": seed,
        "cycles": cycles,
        "device_count": device_count,
        "total_records": total_records,
        "total_bursts": total_bursts,
        "total_anomalies_rejected": total_anomalies_rejected,
        "total_clean_records": total_clean_records,
        "total_findings": len(findings),
        "quarantined_hosts": sorted(quarantined_hosts),
        "burst_actions": burst_actions,
        "host_record_counts": host_record_counts,
        "elapsed_seconds": round(elapsed, 4),
        "records_per_second": round(total_records / max(0.001, elapsed), 2),
        "eval_metrics": eval_metrics,
        "fleet": [w.host_id for w in human_gen.workstations],
        "parity_passed": parity_passed,
        "sqlite_event_count": sqlite_count,
        "jsonl_event_count": jsonl_count,
        "db_path": str(db_path),
        "trace_path": str(trace_path),
    }

    store.update_run_status(
        run_id=run_id,
        status="COMPLETED",
        metadata={
            "metrics": metrics,
        },
    )
    store.close()
    return metrics
