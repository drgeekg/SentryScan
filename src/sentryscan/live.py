"""Continuous live SOC simulation: realistic workstation telemetry handled by real agents."""

from __future__ import annotations

import logging
import random
import threading
import time
from pathlib import Path

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.analysis.report_generator import generate_posture_report
from sentryscan.common.clock import SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.events import EventStatus, EventType
from sentryscan.graphs.supervisor import build_supervisor_graph
from sentryscan.integrity.checker import IntegrityChecker
from sentryscan.knowledge.enricher import KnowledgeEnricher
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase
from sentryscan.llm.factory import get_llm_provider
from sentryscan.observability.recorder import EventRecorder
from sentryscan.security.gate import SecurityGate
from sentryscan.security.identity import AgentIdentity
from sentryscan.security.registry import TrustedAgentRegistry
from sentryscan.simulation.fleet import DeviceFleetSimulator
from sentryscan.simulation.human_traffic import HumanTrafficGenerator
from sentryscan.simulation.poisoning import GroundTruthSidecar, InjectionOperator, PoisoningMutator
from sentryscan.storage.store import SQLiteRunStore

logger = logging.getLogger(__name__)

LIVE_RUN_ID = "run-live"


def run_live(
    store: SQLiteRunStore,
    trace_path: Path | str,
    stop: threading.Event,
    device_count: int | None = None,
    sample_size: int = 20,
    poison_ratio: float = 0.2,
    pace: float = 1.0,
    seed: int = 7,
    clean_cycles_for_decay: int = 10,
    profile: str = "enterprise",
    fleet_spec: str | None = None,
    industry: str = "generic",
) -> None:
    """Loop continuously: stream records, integrity-check, negotiate, scan, triage, record. `pace` scales sleeps."""
    clk = SystemClock()
    id_gen = IdGenerator(seed=seed)
    rng = random.Random(seed)

    recorder = EventRecorder(run_id=LIVE_RUN_ID, output_path=trace_path, clock=clk, sqlite_store=store)
    manifest = {
        "version": "0.1.0",
        "seed": seed,
        "fleet_size": device_count,
        "poison_ratio": poison_ratio,
        "llm_provider": "deterministic",
        "clock": "SystemClock",
        "mode": "live",
        "profile": profile,
        "fleet_spec": fleet_spec,
        "industry": industry,
    }
    store.save_run(run_id=LIVE_RUN_ID, seed=seed, status="RUNNING", created_at=clk.now_iso(), manifest=manifest)
    recorder.record(event_type=EventType.RUN_STARTED, component="supervisor", details={"manifest": manifest})

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
            security_gate=SecurityGate(agent_id=aid, registry=registry, clock=clk, freshness_window_seconds=30.0),
            clean_cycles_for_decay=clean_cycles_for_decay,
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
        llm_provider=get_llm_provider(),
        analyst_tiers=analyst_tiers,
        analyst_identities=ids,
        supervisor_identity=ids["supervisor-agent"],
        max_rounds=4,
    )

    templates = None
    if profile == "enterprise":
        from sentryscan.simulation.asset_types import build_templates, resolve_fleet
        templates = build_templates(resolve_fleet(fleet_spec, device_count, seed))
        device_count = len(templates)
    device_count = device_count or 8
    fleet = DeviceFleetSimulator(
        device_count=device_count,
        clock=clk,
        id_gen=id_gen,
        seed=seed,
        profile=profile,
        templates=templates,
    )
    human_gen: HumanTrafficGenerator | None = None
    if profile in ("human_workstations", "enterprise"):
        human_gen = HumanTrafficGenerator(
            templates=templates,
            device_count=device_count,
            seed=seed,
            clock=clk,
            id_gen=id_gen,
            poison_ratio=poison_ratio,
        )
    if templates is not None:
        from sentryscan.platform import core as platform_core
        platform_core.bootstrap(store, LIVE_RUN_ID, templates, seed=seed, profile=industry)

    mutator = PoisoningMutator(sidecar=GroundTruthSidecar(), seed=seed)
    checker = IntegrityChecker(clock=clk)
    for rec in fleet.generate_fleet_cycle():  # register every device once so the fleet view is complete
        store.save_telemetry_record(rec, run_id=LIVE_RUN_ID, is_poisoned=False)
        checker.check_record(rec)

    ops = [o for o in InjectionOperator if o not in (InjectionOperator.REPLAYED_RECORD,)]
    quarantined: set[str] = set()
    quarantine_at: dict[str, int] = {}  # host -> cycle it was isolated
    release_after = 8  # cycles a host stays isolated before the analyst re-admits it
    msg_seq = cycle = 0
    findings_total = 0
    last_report_at = time.monotonic()  # auto-report only every 30 minutes (1800s)

    def nap(sec: float) -> bool:
        current_pace = pace
        try:
            from sentryscan.platform import core as platform_core
            dyn_p = platform_core.get_setting(store, LIVE_RUN_ID, "simulation_pace", "")
            if dyn_p:
                current_pace = float(dyn_p)
        except Exception:
            pass
        return stop.wait(sec * current_pace)

    shape = random.Random()
    weights = [shape.paretovariate(1.3) for _ in fleet.devices]

    def next_standard_burst() -> dict:
        roll = shape.random()
        if roll < 0.12:
            return {"kind": "storm", "size": shape.randint(25, 70), "poison": shape.uniform(0.5, 0.9),
                    "target": shape.choice(fleet.devices), "gap": shape.uniform(0.01, 0.05)}
        if roll < 0.35:
            return {"kind": "trickle", "size": shape.randint(2, 6), "poison": shape.uniform(0.0, 0.1),
                    "target": None, "gap": shape.uniform(0.2, 0.6)}
        return {"kind": "normal", "size": max(3, int(shape.lognormvariate(2.6, 0.55))),
                "poison": min(0.6, shape.expovariate(1 / max(poison_ratio, 0.01))), "target": None,
                "gap": shape.expovariate(1 / 0.10)}

    while not stop.is_set():
        cycle += 1
        try:
            # 1. Quarantine lifecycle: release hosts after quarantine duration
            for host, since in list(quarantine_at.items()):
                if cycle - since >= release_after:
                    del quarantine_at[host]
                    quarantined.discard(host)
                    with store._lock, store._conn:
                        store._conn.execute("UPDATE findings SET quarantined=0 WHERE run_id=? AND host_id=?", (LIVE_RUN_ID, host))
                    recorder.record(event_type=EventType.STATE_TRANSITION, component="analyst-l3-containment", host_id=host,
                                    details={"action": "quarantine_released"})

            active = [d for d in fleet.devices if d.host_id not in quarantine_at] or fleet.devices
            clean = []

            # 2. Telemetry Generation (Human Workstation vs Standard Fleet)
            post_pause_s = 1.0
            burst_label = "standard"
            burst_host = "fleet"
            burst_total = 0
            rejected_in_cycle = 0
            if human_gen is not None:
                active_host_ids = [d.host_id for d in active]
                h_burst = human_gen.plan_next_human_burst(active_host_ids=active_host_ids)
                ws_info = human_gen.workstation_map[h_burst.host_id]
                post_pause_s = h_burst.post_burst_pause_s
                burst_label = h_burst.action.value
                burst_host = h_burst.host_id
                burst_total = h_burst.record_count

                recorder.record(
                    event_type=EventType.STATE_TRANSITION,
                    component="fleet_sensor",
                    host_id=h_burst.host_id,
                    details={
                        "user_action": h_burst.action.value,
                        "burst_size": h_burst.record_count,
                        "intra_delay_ms": round(h_burst.intra_event_delay_ms, 1),
                        "post_pause_s": round(h_burst.post_burst_pause_s, 2),
                        "is_anomaly": h_burst.is_anomaly,
                        "os_family": ws_info.os_family,
                        "persona": ws_info.persona,
                        "host_label": ws_info.label,
                    },
                )
                burst_records = human_gen.generate_burst_records(h_burst)
                for rec, truth, is_p, inj_type in burst_records:
                    store.save_ground_truth(
                        record_id=rec.record_id, run_id=LIVE_RUN_ID, host_id=rec.host_id, cycle=cycle,
                        is_vulnerable=truth["is_vulnerable"], expected_rules=truth["expected_rules"],
                        is_poisoned=is_p, injection_type=inj_type,
                    )
                    recorder.record(
                        event_type=EventType.RECORD_RECEIVED,
                        component="fleet_sensor",
                        record_id=rec.record_id,
                        host_id=rec.host_id,
                        details={
                            "service": rec.service,
                            "port": rec.port,
                            "is_vulnerable": truth["is_vulnerable"],
                            "expected_rules": truth["expected_rules"],
                            "is_poisoned": is_p,
                            "user_action": h_burst.action.value,
                            "os_family": ws_info.os_family,
                        },
                    )
                    flags = checker.check_record(rec)
                    if flags:
                        rejected_in_cycle += 1
                        store.save_telemetry_record(rec, run_id=LIVE_RUN_ID, is_poisoned=True)
                        recorder.record(
                            event_type=EventType.RECORD_REJECTED,
                            component="integrity_checker",
                            status=EventStatus.REJECTED,
                            record_id=rec.record_id,
                            host_id=rec.host_id,
                            reason_code=flags[0].reason_code.value,
                            details={"flags": len(flags)},
                        )
                    else:
                        clean.append(rec)
                    if nap(h_burst.intra_event_delay_ms / 1000.0):
                        return
            else:
                burst = next_standard_burst()
                burst_label = burst["kind"]
                burst_host = burst["target"].host_id if burst["target"] else "multi-host"
                burst_total = burst["size"]
                recorder.record(event_type=EventType.STATE_TRANSITION, component="fleet_sensor",
                                details={"burst": burst["kind"], "size": burst["size"],
                                         "poison_rate": round(burst["poison"], 2),
                                         "target": burst["target"].host_id if burst["target"] else None})
                act_w = [w for d, w in zip(fleet.devices, weights, strict=False) if d in active] or None
                for _ in range(burst["size"]):
                    if burst["target"] is not None and shape.random() < 0.7:
                        dev = burst["target"]
                    else:
                        dev = shape.choices(active, weights=act_w)[0]
                    rec, truth = fleet.generate_record_with_truth(dev)
                    is_p = False
                    inj_type: str | None = None
                    if shape.random() < burst["poison"]:
                        op = rng.choice(ops)
                        rec = mutator.mutate(baseline=rec, operator=op, new_record_id=id_gen.next_id("record"))
                        is_p = True
                        inj_type = op.value
                    store.save_ground_truth(
                        record_id=rec.record_id, run_id=LIVE_RUN_ID, host_id=rec.host_id, cycle=cycle,
                        is_vulnerable=truth["is_vulnerable"], expected_rules=truth["expected_rules"],
                        is_poisoned=is_p, injection_type=inj_type,
                    )
                    recorder.record(event_type=EventType.RECORD_RECEIVED, component="fleet_sensor", record_id=rec.record_id,
                                    host_id=rec.host_id, details={"service": rec.service, "port": rec.port,
                                                                  "is_vulnerable": truth["is_vulnerable"],
                                                                  "expected_rules": truth["expected_rules"],
                                                                  "is_poisoned": is_p})
                    flags = checker.check_record(rec)
                    if flags:
                        rejected_in_cycle += 1
                        store.save_telemetry_record(rec, run_id=LIVE_RUN_ID, is_poisoned=True)
                        recorder.record(event_type=EventType.RECORD_REJECTED, component="integrity_checker",
                                        status=EventStatus.REJECTED, record_id=rec.record_id, host_id=rec.host_id,
                                        reason_code=flags[0].reason_code.value, details={"flags": len(flags)})
                    else:
                        clean.append(rec)
                    if nap(shape.expovariate(1 / burst["gap"])):
                        return

            # 3. Agents negotiate and scan the clean batch
            half = len(clean) // 2
            if len(clean) < 2:
                print(
                    f"[Cycle #{cycle:03d}] {burst_label} @ {burst_host}: {burst_total} records "
                    f"({rejected_in_cycle} rejected) -> batch too small, skipping negotiation",
                    flush=True,
                )
                if nap(0.5):
                    return
                continue

            recorder.record(
                event_type=EventType.STATE_TRANSITION,
                component="scanner_worker",
                status=EventStatus.OK,
                details={
                    "action": "batch_scan_initiated",
                    "clean_records": len(clean),
                    "batch_alpha_size": half,
                    "batch_beta_size": len(clean) - half,
                },
            )
            state = graph.invoke({
                "run_id": LIVE_RUN_ID, "task_id": id_gen.next_id("task"),
                "batches": {"batch-alpha": [r.model_dump() for r in clean[:half]],
                            "batch-beta": [r.model_dump() for r in clean[half:]]},
                "constraints": {"max_cost": 150.0, "max_time": 600.0},
                "messages": [], "findings": [], "analyst_replies": [], "quarantined_hosts": [], "errors": [],
            })

            # 4. Stream real message traffic
            for msg in state.get("messages", []):
                msg_seq += 1
                store.save_message(msg, seq=msg_seq)
                recorder.record(event_type=EventType.MESSAGE_SENT, component=msg.sender, details={
                    "receiver": msg.receiver, "performative": msg.performative.value,
                    "message_id": msg.message_id, "payload": msg.payload})
                if msg.performative.value == "PROPOSE":
                    rationale = msg.payload.get("proposal", {}).get("rationale", "")
                    if rationale:
                        store.save_llm_call(
                            call_id=f"prop-{msg.message_id}",
                            run_id=LIVE_RUN_ID,
                            provider="deterministic",
                            model="deterministic-rule-v1",
                            role=f"{msg.sender}_proposal",
                            prompt_excerpt=f"Allocation proposal for task {msg.task_id}",
                            response_excerpt=rationale[:300],
                            tokens=len(rationale.split()),
                            latency_ms=2.0,
                            timestamp_utc=clk.now_iso(),
                        )
                if nap(0.08):
                    return

            # 5. Findings and containment decisions
            q_now = set(state.get("quarantined_hosts", []))
            for f in state.get("findings", []):
                is_q = f.host_id in q_now
                store.save_finding(f, cve_id=f.evidence.get("cve_id") if f.evidence else None, quarantined=is_q)
                findings_total += 1
                recorder.record(event_type=EventType.FINDING_CREATED, component="scanner_worker", host_id=f.host_id,
                                finding_id=f.finding_id, rule_id=f.rule_id,
                                details={"severity": f.severity.value, "quarantined": is_q})
                if nap(0.06):
                    return
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
                    },
                )
            for pq_row in store.get_pending_quarantines(run_id=LIVE_RUN_ID):
                if pq_row["status"] == "APPROVED":
                    q_now.add(pq_row["host_id"])
            from sentryscan.agents.remediator import RemediatorAgent
            remediator = RemediatorAgent(clock=clk, id_gen=id_gen)
            for q_host in sorted(q_now - quarantined):
                remediator.remediate_and_store(
                    store=store,
                    run_id=LIVE_RUN_ID,
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
                    },
                )
            quarantined |= q_now
            for host in q_now:
                quarantine_at.setdefault(host, cycle)

            has_threats = any(
                f.severity.value in ("HIGH", "CRITICAL") for f in state.get("findings", [])
            ) or bool(q_now)
            decay_msg = analyst_tiers["L2"].record_cycle_outcome(
                has_threats=has_threats,
                run_id=LIVE_RUN_ID,
                recorder=recorder,
            )
            if decay_msg is not None:
                decay_msg = ids["analyst-l2-incident"].sign_message(decay_msg)
                msg_seq += 1
                store.save_message(decay_msg, seq=msg_seq)
                recorder.record(
                    event_type=EventType.MESSAGE_SENT,
                    component=decay_msg.sender,
                    details={
                        "receiver": decay_msg.receiver,
                        "performative": decay_msg.performative.value,
                        "message_id": decay_msg.message_id,
                        "payload": decay_msg.payload,
                    },
                )

            now_mono = time.monotonic()
            if now_mono - last_report_at >= 1800.0:
                last_report_at = now_mono
                rep = generate_posture_report(
                    store=store, run_id=LIVE_RUN_ID,
                    window_name="Last 30 Minutes (Scheduled)",
                    llm=get_llm_provider(),
                )
                recorder.record(
                    event_type=EventType.REPORT_WRITTEN, component="supervisor",
                    status=EventStatus.OK, details={"report_id": rep["report_id"],
                                                     "score": rep["posture_score"],
                                                     "threat_level": rep["threat_level"]},
                )
                print(
                    f"[Report] 30-Min Scheduled Posture Report generated: {rep['report_id']} "
                    f"(Score: {rep['posture_score']}/100, Level: {rep['threat_level']})",
                    flush=True,
                )

            if cycle % 3 == 1:
                default_desires = {
                    "L1": "SURFACE_CRITICAL_FINDINGS",
                    "L2": "AUDIT_ASSIGNED_HOSTS",
                    "L3": "CONTAIN_COMPROMISED_HOSTS",
                }
                for tier_key, a_inst in analyst_tiers.items():
                    store.save_bdi_snapshot(
                        snapshot_id=id_gen.next_id("snap"),
                        run_id=LIVE_RUN_ID,
                        agent_id=a_inst.agent_id,
                        timestamp_utc=clk.now_iso(),
                        intention_type=(
                            a_inst.active_intention.desire_type.value
                            if a_inst.active_intention
                            else default_desires[tier_key]
                        ),
                        desire_type=default_desires[tier_key],
                        target_host=(
                            a_inst.active_intention.target_host
                            if a_inst.active_intention and a_inst.active_intention.target_host
                            else next(iter(q_now), "none")
                        ),
                        reconsideration_count=len(a_inst.reconsideration_history),
                        beliefs=a_inst.beliefs,
                    )
            if templates is not None and cycle % 5 == 0:
                from sentryscan.platform import core as platform_core
                from sentryscan.platform import pulse as platform_pulse
                if cycle % 40 == 0:
                    platform_core.scan(store, LIVE_RUN_ID, seed)
                platform_pulse.evaluate_controls(store, LIVE_RUN_ID)
            store.update_run_status(run_id=LIVE_RUN_ID, status="RUNNING", metadata={
                "cycles": cycle, "findings_count": findings_total, "quarantined_count": len(quarantined)})
            cycle_msgs = len(state.get("messages", []))
            cycle_findings = len(state.get("findings", []))
            print(
                f"[Cycle #{cycle:03d}] {burst_label} @ {burst_host} ({len(clean)}/{burst_total} clean, {rejected_in_cycle} rejected) "
                f"-> Agents: {cycle_msgs} msgs (total {msg_seq}) | "
                f"Findings: +{cycle_findings} (total {findings_total}) | "
                f"Quarantined: {len(quarantined)}",
                flush=True,
            )
        except Exception as err:
            logger.exception("live cycle %d failed", cycle)
            recorder.record(event_type=EventType.STATE_TRANSITION, component="supervisor",
                            status=EventStatus.ERROR, reason_code="CYCLE_FAILED", details={"error": str(err)[:200]})

        # Human think-time pause before next interactive task or ambient cycle
        if nap(post_pause_s):
            return
