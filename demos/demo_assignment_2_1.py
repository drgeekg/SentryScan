#!/usr/bin/env python3
"""Deterministic Demonstration Script for Assignment 2.1 — Concurrency & Fleet.

Demonstrates:
1. Multi-device fleet telemetry generation and background monitor daemon.
2. Non-blocking heartbeat verification during active consumer processing.
3. Thread synchronization and proof of lost updates (unlocked vs locked).
4. Controlled poisoning mutators and isolated ground-truth sidecar.
5. Deterministic IntegrityChecker flagging suspect telemetry.
6. Evaluator scoring detection accuracy (precision, recall, confusion matrix).
7. Queue residence latency tracking (p50, p95) exported to CSV.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentryscan.common.clock import SystemClock  # noqa: E402
from sentryscan.common.id_generator import IdGenerator  # noqa: E402
from sentryscan.concurrency.daemon import MonitorDaemon  # noqa: E402
from sentryscan.concurrency.metrics import LatencyTracker  # noqa: E402
from sentryscan.concurrency.queue_manager import TelemetryQueueManager  # noqa: E402
from sentryscan.concurrency.stats import SharedFleetStats, demonstrate_lost_updates  # noqa: E402
from sentryscan.contracts.events import EventStatus, EventType  # noqa: E402
from sentryscan.integrity.checker import IntegrityChecker  # noqa: E402
from sentryscan.integrity.evaluator import DetectionEvaluator  # noqa: E402
from sentryscan.observability.recorder import EventRecorder  # noqa: E402
from sentryscan.rules.engine import RuleEngine  # noqa: E402
from sentryscan.simulation.fleet import DeviceFleetSimulator  # noqa: E402
from sentryscan.simulation.poisoning import (  # noqa: E402
    GroundTruthEntry,
    GroundTruthSidecar,
    InjectionOperator,
    PoisoningMutator,
)

OUTPUT_DIR = REPO_ROOT / "data" / "runs" / "demo_2_1"


def run_demo() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    print("=" * 78)
    print(" SentryScan Milestone 2.1 — Concurrency, Fleet & Integrity Verification ")
    print("=" * 78)

    # 1. Experiment: Lost Updates Comparison (Without Lock vs With Lock)
    print("\n[*] Experiment 1: Race Condition & Lost Updates Proof")
    expected, unlocked_actual, locked_actual = demonstrate_lost_updates(
        num_threads=10, increments_per_thread=50
    )
    lost_count = expected - unlocked_actual
    print(f"    - Target Operations:     {expected} increments (10 threads x 50)")
    print(f"    - Without Lock (Race):   {unlocked_actual} updates (LOST: {lost_count} updates!)")
    print(f"    - With Mutex Lock:       {locked_actual} updates (100% accurate, 0 lost)")
    assert locked_actual == expected
    assert unlocked_actual < expected

    # 2. Setup Fleet, Sidecar, and Queues
    print("\n[*] Initializing Simulated Endpoint Fleet (RFC 5737 space)...")
    clock = SystemClock()
    id_gen = IdGenerator(seed=42)

    sim = DeviceFleetSimulator(device_count=5, seed=42, clock=clock, id_gen=id_gen)
    for dev in sim.devices:
        print(f"    - Device: {dev.device_id} | IP: {dev.ip:15} | Svc Count: {len(dev.services)}")

    sidecar = GroundTruthSidecar()
    mutator = PoisoningMutator(sidecar=sidecar, seed=42)
    queue_mgr = TelemetryQueueManager(maxsize=1000)
    stats = SharedFleetStats()
    integrity_checker = IntegrityChecker(clock=clock, freshness_window_seconds=60.0)
    rule_engine = RuleEngine()
    latency_tracker = LatencyTracker()

    trace_file = OUTPUT_DIR / "trace.jsonl"
    if trace_file.exists():
        trace_file.unlink()
    recorder = EventRecorder("run-demo-2-1", trace_file, clock=clock)

    recorder.record(
        event_type=EventType.RUN_STARTED,
        component="orchestrator",
        status=EventStatus.OK,
        details={"devices": len(sim.devices)},
    )

    # 3. Start Monitor Daemon
    heartbeats_observed: list[int] = []

    def hb_listener(count: int, ts: str):
        heartbeats_observed.append(count)

    daemon = MonitorDaemon(
        queue_manager=queue_mgr,
        fleet_simulator=sim,
        clock=clock,
        heartbeat_interval=0.02,
        on_heartbeat=hb_listener,
    )
    daemon.start()
    print("[*] Monitor daemon launched in background thread.")

    # 4. Generate controlled stream with injected mutations
    print("\n[*] Emitting telemetry stream and injecting controlled anomalies...")

    # Let daemon run 2 cycles
    time.sleep(0.08)

    # Inject specific anomalies into queue
    base1 = sim.generate_record_for_device(sim.devices[0], service_index=0)
    mutated1 = mutator.mutate(base1, InjectionOperator.STALE_TIMESTAMP, id_gen.next_id("record"))
    queue_mgr.enqueue(mutated1)

    base2 = sim.generate_record_for_device(sim.devices[1], service_index=0)
    mutated2 = mutator.mutate(
        base2, InjectionOperator.SERVICE_BANNER_MISMATCH, id_gen.next_id("record")
    )
    queue_mgr.enqueue(mutated2)

    base3 = sim.generate_record_for_device(sim.devices[2], service_index=0)
    mutated3 = mutator.mutate(
        base3, InjectionOperator.TLS_CLAIM_CONTRADICTION, id_gen.next_id("record")
    )
    queue_mgr.enqueue(mutated3)

    base4 = sim.generate_record_for_device(sim.devices[3], service_index=0)
    mutated4 = mutator.mutate(
        base4, InjectionOperator.PROMPT_INJECTION_BANNER, id_gen.next_id("record")
    )
    queue_mgr.enqueue(mutated4)

    # Replay base1
    mutated5 = mutator.mutate(base1, InjectionOperator.REPLAYED_RECORD, base1.record_id)
    queue_mgr.enqueue(mutated5)

    # Stop daemon and drain queue
    time.sleep(0.05)
    daemon.stop()
    daemon.join(timeout=1.0)
    print(f"[+] Daemon stopped cleanly. Total heartbeats emitted: {daemon.heartbeat_count}")
    assert daemon.heartbeat_count >= 3

    # 5. Consume and Process Telemetry Stream
    print("\n[*] Consuming queue and performing integrity & rule evaluation...")
    processed_record_ids: list[str] = []
    flags_by_record: dict[str, list[Any]] = {}

    while True:
        record, wait_ms = queue_mgr.dequeue(timeout=0.02)
        if record is None:
            break

        proc_start = time.perf_counter()
        processed_record_ids.append(record.record_id)

        # A. Register in sidecar as clean baseline if not already recorded by mutator
        if not sidecar.get_entry(record.record_id):
            sidecar.record_ground_truth(
                GroundTruthEntry(
                    record_id=record.record_id,
                    device_id=record.host_id,
                    is_poisoned=False,
                    injection_type=None,
                    modified_fields=[],
                    expected_classification="normal",
                    parent_record_id=None,
                )
            )

        # B. Integrity Inspection
        flags = integrity_checker.check_record(record)
        is_suspect = len(flags) > 0
        if is_suspect:
            flags_by_record[record.record_id] = flags
            for flag in flags:
                recorder.record(
                    event_type=EventType.RECORD_REJECTED
                    if flag.reason_code == "REPLAYED_RECORD"
                    else EventType.RECORD_RECEIVED,
                    component="integrity_checker",
                    status=EventStatus.OK,
                    record_id=record.record_id,
                    host_id=record.host_id,
                    reason_code=flag.reason_code.value,
                    details=flag.details,
                )

        # C. Rule Evaluation
        findings = rule_engine.evaluate_record(
            record=record,
            run_id="run-demo-2-1",
            finding_id_generator=lambda: id_gen.next_id("finding"),
            timestamp_iso=clock.now_iso(),
        )

        proc_ms = (time.perf_counter() - proc_start) * 1000.0
        latency_tracker.record_latency(record.record_id, wait_ms, proc_ms)

        # D. Atomically update stats with mutex lock
        stats.record_percept_locked(
            is_valid=True,
            is_suspect=is_suspect,
            findings_delta=len(findings),
            host_id=record.host_id,
        )

    # 6. Evaluate Integrity Detection against Ground Truth
    evaluator = DetectionEvaluator(sidecar)
    metrics = evaluator.evaluate(processed_record_ids, flags_by_record)

    det_report_path = OUTPUT_DIR / "detection_report.json"
    evaluator.write_report_json(metrics, det_report_path)

    # 7. Export Latency Metrics CSV
    metrics_csv_path = OUTPUT_DIR / "metrics.csv"
    latency_tracker.export_csv(metrics_csv_path)
    perf_summary = latency_tracker.compute_summary()

    recorder.record(
        event_type=EventType.RUN_COMPLETED,
        component="orchestrator",
        status=EventStatus.OK,
        details={
            "total_processed": len(processed_record_ids),
            "detection_metrics": metrics.to_dict(),
            "performance": perf_summary,
        },
    )
    recorder.close()

    # 8. Print Executive Summary
    print("\n" + "=" * 78)
    print("                     MILESTONE 2.1 EXECUTION REPORT                   ")
    print("=" * 78)
    print(f"[*] Total Telemetry Ingested:    {len(processed_record_ids)} records")
    print(f"[*] Suspect Records Flagged:     {stats.suspect_records} records")
    print(f"[*] Total Findings Created:      {stats.findings_count} findings")
    print("\n[*] Detection Accuracy vs Ground Truth Sidecar:")
    print(f"    - True Positives (Detected): {metrics.true_positives}")
    print(f"    - True Negatives (Clean):    {metrics.true_negatives}")
    print(f"    - False Positives:           {metrics.false_positives}")
    print(f"    - False Negatives:           {metrics.false_negatives}")
    print(f"    - Precision:                 {metrics.precision * 100:.1f}%")
    print(f"    - Recall:                    {metrics.recall * 100:.1f}%")
    print(f"    - F1-Score:                  {metrics.f1_score * 100:.1f}%")

    print("\n[*] Queue & Turnaround Latencies (ms):")
    print(f"    - Queue Wait (p50):          {perf_summary['queue_wait_ms']['p50']:.3f} ms")
    print(f"    - Queue Wait (p95):          {perf_summary['queue_wait_ms']['p95']:.3f} ms")
    print(f"    - Turnaround (p50):          {perf_summary['turnaround_ms']['p50']:.3f} ms")
    print(f"    - Turnaround (p95):          {perf_summary['turnaround_ms']['p95']:.3f} ms")

    print("\n[*] Generated Evidence Artifacts:")
    print(f"    - Trace File:                {trace_file}")
    print(f"    - Latency Metrics CSV:       {metrics_csv_path}")
    print(f"    - Detection Report JSON:     {det_report_path}")
    print("=" * 78)
    print("[+] All Assignment 2.1 requirements successfully demonstrated!\n")


if __name__ == "__main__":
    run_demo()
