# Rubric Mapping — Assignment 2.1: Concurrent Daemon & Data Integrity

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** 2.1 — Concurrent Daemon & Data Integrity  
**Deliverable Scope:** Background monitor daemon, thread-safe queue, lost update synchronization proof, simulated device fleet, poisoning mutators, isolated ground-truth sidecar, data-integrity checker, detection metrics, and latency metrics CSV.

---

## Rubric Verification Matrix

| Evaluation Criterion | Specific Requirement | Implementation Location | Evidence Artifact & Verification |
|---|---|---|---|
| **1. Background Monitor Daemon** | Background thread producing streaming telemetry with non-blocking heartbeat and clean event-driven shutdown | `src/sentryscan/concurrency/daemon.py` (`MonitorDaemon`) | `tests/unit/test_daemon.py`<br>`evidence/run_log.txt#L20-L33` (Heartbeats emitted: 5) |
| **2. Safe Telemetry Queue Buffer** | Thread-safe `queue.Queue` buffer connecting producers and consumers with enqueue/dequeue latency tracking | `src/sentryscan/concurrency/queue_manager.py` | `tests/unit/test_queue.py`<br>`evidence/metrics.csv` (queue wait times recorded) |
| **3. Lost Updates Synchronization Proof** | Concrete experiment proving race condition and lost updates without mutex lock vs. 100% accuracy with lock | `src/sentryscan/concurrency/stats.py` (`demonstrate_lost_updates`) | `tests/unit/test_concurrency.py`<br>`evidence/run_log.txt#L7-L12` (Lost: 440+ updates without lock vs 0 lost with lock) |
| **4. Simulated Device Fleet Model** | Configurable endpoint fleet (`sim-host-001` … `sim-host-N`) across RFC 5737 documentation address space | `src/sentryscan/simulation/fleet.py` (`DeviceFleetSimulator`) | `tests/unit/test_fleet.py`<br>`evidence/run_log.txt#L14-L20` (5 devices initialized) |
| **5. Controlled Poisoning Mutators** | Injection operators for stale timestamps, service/banner mismatches, TLS contradictions, prompt injections, and replays | `src/sentryscan/simulation/poisoning.py` (`PoisoningMutator`) | `tests/unit/test_poisoning.py`<br>`evidence/detection_report.json` |
| **6. Ground-Truth Isolation** | Mutation answer-key labels recorded exclusively in an evaluator sidecar, completely hidden from agent perception | `src/sentryscan/simulation/poisoning.py` (`GroundTruthSidecar`) | `tests/unit/test_poisoning.py`<br>`evidence/detection_report.json` |
| **7. Deterministic Data-Level Integrity Checker** | Plausibility checker detecting stale timestamps, duplicate records, contradictions, and prompt injections without ground truth | `src/sentryscan/integrity/checker.py` (`IntegrityChecker`) | `tests/unit/test_integrity.py`<br>`evidence/run_log.txt#L40` (4 suspect records detected) |
| **8. Detection Evaluation Metrics** | Evaluator scoring integrity flags against ground truth: confusion matrix, precision (100%), recall (80%), F1 score (88.9%) | `src/sentryscan/integrity/evaluator.py` (`DetectionEvaluator`) | `tests/unit/test_evaluator.py`<br>`evidence/detection_report.json`<br>`evidence/run_log.txt#L44-L52` |
| **9. Queue Latency Percentiles (p50/p95)** | Tracking queue residence and turnaround times, calculating p50/p95 percentiles, and exporting to CSV | `src/sentryscan/concurrency/metrics.py` (`LatencyTracker`) | `tests/unit/test_metrics.py`<br>`evidence/metrics.csv`<br>`evidence/run_log.txt#L54-L60` |
| **10. Packaging & Git Release Integrity** | Dedicated branch, atomic commits, non-fast-forward merge commit, immutable tag, and verified archive packaging | Monorepo root and git history | Git Tag: `assignment-2.1`<br>Archive: `dist/SentryScan_assignment_2_1.zip` |
