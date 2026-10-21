# Assignment 2.1 — Concurrency, Fleet Simulation & Data Integrity

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-2.1`  

---

## 1. Architectural Increment Overview

Assignment 2.1 introduces multithreaded concurrency, realistic endpoint fleet modeling, data poisoning injection, and deterministic data-level integrity auditing:

1. **Simulated Device Fleet:**
   - [`src/sentryscan/simulation/fleet.py`](../../src/sentryscan/simulation/fleet.py): Models heterogeneous endpoint devices (`sim-host-001` … `sim-host-N`) operating in IETF RFC 5737 documentation space (`192.0.2.0/24`, `198.51.100.0/24`), ensuring zero live network probing.
2. **Background Monitor Daemon & Clean Shutdown:**
   - [`src/sentryscan/concurrency/daemon.py`](../../src/sentryscan/concurrency/daemon.py): Runs a non-blocking `threading.Thread` generating telemetry cycles and emitting periodic heartbeat signals. Utilizes `threading.Event` for graceful shutdown without thread leaks.
3. **Thread-Safe Queue Manager & Latency Metrics:**
   - [`src/sentryscan/concurrency/queue_manager.py`](../../src/sentryscan/concurrency/queue_manager.py): Buffers incoming telemetry using thread-safe `queue.Queue`.
   - [`src/sentryscan/concurrency/metrics.py`](../../src/sentryscan/concurrency/metrics.py): Records entry/exit timestamps, computing queue wait times and turnaround metrics (p50, p95), exported to [`evidence/metrics.csv`](evidence/metrics.csv).
4. **Thread Synchronization & Lost Updates Experiment:**
   - [`src/sentryscan/concurrency/stats.py`](../../src/sentryscan/concurrency/stats.py): Proves race conditions when multiple threads update shared statistics without synchronization (yielding hundreds of lost updates), and demonstrates 100% update accuracy with `threading.Lock`.
5. **Controlled Poisoning Mutators & Isolated Ground Truth:**
   - [`src/sentryscan/simulation/poisoning.py`](../../src/sentryscan/simulation/poisoning.py): Injects anomalies (stale timestamps, service/banner mismatches, TLS contradictions, rate bursts, prompt injection banners). True labels are stored exclusively in an isolated `GroundTruthSidecar` invisible to the analysis pipeline.
6. **Deterministic Data-Level Integrity Checker:**
   - [`src/sentryscan/integrity/checker.py`](../../src/sentryscan/integrity/checker.py): Rules-as-data engine detecting implausible telemetry (`STALE_RECORD`, `REPLAYED_RECORD`, `FIELD_CONTRADICTION`, `SUSPECT_TEXT`) without access to ground truth.
7. **Detection Accuracy Evaluation:**
   - [`src/sentryscan/integrity/evaluator.py`](../../src/sentryscan/integrity/evaluator.py): Out-of-band evaluation job comparing integrity flags against ground truth, computing precision, recall, and confusion matrix exported to [`evidence/detection_report.json`](evidence/detection_report.json).

---

## 2. Execution Evidence & Verification

Demonstration artifacts generated from execution:
- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Latency Metrics CSV:** [`evidence/metrics.csv`](evidence/metrics.csv)
- **Detection Report JSON:** [`evidence/detection_report.json`](evidence/detection_report.json)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **Concurrency & Lost Updates:**
  - Unlocked: ~54 updates out of 500 target (446 lost updates due to race conditions).
  - Mutex Locked: Exactly 500/500 updates (0 lost updates).
- **Daemon Lifecycle:** Non-blocking heartbeat confirmed (5 heartbeats emitted while consumer worked concurrently).
- **Integrity Detection vs. Ground Truth:**
  - True Positives: 4
  - True Negatives: 60
  - False Positives: 0 (100.0% Precision)
  - False Negatives: 1 (80.0% Recall, 88.9% F1-Score)
- **Queue Performance:**
  - Queue Wait (p50): ~68 ms | (p95): ~132 ms

---

## 3. Reproduction Instructions

```bash
# Run deterministic concurrency and fleet demonstration
python demos/demo_assignment_2_1.py

# Run unit and integration tests
pytest -v tests/

# Verify linter
ruff check .

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-2.1
```
