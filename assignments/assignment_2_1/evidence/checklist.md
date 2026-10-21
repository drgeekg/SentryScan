# Assignment 2.1 Acceptance & Verification Checklist

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** 2.1 — Concurrency, Fleet Simulation & Data Integrity  
**Git Tag:** `assignment-2.1`  

---

## Global Definition of Done Verification

- [x] **Simulated Fleet Modeled:** Fictitious endpoint fleet (`sim-host-001` … `sim-host-N`) in RFC 5737 space implemented in `src/sentryscan/simulation/fleet.py`.
- [x] **Monitor Daemon Implemented:** Background `threading.Thread` generating telemetry with non-blocking heartbeat and clean `threading.Event` shutdown implemented in `src/sentryscan/concurrency/daemon.py`.
- [x] **Safe Queue Buffer Implemented:** Thread-safe `queue.Queue` buffer connecting producers and consumers with latency measurement implemented in `src/sentryscan/concurrency/queue_manager.py`.
- [x] **Lost Updates Experiment:** Race condition proven with hundreds of lost updates without locks; 100% update accuracy proven with `threading.Lock` in `src/sentryscan/concurrency/stats.py`.
- [x] **Controlled Poisoning Mutators:** Injected anomalies (stale timestamps, banner mismatches, TLS contradictions, prompt injections, replays) implemented in `src/sentryscan/simulation/poisoning.py`.
- [x] **Ground-Truth Isolation:** Evaluator-only `GroundTruthSidecar` stores mutation labels out-of-band, strictly isolated from agent perception.
- [x] **Data-Level Integrity Checker:** Rules-as-data engine detecting implausible records without ground truth implemented in `src/sentryscan/integrity/checker.py`.
- [x] **Detection Evaluation Metrics:** Out-of-band evaluation job computes precision, recall, and confusion matrix exported to `evidence/detection_report.json`.
- [x] **Queue Latency Metrics:** Queue wait times and turnaround metrics (p50, p95) calculated and exported to `evidence/metrics.csv`.
- [x] **All Tests Passing:** 38 unit and integration tests passing (`pytest tests/`).
- [x] **Clean Linter:** `ruff check .` passes with zero errors.
- [x] **Git Workflow Adherence:** Authored on short-lived branch `assignment/2.1-concurrent-daemon`, merged into `main` with a non-fast-forward merge commit, and tagged with immutable `assignment-2.1`.
- [x] **Reproducible Packaging:** Package archive built strictly from the immutable tag via `scripts/package_assignment.py`.
