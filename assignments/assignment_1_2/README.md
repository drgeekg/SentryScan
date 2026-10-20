# Assignment 1.2 — Deterministic Rule-Based Reflex Reasoner

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-1.2`  

---

## 1. Architectural Increment Overview

Assignment 1.2 implements the executable core of the **SentryScan Reflex Reasoner**, delivering an end-to-end, deterministic Sense–Parse–Decide–Act agent loop:

1. **Injectable Time & Determinism Primitives:**
   - [`src/sentryscan/common/clock.py`](../../src/sentryscan/common/clock.py): `FakeClock` enables instantaneous virtual time advancement without real wall-clock sleeps, ensuring consistent, repeatable timestamps.
   - [`src/sentryscan/common/id_generator.py`](../../src/sentryscan/common/id_generator.py): Seeded and sequential ID generators produce monotonic zero-padded identifiers (`tel-000001`, `fnd-000001`, `evt-000001`).
2. **Typed Contracts & Test Fixture:**
   - [`src/sentryscan/contracts/telemetry.py`](../../src/sentryscan/contracts/telemetry.py) and [`src/sentryscan/contracts/finding.py`](../../src/sentryscan/contracts/finding.py): Strongly-typed Pydantic schemas enforcing port bounds ($1 \dots 65535$), non-empty host identifiers, and categorical severities.
   - [`fixtures/telemetry/sample_seed42.json`](../../fixtures/telemetry/sample_seed42.json): Seeded dataset of 20 records (18 valid diverse services across 10 synthetic hosts + 2 malformed records with out-of-range port and blank host ID).
3. **Sensor Parsing & Quarantine:**
   - [`src/sentryscan/sensors/parser.py`](../../src/sentryscan/sensors/parser.py): `TelemetryParser` validates raw records and isolates malformed payloads into `record_rejected` audit events with explicit reason codes (`MALFORMED_TELEMETRY`).
4. **Explicit Condition-Action Rule Engine:**
   - [`src/sentryscan/rules/engine.py`](../../src/sentryscan/rules/engine.py): Implements 6 explicit production rules:
     - `RULE-001`: Unencrypted Telnet Exposure (`HIGH`)
     - `RULE-002`: Unauthenticated Anonymous FTP (`MEDIUM`)
     - `RULE-003`: Deprecated TLS/SSL Protocol Versions (`HIGH`)
     - `RULE-004`: Default Administrative Credentials (`CRITICAL`)
     - `RULE-005`: Known Critical Exploit Banner Matches (`CRITICAL`)
     - `RULE-006`: Unencrypted Administrative HTTP Interfaces (`MEDIUM`)
     - *Unmatched Records:* Valid records matching zero rules trigger an explicit `unmatched_record` audit event with reason `NO_RULES_MATCHED`.
5. **Single-Writer Event Bus & Persistence:**
   - [`src/sentryscan/observability/recorder.py`](../../src/sentryscan/observability/recorder.py): Single-writer `EventRecorder` assigns monotonic, gap-free sequence numbers (`seq: 1 ... N`) and appends JSONL entries to disk.
6. **Actuators & Report Rendering:**
   - [`src/sentryscan/actuators/report.py`](../../src/sentryscan/actuators/report.py): Renders formatted Rich console overview tables and serializes structured `findings.json` and `summary.json`.

---

## 2. Execution Evidence & Verification

Deterministic demonstration output is captured directly from execution:
- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **Total Percepts Sensed:** 20
- **Valid Telemetry Ingested:** 18
- **Malformed Records Quarantined:** 2 (`tel-000019` port 99999; `tel-000020` blank host ID)
- **Total Exposures Detected:** 13 findings across `CRITICAL` (4), `HIGH` (5), and `MEDIUM` (4)
- **Trace Sequence Integrity:** 100% gap-free monotonic sequence numbers (`seq: 1 ... 51`)

---

## 3. Reproduction Instructions

To reproduce the deterministic demonstration and execute all tests:

```bash
# Run deterministic demonstration script
python demos/demo_assignment_1_2.py

# Run CLI command
python src/sentryscan/cli.py run-reflex --fixture fixtures/telemetry/sample_seed42.json

# Run unit and integration test suite
pytest -v tests/

# Verify code formatting and linting
ruff check .

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-1.2
```
