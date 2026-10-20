# Rubric Mapping — Assignment 1.2: Rule-Based Reflex Reasoner

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** 1.2 — Rule-Based Reasoner  
**Deliverable Scope:** Deterministic reflex reasoner, explicit rule table, JSONL event recorder, seeded fixtures, and captured execution evidence.  

---

## Rubric Verification Matrix

| Evaluation Criterion | Specific Requirement | Implementation Location | Evidence Artifact & Verification |
|---|---|---|---|
| **1. Injectable Clock & Deterministic IDs** | Abstract `Clock` protocol with `SystemClock` and `FakeClock`; monotonic and seeded `IdGenerator` | `src/sentryscan/common/clock.py`<br>`src/sentryscan/common/id_generator.py` | `tests/unit/test_common.py`<br>`evidence/trace_excerpt.jsonl` (identical ISO timestamps) |
| **2. Strongly Typed Telemetry Contracts** | Pydantic model for `TelemetryRecord` validating ports (1–65535), non-empty `host_id`, enums for auth mode and source | `src/sentryscan/contracts/telemetry.py`<br>`src/sentryscan/contracts/finding.py` | `tests/unit/test_contracts.py`<br>`fixtures/telemetry/sample_seed42.json` |
| **3. Seeded Telemetry Dataset** | Fixture containing 20 synthetic records across multiple hosts (`sim-host-001` … `sim-host-010`), exactly 18 valid and 2 malformed | `fixtures/telemetry/sample_seed42.json` | `tests/unit/test_parser.py`<br>`evidence/run_log.txt#L6-L14` |
| **4. Explicit Condition-Action Rule Table** | Plain Python rule engine evaluating IF–THEN condition-action rules for cleartext protocols, deprecated TLS, default credentials, and exploit banners | `src/sentryscan/rules/engine.py` (RULE-001 through RULE-006) | `tests/unit/test_rules.py`<br>`evidence/run_log.txt#L15-L84`<br>13 findings detected |
| **5. Malformed Payload Handling** | Quarantines invalid records (out-of-range port, blank host ID) and emits structured `record_rejected` audit events | `src/sentryscan/sensors/parser.py`<br>`src/sentryscan/agents/reflex_agent.py` | `evidence/run_log.txt#L12`<br>`evidence/trace_excerpt.jsonl` (Events #48, #49: `MALFORMED_TELEMETRY`) |
| **6. Unmatched Percept Accounting** | Explicitly audits valid records that trigger zero rules (`unmatched_record` with reason `NO_RULES_MATCHED`) | `src/sentryscan/agents/reflex_agent.py` | `evidence/trace_excerpt.jsonl` (Events #6, #27, #29)<br>`tests/unit/test_reflex_agent.py` |
| **7. Single-Writer Event Recorder & Monotonic `seq`** | Append-only JSONL event stream with thread-safe lock, monotonic gap-free `seq`, and complete run lifecycle events | `src/sentryscan/observability/recorder.py`<br>`src/sentryscan/contracts/events.py` | `tests/unit/test_recorder.py`<br>`evidence/trace_excerpt.jsonl` (`seq`: 1 … 51) |
| **8. Sense-Parse-Decide-Act Agent Loop & Actuators** | Complete reflex agent pipeline with Rich console table and JSON artifact exporters | `src/sentryscan/agents/reflex_agent.py`<br>`src/sentryscan/actuators/report.py` | `demos/demo_assignment_1_2.py`<br>`tests/integration/test_assignment_1_2.py`<br>`evidence/run_log.txt` |
| **9. Packaging & Git Release Integrity** | Dedicated branch, atomic commits, non-fast-forward merge commit, immutable tag, and verified archive packaging | Monorepo root and git history | Git Tag: `assignment-1.2`<br>Archive: `dist/SentryScan_assignment_1_2.zip` |
