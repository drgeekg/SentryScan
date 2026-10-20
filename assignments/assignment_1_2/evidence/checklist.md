# Assignment 1.2 Acceptance & Verification Checklist

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** 1.2 — Rule-Based Reflex Reasoner  
**Git Tag:** `assignment-1.2`  

---

## Global Definition of Done Verification

- [x] **Core Functionality Implemented:** Sense-Parse-Decide-Act reflex loop implemented in `src/sentryscan/agents/reflex_agent.py`.
- [x] **Injectable Clock & Deterministic IDs:** `FakeClock` and `IdGenerator` implemented and unit tested.
- [x] **Telemetry Contracts & Fixtures:** 20 seeded records in `fixtures/telemetry/sample_seed42.json`, strictly validated by Pydantic models.
- [x] **Explicit Rule Engine:** 6 explicit condition-action production rules implemented in `src/sentryscan/rules/engine.py`.
- [x] **Malformed Record Quarantine:** Both malformed records rejected and audited with `record_rejected` events and `MALFORMED_TELEMETRY` codes.
- [x] **Unmatched Record Accounting:** Records matching zero rules explicitly logged with `unmatched_record` events and `NO_RULES_MATCHED`.
- [x] **Audit Trace Completeness:** Single-writer `EventRecorder` assigns monotonic, gap-free `seq` numbers to an append-only JSONL file.
- [x] **Actuators & CLI:** Rich console table output and JSON findings exporter wired; runnable via `demos/demo_assignment_1_2.py` and `sentryscan run-reflex`.
- [x] **Test Suite Passing:** All 20 unit and integration tests passing (`pytest tests/`).
- [x] **Clean Linter:** `ruff check .` passes with zero warnings.
- [x] **Git Workflow Adherence:** Authored on short-lived branch `assignment/1.2-reflex-reasoner`, merged into `main` with a non-fast-forward merge commit, and tagged with immutable `assignment-1.2`.
- [x] **Reproducible Packaging:** Package archive built strictly from the immutable tag via `scripts/package_assignment.py`.
