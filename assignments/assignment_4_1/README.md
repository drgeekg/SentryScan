# Assignment 4.1 — Deliberative BDI Modelling & Reconsideration

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-4.1`  

---

## 1. Architectural Increment Overview

Assignment 4.1 transitions the Analyst from a reactive reflex responder to a fully deliberative agent governed by the classical **Belief-Desire-Intention (BDI)** cognitive architecture, orchestrated via a compiled LangGraph workflow:

1. **Epistemic Separation of Mental States:**
   - **Beliefs (`BeliefBase`, `HostBelief`, `FleetBelief`):**
     [`src/sentryscan/bdi/beliefs.py`](../../src/sentryscan/bdi/beliefs.py): Represents validated environmental state—synthetic host telemetry, security posture, active findings, quarantine status, and resource budgets. The belief revision operator detects *material* belief changes (escalations to `HIGH` or `CRITICAL` severity).
   - **Desires (`Desire`, `DesireType`):**
     [`src/sentryscan/bdi/desires.py`](../../src/sentryscan/bdi/desires.py): Models ranked, context-sensitive operational goals:
     1. `CONTAIN_COMPROMISED_HOSTS` (Priority 100.0)
     2. `SURFACE_CRITICAL_FINDINGS` (Priority 80.0–90.0)
     3. `CONSERVE_BUDGET` (Priority 55.0–85.0)
     4. `AUDIT_ASSIGNED_HOSTS` (Priority 60.0)
     5. `MAINTAIN_AUDIT_TRAIL` (Priority 20.0)
     Desires dynamically evaluate their feasibility (`is_eligible()`) against current beliefs.
   - **Intentions (`Intention`, `IntentionStep`):**
     [`src/sentryscan/bdi/intentions.py`](../../src/sentryscan/bdi/intentions.py): Concrete, committed plans consisting of an ordered sequence of atomic operational steps (`QUARANTINE_HOST`, `SET_SCAN_CADENCE`, `SCHEDULE_PRIORITY_PORTS`, etc.) with explicit lifecycle states (`ACTIVE`, `COMPLETED`, `ABANDONED`).

2. **Deliberation and Intention Selection:**
   - [`src/sentryscan/bdi/deliberation.py`](../../src/sentryscan/bdi/deliberation.py): `BDIDeliberator` performs option generation, feasibility filtering, priority ranking, and intention synthesis.

3. **LangGraph Analyst Workflow & Reconsideration Loop:**
   - [`src/sentryscan/graphs/analyst_graph.py`](../../src/sentryscan/graphs/analyst_graph.py): Implements the BDI reasoning loop as a compiled StateGraph:
     $$\text{Perceive} \longrightarrow \text{Check Reconsideration} \overset{\text{replan}}{\underset{\text{continue}}{\rightrightarrows}} \begin{cases} \text{Deliberate \& Plan} \longrightarrow \text{Execute Step} \\ \text{Execute Step} \end{cases} \longrightarrow \text{END}$$
   - When a material belief update occurs (e.g. injected `CRITICAL` exploit on `sim-host-007`), the agent safely abandons the current intention with a logged rationale, adopts the emergency containment intention, and accelerates scan cadence to 50ms with host quarantine.

4. **Forensic Reconsideration Auditing:**
   - [`src/sentryscan/graphs/analyst_state.py`](../../src/sentryscan/graphs/analyst_state.py): Every intention transition or preemption emits a structured `ReconsiderationRecord` capturing before/after intention IDs, desire types, triggers, and timestamps.

---

## 2. Benchmark Evidence & Deliverables

- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **BDI State Transition Log:** [`evidence/bdi_transition_log.md`](evidence/bdi_transition_log.md)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **Nominal Telemetry:** Routine `INFO` and `LOW` findings advance the fleet audit intention without triggering replanning.
- **Injected Threat Preemption:** Injection of a `CRITICAL` finding on `sim-host-007` instantly triggers reconsideration, marking `intention-000001` as `ABANDONED` and adopting `intention-000002` (`CONTAIN_COMPROMISED_HOSTS`).
- **Autonomous Quarantine:** The agent emits a `PARAMS_UPDATE` with `quarantine_flag=True` and `scan_interval_ms=50`.
- **Post-Containment Progression:** Once `sim-host-007` is quarantined, the agent smoothly transitions to `SURFACE_CRITICAL_FINDINGS` for deep forensic triage.
- **Unit & Integration Suite:** 105 passed across all test suites with 0 warnings and 0 failures.

---

## 3. Reproduction Instructions

```bash
# Run deterministic BDI deliberative simulation
python demos/demo_assignment_4_1.py

# Run unit and integration tests
pytest -v tests/

# Verify code style and linter
ruff check .

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-4.1
```
