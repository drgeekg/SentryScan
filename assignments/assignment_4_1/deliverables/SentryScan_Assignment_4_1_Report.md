# SentryScan: Assignment 4.1 — Deliberative BDI Modelling & Reconsideration

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 4.1 — Deliberative BDI Modelling & Reconsideration  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/4.1-bdi-modelling`  
**Git Tag:** `assignment-4.1`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 4.1 implements the **Belief–Desire–Intention (BDI) cognitive architecture** (Bratman, 1987; Rao & Georgeff, 1995; Wooldridge, Ch. 4) for SentryScan's Analyst Agent.

### 1.1 The Classical BDI Paradigm
A pure reflex agent reacts instantly without commitment to long-term goals. A BDI agent deliberates and commits to intentions:
- **Beliefs ($B$):** The agent's knowledge about the operational environment (host states, open ports, observed vulnerabilities, active policies).
- **Desires ($D$):** The potential goals or operational states the agent wishes to achieve (audit fleet, contain compromised hosts, surface critical alerts).
- **Intentions ($I$):** The committed desires chosen for execution, organized into concrete procedural plans.

### 1.2 Intention Reconsideration & Epistemic Preemption
An agent cannot re-deliberate after every minor percept (computational waste), nor can it pursue a plan stubbornly when the environment has changed catastrophically:
- **Kinny & Georgeff (1991) Reconsideration Trade-off:** SentryScan implements *bold-agent deliberation* with explicit **material belief update filters**.
- **Deliberative Preemption:** Routine telemetry (e.g., informational banner) retains active plans. The arrival of a `CRITICAL` vulnerability finding triggers an immediate interrupt, cleanly abandoning obsolete intentions and adopting emergency containment.

---

## 2. Architecture & Implementation Specification

```
                  Percepts (Telemetry / Messages)
                                 │
                                 ▼
                     ┌──────────────────────┐
                     │ Update Belief Base   │
                     │    (BeliefBase)      │
                     └──────────┬───────────┘
                                │
                                ▼
                     ┌──────────────────────┐
            No       │ Material Change in   │
       ┌─────────────┤ Beliefs Detected?    │
       │             └──────────┬───────────┘
       │                        │ Yes
       ▼                        ▼
 ┌───────────┐       ┌──────────────────────┐
 │ Continue  │       │ Re-deliberate & Plan │
 │ Active    │       │ 1. Filter Desires    │
 │ Intention │       │ 2. Priority Argmax   │
 └───────────┘       │ 3. Synthesize Steps  │
                     └──────────┬───────────┘
                                │
                                ▼
                     ┌──────────────────────┐
                     │ Intention Transition │
                     │ Old: ABANDONED       │
                     │ New: ADOPTED         │
                     └──────────────────────┘
```

### 2.1 Concrete Desires & Intention Synthesis (`src/sentryscan/bdi/deliberation.py`)

| Desire Identifier | Eligibility Condition | Intention Plan Synthesized | Action Generated |
|---|---|---|---|
| `CONTAIN_COMPROMISED_HOSTS` | Active `CRITICAL` / `HIGH` finding on unquarantined host | 1. `QUARANTINE_HOST`<br>2. `SET_SCAN_CADENCE (50ms)`<br>3. `SCHEDULE_PRIORITY_PORTS` | `quarantine_flag=True`<br>`cadence=50ms` |
| `SURFACE_CRITICAL_FINDINGS` | Host quarantined; findings unacknowledged | 1. `PUBLISH_CRITICAL_ALERT`<br>2. `SET_SCAN_CADENCE (100ms)` | `cadence=100ms` |
| `AUDIT_ASSIGNED_HOSTS` | Baseline state; no critical alerts active | 1. `SET_SCAN_CADENCE (250ms)`<br>2. `DISPATCH_ROUTINE_PROBE` | `cadence=250ms` (Nominal) |

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. Distinct Beliefs, Desires, and Intentions** | `src/sentryscan/bdi/beliefs.py`, `src/sentryscan/bdi/desires.py`, `src/sentryscan/bdi/intentions.py`: Epistemic separation into `BeliefBase`, `Desire`, and `Intention` | `tests/unit/test_bdi_models.py`<br>`evidence/bdi_transition_log.md` | **PASSED** |
| **2. Deliberation & Option Selection** | `src/sentryscan/bdi/deliberation.py`: Option generation, feasibility filtering, and dynamic priority ranking selecting $d^* = \arg\max Priority(d)$ | `tests/unit/test_bdi_deliberation.py`<br>`demos/demo_assignment_4_1.py` Cycle 1 | **PASSED** |
| **3. Plan Synthesis & Intention Steps** | `src/sentryscan/bdi/deliberation.py`: Instantiates concrete ordered steps (`QUARANTINE_HOST`, `SET_SCAN_CADENCE`, etc.) with status tracking | `tests/unit/test_bdi_deliberation.py`<br>`evidence/bdi_transition_log.md` | **PASSED** |
| **4. LangGraph Deliberative Workflow** | `src/sentryscan/graphs/analyst_graph.py`: Compiled LangGraph orchestrating `perceive` $	o$ `check_reconsideration` $	o$ `deliberate_and_plan` $	o$ `execute_step` | `tests/unit/test_analyst_graph.py`<br>`src/sentryscan/agents/analyst.py` | **PASSED** |
| **5. Material Reconsideration Trigger** | `src/sentryscan/graphs/analyst_graph.py`: Detects escalations to `CRITICAL`/`HIGH` severity and triggers intentional preemption | `tests/integration/test_bdi_reconsideration.py`<br>`demos/demo_assignment_4_1.py` Cycle 3 | **PASSED** |
| **6. Clean Intention Abandonment & Transition** | Previous intention `intention-000001` cleanly transitioned to `ABANDONED` with recorded rationale rather than silent overwriting | `tests/integration/test_bdi_reconsideration.py`<br>`evidence/bdi_transition_log.md` Cycle 3 | **PASSED** |
| **7. Emergency Containment Execution** | Autonomous quarantine flag (`quarantine_flag=True`) and high-frequency sampling (`50ms`) emitted via `PARAMS_UPDATE` message | `tests/unit/test_analyst.py`<br>`demos/demo_assignment_4_1.py` Cycle 3 | **PASSED** |
| **8. Post-Containment Intention Shift** | Following host quarantine, agent autonomously transitions from `CONTAIN_COMPROMISED_HOSTS` to `SURFACE_CRITICAL_FINDINGS` | `evidence/bdi_transition_log.md` Cycle 4 | **PASSED** |
| **9. Trace & Single-Writer Auditing** | Sequential event log recording message reception, state transitions, and generated parameter adaptations via `src/sentryscan/observability/recorder.py` | `evidence/trace_excerpt.jsonl` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 BDI State Transition & Reconsideration Log (`evidence/bdi_transition_log.md`)

| Cycle | Trigger | Target Host | Severity | Old Intention | New Intention | Reason | Generated Action |
|---|---|---|---|---|---|---|---|
| **1 (Init)** | `INITIAL_DELIBERATION` | `192.0.2.10` | `INFO` | None | `intention-000001` (AUDIT) | Initial boot | `NOMINAL (250ms)` |
| **2 (Routine)** | `ROUTINE_TELEMETRY` | `192.0.2.20` | `LOW` | `intention-000001` | Retained (No Change) | Non-material | `NOMINAL (500ms)` |
| **3 (Preempt)** | `MATERIAL_BELIEF_UPDATE` | `sim-host-007` | **`CRITICAL`** | `intention-000001` [ABANDONED] | `intention-000002` (CONTAIN) | Critical alert on host | `QUARANTINE=True (50ms)` |
| **4 (Shift)** | `CONTAINMENT_SATISFIED` | `sim-host-007` | `CRITICAL (Quar)`| `intention-000002` [SUCCEEDED] | `intention-000003` (SURFACE) | Containment satisfied | `DEEP_INSPECT (100ms)` |

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_4_1/deliverables/SentryScan_Assignment_4_1_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/4.1-bdi-modelling`
4. **Immutable Git Tag:** `assignment-4.1`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_4_1.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_4_1.zip.sha256`

### 5.2 Verification Commands
```bash
# Run BDI deliberation demonstration
python demos/demo_assignment_4_1.py

# Execute BDI unit and integration tests
pytest -v tests/unit/test_bdi_models.py tests/unit/test_bdi_deliberation.py tests/integration/test_bdi_reconsideration.py
```
