# Assignment 4.1 — Rubric to Evidence Mapping

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** Assignment 4.1 (BDI Deliberative Modeling & Reconsideration)  
**Date:** 2026-10-21  

---

## Evaluation Criteria & Implementation Evidence

| Rubric Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|---|
| **1. Distinct Beliefs, Desires, and Intentions** | [`src/sentryscan/bdi/beliefs.py`](../../src/sentryscan/bdi/beliefs.py), [`src/sentryscan/bdi/desires.py`](../../src/sentryscan/bdi/desires.py), [`src/sentryscan/bdi/intentions.py`](../../src/sentryscan/bdi/intentions.py): Epistemic separation into `BeliefBase`, `Desire`, and `Intention` | [`tests/unit/test_bdi_models.py`](../../tests/unit/test_bdi_models.py), [`assignments/assignment_4_1/evidence/bdi_transition_log.md`](evidence/bdi_transition_log.md) | **PASSED** |
| **2. Deliberation & Option Selection** | [`src/sentryscan/bdi/deliberation.py`](../../src/sentryscan/bdi/deliberation.py): Option generation, feasibility filtering, and dynamic priority ranking selecting $d^* = \arg\max_{d \in D_{elig}} Priority(d)$ | [`tests/unit/test_bdi_deliberation.py`](../../tests/unit/test_bdi_deliberation.py), [`demos/demo_assignment_4_1.py`](../../demos/demo_assignment_4_1.py) Cycle 1 | **PASSED** |
| **3. Plan Synthesis & Intention Steps** | [`src/sentryscan/bdi/deliberation.py`](../../src/sentryscan/bdi/deliberation.py): Instantiates concrete ordered steps (`QUARANTINE_HOST`, `SET_SCAN_CADENCE`, `SCHEDULE_PRIORITY_PORTS`) with status tracking | [`tests/unit/test_bdi_deliberation.py`](../../tests/unit/test_bdi_deliberation.py), [`evidence/bdi_transition_log.md`](evidence/bdi_transition_log.md) | **PASSED** |
| **4. LangGraph Deliberative Workflow** | [`src/sentryscan/graphs/analyst_graph.py`](../../src/sentryscan/graphs/analyst_graph.py): Compiled LangGraph orchestrating `perceive` $\to$ `check_reconsideration` $\to$ `deliberate_and_plan` $\to$ `execute_step` | [`tests/unit/test_analyst_graph.py`](../../tests/unit/test_analyst_graph.py), [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py) | **PASSED** |
| **5. Material Reconsideration Trigger** | [`src/sentryscan/graphs/analyst_graph.py`](../../src/sentryscan/graphs/analyst_graph.py): Detects escalations to `CRITICAL`/`HIGH` severity and triggers intentional preemption | [`tests/integration/test_bdi_reconsideration.py`](../../tests/integration/test_bdi_reconsideration.py), [`demos/demo_assignment_4_1.py`](../../demos/demo_assignment_4_1.py) Cycle 3 | **PASSED** |
| **6. Clean Intention Abandonment & Transition** | Previous intention `intention-000001` cleanly transitioned to `ABANDONED` with recorded rationale rather than silent overwriting | [`tests/integration/test_bdi_reconsideration.py`](../../tests/integration/test_bdi_reconsideration.py), [`evidence/bdi_transition_log.md`](evidence/bdi_transition_log.md) Cycle 3 | **PASSED** |
| **7. Emergency Containment Execution** | Autonomous quarantine flag (`quarantine_flag=True`) and high-frequency sampling (`50ms`) emitted via `PARAMS_UPDATE` message | [`tests/unit/test_analyst.py`](../../tests/unit/test_analyst.py), [`demos/demo_assignment_4_1.py`](../../demos/demo_assignment_4_1.py) Cycle 3 | **PASSED** |
| **8. Post-Containment Intention Shift** | Following host quarantine, agent autonomously transitions from `CONTAIN_COMPROMISED_HOSTS` to `SURFACE_CRITICAL_FINDINGS` | [`evidence/bdi_transition_log.md`](evidence/bdi_transition_log.md) Cycle 4 | **PASSED** |
| **9. Trace & Single-Writer Auditing** | Sequential event log recording message reception, state transitions, and generated parameter adaptations via [`src/sentryscan/observability/recorder.py`](../../src/sentryscan/observability/recorder.py) | [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl) | **PASSED** |
