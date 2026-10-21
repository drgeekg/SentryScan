# Assignment 3.1 — Rubric to Evidence Mapping

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** Assignment 3.1 (Multi-Agent Coordination & Negotiation)  
**Date:** 2026-10-21  

---

## Evaluation Criteria & Implementation Evidence

| Rubric Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|---|
| **1. LangGraph Supervisor Workflow** | [`src/sentryscan/graphs/supervisor.py`](../../src/sentryscan/graphs/supervisor.py): `StateGraph(SupervisorState)` with negotiation, worker fan-out, and result aggregation | [`tests/unit/test_supervisor_graph.py`](../../tests/unit/test_supervisor_graph.py), [`demos/demo_assignment_3_1.py`](../../demos/demo_assignment_3_1.py) Step 2 | **PASSED** |
| **2. Role Separation (Scout vs. Triage)** | [`src/sentryscan/agents/scout.py`](../../src/sentryscan/agents/scout.py) (coverage-maximizing) and [`src/sentryscan/agents/triage.py`](../../src/sentryscan/agents/triage.py) (risk-prioritizing) | [`tests/unit/test_proposal_roles.py`](../../tests/unit/test_proposal_roles.py), [`evidence/negotiation_timeline.md`](evidence/negotiation_timeline.md) | **PASSED** |
| **3. Contract-Net Negotiation Protocol** | [`src/sentryscan/negotiation/protocol.py`](../../src/sentryscan/negotiation/protocol.py): `CFP` $\to$ `PROPOSE` $\to$ `COUNTERPROPOSE` $\to$ `ACCEPT` / `REJECT` $\to$ `CONFIRM` | [`evidence/negotiation_timeline.md`](evidence/negotiation_timeline.md), [`tests/unit/test_negotiation.py`](../../tests/unit/test_negotiation.py) | **PASSED** |
| **4. Inline Bid Scoring Seam (`score_bid`)** | [`src/sentryscan/negotiation/scoring.py`](../../src/sentryscan/negotiation/scoring.py): Objective formula over normalized coverage, cost, time, and risk with hard constraint filtering ($-\infty$) | [`tests/unit/test_negotiation.py`](../../tests/unit/test_negotiation.py) (`test_score_bid_valid`, `test_score_bid_constraint_violations`) | **PASSED** |
| **5. Dynamic Runtime Fan-Out via `Send`** | [`src/sentryscan/graphs/supervisor.py`](../../src/sentryscan/graphs/supervisor.py): Returns `[Send("scanner_worker", ...)]` dynamically dispatching parallel worker instances per awarded batch | [`tests/unit/test_supervisor_graph.py`](../../tests/unit/test_supervisor_graph.py), [`evidence/run_log.txt`](evidence/run_log.txt) Step 2 | **PASSED** |
| **6. Provider-Neutral Advisory LLM Layer** | [`src/sentryscan/llm/`](../../src/sentryscan/llm/): `LLMProvider` protocol with `DeterministicLLMProvider` (offline template generation) and `FakeLLMProvider` | [`tests/unit/test_llm.py`](../../tests/unit/test_llm.py), [`tests/integration/test_multi_agent_coordination.py`](../../tests/integration/test_multi_agent_coordination.py) (`test_llm_advisory_non_authoritative`) | **PASSED** |
| **7. Bounded Loop & `UNRESOLVED` Termination** | Hard limit (default: 5 rounds) terminating safely in `UNRESOLVED` when constraints cannot be satisfied | [`tests/unit/test_negotiation.py`](../../tests/unit/test_negotiation.py) (`test_negotiation_unresolved_after_max_rounds`), `demo_assignment_3_1.py` Step 3 | **PASSED** |
| **8. Determinism Contract (LLM Off)** | Deterministic single-threaded execution ensures 0 drift across runs with LLM off or deterministic provider | [`tests/integration/test_multi_agent_coordination.py`](../../tests/integration/test_multi_agent_coordination.py) (`test_trace_identical_with_llm_off`) | **PASSED** |
| **9. Trace Persistence & Single-Writer Auditing** | Sequential JSONL event log capturing every message, proposal, and finding via [`src/sentryscan/observability/recorder.py`](../../src/sentryscan/observability/recorder.py) | [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl) | **PASSED** |
