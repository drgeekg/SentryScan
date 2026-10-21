# Assignment 3.2 — Rubric to Evidence Mapping

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** Assignment 3.2 (Multi-Attribute Utility Optimization & Infeasibility Filtering)  
**Date:** 2026-10-21  

---

## Evaluation Criteria & Implementation Evidence

| Rubric Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|---|
| **1. Normalized Multi-Attribute Utility Function** | [`src/sentryscan/optimizer/formula.py`](../../src/sentryscan/optimizer/formula.py): Implements $U(o) = w_1\bar{C}_{sev} + w_2\bar{C}_{hosts} - w_3\overline{Cost} - w_4\overline{Time} - w_5\overline{Risk}$ with bounded $[0, 1]$ normalization | [`tests/unit/test_optimizer_formula.py`](../../tests/unit/test_optimizer_formula.py), [`evidence/candidate_comparison_table.md`](evidence/candidate_comparison_table.md) | **PASSED** |
| **2. Validated Weight Profiles** | [`src/sentryscan/optimizer/weights.py`](../../src/sentryscan/optimizer/weights.py): `UtilityWeights` model with $\sum w_i = 1.0$ validation, non-negativity constraint, and posture presets (`default_balanced`, `risk_first`, `coverage_first`) | [`tests/unit/test_optimizer_formula.py`](../../tests/unit/test_optimizer_formula.py), [`evidence/weight_sensitivity_report.json`](evidence/weight_sensitivity_report.json) | **PASSED** |
| **3. Hard Constraint & Infeasibility Filtering** | [`src/sentryscan/optimizer/engine.py`](../../src/sentryscan/optimizer/engine.py): Strict isolation of invalid candidates (exceeding budget/latency bounds or empty plan batches) with explicit rejection reasons and $-\infty$ utility assignment | [`tests/unit/test_optimizer_engine.py`](../../tests/unit/test_optimizer_engine.py), [`evidence/candidate_comparison_table.md`](evidence/candidate_comparison_table.md) | **PASSED** |
| **4. Feasible Argmax Selection & Deterministic Ties** | [`src/sentryscan/optimizer/engine.py`](../../src/sentryscan/optimizer/engine.py): Selection of $o^* = \arg\max_{o \in O_{feas}} U(o)$ with deterministic tie-breaking by severity, coverage, cost, and plan ID | [`tests/unit/test_optimizer_engine.py`](../../tests/unit/test_optimizer_engine.py), [`demos/demo_assignment_3_2.py`](../../demos/demo_assignment_3_2.py) Step 1 | **PASSED** |
| **5. Robust Edge & Boundary Handling** | Safe handling of empty candidate sets, zero-range attribute spans, non-finite values (NaN, Inf), and all-infeasible candidate pools without crashes | [`tests/unit/test_optimizer_edge_cases.py`](../../tests/unit/test_optimizer_edge_cases.py) | **PASSED** |
| **6. Verification Against Independent Exhaustive Search** | Exhaustive baseline verification checking 100% mathematical parity against independent brute-force evaluation over diverse candidate sets | [`tests/unit/test_optimizer_brute_force.py`](../../tests/unit/test_optimizer_brute_force.py), [`evidence/run_log.txt`](evidence/run_log.txt) Step 2 | **PASSED** |
| **7. Negotiation Seam Integration (`score_bid`)** | Seamless refactoring of [`src/sentryscan/negotiation/scoring.py`](../../src/sentryscan/negotiation/scoring.py) to delegate to `PlanOptimizer` preserving 100% backward compatibility | [`tests/unit/test_negotiation.py`](../../tests/unit/test_negotiation.py), [`tests/integration/test_multi_agent_coordination.py`](../../tests/integration/test_multi_agent_coordination.py) | **PASSED** |
| **8. Multi-Scenario Weight Sensitivity Analysis** | Demonstrating rank-order and winner shifts across operational postures (balanced, risk-first, coverage-first, cost-constrained) | [`evidence/weight_sensitivity_report.json`](evidence/weight_sensitivity_report.json), [`demos/demo_assignment_3_2.py`](../../demos/demo_assignment_3_2.py) Step 3 | **PASSED** |
| **9. Trace & Single-Writer Auditing** | Sequential event log recording optimization requests, candidate scoring, and winner selection via [`src/sentryscan/observability/recorder.py`](../../src/sentryscan/observability/recorder.py) | [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl) | **PASSED** |
