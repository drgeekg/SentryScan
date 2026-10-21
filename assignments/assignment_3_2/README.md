# Assignment 3.2 — Multi-Attribute Utility Optimization & Infeasibility Filtering

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-3.2`  

---

## 1. Architectural Increment Overview

Assignment 3.2 implements the formal multi-attribute utility optimization engine for evaluating, filtering, and selecting optimal candidate execution plans during multi-agent task allocation:

1. **Normalized Multi-Attribute Utility Formula:**
   - [`src/sentryscan/optimizer/formula.py`](../../src/sentryscan/optimizer/formula.py): Implements the transparent objective function:
     $$U(o) = w_1\,\bar{C}_{severity}(o) + w_2\,\bar{C}_{hosts}(o) - w_3\,\overline{Cost}(o) - w_4\,\overline{Time}(o) - w_5\,\overline{Risk}(o)$$
     where each attribute is normalized to $[0, 1]$ relative to configurable bounds. Zero-range denominators and non-finite numbers (NaN/Inf) are handled safely.
2. **Configurable & Validated Weights:**
   - [`src/sentryscan/optimizer/weights.py`](../../src/sentryscan/optimizer/weights.py): `UtilityWeights` model enforcing $\sum w_i = 1.0$ and $w_i \ge 0$. Provides verified presets for `default_balanced`, `risk_first`, and `coverage_first` operational postures.
3. **Hard Constraint Filtering & Argmax Selection:**
   - [`src/sentryscan/optimizer/engine.py`](../../src/sentryscan/optimizer/engine.py): `PlanOptimizer` isolates candidates violating hard budget or latency bounds ($Cost > MaxCost$, $Time > MaxTime$, empty batch list) with explicit rejection reasons, returning:
     $$o^{*} = \arg\max_{o \in O_{feasible}} U(o)$$
     Deterministic tie-breaking resolves identical scores by severity coverage, host coverage, cost, and alphabetical plan ID.
4. **Seamless Seam Replacement:**
   - [`src/sentryscan/negotiation/scoring.py`](../../src/sentryscan/negotiation/scoring.py): In `refactor(a3.2)`, the temporary inline `score_bid()` heuristic from Milestone 3.1 was replaced with `PlanOptimizer` behind the exact same function signature, preserving 100% backwards compatibility with zero changes to existing tests.
5. **Independent Exhaustive Verification:**
   - [`tests/unit/test_optimizer_brute_force.py`](../../tests/unit/test_optimizer_brute_force.py): An independent brute-force algorithm tests 20 randomly and deterministically generated candidates, confirming that `PlanOptimizer` finds the true mathematical maximum in 100% of cases.

---

## 2. Benchmark Evidence & Deliverables

Demonstration artifacts generated from execution:
- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Ten-Candidate Comparison Table:** [`evidence/candidate_comparison_table.md`](evidence/candidate_comparison_table.md)
- **Weight Sensitivity Report (JSON):** [`evidence/weight_sensitivity_report.json`](evidence/weight_sensitivity_report.json)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **10-Candidate Optimization:** Evaluated 10 distinct candidate plans under $Cost \le 50.0, Time \le 400.0$ ms. Plans `plan-06` (cost exceeded), `plan-07` (time exceeded), and `plan-08` (empty batch) were rejected as infeasible ($-\infty$).
- **Winner Selection:** `plan-04-balanced-opt` was selected as the optimal plan ($U(o) = +0.4365$).
- **Exhaustive Parity:** 100% match between `PlanOptimizer` and independent manual exhaustive search.
- **Weight Sensitivity Shift:** Proved that under cost-constrained weights ($w_{cost}=0.50$), the winner shifted from `plan-04` to `plan-10-high-risk-lean` ($U(o) = +0.0580$).
- **Unit & Integration Tests:** 80 passed across all test suites (`test_optimizer_formula`, `test_optimizer_engine`, `test_optimizer_edge_cases`, `test_optimizer_brute_force`, `test_negotiation`, `test_multi_agent_coordination`).

---

## 3. Reproduction Instructions

```bash
# Run deterministic utility optimization demonstration
python demos/demo_assignment_3_2.py

# Run unit and integration tests
pytest -v tests/

# Verify code style and linter
ruff check .

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-3.2
```
