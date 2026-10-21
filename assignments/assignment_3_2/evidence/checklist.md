# Assignment 3.2 Acceptance Checklist

- [x] Normalized utility equation implemented in `src/sentryscan/optimizer/formula.py` with bounded $[0, 1]$ attribute normalization:
  $$U(o) = w_1\bar{C}_{sev} + w_2\bar{C}_{hosts} - w_3\overline{Cost} - w_4\overline{Time} - w_5\overline{Risk}$$
- [x] Configurable and validated weight vectors implemented in `src/sentryscan/optimizer/weights.py` (`UtilityWeights`) enforcing $\sum w_i = 1.0$ and non-negativity.
- [x] Hard constraint filtering implemented in `src/sentryscan/optimizer/engine.py` isolating infeasible candidates violating budget, latency, or host criteria.
- [x] Feasible argmax selector implemented with deterministic tie-breaking.
- [x] Edge case handling verified for empty candidate sets, zero-range denominators, non-finite values (NaN, Inf), and all-infeasible candidate pools.
- [x] Verification against independent exhaustive search implemented in `tests/unit/test_optimizer_brute_force.py` with 100% mathematical parity.
- [x] Seamless refactoring of `score_bid()` in `src/sentryscan/negotiation/scoring.py` to route through `PlanOptimizer` preserving 100% backward compatibility.
- [x] Ten candidate plans scored and reported with detailed feasibility criteria in `evidence/candidate_comparison_table.md`.
- [x] Weight sensitivity report generated demonstrating winner shifts under operational trade-offs in `evidence/weight_sensitivity_report.json`.
- [x] Reproduction demo script implemented in `demos/demo_assignment_3_2.py` and run log captured in `evidence/run_log.txt`.
- [x] Single-writer trace recorded in `evidence/trace_excerpt.jsonl`.
- [x] All 80 unit and integration tests pass cleanly with 0 failures and 0 warnings.
- [x] Ruff lint checks pass cleanly with 0 errors across entire repository.
