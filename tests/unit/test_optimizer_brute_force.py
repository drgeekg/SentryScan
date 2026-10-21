"""Independent brute-force verification proving optimizer optimality."""

from __future__ import annotations

import random

from sentryscan.optimizer.engine import PlanOptimizer
from sentryscan.optimizer.formula import CandidatePlan
from sentryscan.optimizer.weights import UtilityWeights


def _independent_brute_force(
    candidates: list[CandidatePlan],
    weights: UtilityWeights,
    max_cost: float,
    max_time: float,
    cost_bounds: tuple[float, float] = (0.0, 100.0),
    time_bounds: tuple[float, float] = (0.0, 1000.0),
) -> tuple[str | None, float | None]:
    """Independent exhaustive search through candidates."""
    best_plan_id = None
    best_utility = -float("inf")

    c_min, c_max = cost_bounds
    t_min, t_max = time_bounds

    for plan in candidates:
        # Check hard feasibility constraints
        if not plan.batch_ids or plan.cost > max_cost or plan.time_ms > max_time:
            continue

        # Independent manual normalization
        norm_sev = plan.severity_coverage
        norm_hosts = plan.host_coverage
        norm_cost = (plan.cost - c_min) / (c_max - c_min)
        norm_time = (plan.time_ms - t_min) / (t_max - t_min)
        norm_risk = plan.risk

        # Objective formula
        u = (
            weights.w_severity * norm_sev
            + weights.w_hosts * norm_hosts
            - weights.w_cost * norm_cost
            - weights.w_time * norm_time
            - weights.w_risk * norm_risk
        )
        u = round(u, 4)

        if u > best_utility:
            best_utility = u
            best_plan_id = plan.plan_id

    return best_plan_id, (best_utility if best_plan_id else None)


def test_optimizer_matches_exhaustive_search():
    rng = random.Random(42)
    candidates: list[CandidatePlan] = []

    # Generate 20 diverse candidate plans
    for i in range(1, 21):
        candidates.append(
            CandidatePlan(
                plan_id=f"cand-{i:02d}",
                batch_ids=[f"batch-{i}"],
                severity_coverage=round(rng.uniform(0.1, 1.0), 2),
                host_coverage=round(rng.uniform(0.1, 1.0), 2),
                cost=round(rng.uniform(5.0, 80.0), 1),
                time_ms=round(rng.uniform(40.0, 600.0), 1),
                risk=round(rng.uniform(0.02, 0.30), 2),
            )
        )

    constraints = {"max_cost": 50.0, "max_time": 400.0}
    weights = UtilityWeights.default()

    # 1. Run independent brute force
    bf_winner, bf_score = _independent_brute_force(
        candidates,
        weights,
        max_cost=50.0,
        max_time=400.0,
    )

    # 2. Run production PlanOptimizer
    optimizer = PlanOptimizer(weights=weights)
    opt_result = optimizer.optimize(candidates, constraints)

    assert opt_result.status == "OPTIMAL_FOUND"
    assert opt_result.winner is not None
    assert opt_result.best_score is not None

    # 3. Assert mathematical equality
    assert opt_result.winner.plan_id == bf_winner
    assert opt_result.best_score.utility_score == bf_score
