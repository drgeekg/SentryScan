"""Unit tests for the PlanOptimizer filtering and argmax selection."""

from __future__ import annotations

from sentryscan.optimizer.engine import PlanOptimizer
from sentryscan.optimizer.formula import CandidatePlan
from sentryscan.optimizer.weights import UtilityWeights


def test_optimizer_selects_feasible_argmax():
    optimizer = PlanOptimizer(weights=UtilityWeights.default())

    c1 = CandidatePlan(
        plan_id="plan-low-cost",
        batch_ids=["b1"],
        severity_coverage=0.4,
        host_coverage=0.5,
        cost=10.0,
        time_ms=50.0,
        risk=0.2,
    )
    c2 = CandidatePlan(
        plan_id="plan-balanced",
        batch_ids=["b1", "b2"],
        severity_coverage=0.85,
        host_coverage=0.8,
        cost=25.0,
        time_ms=120.0,
        risk=0.08,
    )
    c3 = CandidatePlan(
        plan_id="plan-infeasible-cost",
        batch_ids=["b1", "b2", "b3"],
        severity_coverage=0.95,
        host_coverage=0.95,
        cost=85.0,  # Exceeds constraint 50.0
        time_ms=200.0,
        risk=0.05,
    )

    constraints = {"max_cost": 50.0, "max_time": 300.0}
    result = optimizer.optimize([c1, c2, c3], constraints)

    assert result.status == "OPTIMAL_FOUND"
    assert result.winner is not None
    # c3 is filtered out for exceeding max_cost 50.0
    assert "plan-infeasible-cost" in result.infeasible_reasons
    assert result.winner.plan_id == "plan-balanced"
    assert result.best_score is not None
    assert result.best_score.plan_id == "plan-balanced"


def test_optimizer_all_infeasible():
    optimizer = PlanOptimizer()
    c1 = CandidatePlan(
        plan_id="plan-too-expensive",
        batch_ids=["b1"],
        severity_coverage=0.5,
        host_coverage=0.5,
        cost=100.0,
        time_ms=50.0,
        risk=0.1,
    )
    result = optimizer.optimize([c1], constraints={"max_cost": 10.0, "max_time": 100.0})

    assert result.status == "NO_FEASIBLE_OPTION"
    assert result.winner is None
    assert result.best_score is None
    assert "plan-too-expensive" in result.infeasible_reasons
