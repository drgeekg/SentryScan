"""Edge case, tie-breaking, invalid input, and weight sensitivity tests for PlanOptimizer."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentryscan.optimizer.engine import PlanOptimizer
from sentryscan.optimizer.formula import CandidatePlan, normalize_value
from sentryscan.optimizer.weights import UtilityWeights


def test_empty_candidate_list():
    optimizer = PlanOptimizer()
    result = optimizer.optimize([], constraints={"max_cost": 50.0, "max_time": 200.0})
    assert result.status == "NO_FEASIBLE_OPTION"
    assert result.winner is None
    assert len(result.evaluated_scores) == 0


def test_invalid_negative_numbers_rejected_by_model():
    with pytest.raises(ValidationError):
        CandidatePlan(
            plan_id="plan-bad",
            severity_coverage=-0.5,  # Negative coverage prohibited
            host_coverage=0.5,
            cost=10.0,
            time_ms=50.0,
            risk=0.1,
        )

    with pytest.raises(ValidationError):
        CandidatePlan(
            plan_id="plan-bad-cost",
            severity_coverage=0.5,
            host_coverage=0.5,
            cost=-5.0,  # Negative cost prohibited
            time_ms=50.0,
            risk=0.1,
        )


def test_zero_range_normalization_no_division_by_zero():
    # When min == max
    assert normalize_value(50.0, 50.0, 50.0) == 0.0
    assert normalize_value(100.0, 100.0, 100.0) == 0.0


def test_non_finite_normalization_rejected():
    with pytest.raises(ValueError, match="Invalid non-finite"):
        normalize_value(float("nan"), 0.0, 100.0)
    with pytest.raises(ValueError, match="Invalid non-finite"):
        normalize_value(float("inf"), 0.0, 100.0)


def test_deterministic_tie_breaking():
    optimizer = PlanOptimizer(weights=UtilityWeights.default())

    # Two plans producing identical scores, but plan A has higher severity coverage
    c1 = CandidatePlan(
        plan_id="plan-tie-A",
        batch_ids=["b1"],
        severity_coverage=0.8,
        host_coverage=0.5,
        cost=20.0,
        time_ms=100.0,
        risk=0.1,
    )
    c2 = CandidatePlan(
        plan_id="plan-tie-B",
        batch_ids=["b2"],
        severity_coverage=0.8,
        host_coverage=0.5,
        cost=20.0,
        time_ms=100.0,
        risk=0.1,
    )

    result = optimizer.optimize([c2, c1], constraints={"max_cost": 50.0, "max_time": 200.0})
    assert result.status == "OPTIMAL_FOUND"
    assert result.winner is not None
    # Tie broken deterministically by plan_id alphabetically: plan-tie-A
    assert result.winner.plan_id == "plan-tie-A"


def test_weight_sensitivity_winner_shift():
    # Plan A: High risk / severity coverage, but higher cost
    plan_a = CandidatePlan(
        plan_id="plan-high-risk-high-cost",
        batch_ids=["b1", "b2"],
        severity_coverage=0.95,
        host_coverage=0.90,
        cost=70.0,
        time_ms=250.0,
        risk=0.05,
    )

    # Plan B: Moderate coverage, very low cost
    plan_b = CandidatePlan(
        plan_id="plan-low-cost-mod-coverage",
        batch_ids=["b3"],
        severity_coverage=0.60,
        host_coverage=0.55,
        cost=15.0,
        time_ms=60.0,
        risk=0.15,
    )

    constraints = {"max_cost": 100.0, "max_time": 500.0}

    # Under risk_first weighting (w_severity=0.55, w_cost=0.10): Plan A should win
    opt_risk = PlanOptimizer(weights=UtilityWeights.risk_first())
    res_risk = opt_risk.optimize([plan_a, plan_b], constraints)
    assert res_risk.winner is not None
    assert res_risk.winner.plan_id == "plan-high-risk-high-cost"

    # Under cost-sensitive weighting: w_cost=0.50, w_severity=0.15, w_hosts=0.15
    cost_weights = UtilityWeights(
        w_severity=0.15,
        w_hosts=0.15,
        w_cost=0.50,
        w_time=0.10,
        w_risk=0.10,
    )
    opt_cost = PlanOptimizer(weights=cost_weights)
    res_cost = opt_cost.optimize([plan_a, plan_b], constraints)
    assert res_cost.winner is not None
    assert res_cost.winner.plan_id == "plan-low-cost-mod-coverage"
