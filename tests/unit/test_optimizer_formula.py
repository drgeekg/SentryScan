"""Unit tests for the multi-attribute utility formula and weight validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentryscan.optimizer.formula import CandidatePlan, compute_utility, normalize_value
from sentryscan.optimizer.weights import UtilityWeights


def test_utility_weights_validation():
    # Valid default weights
    w = UtilityWeights.default()
    assert round(w.w_severity + w.w_hosts + w.w_cost + w.w_time + w.w_risk, 2) == 1.0

    # Invalid weights sum
    with pytest.raises(ValidationError):
        UtilityWeights(w_severity=0.5, w_hosts=0.5, w_cost=0.5, w_time=0.5, w_risk=0.5)


def test_normalize_value():
    assert normalize_value(50, 0, 100) == 0.5
    assert normalize_value(0, 0, 100) == 0.0
    assert normalize_value(100, 0, 100) == 1.0
    # Values beyond bounds are clamped
    assert normalize_value(150, 0, 100) == 1.0
    assert normalize_value(-20, 0, 100) == 0.0
    # Zero-range safe handling
    assert normalize_value(10, 10, 10) == 0.0


def test_compute_utility_breakdown():
    weights = UtilityWeights(
        w_severity=0.4, w_hosts=0.3, w_cost=0.1, w_time=0.1, w_risk=0.1
    )
    plan = CandidatePlan(
        plan_id="plan-01",
        severity_coverage=0.9,
        host_coverage=0.8,
        cost=20.0,
        time_ms=100.0,
        risk=0.05,
    )
    score = compute_utility(
        plan,
        weights,
        bounds={"cost": (0.0, 100.0), "time": (0.0, 500.0)},
    )

    assert score.plan_id == "plan-01"
    assert score.norm_severity == 0.9
    assert score.norm_hosts == 0.8
    assert score.norm_cost == 0.2
    assert score.norm_time == 0.2
    assert score.norm_risk == 0.05

    # Expected: 0.4*0.9 + 0.3*0.8 - 0.1*0.2 - 0.1*0.2 - 0.1*0.05
    # = 0.36 + 0.24 - 0.02 - 0.02 - 0.005 = 0.555
    assert score.utility_score == 0.555
