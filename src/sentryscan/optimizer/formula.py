"""Normalized multi-attribute utility calculation formula."""

from __future__ import annotations

import math

from pydantic import BaseModel, Field

from sentryscan.optimizer.weights import UtilityWeights


class CandidatePlan(BaseModel):
    """Candidate execution plan representing an allocation option."""

    plan_id: str = Field(..., description="Unique plan identifier")
    proposer: str = Field(default="", description="Originating agent identity")
    batch_ids: list[str] = Field(default_factory=list, description="Target batch IDs")
    severity_coverage: float = Field(..., ge=0.0, description="Severity coverage score")
    host_coverage: float = Field(..., ge=0.0, description="Host coverage score")
    cost: float = Field(..., ge=0.0, description="Estimated execution cost")
    time_ms: float = Field(..., ge=0.0, description="Estimated execution latency in ms")
    risk: float = Field(..., ge=0.0, le=1.0, description="Estimated residual risk [0, 1]")


class EvaluationScore(BaseModel):
    """Structured breakdown of normalized utility evaluation for a candidate plan."""

    plan_id: str
    utility_score: float
    norm_severity: float
    norm_hosts: float
    norm_cost: float
    norm_time: float
    norm_risk: float


def normalize_value(val: float, min_val: float, max_val: float) -> float:
    """Normalize a value to [0, 1] range, handling zero-range safely."""
    if math.isnan(val) or math.isinf(val):
        raise ValueError(f"Invalid non-finite value in normalization: {val}")
    if max_val <= min_val:
        return 0.0
    norm = (val - min_val) / (max_val - min_val)
    return max(0.0, min(1.0, norm))


def compute_utility(
    plan: CandidatePlan,
    weights: UtilityWeights,
    bounds: dict[str, tuple[float, float]] | None = None,
) -> EvaluationScore:
    """Compute the multi-attribute utility score for a candidate plan.

    Formula:
        U(o) = w_1 * C_sev + w_2 * C_hosts - w_3 * Cost - w_4 * Time - w_5 * Risk
    """
    b = bounds or {}

    sev_min, sev_max = b.get("severity", (0.0, 1.0))
    host_min, host_max = b.get("hosts", (0.0, 1.0))
    cost_min, cost_max = b.get("cost", (0.0, 100.0))
    time_min, time_max = b.get("time", (0.0, 1000.0))

    norm_sev = normalize_value(plan.severity_coverage, sev_min, sev_max)
    norm_hosts = normalize_value(plan.host_coverage, host_min, host_max)
    norm_cost = normalize_value(plan.cost, cost_min, cost_max)
    norm_time = normalize_value(plan.time_ms, time_min, time_max)
    norm_risk = max(0.0, min(1.0, plan.risk))

    utility = (
        weights.w_severity * norm_sev
        + weights.w_hosts * norm_hosts
        - weights.w_cost * norm_cost
        - weights.w_time * norm_time
        - weights.w_risk * norm_risk
    )

    return EvaluationScore(
        plan_id=plan.plan_id,
        utility_score=round(utility, 4),
        norm_severity=round(norm_sev, 4),
        norm_hosts=round(norm_hosts, 4),
        norm_cost=round(norm_cost, 4),
        norm_time=round(norm_time, 4),
        norm_risk=round(norm_risk, 4),
    )
