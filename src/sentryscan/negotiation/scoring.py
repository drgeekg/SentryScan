"""Scoring seam delegating proposal evaluation to the PlanOptimizer engine."""

from __future__ import annotations

from typing import Any

from sentryscan.contracts.proposal import Proposal
from sentryscan.optimizer.engine import PlanOptimizer
from sentryscan.optimizer.formula import CandidatePlan
from sentryscan.optimizer.weights import UtilityWeights


def score_bid(
    proposal: Proposal,
    weights: dict[str, float] | None = None,
    constraints: dict[str, Any] | None = None,
) -> float:
    """Evaluate and score a proposal bid delegating to the production PlanOptimizer.

    Maintains exact backwards compatibility with Milestone 3.1 signature.
    Returns -infinity if hard constraints are violated (infeasible option).
    """
    c = constraints or {}

    # Map weights dict to validated UtilityWeights model if provided
    if weights is not None:
        try:
            # Map simple dict keys to UtilityWeights fields
            w_sev = float(weights.get("severity", weights.get("coverage", 0.35)))
            w_hosts = float(weights.get("hosts", weights.get("coverage", 0.25)))
            w_cost = float(weights.get("cost", 0.15))
            w_time = float(weights.get("time", 0.15))
            w_risk = float(weights.get("risk", 0.10))
            total = w_sev + w_hosts + w_cost + w_time + w_risk
            opt_weights = UtilityWeights(
                w_severity=w_sev / total,
                w_hosts=w_hosts / total,
                w_cost=w_cost / total,
                w_time=w_time / total,
                w_risk=w_risk / total,
            )
        except Exception:
            opt_weights = UtilityWeights.default()
    else:
        opt_weights = UtilityWeights.default()

    optimizer = PlanOptimizer(weights=opt_weights)

    # Convert Proposal envelope into CandidatePlan
    candidate = CandidatePlan(
        plan_id=proposal.proposal_id,
        proposer=proposal.proposer,
        batch_ids=proposal.batch_ids,
        severity_coverage=proposal.est_coverage,
        host_coverage=proposal.est_coverage,
        cost=proposal.est_cost,
        time_ms=proposal.est_time,
        risk=proposal.risk,
    )

    result = optimizer.optimize([candidate], constraints=c)
    if result.status == "OPTIMAL_FOUND" and result.best_score is not None:
        return result.best_score.utility_score

    return -float("inf")
