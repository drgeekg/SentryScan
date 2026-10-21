"""Scoring seam for Contract-Net proposals prior to full 3.2 optimizer."""

from __future__ import annotations

from typing import Any

from sentryscan.contracts.proposal import Proposal

DEFAULT_WEIGHTS = {
    "coverage": 0.50,
    "cost": 0.20,
    "time": 0.15,
    "risk": 0.15,
}


def score_bid(
    proposal: Proposal,
    weights: dict[str, float] | None = None,
    constraints: dict[str, Any] | None = None,
) -> float:
    """Evaluate and score a proposal bid against constraints and weights.

    Returns -infinity if hard constraints are violated (infeasible option).
    """
    w = weights if weights is not None else DEFAULT_WEIGHTS
    c = constraints if constraints is not None else {}

    max_cost = float(c.get("max_cost", 100.0))
    max_time = float(c.get("max_time", 1000.0))

    # Hard constraints filtering
    if proposal.est_cost > max_cost:
        return -float("inf")
    if proposal.est_time > max_time:
        return -float("inf")
    if not proposal.batch_ids:
        return -float("inf")

    # Normalization
    norm_cost = min(1.0, proposal.est_cost / max(1.0, max_cost))
    norm_time = min(1.0, proposal.est_time / max(1.0, max_time))
    norm_coverage = max(0.0, min(1.0, proposal.est_coverage))
    norm_risk = max(0.0, min(1.0, proposal.risk))

    # Objective formula
    score = (
        w.get("coverage", 0.50) * norm_coverage
        - w.get("cost", 0.20) * norm_cost
        - w.get("time", 0.15) * norm_time
        - w.get("risk", 0.15) * norm_risk
    )

    return round(score, 4)
