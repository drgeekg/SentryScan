"""Optimization engine filtering infeasible candidates and selecting feasible argmax."""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel

from sentryscan.optimizer.formula import CandidatePlan, EvaluationScore, compute_utility
from sentryscan.optimizer.weights import UtilityWeights

logger = logging.getLogger(__name__)


class OptimizationResult(BaseModel):
    """Authoritative result envelope of the multi-attribute optimization process."""

    status: str  # "OPTIMAL_FOUND" or "NO_FEASIBLE_OPTION"
    winner: CandidatePlan | None
    best_score: EvaluationScore | None
    evaluated_scores: list[EvaluationScore]
    infeasible_reasons: dict[str, str]  # plan_id -> rejection reason


class PlanOptimizer:
    """Multi-attribute utility optimizer selecting the optimal feasible candidate plan."""

    def __init__(
        self,
        weights: UtilityWeights | None = None,
        default_bounds: dict[str, tuple[float, float]] | None = None,
    ) -> None:
        self.weights = weights if weights is not None else UtilityWeights.default()
        self.default_bounds = default_bounds or {
            "severity": (0.0, 1.0),
            "hosts": (0.0, 1.0),
            "cost": (0.0, 100.0),
            "time": (0.0, 1000.0),
        }

    def filter_feasible(
        self,
        candidates: list[CandidatePlan],
        constraints: dict[str, Any],
    ) -> tuple[list[CandidatePlan], dict[str, str]]:
        """Filter candidate plans against hard constraints, recording rejection reasons."""
        max_cost = float(constraints.get("max_cost", 100.0))
        max_time = float(constraints.get("max_time", 1000.0))

        feasible: list[CandidatePlan] = []
        infeasible_reasons: dict[str, str] = {}

        for plan in candidates:
            if not plan.batch_ids:
                infeasible_reasons[plan.plan_id] = "EMPTY_BATCH_LIST"
                continue
            if plan.cost > max_cost:
                infeasible_reasons[plan.plan_id] = f"COST_EXCEEDED ({plan.cost} > {max_cost})"
                continue
            if plan.time_ms > max_time:
                infeasible_reasons[plan.plan_id] = f"TIME_EXCEEDED ({plan.time_ms} > {max_time})"
                continue

            feasible.append(plan)

        return feasible, infeasible_reasons

    def optimize(
        self,
        candidates: list[CandidatePlan],
        constraints: dict[str, Any],
        bounds: dict[str, tuple[float, float]] | None = None,
    ) -> OptimizationResult:
        """Select the optimal feasible candidate plan maximizing utility U(o)."""
        active_bounds = bounds or self.default_bounds
        feasible_plans, infeasible_reasons = self.filter_feasible(candidates, constraints)

        if not feasible_plans:
            return OptimizationResult(
                status="NO_FEASIBLE_OPTION",
                winner=None,
                best_score=None,
                evaluated_scores=[],
                infeasible_reasons=infeasible_reasons,
            )

        # Compute utility score for all feasible candidates
        evaluated_scores: list[EvaluationScore] = []
        plan_map: dict[str, CandidatePlan] = {}

        for plan in feasible_plans:
            score = compute_utility(plan, self.weights, bounds=active_bounds)
            evaluated_scores.append(score)
            plan_map[plan.plan_id] = plan

        # Select argmax with deterministic tie-breaking:
        # 1. utility_score (DESC)
        # 2. severity_coverage (DESC)
        # 3. host_coverage (DESC)
        # 4. cost (ASC)
        # 5. plan_id (ASC)
        def sort_key(score: EvaluationScore) -> tuple[float, float, float, float, str]:
            p = plan_map[score.plan_id]
            return (
                -score.utility_score,
                -p.severity_coverage,
                -p.host_coverage,
                p.cost,
                score.plan_id,
            )

        sorted_scores = sorted(evaluated_scores, key=sort_key)
        best_score = sorted_scores[0]
        winner = plan_map[best_score.plan_id]

        return OptimizationResult(
            status="OPTIMAL_FOUND",
            winner=winner,
            best_score=best_score,
            evaluated_scores=evaluated_scores,
            infeasible_reasons=infeasible_reasons,
        )
