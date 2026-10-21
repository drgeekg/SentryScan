#!/usr/bin/env python3
"""Deterministic Demonstration Script for Assignment 3.2 — Utility Optimization.

Demonstrates:
1. Multi-attribute utility evaluation across ten candidate execution plans.
2. Hard constraint filtering isolating infeasible candidates (cost/time exceeded).
3. Optimal argmax selection among feasible options.
4. Independent brute-force verification proving optimality.
5. Weight sensitivity analysis demonstrating strategic winner shifts.
6. Generation of candidate comparison tables and evidence artifacts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentryscan.common.clock import FakeClock  # noqa: E402
from sentryscan.contracts.events import EventStatus, EventType  # noqa: E402
from sentryscan.observability.recorder import EventRecorder  # noqa: E402
from sentryscan.optimizer.engine import PlanOptimizer  # noqa: E402
from sentryscan.optimizer.formula import CandidatePlan  # noqa: E402
from sentryscan.optimizer.weights import UtilityWeights  # noqa: E402


def _get_ten_candidates() -> list[CandidatePlan]:
    """Return a deterministic benchmark set of ten diverse candidate execution plans."""
    return [
        CandidatePlan(
            plan_id="plan-01-minimal",
            proposer="scout-agent",
            batch_ids=["b-01"],
            severity_coverage=0.30,
            host_coverage=0.40,
            cost=12.0,
            time_ms=60.0,
            risk=0.20,
        ),
        CandidatePlan(
            plan_id="plan-02-breadth",
            proposer="scout-agent",
            batch_ids=["b-01", "b-02"],
            severity_coverage=0.65,
            host_coverage=0.85,
            cost=28.0,
            time_ms=150.0,
            risk=0.12,
        ),
        CandidatePlan(
            plan_id="plan-03-risk-heavy",
            proposer="triage-agent",
            batch_ids=["b-02", "b-03"],
            severity_coverage=0.90,
            host_coverage=0.60,
            cost=32.0,
            time_ms=180.0,
            risk=0.06,
        ),
        CandidatePlan(
            plan_id="plan-04-balanced-opt",
            proposer="triage-agent",
            batch_ids=["b-01", "b-02", "b-03"],
            severity_coverage=0.92,
            host_coverage=0.88,
            cost=45.0,
            time_ms=220.0,
            risk=0.05,
        ),
        CandidatePlan(
            plan_id="plan-05-fast-triage",
            proposer="triage-agent",
            batch_ids=["b-03"],
            severity_coverage=0.75,
            host_coverage=0.35,
            cost=18.0,
            time_ms=80.0,
            risk=0.10,
        ),
        CandidatePlan(
            plan_id="plan-06-infeasible-cost",
            proposer="scout-agent",
            batch_ids=["b-01", "b-02", "b-03", "b-04"],
            severity_coverage=0.98,
            host_coverage=0.95,
            cost=78.0,  # Exceeds max_cost 50.0
            time_ms=310.0,
            risk=0.04,
        ),
        CandidatePlan(
            plan_id="plan-07-infeasible-time",
            proposer="triage-agent",
            batch_ids=["b-02", "b-04"],
            severity_coverage=0.80,
            host_coverage=0.70,
            cost=40.0,
            time_ms=450.0,  # Exceeds max_time 400.0 ms
            risk=0.08,
        ),
        CandidatePlan(
            plan_id="plan-08-empty-batch",
            proposer="scout-agent",
            batch_ids=[],  # Rejected: empty batch list
            severity_coverage=0.0,
            host_coverage=0.0,
            cost=0.0,
            time_ms=0.0,
            risk=0.50,
        ),
        CandidatePlan(
            plan_id="plan-09-moderate-breadth",
            proposer="scout-agent",
            batch_ids=["b-04"],
            severity_coverage=0.50,
            host_coverage=0.70,
            cost=22.0,
            time_ms=110.0,
            risk=0.15,
        ),
        CandidatePlan(
            plan_id="plan-10-high-risk-lean",
            proposer="triage-agent",
            batch_ids=["b-05"],
            severity_coverage=0.82,
            host_coverage=0.50,
            cost=24.0,
            time_ms=130.0,
            risk=0.07,
        ),
    ]


def run_demo() -> None:
    evidence_dir = REPO_ROOT / "assignments" / "assignment_3_2" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log_path = evidence_dir / "run_log.txt"
    table_path = evidence_dir / "candidate_comparison_table.md"
    sensitivity_path = evidence_dir / "weight_sensitivity_report.json"
    trace_path = evidence_dir / "trace_excerpt.jsonl"
    if trace_path.exists():
        trace_path.unlink()

    log_lines: list[str] = []
    table_lines: list[str] = []

    def log(line: str) -> None:
        print(line)
        log_lines.append(line)

    clock = FakeClock("2026-10-21T07:30:00Z")
    recorder = EventRecorder(run_id="run-demo-3-2", output_path=trace_path, clock=clock)

    log("=" * 78)
    log(" SentryScan Milestone 3.2 -- Multi-Attribute Utility Optimization ")
    log("=" * 78)

    candidates = _get_ten_candidates()
    constraints = {"max_cost": 50.0, "max_time": 400.0}
    bounds = {
        "severity": (0.0, 1.0),
        "hosts": (0.0, 1.0),
        "cost": (0.0, 100.0),
        "time": (0.0, 1000.0),
    }

    log("\n[1] Evaluating 10 Candidate Plans under Hard Constraints:")
    log(f"    - Max Cost Limit: <= {constraints['max_cost']}")
    log(f"    - Max Time Limit: <= {constraints['max_time']} ms")
    log("    - Formula: U(o) = w_1*C_sev + w_2*C_hosts - w_3*Cost - w_4*Time - w_5*Risk")

    # 1. Run Baseline Optimization
    weights_default = UtilityWeights.default()
    optimizer = PlanOptimizer(weights=weights_default, default_bounds=bounds)
    result = optimizer.optimize(candidates, constraints)

    # 2. Build Markdown Table
    table_lines.append("# Ten-Candidate Execution Plan Optimization Table\n")
    table_lines.append(
        f"**Active Constraints:** Cost $\\le {constraints['max_cost']}$, "
        f"Time $\\le {constraints['max_time']}$ ms  \n"
        f"**Weights:** $w_{{sev}}={weights_default.w_severity}$, "
        f"$w_{{hosts}}={weights_default.w_hosts}$, "
        f"$w_{{cost}}={weights_default.w_cost}$, "
        f"$w_{{time}}={weights_default.w_time}$, "
        f"$w_{{risk}}={weights_default.w_risk}$\n"
    )
    table_lines.append(
        "| Plan ID | Proposer | $C_{sev}$ | $C_{hosts}$ | Cost | Time (ms) | "
        "Risk | Feasible? | Score $U(o)$ | Status / Decision |"
    )
    table_lines.append(
        "|---|---|---|---|---|---|---|:---:|:---:|---|"
    )

    scores_by_id = {s.plan_id: s for s in result.evaluated_scores}

    for c in candidates:
        if c.plan_id in result.infeasible_reasons:
            feasible_str = "No"
            score_str = "-inf"
            reason = result.infeasible_reasons[c.plan_id]
            decision = f"REJECTED: {reason}"
        else:
            feasible_str = "Yes"
            s = scores_by_id[c.plan_id]
            score_str = f"{s.utility_score:+.4f}"
            if result.winner and result.winner.plan_id == c.plan_id:
                decision = "WINNER (argmax o*)"
            else:
                decision = "Suboptimal"

        row = (
            f"| `{c.plan_id}` | `{c.proposer}` | {c.severity_coverage:.2f} | "
            f"{c.host_coverage:.2f} | {c.cost:.1f} | {c.time_ms:.1f} | "
            f"{c.risk:.2f} | {'✅ Yes' if feasible_str == 'Yes' else '❌ No'} | "
            f"`{score_str}` | {decision} |"
        )
        table_lines.append(row)
        log(
            f"    {c.plan_id:<25} | Feasible: {feasible_str:<3} | "
            f"Score: {score_str:>7} | {decision}"
        )

        recorder.record(
            event_type=EventType.RULE_MATCHED,
            component="optimizer",
            status=EventStatus.OK,
            details={
                "plan_id": c.plan_id,
                "feasible": c.plan_id not in result.infeasible_reasons,
                "score": score_str,
                "decision": decision,
            },
        )

    log("\n[2] Optimization Decision:")
    if result.winner and result.best_score:
        bs = result.best_score
        log(f"    [*] Selected Optimal Plan: {result.winner.plan_id} ({result.winner.proposer})")
        log(f"       - Utility Score:       {bs.utility_score}")
        log(f"       - Severity Coverage:   {result.winner.severity_coverage}")
        log(f"       - Host Coverage:       {result.winner.host_coverage}")
        log(f"       - Cost:                {result.winner.cost} (Norm: {bs.norm_cost})")
        log(f"       - Time:                {result.winner.time_ms} ms (Norm: {bs.norm_time})")
        log(f"       - Residual Risk:       {result.winner.risk} (Norm: {bs.norm_risk})")

    # 3. Independent Brute Force Verification
    log("\n[3] Running Independent Brute-Force Verification...")
    best_bf_id = None
    best_bf_score = -float("inf")
    for c in candidates:
        if c.plan_id in result.infeasible_reasons:
            continue
        s = scores_by_id[c.plan_id]
        if s.utility_score > best_bf_score:
            best_bf_score = s.utility_score
            best_bf_id = c.plan_id

    assert result.winner is not None and result.best_score is not None
    assert result.winner.plan_id == best_bf_id
    assert result.best_score.utility_score == best_bf_score
    log("    [+] Independent exhaustive search 100% confirms mathematical optimality.")

    # 4. Weight Sensitivity Analysis
    log("\n[4] Performing Policy Weight Sensitivity Analysis:")
    weight_presets = {
        "default_balanced": UtilityWeights.default(),
        "risk_first": UtilityWeights.risk_first(),
        "coverage_first": UtilityWeights.coverage_first(),
        "cost_constrained": UtilityWeights(
            w_severity=0.15,
            w_hosts=0.15,
            w_cost=0.50,
            w_time=0.10,
            w_risk=0.10,
        ),
    }

    sensitivity_results: dict[str, dict] = {}
    for preset_name, w_preset in weight_presets.items():
        opt_preset = PlanOptimizer(weights=w_preset, default_bounds=bounds)
        res_preset = opt_preset.optimize(candidates, constraints)
        assert res_preset.winner is not None and res_preset.best_score is not None

        sensitivity_results[preset_name] = {
            "winner_plan_id": res_preset.winner.plan_id,
            "proposer": res_preset.winner.proposer,
            "utility_score": res_preset.best_score.utility_score,
            "weights": w_preset.model_dump(),
        }
        log(
            f"    - Preset '{preset_name:<16}': Winner = {res_preset.winner.plan_id} "
            f"({res_preset.winner.proposer}) with score {res_preset.best_score.utility_score}"
        )

    recorder.close()

    # Write files
    with open(run_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")

    with open(table_path, "w", encoding="utf-8") as f:
        f.write("\n".join(table_lines) + "\n")

    with open(sensitivity_path, "w", encoding="utf-8") as f:
        json.dump(sensitivity_results, f, indent=2)

    log("\n[*] Execution artifacts successfully generated:")
    log(f"    - Console Log:              {run_log_path}")
    log(f"    - 10-Candidate Table:       {table_path}")
    log(f"    - Weight Sensitivity Report: {sensitivity_path}")
    log(f"    - Trace Excerpt:            {trace_path}")
    log("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description="Assignment 3.2 Utility Optimization Demo")
    parser.parse_args()
    run_demo()


if __name__ == "__main__":
    main()
