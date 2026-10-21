"""Triage Agent: Specializes in risk-first and critical-severity batch proposals."""

from __future__ import annotations

from typing import Any

from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.proposal import Proposal
from sentryscan.llm.interface import LLMProvider, LLMRequest


class TriageAgent:
    """Agent role proposing batch allocations prioritizing critical and high-severity risks."""

    def __init__(
        self,
        agent_id: str = "triage-agent",
        llm_provider: LLMProvider | None = None,
        id_gen: IdGenerator | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.llm_provider = llm_provider
        self.id_gen = id_gen if id_gen is not None else IdGenerator()

    def propose(
        self,
        task_id: str,
        batches: dict[str, list[dict[str, Any]]],
        constraints: dict[str, Any],
        round_num: int = 1,
    ) -> Proposal:
        """Formulate a risk-first proposal under given constraints."""
        max_cost = float(constraints.get("max_cost", 100.0))
        max_time = float(constraints.get("max_time", 1000.0))

        # Evaluate risk score for each batch based on service and banner attributes
        batch_risks: list[tuple[str, float, float, float]] = []
        for bid, records in batches.items():
            risk_score = 0.0
            for r in records:
                port = r.get("port", 0)
                service = str(r.get("service", "")).lower()
                banner = str(r.get("banner", "")).lower()

                if port == 23 or "telnet" in service:
                    risk_score += 0.8
                elif "openssh 7.2" in banner or port == 22:
                    risk_score += 0.7
                elif "tls 1.0" in banner or port == 443:
                    risk_score += 0.5
                else:
                    risk_score += 0.2

            cost = 10.0 + len(records) * 1.5
            time_ms = 40.0 + len(records) * 12.0
            batch_risks.append((bid, risk_score, cost, time_ms))

        # Sort batches by risk score descending (urgent findings first)
        batch_risks.sort(key=lambda x: x[1], reverse=True)

        selected_batches: list[str] = []
        total_cost = 0.0
        total_time = 0.0
        total_risk_addressed = 0.0
        max_possible_risk = sum(r[1] for r in batch_risks) or 1.0

        # Concession scaling in multi-turn negotiation
        cost_limit = max_cost * (0.95 ** (round_num - 1))

        for bid, risk_val, cost, time_ms in batch_risks:
            if (total_cost + cost <= cost_limit) and (total_time + time_ms <= max_time):
                selected_batches.append(bid)
                total_cost += cost
                total_time += time_ms
                total_risk_addressed += risk_val

        if not selected_batches and batch_risks:
            bid, risk_val, cost, time_ms = batch_risks[0]
            selected_batches.append(bid)
            total_cost = cost
            total_time = time_ms
            total_risk_addressed = risk_val

        coverage_ratio = total_risk_addressed / max_possible_risk

        rationale = (
            f"Triage plan selecting {len(selected_batches)} high-exposure batches "
            f"addressing {total_risk_addressed:.1f} risk score."
        )
        if self.llm_provider:
            req = LLMRequest(
                role="triage_proposal",
                system="You are TriageAgent proposing telemetry batch allocations.",
                messages=[
                    {
                        "role": "user",
                        "content": (
                            f"Task {task_id}, round {round_num}. "
                            f"Batches: {selected_batches}, risk: {coverage_ratio:.2f}."
                        ),
                    }
                ],
                request_id=self.id_gen.next_id("llm_req"),
            )
            try:
                llm_resp = self.llm_provider.generate(req)
                rationale = llm_resp.text
            except Exception:
                pass

        return Proposal(
            proposal_id=self.id_gen.next_id("proposal"),
            proposer=self.agent_id,
            task_id=task_id,
            batch_ids=selected_batches,
            est_cost=round(total_cost, 2),
            est_time=round(total_time, 2),
            est_coverage=round(min(1.0, coverage_ratio), 2),
            risk=0.08,  # Lower residual risk because high threats are prioritized
            round=round_num,
            rationale=rationale,
        )
