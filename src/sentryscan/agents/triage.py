"""Triage Agent: Specializes in risk-first and critical-severity batch proposals."""

from __future__ import annotations

from typing import Any

from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.proposal import Proposal
from sentryscan.llm.interface import LLMProvider, LLMRequest


class TriageAgent:
    """Agent role proposing batch allocations prioritizing critical and high-severity risks."""

    MIN_WEIGHT: float = 0.05
    MAX_WEIGHT: float = 1.0
    STEP_DELTA: float = 0.05

    def __init__(
        self,
        agent_id: str = "triage-agent",
        llm_provider: LLMProvider | None = None,
        id_gen: IdGenerator | None = None,
        port_weights: dict[int | str, float] | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.llm_provider = llm_provider
        self.id_gen = id_gen if id_gen is not None else IdGenerator()
        default_w: dict[int | str, float] = {23: 0.8, 22: 0.7, 443: 0.5, 80: 0.6, 21: 0.5, "default": 0.2}
        if port_weights:
            for k, v in port_weights.items():
                key = int(k) if str(k).isdigit() else str(k)
                default_w[key] = max(self.MIN_WEIGHT, min(self.MAX_WEIGHT, float(v)))
        self.port_weights: dict[int | str, float] = default_w

    def update_port_weight(self, port: int | str, confirmed: bool) -> tuple[float, float]:
        """Update bounded port risk weight (+STEP_DELTA on confirmed, -STEP_DELTA on false positive)."""
        key: int | str = int(port) if str(port).isdigit() else str(port)
        old_w = float(self.port_weights.get(key, self.port_weights.get("default", 0.2)))
        delta = self.STEP_DELTA if confirmed else -self.STEP_DELTA
        new_w = round(max(self.MIN_WEIGHT, min(self.MAX_WEIGHT, old_w + delta)), 4)
        self.port_weights[key] = new_w
        return old_w, new_w

    def export_weights(self) -> dict[str, float]:
        """Export port weights with string keys for SQLite persistence."""
        return {f"triage_port_{k}": float(v) for k, v in self.port_weights.items()}

    def load_weights(self, stored: dict[str, float]) -> None:
        """Load persisted weights from SQLite dict."""
        for k, v in stored.items():
            if k.startswith("triage_port_"):
                raw = k.removeprefix("triage_port_")
                key: int | str = int(raw) if raw.isdigit() else raw
                self.port_weights[key] = max(self.MIN_WEIGHT, min(self.MAX_WEIGHT, float(v)))

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

                if port in self.port_weights:
                    risk_score += self.port_weights[port]
                elif port == 23 or "telnet" in service:
                    risk_score += self.port_weights.get(23, 0.8)
                elif "openssh 7.2" in banner or port == 22:
                    risk_score += self.port_weights.get(22, 0.7)
                elif "tls 1.0" in banner or port == 443:
                    risk_score += self.port_weights.get(443, 0.5)
                else:
                    risk_score += self.port_weights.get("default", 0.2)

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
