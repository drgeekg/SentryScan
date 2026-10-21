"""Scout Agent: Specializes in broad host and subnet coverage proposals."""

from __future__ import annotations

from typing import Any

from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.proposal import Proposal
from sentryscan.llm.interface import LLMProvider, LLMRequest


class ScoutAgent:
    """Agent role proposing batch allocations that maximize host coverage across the fleet."""

    def __init__(
        self,
        agent_id: str = "scout-agent",
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
        """Formulate a coverage-focused proposal under given constraints."""
        max_cost = float(constraints.get("max_cost", 100.0))
        max_time = float(constraints.get("max_time", 1000.0))

        # Score batches by unique hosts
        batch_host_counts: list[tuple[str, int, float, float]] = []
        all_hosts: set[str] = set()

        for bid, records in batches.items():
            hosts = {r.get("host_id", "") for r in records if r.get("host_id")}
            all_hosts.update(hosts)
            # Cost model: 10.0 base per batch + 1.0 per record
            cost = 10.0 + len(records) * 1.0
            # Time model: 30.0 ms base per batch + 10.0 ms per record
            time_ms = 30.0 + len(records) * 10.0
            batch_host_counts.append((bid, len(hosts), cost, time_ms))

        # Sort batches by unique host count descending (breadth priority)
        batch_host_counts.sort(key=lambda x: x[1], reverse=True)

        selected_batches: list[str] = []
        total_cost = 0.0
        total_time = 0.0
        covered_hosts: set[str] = set()

        # In later rounds (concession), tighten selection
        cost_limit = max_cost * (0.9 ** (round_num - 1))

        for bid, _, cost, time_ms in batch_host_counts:
            if (total_cost + cost <= cost_limit) and (total_time + time_ms <= max_time):
                selected_batches.append(bid)
                total_cost += cost
                total_time += time_ms
                for r in batches[bid]:
                    if r.get("host_id"):
                        covered_hosts.add(r["host_id"])

        if not selected_batches and batch_host_counts:
            # Always select at least one minimal batch if available
            bid, _, cost, time_ms = batch_host_counts[-1]
            selected_batches.append(bid)
            total_cost = cost
            total_time = time_ms
            for r in batches[bid]:
                if r.get("host_id"):
                    covered_hosts.add(r["host_id"])

        coverage_ratio = len(covered_hosts) / max(1, len(all_hosts))

        # Rationale via LLM provider if available
        rationale = (
            f"Coverage plan selecting {len(selected_batches)} batches covering "
            f"{len(covered_hosts)}/{len(all_hosts)} unique hosts."
        )
        if self.llm_provider:
            req = LLMRequest(
                role="scout_proposal",
                system="You are ScoutAgent proposing telemetry batch allocations.",
                messages=[
                    {
                        "role": "user",
                        "content": (
                            f"Task {task_id}, round {round_num}. "
                            f"Selected batches: {selected_batches}, coverage: {coverage_ratio:.2f}."
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
            est_coverage=round(coverage_ratio, 2),
            risk=0.15,
            round=round_num,
            rationale=rationale,
        )
