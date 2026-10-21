"""Contract-Net negotiation protocol orchestrator."""

from __future__ import annotations

import logging
from typing import Any

from sentryscan.agents.scout import ScoutAgent
from sentryscan.agents.triage import TriageAgent
from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Message, Performative
from sentryscan.contracts.proposal import Proposal
from sentryscan.negotiation.scoring import score_bid

logger = logging.getLogger(__name__)


class NegotiationResult:
    """Outcome of a completed or terminated Contract-Net negotiation session."""

    def __init__(
        self,
        status: str,
        winning_proposal: Proposal | None,
        winning_proposer: str | None,
        awarded_batch_ids: list[str],
        rounds_completed: int,
        messages: list[Message],
    ) -> None:
        self.status = status  # "CONSENSUS_REACHED" or "UNRESOLVED"
        self.winning_proposal = winning_proposal
        self.winning_proposer = winning_proposer
        self.awarded_batch_ids = awarded_batch_ids
        self.rounds_completed = rounds_completed
        self.messages = messages


class ContractNetNegotiator:
    """Multi-turn Contract-Net protocol supervisor coordinating Scout and Triage bidding."""

    def __init__(
        self,
        supervisor_id: str = "supervisor-agent",
        scout_agent: ScoutAgent | None = None,
        triage_agent: TriageAgent | None = None,
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
        max_rounds: int = 5,
    ) -> None:
        self.supervisor_id = supervisor_id
        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator()
        self.scout = scout_agent if scout_agent is not None else ScoutAgent(id_gen=self.id_gen)
        self.triage = triage_agent if triage_agent is not None else TriageAgent(id_gen=self.id_gen)
        self.max_rounds = max_rounds

    def run_negotiation(
        self,
        task_id: str,
        run_id: str,
        batches: dict[str, list[dict[str, Any]]],
        initial_constraints: dict[str, Any],
    ) -> NegotiationResult:
        """Run multi-turn negotiation until consensus handshake or max rounds exceeded."""
        messages: list[Message] = []
        constraints = dict(initial_constraints)

        for current_round in range(1, self.max_rounds + 1):
            # 1. Supervisor issues CFP (or COUNTERPROPOSE if round > 1)
            performative = Performative.CFP if current_round == 1 else Performative.COUNTERPROPOSE

            for peer in [self.scout.agent_id, self.triage.agent_id]:
                cfp_msg = Message(
                    message_id=self.id_gen.next_id("message"),
                    run_id=run_id,
                    sender=self.supervisor_id,
                    receiver=peer,
                    performative=performative,
                    timestamp_utc=self.clock.now_iso(),
                    nonce=self.id_gen.seeded_token(16),
                    task_id=task_id,
                    payload={"round": current_round, "constraints": constraints},
                )
                messages.append(cfp_msg)

            # 2. Scout submits PROPOSE
            scout_proposal = self.scout.propose(
                task_id=task_id,
                batches=batches,
                constraints=constraints,
                round_num=current_round,
            )
            scout_msg = Message(
                message_id=self.id_gen.next_id("message"),
                run_id=run_id,
                sender=self.scout.agent_id,
                receiver=self.supervisor_id,
                performative=Performative.PROPOSE,
                timestamp_utc=self.clock.now_iso(),
                nonce=self.id_gen.seeded_token(16),
                task_id=task_id,
                payload={"proposal": scout_proposal.model_dump()},
            )
            messages.append(scout_msg)

            # 3. Triage submits PROPOSE
            triage_proposal = self.triage.propose(
                task_id=task_id,
                batches=batches,
                constraints=constraints,
                round_num=current_round,
            )
            triage_msg = Message(
                message_id=self.id_gen.next_id("message"),
                run_id=run_id,
                sender=self.triage.agent_id,
                receiver=self.supervisor_id,
                performative=Performative.PROPOSE,
                timestamp_utc=self.clock.now_iso(),
                nonce=self.id_gen.seeded_token(16),
                task_id=task_id,
                payload={"proposal": triage_proposal.model_dump()},
            )
            messages.append(triage_msg)

            # 4. Supervisor scores bids
            score_scout = score_bid(scout_proposal, constraints=constraints)
            score_triage = score_bid(triage_proposal, constraints=constraints)

            logger.info(
                "Round %d scores: Scout=%s, Triage=%s",
                current_round,
                score_scout,
                score_triage,
            )

            # Determine best feasible proposal
            best_candidate: tuple[Proposal, str, float] | None = None
            other_candidate: tuple[Proposal, str, float] | None = None

            if score_scout > -float("inf") or score_triage > -float("inf"):
                if score_triage >= score_scout:
                    best_candidate = (triage_proposal, self.triage.agent_id, score_triage)
                    other_candidate = (scout_proposal, self.scout.agent_id, score_scout)
                else:
                    best_candidate = (scout_proposal, self.scout.agent_id, score_scout)
                    other_candidate = (triage_proposal, self.triage.agent_id, score_triage)

            if best_candidate is not None:
                prop, proposer, score = best_candidate
                other_prop, other_proposer, _ = other_candidate  # type: ignore[misc]

                # Handshake: ACCEPT to winner, REJECT to other
                accept_msg = Message(
                    message_id=self.id_gen.next_id("message"),
                    run_id=run_id,
                    sender=self.supervisor_id,
                    receiver=proposer,
                    performative=Performative.ACCEPT,
                    timestamp_utc=self.clock.now_iso(),
                    nonce=self.id_gen.seeded_token(16),
                    task_id=task_id,
                    payload={
                        "proposal_id": prop.proposal_id,
                        "score": score,
                        "round": current_round,
                        "awarded_batch_ids": prop.batch_ids,
                    },
                )
                messages.append(accept_msg)

                reject_msg = Message(
                    message_id=self.id_gen.next_id("message"),
                    run_id=run_id,
                    sender=self.supervisor_id,
                    receiver=other_proposer,
                    performative=Performative.REJECT,
                    timestamp_utc=self.clock.now_iso(),
                    nonce=self.id_gen.seeded_token(16),
                    task_id=task_id,
                    payload={
                        "proposal_id": other_prop.proposal_id,
                        "reason": "Alternative proposal yielded higher normalized utility score",
                    },
                )
                messages.append(reject_msg)

                # Winning agent confirms award (CONFIRM)
                confirm_msg = Message(
                    message_id=self.id_gen.next_id("message"),
                    run_id=run_id,
                    sender=proposer,
                    receiver=self.supervisor_id,
                    performative=Performative.CONFIRM,
                    timestamp_utc=self.clock.now_iso(),
                    nonce=self.id_gen.seeded_token(16),
                    task_id=task_id,
                    payload={"proposal_id": prop.proposal_id, "status": "AWARD_CONFIRMED"},
                )
                messages.append(confirm_msg)

                return NegotiationResult(
                    status="CONSENSUS_REACHED",
                    winning_proposal=prop,
                    winning_proposer=proposer,
                    awarded_batch_ids=prop.batch_ids,
                    rounds_completed=current_round,
                    messages=messages,
                )

            # Infeasible in this round -> Concede / update constraints for next round
            constraints["max_cost"] = constraints.get("max_cost", 100.0) * 1.15
            constraints["max_time"] = constraints.get("max_time", 1000.0) * 1.15

        # If max rounds exceeded without consensus
        return NegotiationResult(
            status="UNRESOLVED",
            winning_proposal=None,
            winning_proposer=None,
            awarded_batch_ids=[],
            rounds_completed=self.max_rounds,
            messages=messages,
        )
