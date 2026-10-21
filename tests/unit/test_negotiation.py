"""Unit tests for Contract-Net negotiation protocol and bid scoring."""

from __future__ import annotations

from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Performative
from sentryscan.contracts.proposal import Proposal
from sentryscan.negotiation.protocol import ContractNetNegotiator
from sentryscan.negotiation.scoring import score_bid


def _sample_proposal(cost: float = 20.0, time_ms: float = 100.0, cov: float = 0.8) -> Proposal:
    return Proposal(
        proposal_id="prop-test",
        proposer="test-agent",
        task_id="task-01",
        batch_ids=["b-1", "b-2"],
        est_cost=cost,
        est_time=time_ms,
        est_coverage=cov,
        risk=0.1,
    )


def test_score_bid_valid():
    p = _sample_proposal()
    score = score_bid(p, constraints={"max_cost": 50.0, "max_time": 200.0})
    assert score > -float("inf")
    assert isinstance(score, float)


def test_score_bid_constraint_violations():
    p_expensive = _sample_proposal(cost=80.0)
    score_exp = score_bid(p_expensive, constraints={"max_cost": 50.0, "max_time": 200.0})
    assert score_exp == -float("inf")

    p_slow = _sample_proposal(time_ms=300.0)
    score_slow = score_bid(p_slow, constraints={"max_cost": 50.0, "max_time": 200.0})
    assert score_slow == -float("inf")

    p_empty = Proposal(
        proposal_id="prop-empty",
        proposer="test",
        task_id="t1",
        batch_ids=[],
        est_cost=10.0,
        est_time=10.0,
        est_coverage=0.0,
        risk=0.0,
    )
    assert score_bid(p_empty) == -float("inf")


def test_negotiation_consensus_reached():
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    negotiator = ContractNetNegotiator(clock=clock, id_gen=id_gen, max_rounds=5)

    batches = {
        "b1": [{"host_id": "192.0.2.10", "port": 22, "service": "ssh"}],
        "b2": [{"host_id": "192.0.2.11", "port": 23, "service": "telnet"}],
    }

    result = negotiator.run_negotiation(
        task_id="task-alloc-01",
        run_id="run-neg-01",
        batches=batches,
        initial_constraints={"max_cost": 100.0, "max_time": 500.0},
    )

    assert result.status == "CONSENSUS_REACHED"
    assert result.winning_proposal is not None
    assert result.winning_proposer in ("scout-agent", "triage-agent")
    assert len(result.awarded_batch_ids) > 0

    # Verify message handshake sequence
    performatives = [m.performative for m in result.messages]
    assert Performative.CFP in performatives
    assert Performative.PROPOSE in performatives
    assert Performative.ACCEPT in performatives
    assert Performative.REJECT in performatives
    assert Performative.CONFIRM in performatives


def test_negotiation_multi_round_counterproposal():
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    negotiator = ContractNetNegotiator(clock=clock, id_gen=id_gen, max_rounds=5)

    batches = {
        "b1": [{"host_id": "192.0.2.10", "port": 22, "service": "ssh"}],
        "b2": [{"host_id": "192.0.2.11", "port": 80, "service": "http"}],
    }

    # Start with cost constraint slightly below initial proposals (~12 cost)
    result = negotiator.run_negotiation(
        task_id="task-alloc-02",
        run_id="run-neg-02",
        batches=batches,
        initial_constraints={"max_cost": 10.0, "max_time": 500.0},
    )

    assert result.status == "CONSENSUS_REACHED"
    assert result.rounds_completed > 1
    performatives = [m.performative for m in result.messages]
    assert Performative.COUNTERPROPOSE in performatives


def test_negotiation_unresolved_after_max_rounds():
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=42)
    # Impossible constraints: 0 cost allowed, max 2 rounds
    negotiator = ContractNetNegotiator(clock=clock, id_gen=id_gen, max_rounds=2)

    batches = {
        "b1": [{"host_id": "192.0.2.10", "port": 22, "service": "ssh"}],
    }

    result = negotiator.run_negotiation(
        task_id="task-alloc-03",
        run_id="run-neg-03",
        batches=batches,
        initial_constraints={"max_cost": 0.001, "max_time": 0.001},
    )

    assert result.status == "UNRESOLVED"
    assert result.winning_proposal is None
    assert result.rounds_completed == 2
