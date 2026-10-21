"""Integration tests verifying multi-agent consensus, bounded termination, and determinism."""

from __future__ import annotations

from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Performative
from sentryscan.graphs.supervisor import build_supervisor_graph
from sentryscan.llm.deterministic import DeterministicLLMProvider
from sentryscan.llm.fake import FakeLLMProvider
from sentryscan.negotiation.protocol import ContractNetNegotiator


def _standard_batches():
    return {
        "b-01": [
            {
                "record_id": "tel-01",
                "host_id": "sim-host-001",
                "ip": "192.0.2.10",
                "port": 22,
                "service": "ssh",
                "banner": "SSH-2.0-OpenSSH_7.2p2",
                "auth_mode": "required",
                "generated_at": "2026-10-21T07:00:00Z",
            }
        ],
        "b-02": [
            {
                "record_id": "tel-02",
                "host_id": "sim-host-002",
                "ip": "192.0.2.11",
                "port": 23,
                "service": "telnet",
                "banner": "Linux telnetd",
                "auth_mode": "default",
                "generated_at": "2026-10-21T07:00:00Z",
            }
        ],
    }


def test_turn_by_turn_timeline_and_handshake():
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=100)
    negotiator = ContractNetNegotiator(clock=clock, id_gen=id_gen, max_rounds=3)

    batches = _standard_batches()
    result = negotiator.run_negotiation(
        task_id="task-timeline-01",
        run_id="run-timeline-01",
        batches=batches,
        initial_constraints={"max_cost": 50.0, "max_time": 200.0},
    )

    assert result.status == "CONSENSUS_REACHED"
    msgs = result.messages

    # Verify chronological sequence: CFP -> PROPOSE -> ACCEPT/REJECT -> CONFIRM
    assert msgs[0].performative == Performative.CFP
    assert msgs[1].performative == Performative.CFP
    assert msgs[2].performative == Performative.PROPOSE
    assert msgs[3].performative == Performative.PROPOSE
    assert msgs[4].performative == Performative.ACCEPT
    assert msgs[5].performative == Performative.REJECT
    assert msgs[6].performative == Performative.CONFIRM

    # Confirm handshake participants
    winner = result.winning_proposer
    assert msgs[4].receiver == winner
    assert msgs[6].sender == winner


def test_bounded_unresolved_termination():
    clock = FakeClock("2026-10-21T07:00:00Z")
    id_gen = IdGenerator(seed=200)
    # Tightly bounded to 3 rounds with zero cost tolerance
    negotiator = ContractNetNegotiator(clock=clock, id_gen=id_gen, max_rounds=3)

    result = negotiator.run_negotiation(
        task_id="task-unresolved-01",
        run_id="run-unresolved-01",
        batches=_standard_batches(),
        initial_constraints={"max_cost": 0.0001, "max_time": 0.0001},
    )

    assert result.status == "UNRESOLVED"
    assert result.winning_proposal is None
    assert result.rounds_completed == 3
    # Check that counterproposals were issued across rounds 2 and 3
    counter_props = [m for m in result.messages if m.performative == Performative.COUNTERPROPOSE]
    assert len(counter_props) == 4  # 2 recipients x 2 retry rounds


def test_trace_identical_with_llm_off():
    # Determinism Contract: Runs with LLM off must yield identical results
    clock1 = FakeClock("2026-10-21T07:00:00Z")
    id_gen1 = IdGenerator(seed=42)
    app1 = build_supervisor_graph(clock=clock1, id_gen=id_gen1, llm_provider=None)

    clock2 = FakeClock("2026-10-21T07:00:00Z")
    id_gen2 = IdGenerator(seed=42)
    app2 = build_supervisor_graph(clock=clock2, id_gen=id_gen2, llm_provider=None)

    batches = _standard_batches()
    state1 = app1.invoke(
        {
            "run_id": "run-det-01",
            "task_id": "task-det-01",
            "batches": batches,
            "constraints": {"max_cost": 80.0, "max_time": 400.0},
            "messages": [],
            "findings": [],
            "errors": [],
        }
    )

    state2 = app2.invoke(
        {
            "run_id": "run-det-01",
            "task_id": "task-det-01",
            "batches": batches,
            "constraints": {"max_cost": 80.0, "max_time": 400.0},
            "messages": [],
            "findings": [],
            "errors": [],
        }
    )

    # Assert exact identity across outcomes
    assert state1["phase"] == state2["phase"] == "COMPLETED"
    assert state1["awarded_proposer"] == state2["awarded_proposer"]
    assert state1["awarded_batch_ids"] == state2["awarded_batch_ids"]
    assert len(state1["findings"]) == len(state2["findings"])
    assert len(state1["messages"]) == len(state2["messages"])

    for f1, f2 in zip(state1["findings"], state2["findings"], strict=False):
        assert f1.rule_id == f2.rule_id
        assert f1.severity == f2.severity
        assert f1.host_id == f2.host_id


def test_llm_advisory_non_authoritative():
    # Verify that changing LLM text does not alter mathematical scoring or winner selection
    clock1 = FakeClock("2026-10-21T07:00:00Z")
    id_gen1 = IdGenerator(seed=42)
    llm_det = DeterministicLLMProvider()
    app_det = build_supervisor_graph(clock=clock1, id_gen=id_gen1, llm_provider=llm_det)

    clock2 = FakeClock("2026-10-21T07:00:00Z")
    id_gen2 = IdGenerator(seed=42)
    llm_fake = FakeLLMProvider(default_text="Completely different arbitrary LLM output")
    app_fake = build_supervisor_graph(clock=clock2, id_gen=id_gen2, llm_provider=llm_fake)

    batches = _standard_batches()
    state_det = app_det.invoke(
        {
            "run_id": "run-llm-01",
            "task_id": "task-llm-01",
            "batches": batches,
            "constraints": {"max_cost": 80.0, "max_time": 400.0},
            "messages": [],
            "findings": [],
            "errors": [],
        }
    )
    state_fake = app_fake.invoke(
        {
            "run_id": "run-llm-01",
            "task_id": "task-llm-01",
            "batches": batches,
            "constraints": {"max_cost": 80.0, "max_time": 400.0},
            "messages": [],
            "findings": [],
            "errors": [],
        }
    )

    # Awarded proposer and batches must remain 100% identical
    assert state_det["awarded_proposer"] == state_fake["awarded_proposer"]
    assert state_det["awarded_batch_ids"] == state_fake["awarded_batch_ids"]
    assert len(state_det["findings"]) == len(state_fake["findings"])
