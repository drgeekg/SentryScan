# Assignment 3.1 — Multi-Agent Coordination, Negotiation & LangGraph Orchestration

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-3.1`  

---

## 1. Architectural Increment Overview

Assignment 3.1 establishes the foundational multi-agent coordination architecture using LangGraph, multi-turn Contract-Net negotiation, role-separated bidding agents, dynamic subagent fan-out via `Send`, and a provider-neutral LLM abstraction layer:

1. **Typed Graph State & Reducers:**
   - [`src/sentryscan/graphs/state.py`](../../src/sentryscan/graphs/state.py): Defines `SupervisorState` with accumulators (`operator.add` channels for `messages`, `findings`, and `errors`) ensuring thread-safe fan-out collection and deterministic state convergence.
2. **Provider-Neutral Advisory LLM Layer:**
   - [`src/sentryscan/llm/`](../../src/sentryscan/llm/): Defines `LLMRequest`, `LLMResponse`, and `LLMProvider` protocol. Implements `DeterministicLLMProvider` (default, zero-network, reproducible template reasoning) and `FakeLLMProvider` (mock/scripted for tests). Per HLD §7.4, LLM output is strictly advisory (drafting proposal rationales), never holds authority over security decisions, and does not alter mathematical utility scoring.
3. **Role-Separated Proposing Agents:**
   - [`src/sentryscan/contracts/proposal.py`](../../src/sentryscan/contracts/proposal.py): Formal `Proposal` contract with fields `proposal_id`, `proposer`, `task_id`, `batch_ids`, `est_cost`, `est_time`, `est_coverage`, `risk`, `round`, and `rationale`.
   - [`src/sentryscan/agents/scout.py`](../../src/sentryscan/agents/scout.py): `ScoutAgent` prioritizing broad host diversity and subnet coverage.
   - [`src/sentryscan/agents/triage.py`](../../src/sentryscan/agents/triage.py): `TriageAgent` prioritizing critical/high-severity exposure ordering.
4. **Multi-Turn Contract-Net Negotiation Protocol:**
   - [`src/sentryscan/negotiation/protocol.py`](../../src/sentryscan/negotiation/protocol.py): Executes the standard speech-act sequence:
     $$\text{CFP} \longrightarrow \text{PROPOSE} \longrightarrow \text{COUNTERPROPOSE} \longrightarrow \text{ACCEPT} / \text{REJECT} \longrightarrow \text{CONFIRM}$$
   - Includes concession formulas across rounds and enforces a strict round limit (default: 5 rounds) terminating safely in `UNRESOLVED` when constraints cannot be satisfied.
5. **Inline Bid Scoring Seam:**
   - [`src/sentryscan/negotiation/scoring.py`](../../src/sentryscan/negotiation/scoring.py): `score_bid()` evaluates normalized coverage, cost, time, and risk, while strictly filtering infeasible proposals (returning $-\infty$). This serves as the documented seam to be swapped by the full multi-attribute optimizer in Assignment 3.2.
6. **LangGraph Dynamic Worker Fan-Out via `Send`:**
   - [`src/sentryscan/graphs/supervisor.py`](../../src/sentryscan/graphs/supervisor.py): Implements the compiled LangGraph supervisor workflow. Upon consensus, dynamically fans out parallel `scanner_worker` nodes for each awarded batch using `Send`. Each worker evaluates records using the plain-Python `RuleEngine` from Milestone 1.2 and streams findings into the state accumulator.

---

## 2. Execution Evidence & Verification

Demonstration artifacts generated from execution:
- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Turn-by-Turn Timeline:** [`evidence/negotiation_timeline.md`](evidence/negotiation_timeline.md)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **Negotiation Handshake:** Complete turn-by-turn timeline recorded (CFP $\to$ PROPOSE $\to$ COUNTERPROPOSE $\to$ PROPOSE $\to$ ACCEPT/REJECT $\to$ CONFIRM).
- **LangGraph Fan-Out:** Verified dynamic dispatch via `Send`, evaluating all awarded batches in parallel workers and aggregating 6 distinct findings.
- **Bounded Unresolved Termination:** Verified that impossible budget constraints terminate cleanly in `UNRESOLVED` at the round limit without infinite loops.
- **Determinism Contract:** Verified 100% identical decision outcomes, findings, and messages across runs with LLM off (0 drift).
- **Unit & Integration Tests:** 70 passed across all test suites (`test_graph_state`, `test_llm`, `test_proposal_roles`, `test_negotiation`, `test_supervisor_graph`, `test_multi_agent_coordination`).

---

## 3. Reproduction Instructions

```bash
# Run deterministic multi-agent coordination demonstration
python demos/demo_assignment_3_1.py

# Run unit and integration tests
pytest -v tests/

# Verify code style and linter
ruff check .

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-3.1
```
