# SentryScan: Assignment 3.1 — Multi-Agent Coordination, Negotiation & LangGraph

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 3.1 — Multi-Agent Coordination & Negotiation  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/3.1-multi-agent-coordination`  
**Git Tag:** `assignment-3.1`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 3.1 implements a distributed **Multi-Agent Coordination & Negotiation architecture** orchestrated by a compiled LangGraph state workflow, modeling the classical **FIPA Contract-Net Protocol (CNP)** (Smith, 1980; Wooldridge, Ch. 7).

### 1.1 Conflicting Agent Roles & Rational Self-Interest
Rather than homogeneous workers, SentryScan coordinates specialized agents with distinct operational preferences:
- **Scout Agent:** Maximizes *host coverage breadth* across the network fleet.
- **Triage Agent:** Maximizes *critical severity risk mitigation*, prioritizing known high-risk hosts.
- **Supervisor Agent:** Acts as the auctioneer, balancing budget constraints and optimizing global system utility.

### 1.2 Bounded Contract-Net Negotiation Protocol
1. Supervisor broadcasts `Call for Proposals (CFP)` specifying constraints (max cost, deadline).
2. Scout and Triage compute candidate plans and return formal `PROPOSE` bids.
3. Supervisor evaluates bids via an objective utility function. If constraints are unsatisfied, Supervisor issues `COUNTERPROPOSE` with relaxed tolerances.
4. When a bid satisfies criteria, Supervisor issues `ACCEPT` to the winning contractor and `REJECT` to the other. Winning agent sends `CONFIRM`.
5. Negotiation terminates within a hard bounded limit ($\le 5$ rounds); if consensus is unachievable, terminates safely in `UNRESOLVED`.

---

## 2. Architecture & Implementation Specification

```
                       ┌────────────────────────┐
                       │    Supervisor Agent    │
                       │ (LangGraph Coordinator)│
                       └───────────┬────────────┘
                                   │
                ┌──────────────────┴──────────────────┐
                │ Broadcast CFP (Budget Constraints)  │
                ▼                                     ▼
     ┌──────────────────────┐              ┌──────────────────────┐
     │     Scout Agent      │              │     Triage Agent     │
     │  (Coverage Focus)    │              │   (Risk Priority)    │
     └──────────┬───────────┘              └──────────┬───────────┘
                │ Submit Proposal                     │ Submit Proposal
                │ (batch-03, cov=0.2, cost=11)        │ (batch-02, cov=0.54, cost=13)
                ▼                                     ▼
     ┌────────────────────────────────────────────────────────────┐
     │       Supervisor Scoring & Evaluation (score_bid)          │
     │      Constraint Relax -> Round 2 Counterproposal           │
     └──────────────────────────────┬─────────────────────────────┘
                                    │
                                    ▼
                     AWARD: Scout Agent Accepted
                     Dynamic Fan-Out via Send("scanner_worker")
```

### 2.1 Dynamic Runtime Fan-Out via LangGraph `Send`
Once the winning proposal is awarded, the supervisor graph dynamically branches execution to parallel worker instances:
```python
# Dispatches parallel scanner workers per awarded telemetry batch
return [Send("scanner_worker", {"batch_id": b, "run_id": state["run_id"]}) 
        for b in awarded_proposal.batch_ids]
```

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. LangGraph Supervisor Workflow** | `src/sentryscan/graphs/supervisor.py`: `StateGraph(SupervisorState)` with negotiation, worker fan-out, and result aggregation | `tests/unit/test_supervisor_graph.py`<br>`demos/demo_assignment_3_1.py` Step 2 | **PASSED** |
| **2. Role Separation (Scout vs. Triage)** | `src/sentryscan/agents/scout.py` (coverage-maximizing) and `src/sentryscan/agents/triage.py` (risk-prioritizing) | `tests/unit/test_proposal_roles.py`<br>`evidence/negotiation_timeline.md` | **PASSED** |
| **3. Contract-Net Negotiation Protocol** | `src/sentryscan/negotiation/protocol.py`: `CFP` $	o$ `PROPOSE` $	o$ `COUNTERPROPOSE` $	o$ `ACCEPT` / `REJECT` $	o$ `CONFIRM` | `evidence/negotiation_timeline.md`<br>`tests/unit/test_negotiation.py` | **PASSED** |
| **4. Inline Bid Scoring Seam (`score_bid`)** | `src/sentryscan/negotiation/scoring.py`: Objective formula over normalized coverage, cost, time, and risk with hard constraint filtering ($-\infty$) | `tests/unit/test_negotiation.py` (`test_score_bid_valid`, `test_score_bid_constraint_violations`) | **PASSED** |
| **5. Dynamic Runtime Fan-Out via `Send`** | `src/sentryscan/graphs/supervisor.py`: Returns `[Send("scanner_worker", ...)]` dynamically dispatching parallel worker instances per awarded batch | `tests/unit/test_supervisor_graph.py`<br>`evidence/run_log.txt` Step 2 | **PASSED** |
| **6. Provider-Neutral Advisory LLM Layer** | `src/sentryscan/llm/`: `LLMProvider` protocol with `DeterministicLLMProvider` (offline template generation) and `FakeLLMProvider` | `tests/unit/test_llm.py`<br>`tests/integration/test_multi_agent_coordination.py` | **PASSED** |
| **7. Bounded Loop & `UNRESOLVED` Termination** | Hard limit (default: 5 rounds) terminating safely in `UNRESOLVED` when constraints cannot be satisfied | `tests/unit/test_negotiation.py` (`test_negotiation_unresolved_after_max_rounds`) | **PASSED** |
| **8. Determinism Contract (LLM Off)** | Deterministic single-threaded execution ensures 0 drift across runs with LLM off or deterministic provider | `tests/integration/test_multi_agent_coordination.py` (`test_trace_identical_with_llm_off`) | **PASSED** |
| **9. Trace Persistence & Single-Writer Auditing** | Sequential JSONL event log capturing every message, proposal, and finding via `src/sentryscan/observability/recorder.py` | `evidence/trace_excerpt.jsonl` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Turn-by-Turn Negotiation Timeline (`evidence/negotiation_timeline.md`)

| Step | Sender | Receiver | Performative | Summary | Nonce |
|---|---|---|---|---|---|
| 1 | `supervisor` | `scout` | `CFP` | Round 1 Constraints: `max_cost=10.5, max_time=250.0` | `30877432d1026706` |
| 2 | `supervisor` | `triage` | `CFP` | Round 1 Constraints: `max_cost=10.5, max_time=250.0` | `d7e805da846a32c3` |
| 3 | `scout` | `supervisor` | `PROPOSE` | Batches: `['batch-03']`, Cost: 11.0, Coverage: 0.20 | `bb81e3c29b621792` |
| 4 | `triage` | `supervisor` | `PROPOSE` | Batches: `['batch-02']`, Cost: 13.0, Coverage: 0.54 | `73c8eb5bb682575e` |
| 5-6 | `supervisor` | Both | `COUNTERPROPOSE` | Round 2 Constraints Relaxed: `max_cost=12.075, max_time=287.5` | — |
| 7-8 | Both | `supervisor` | `PROPOSE` | Re-submitted matching proposals under relaxed budget | — |
| 9 | `supervisor` | `scout` | `ACCEPT` | **AWARDED:** `['batch-03']`, Score: `-0.1256` | `71722f244f58d669` |
| 10 | `supervisor` | `triage` | `REJECT` | Rejected: Lower relative utility score under cost cap | `cbee3772a0770217` |
| 11 | `scout` | `supervisor` | `CONFIRM` | Award confirmed, worker execution begins | `21a278f64f7fd633` |

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_3_1/deliverables/SentryScan_Assignment_3_1_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/3.1-multi-agent-coordination`
4. **Immutable Git Tag:** `assignment-3.1`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_3_1.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_3_1.zip.sha256`

### 5.2 Verification Commands
```bash
# Run multi-agent negotiation demonstration
python demos/demo_assignment_3_1.py

# Execute supervisor graph and negotiation tests
pytest -v tests/unit/test_supervisor_graph.py tests/unit/test_negotiation.py
```
