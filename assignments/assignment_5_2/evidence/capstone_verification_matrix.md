# Assignment 5.2 — Capstone Architecture & Verification Matrix

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Milestone:** Assignment 5.2 (Capstone Architecture, Web Dashboard & UI Orchestration)  
**Execution Date:** 2026-10-21  

---

## 1. Capstone Requirements Verification Matrix

| Requirement | Architectural Component | Implementation Verification | Status |
|---|---|---|---|
| **M1: Switchable LLM Advisory** | [`src/sentryscan/llm/`](../../src/sentryscan/llm/) | `DeterministicLLMProvider` advisory without code changes | **PASSED** |
| **M2: Persistent Event Pipeline** | [`src/sentryscan/observability/`](../../src/sentryscan/observability/) | Single-writer `EventRecorder` assigns monotonic `seq` | **PASSED** |
| **M3: Animated Multi-Agent Canvas** | [`frontend/dist/index.html`](../../frontend/dist/index.html) | HTML5 Canvas particle animation of inter-agent messages | **PASSED** |
| **M4: Synthetic Fleet & Poisoning** | [`src/sentryscan/simulation/`](../../src/sentryscan/simulation/) | RFC 5737 fleet, mutators with isolated ground truth | **PASSED** |
| **M5: Persistent Run Inspection** | [`src/sentryscan/storage/`](../../src/sentryscan/storage/) | Queryable SQLite run store supporting replay without mutation | **PASSED** |
| **M6: Git Commits, Tags & ZIP** | Git history & [`package_assignment.py`](../../scripts/package_assignment.py) | Atomic commits, immutable tags, SHA-256 archive manifest | **PASSED** |
| **M7: Contract-Net Negotiation** | [`src/sentryscan/graphs/supervisor.py`](../../src/sentryscan/graphs/supervisor.py) | Scout vs. Triage negotiation, multi-attribute utility formula | **PASSED** |
| **M8: Deliberative BDI Reasoning** | [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py) | Intention preemption, knowledge enrichment, host quarantine | **PASSED** |
| **M9: Message Security Gate** | [`src/sentryscan/security/`](../../src/sentryscan/security/) | Ed25519 identity, canonical signing, fail-closed gate | **PASSED** |
| **M10: Event Parity & Resync** | [`src/sentryscan/storage/store.py`](../../src/sentryscan/storage/store.py) | Parity test: count(SQLite) == count(JSONL), zero gaps | **PASSED** |

---

## 2. End-to-End Simulation Run Metrics

- **Simulation Run ID:** `run-capstone-evidence`
- **LangGraph Orchestration Phase:** `COMPLETED`
- **Awarded Negotiation Winner:** `scout-agent`
- **Total Identified Findings:** `5`
- **Quarantined Target Hosts:** `['sim-host-003']`
- **SQLite Indexed Rows:** `31`
- **JSONL Stream Lines:** `31`
- **Sequence Gap Check:** `has_seq_gaps=False`
- **Strict Parity Status:** `VERIFIED (100% Match)`

---

## 3. Architecture Layout

```text
                         +-----------------------------------+
                         |     Simulated Fleet Generator     |
                         | (RFC 5737 Space, Normal + Poison) |
                         +-----------------------------------+
                                           |
                                           v
                         +-----------------------------------+
                         |   LangGraph Supervisor Workflow   |
                         | - Contract-Net Scout vs Triage    |
                         | - Multi-Attribute Utility Filter  |
                         | - Dynamic Worker Send Fan-Out     |
                         +-----------------------------------+
                                           |
                                           v
                         +-----------------------------------+
                         |    Inbound Security Gate & BDI    |
                         | - Ed25519 Canonical Verification  |
                         | - Knowledge Enrichment (NVD 2.0)  |
                         | - Autonomous Host Quarantine      |
                         +-----------------------------------+
                                           |
                                           v
               +---------------------------+---------------------------+
               |                                                       |
               v                                                       v
  +--------------------------+                           +--------------------------+
  | Authoritative JSONL Trace|                           |  Indexed SQLite Run Store|
  | (Append-Only Log Stream) |                           |  (Queryable Entities)    |
  +--------------------------+                           +--------------------------+
               |                                                       |
               +---------------------------+---------------------------+
                                           | (100% Parity Verified)
                                           v
                         +-----------------------------------+
                         | Loopback FastAPI & WebSocket Gate |
                         | - REST History & WebSocket Stream |
                         | - Rich CLI Terminal Dashboard     |
                         | - Interactive HTML5 SPA Dashboard |
                         +-----------------------------------+
```
