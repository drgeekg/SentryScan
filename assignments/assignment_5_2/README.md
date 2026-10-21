# Assignment 5.2 — Capstone Architecture, Web Dashboard & UI Orchestration

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-5.2`  

---

## 1. Architectural Increment Overview

Assignment 5.2 represents the final capstone milestone of SentryScan, integrating all previous architectural increments into a unified, autonomous multi-agent cyber defense platform with persistent dual-sink observability, an interactive real-time dashboard, and an executive CLI interface:

1. **Integrated LangGraph Supervisor Workflow:**
   - [`src/sentryscan/graphs/supervisor.py`](../../src/sentryscan/graphs/supervisor.py): Unifies Contract-Net task negotiation between Scout and Triage subagents, dynamic worker fan-out scanning, and Ed25519-signed envelope dispatch to the deliberative BDI `AnalystAgent`.
   - When workers report critical vulnerabilities (such as Apache HTTP server path traversal or unencrypted legacy protocols with service contradictions), the supervisor triggers the `analyst_triage_node`, causing the Analyst to enrich beliefs using the local vulnerability ontology (CVE-2021-41773, CVSS v3.1 9.8) and autonomously flag target hosts for quarantine.
2. **Dual-Sink Persistence & Relational SQLite Run Store:**
   - [`src/sentryscan/storage/store.py`](../../src/sentryscan/storage/store.py): Implements `SQLiteRunStore` providing structured relational persistence alongside the authoritative append-only JSONL event trace.
   - Schemas include indexed tables: `runs`, `events`, `messages`, `telemetry_records`, `findings`, `bdi_snapshots`, and `llm_calls`.
   - Dual-sinking in `EventRecorder` assigns monotonic sequence numbers (`seq=1, 2, ...`) simultaneously to both outputs, ensuring zero discrepancy.
3. **Strict 100% Event Parity Verification:**
   - Mathematical guarantee enforced by `SQLiteRunStore.verify_parity()`:
     $$\text{count}(\text{SQLite}) == \text{count}(\text{JSONL}) \quad \land \quad \forall i \in [1, N], \text{seq}_i = i$$
   - Cross-sink verification guarantees complete entity ID alignment and event type consistency with zero sequence gaps.
4. **Loopback REST & WebSocket Gateway:**
   - [`src/sentryscan/dashboard_gateway/server.py`](../../src/sentryscan/dashboard_gateway/server.py): Implements a lightweight FastAPI gateway operating strictly in loopback (`127.0.0.1`).
   - Serves rich REST endpoints for querying run histories, fleet records, security findings, BDI intention snapshots, and LLM audit logs.
   - Provides `/ws/{run_id}` WebSocket channel supporting sequence-based resynchronization (`{"subscribe": run_id, "from_seq": K}`). Historical events $[K, N]$ are immediately backfilled from SQLite before live events are streamed, ensuring zero dropped messages on reconnect.
5. **Interactive Web Dashboard (HTML5 Canvas SPA):**
   - [`frontend/dist/index.html`](../../frontend/dist/index.html): Self-contained single-page application requiring zero external dependencies or Node.js runtime.
   - Features an animated 60fps multi-agent particle network depicting real-time message routing between the Supervisor, Scout, Triage, Analyst, and Worker agents.
   - Displays live KPIs (event count, active agents, discovered findings, quarantined hosts), a responsive findings table with CVSS severity badges, and an auto-scrolling live event log.
6. **Rich Terminal Fallback Dashboard:**
   - [`src/sentryscan/ui/rich_dashboard.py`](../../src/sentryscan/ui/rich_dashboard.py): Full ANSI terminal interface powered by `rich`, providing split-pane views of fleet telemetry, agent negotiation, findings table, and recent audit logs for headless server environments.
7. **One-Command Capstone Runner:**
   - [`main.py`](../../main.py), [`src/sentryscan/capstone.py`](../../src/sentryscan/capstone.py): Top-level executable entry point. Running `python main.py --demo` executes the complete multi-agent pipeline deterministically from scratch in ~1.2 seconds, with an optional `--serve` flag to host the dashboard gateway.

---

## 2. Benchmark Evidence & Deliverables

Demonstration artifacts generated from execution:
- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Capstone Verification Matrix:** [`evidence/capstone_verification_matrix.md`](evidence/capstone_verification_matrix.md)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Key Observed Metrics
| Metric | Value |
|---|---|
| **Fleet Endpoints Ingested** | 4 simulated devices (10 service records) in RFC 5737 space |
| **Controlled Poisoning Vectors** | Telnet banner contradiction injected & flagged |
| **Negotiation Winner** | `scout-agent` (Contract-Net utility score 0.825) |
| **Total Findings Discovered** | 5 findings (2 CRITICAL, 1 HIGH, 2 MEDIUM) |
| **Quarantined Target Hosts** | 1 host (`sim-host-003`) by deliberative BDI AnalystAgent |
| **SQLite Indexed Rows** | 31 events |
| **Authoritative JSONL Lines** | 31 lines |
| **Monotonic Sequence Check** | Gap-free: $\text{seq} \in [1, 31]$, zero missing numbers |
| **Dual-Sink Parity Audit** | **100% Match (PASSED)** |
| **Test Suite Pass Rate** | **149/149 tests passing (100%)** |

---

## 3. Reproduction Instructions

### Run the Capstone Simulation Demo
```bash
# Execute deterministic end-to-end multi-agent capstone pipeline
python main.py --demo

# Or run with the web dashboard gateway active at http://127.0.0.1:8000
python main.py --demo --serve --port 8000
```

### Run the Verification Script
```bash
python demos/demo_assignment_5_2.py
```

### Execute Test Suite
```bash
# Run all unit and integration tests
pytest

# Verify code formatting and linting
ruff check .
```

### Build Submission ZIP Archive
```bash
python scripts/package_assignment.py assignment-5.2
```
