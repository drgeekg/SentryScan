# SentryScan

[![CI Pipeline](https://github.com/drgeekg/SentryScan/actions/workflows/ci.yml/badge.svg)](https://github.com/drgeekg/SentryScan/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Architecture Status](https://img.shields.io/badge/architecture-v1.2-purple.svg)](docs/hld/SentryScan_HLD_v1.2.md)
[![Determinism](https://img.shields.io/badge/audit-deterministic-success.svg)](#determinism-contract)

**Autonomous Security Telemetry Analysis & Vulnerability Assessment Platform**  
*Deterministic Triage, Multi-Agent Coordination, and Verifiable Security Intelligence.*

---

## 1. Overview & Purpose

Modern enterprise networks generate vast amounts of operational security telemetry—service banners, TLS configurations, listening ports, and device state announcements. Security Operations Centers (SOCs) face two critical hurdles:
1. **Severe Alert Fatigue:** High volumes of uncorrelated, noisy alerts obscure critical vulnerabilities.
2. **Operational Fragility of Active Probing:** Intrusive port scanning, packet fuzzing, and live exploit checks can disrupt fragile production services, trigger network locks, or violate compliance policies.

**SentryScan** solves this by providing a **non-intrusive, autonomous agentic platform** for continuous security posture evaluation. Instead of probing live network targets, SentryScan continuously ingests, normalizes, and analyzes streaming endpoint telemetry. It identifies authentic vulnerabilities through deterministic rule tables, detects telemetry tampering via statistical and structural integrity checks, and orchestrates multi-agent task allocation to prioritize high-risk remediation.

---

## 2. System Architecture

SentryScan combines classical deliberative agent paradigms with modern multi-agent orchestration:

```text
       +------------------------------------------------------------------+
       |               Simulated Enterprise Endpoint Fleet                |
       |             (RFC 5737 / RFC 3849 Synthetic IP Space)             |
       +------------------------------------------------------------------+
                                        |
                         Raw Telemetry Stream (JSON)
                                        v
       +------------------------------------------------------------------+
       |                    Sensors & Ingestion Layer                     |
       |   - Schema Validation & Parser       - Injected Clock Binding    |
       |   - Malformed Payload Quarantine     - Documented Display IP     |
       +------------------------------------------------------------------+
                                        |
       +--------------------------------+---------------------------------+
       |                                                                  |
       v                                                                  v
+-------------------------------+              +----------------------------------+
|    Data-Integrity Checker     |              |     Reflex Condition-Action      |
|  - Stale Timestamp Detection  |              |           Rule Engine            |
|  - Service/Banner Contradict  |              |  - Explicit IF-THEN Table        |
|  - Baseline Drift Anomalies   |              |  - Deterministic Severity/Score  |
+-------------------------------+              +----------------------------------+
       |                                                                  |
       +--------------------------------+---------------------------------+
                                        v
       +------------------------------------------------------------------+
       |           Audit & Single-Writer Event Recorder (seq)             |
       |  - Append-Only JSONL Trace           - Queryable SQLite Run Store|
       +------------------------------------------------------------------+
                                        |
                                        v
       +------------------------------------------------------------------+
       |             Future Multi-Agent Orchestration (v0.5+)             |
       |  - LangGraph Supervisor Graph        - Scout vs Triage Contract  |
       |  - Mathematical Utility Maximizer    - Deliberative BDI Engine   |
       |  - Ed25519 Cryptographic Gate        - Switchable Advisory LLM   |
       +------------------------------------------------------------------+
```

### Core Architectural Pillars
- **Authoritative Determinism:** All core evaluation logic—rule matching, data-integrity scoring, utility maximization, and BDI state transitions—is strictly deterministic. Identical random seeds produce byte-identical execution traces.
- **Provider-Switchable Advisory LLM Layer:** Pluggable model providers (Local Ollama, NVIDIA NIM, OpenRouter, Google Gemini, Anthropic, OpenAI) are strictly advisory and schema-validated. An automated deterministic mock provider guarantees test pass rates without API keys.
- **Single-Writer Event Bus:** To ensure bulletproof forensic reproducibility, all percepts, decisions, messages, and state changes pass through a single-writer event recorder that assigns monotonic, gap-free sequence numbers (`seq`).
- **Two-Tier Defensive Gate:** Clear separation between **data integrity** (detecting corrupted or poisoned telemetry records) and **message authentication** (Ed25519 cryptographic signatures and replay caches for inter-agent communication).
- **Ethical Simulation Boundary:** Operates exclusively on synthetic telemetry utilizing IETF documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849: `2001:db8::/32`). SentryScan never crafts active network packets.

---

## 3. Implementation Status & Roadmap

| Version | Status | Milestone | Key Deliverables |
|---|---|---|---|
| **v0.1** | **Released** | Core Foundations | Monorepo baseline, CI/CD pipeline, secret scanning, reproducible packager, High-Level Design (HLD v1.2), formal PEAS & environment model |
| **v0.2** | **Released** | Reflex Reasoner | Injectable clock & deterministic ID generator, telemetry contracts, explicit condition-action rules, JSONL trace recorder, sense-parse-decide-act loop |
| **v0.3** | **Released** | Concurrency & Fleet | Multi-device fleet simulator, background monitor daemon, thread-safe queues, data-integrity checker, isolated ground-truth sidecar |
| **v0.4** | **Released** | Distributed Transport | Length-prefixed binary TCP socket transport, Transport interface with in-process adapter, autonomous Analyst agent with adaptive PARAMS_UPDATE |
| **v0.5** | **Active** | Multi-Agent Coordination | LangGraph supervisor graph, Scout and Triage roles, Contract-Net negotiation (`CFP` $\to$ `PROPOSE` $\to$ `ACCEPT`), subagent fan-out via `Send` |
| **v0.6** | Planned | Utility Optimization | Normalized multi-attribute utility formula, hard constraint filtering, exhaustive optimality verification |
| **v0.7** | Planned | Deliberative BDI | Epistemic Beliefs, Desires, and committed Intentions; autonomous intention reconsideration upon critical finding updates |
| **v0.8** | Planned | Context Enrichment | Vulnerability knowledge ontology, read-only NVD CVE adapter with resilient caching and offline fallback |
| **v0.9** | Planned | Cryptographic Security | Ed25519 message signatures, canonical RFC 8785 envelope bytes, bounded anti-replay nonce cache, security gate |
| **v1.0** | Planned | Capstone & UI | Full supervisor graph integration, SQLite entity persistence, FastAPI WebSocket gateway, live browser visualization |

---

## 4. Repository Layout

```text
sentryscan/
├── .github/workflows/ci.yml       # Automated CI (linting, pytest, secret scanning)
├── assignments/                   # Formal milestone verification & academic packages
│   └── assignment_1_1/            # Environment & PEAS architecture specification
├── config/                        # Runtime configurations and templates
├── docs/                          # Architectural documentation & HLD
│   └── hld/SentryScan_HLD_v1.2.md # Complete architectural reference
├── fixtures/telemetry/            # Seeded deterministic test telemetry
├── scripts/                       # Developer automation scripts
│   ├── export_specification_pdf.py# Headless specification PDF generator
│   └── package_assignment.py      # Tag-based reproducible archive packager
├── src/sentryscan/                # Production package
│   ├── contracts/                 # Strongly typed Pydantic models
│   ├── common/                    # Clock, ID generators, utilities
│   ├── rules/                     # Deterministic rule table & engine
│   ├── sensors/                   # Stream parsers & telemetry normalizers
│   ├── actuators/                 # Finding publishers & reporting tools
│   ├── agents/                    # Reflex and deliberative agent implementations
│   ├── transport/                 # Binary framing, TCP socket client/server, in-process adapter
│   └── observability/             # Event bus, JSONL & SQLite recorders
└── tests/                         # Comprehensive unit & integration tests
```

---

## 5. Quickstart & Installation

### Prerequisites
- Python 3.11 or 3.12
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/drgeekg/SentryScan.git
cd SentryScan

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate       # On Linux/macOS
.venv\Scripts\Activate.ps1      # On Windows PowerShell

# Install package and dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

### Running Tests and Linting
```bash
# Run complete test suite with coverage
pytest -v --cov=sentryscan tests/

# Run code style and lint checks
ruff check .
```

---

## 6. Milestone Packages & Case Studies

For audit and evaluation purposes, each major development milestone maintains a self-contained case study package inside [`assignments/`](assignments/):
- **Milestone 1.1:** [Agent Foundations & PEAS Taxonomy](assignments/assignment_1_1/README.md) — Comprehensive technical specification ([PDF](assignments/assignment_1_1/deliverables/SentryScan_Design_Specification.pdf)), 7-dimensional environment classification, and Unit-1 OOP vs. Agent comparative analysis.
- **Milestone 1.2:** [Rule-Based Reflex Reasoner](assignments/assignment_1_2/README.md) — Executable Sense-Parse-Decide-Act loop, explicit condition-action rule table, malformed payload quarantine, unmatched record auditing, and monotonic `seq` JSONL event recorder.
- **Milestone 2.1:** [Concurrency & Data Integrity](assignments/assignment_2_1/README.md) — Multi-device simulated fleet in RFC 5737 space, background monitor daemon with non-blocking heartbeat, thread-safe queue manager, lost updates race condition proof, controlled poisoning mutators with isolated ground-truth sidecar, and deterministic data-level integrity checker.
- **Milestone 2.2:** [Socket Messaging & Autonomous Analyst](assignments/assignment_2_2/README.md) — 4-byte big-endian length-prefixed JSON binary framing, robust TCP socket client and server with reconnect/backoff, abstract `Transport` protocol with in-process adapter, and autonomous `AnalystAgent` providing adaptive scanning parameter updates in response to `ALERT` messages.

To package any tagged milestone into an immutable, reproducible archive:
```bash
python scripts/package_assignment.py assignment-1.1
```

---

## 7. License & Credits

- **Author:** R Ganesh ([@drgeekg](https://github.com/drgeekg))
- **License:** MIT License. See [LICENSE](LICENSE) for details.
