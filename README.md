# SentryScan

**Authorized Vulnerability Scanner Agent Simulation for Synthetic Security Telemetry**  
**Course:** 21CSE525T — Agent Technology  
**Author:** R Ganesh [RA2212704010031]  
**Language:** Python 3.11+ / 3.12  

---

## 1. Executive Overview

SentryScan is an autonomous vulnerability analysis agent designed to process, correlate, and prioritize simulated security telemetry across a synthetic multi-host fleet. Built across ten structured assignment milestones, the system evolves from a simple deterministic reflex reasoner into a multi-agent deliberative system featuring LangGraph coordination, Contract-Net negotiation, explicit utility optimization, BDI mental models, and Ed25519 cryptographic message authentication.

### Key Architectural Pillars

- **Deterministic Core:** Authoritative decision paths, rule evaluation, utility scoring, and BDI state transitions are 100% reproducible and deterministic under seeded pseudorandom generation.
- **Provider-Switchable LLM Layer (Advisory Only):** Pluggable support for Local Ollama, NVIDIA NIM, OpenRouter, and commercial cloud providers. LLM output is strictly advisory and validated against typed schemas; graded runs default to the deterministic mock provider.
- **Single-Writer Event Bus & Persistence:** Every percept, decision, message, proposal, and belief update is assigned a monotonic sequence number (`seq`) and persisted to append-only JSONL and queryable SQLite stores.
- **Data Integrity vs. Authentication:** Explicit separation between telemetry plausibility checks (`IntegrityChecker`) and cryptographic inter-agent message validation (Ed25519 security gate).

---

## 2. Safety Boundaries & Non-Goals

> [!IMPORTANT]
> **Strict Simulation Boundary:** SentryScan is exclusively a simulation and telemetry-analysis platform. It does **not** perform active network scanning, raw packet crafting, exploit execution, credential brute-forcing, or unauthorized access.

1. **Synthetic Telemetry Only:** All targets, services, and banners originate from deterministic fixtures or the in-memory `DeviceFleetSimulator`.
2. **Documentation-Range Addressing:** Host network identifiers use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 3849 (`2001:db8::/32`) test prefixes and are never probed.
3. **Ground-Truth Isolation:** Deliberately injected telemetry mutations (poisoning) are tracked in an isolated evaluator-only store. Agents cannot access ground truth labels.
4. **Untrusted Telemetry:** Service banners and telemetry text are treated as untrusted data and wrapped with boundaries to prevent prompt-injection attacks against advisory LLM modules.

---

## 3. Repository Structure

```text
sentryscan/
├── .github/workflows/ci.yml     # Automated CI (linting, tests, secret scanning)
├── assignments/                 # Milestone-specific deliverables and evidence
│   └── TEMPLATE/                # Standard template for assignment artifacts
├── config/                      # Configuration files and templates
├── docs/                        # Architecture specs and High-Level Design (HLD)
│   └── hld/SentryScan_HLD_v1.2.md
├── fixtures/telemetry/          # Seeded deterministic synthetic test fixtures
├── scripts/                     # Automation scripts (packaging, trace normalization)
├── src/sentryscan/              # Core production package
│   ├── contracts/               # Typed Pydantic data schemas
│   ├── common/                  # Injectable clock, determinism helpers
│   ├── rules/                   # Deterministic reflex condition-action rules
│   ├── simulation/              # Synthetic fleet and poisoning generators
│   ├── agents/                  # LangGraph supervisor and specialist roles
│   └── observability/           # Single-writer recorder, JSONL/SQLite sinks
└── tests/                       # Unit and integration test suites
```

---

## 4. Setup and Quickstart

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
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install pinned dependencies and package in editable mode
pip install -r requirements.txt
pip install -e .
```

### Running Tests and Linting
```bash
# Run test suite
pytest -v

# Run linter
ruff check .
```

---

## 5. Ten-Assignment Evolution Roadmap

| Unit / Milestone | Focus Area | Architectural Deliverable | Git Tag |
|---|---|---|---|
| **P0** | Foundation | Monorepo baseline, CI, packaging, HLD | `p0-baseline` |
| **1.1** | Agent Foundations | PEAS table, environment taxonomy, OOP vs Agent analysis | `assignment-1.1` |
| **1.2** | Reflex Reasoner | Deterministic condition-action engine, JSONL event recorder | `assignment-1.2` |
| **2.1** | Concurrency & Data | Monitor daemon, safe queues, fleet simulator, integrity checker | `assignment-2.1` |
| **2.2** | Socket Transport | Localhost TCP socket framing, autonomous Analyst agent | `assignment-2.2` |
| **3.1** | Multi-Agent System | LangGraph supervisor, Scout/Triage roles, Contract-Net CFP | `assignment-3.1` |
| **3.2** | Utility Optimization | Explicit mathematical utility scoring, constraint filtering | `assignment-3.2` |
| **4.1** | Deliberative Agent | BDI mental state model (Beliefs, Desires, Intentions) | `assignment-4.1` |
| **4.2** | Knowledge & Context | Vulnerability ontology, read-only NVD adapter with caching | `assignment-4.2` |
| **E1** | LLM Enabler | Multi-provider adapters (Ollama, Nvidia, OpenRouter, Gemini) | `enabler-llm-providers` |
| **5.1** | Cryptographic Security | Ed25519 envelope signatures, replay cache, security gate | `assignment-5.1` |
| **5.2** | Capstone System | Integrated supervisor graph, SQLite replay, live dashboard | `assignment-5.2` |
