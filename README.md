# SentryScan

[![CI Pipeline](https://github.com/drgeekg/SentryScan/actions/workflows/ci.yml/badge.svg)](https://github.com/drgeekg/SentryScan/actions/workflows/ci.yml)
[![Python Version](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform Version](https://img.shields.io/badge/platform-v2.0-purple.svg)](docs/hld/SentryScan_HLD_v1.2.md)
[![Architecture Status](https://img.shields.io/badge/architecture-dual--product-success.svg)](#1-the-two-integrated-products)

**Autonomous Agentic Security Telemetry Analysis & Cyber Risk Intelligence Platform**  
*Dual-Product Suite: Executive Compliance & Risk Portal + Deep Tactical Multi-Agent SOC Console.*

---

## 1. The Two Integrated Products

SentryScan has evolved into a **dual-product enterprise cyber security suite**, addressing both high-level executive compliance & risk posture and deep tactical multi-agent SOC investigation:

```text
                               +---------------------------------------------+
                               |                 SentryScan                  |
                               |    Autonomous Cyber Security Platform v2.0  |
                               +---------------------------------------------+
                                      /                               \
                                     /                                 \
        +-------------------------------------------+   +-------------------------------------------+
        |                 PRODUCT 1                 |   |                 PRODUCT 2                 |
        |       Executive Cyber & Compliance        |   |            Master Cyber Console           |
        |               PORTAL (/)                  |   |                 (/master)                 |
        +-------------------------------------------+   +-------------------------------------------+
        | • POLARIS: Continuous Compliance Controls |   | • VIGIL: LangGraph Multi-Agent SOC        |
        | • SENTRA: Sensitive Data Discovery        |   | • Live Interactive Agent Topology Graph   |
        | • AI SOC Threat Copilot with Pre-Prompts  |   | • Contract-Net Bidding & Negotiation View |
        | • 30-Min Executive Posture Assessments    |   | • Multi-Stage BDI Deliberation Inspector  |
        | • In-Browser Real-Time Executive PDFs     |   | • Live Simulation & Threat Injection Box  |
        | • Enterprise Asset Inventory (11 Classes) |   | • Dry-Run Containment Playbooks (L1/L2/L3)|
        +-------------------------------------------+   +-------------------------------------------+
```

---

### Product Comparison Matrix

| Capability / Dimension | Product 1: Executive Cyber & Compliance Portal (`/`) | Product 2: Master Cyber Console (`/master`) |
| :--- | :--- | :--- |
| **Primary Audience** | CISOs, Risk Officers, Compliance Auditors, SecOps Leadership | SOC Analysts, Incident Responders, Threat Hunters, Agent Researchers |
| **Access Route** | `http://127.0.0.1:8000/` or `/#/overview`, `/#/copilot` | `http://127.0.0.1:8000/master` or `/#/agents` |
| **Primary Engines** | **POLARIS** (Compliance) + **SENTRA** (Data Discovery) | **VIGIL** (Agentic SOC Multi-Agent Collective) |
| **Intelligence Interface** | Interactive SOC Threat Copilot + 30-Min Posture Reports | BDI Beliefs/Desires/Intentions Inspector + Contract-Net Stream |
| **Reporting & Export** | Real-Time In-Browser PDF Generator (Header, Footer, Tables) | Dry-Run Host Containment Playbooks (iptables & nftables) |
| **Controls & Simulation** | Framework Switcher (ISO 27001, NIST CSF), Remediation Tasks | Live Mutator Injector (Banner Mismatch, TLS Breach, Replays) |
| **Fleet Visibility** | 11 Typed Enterprise Asset Classes with Public/Private Exposure | Dynamic Graph Topology with Animated Inter-Agent Pulse Lines |

---

## 2. Product 1: Executive Cyber & Compliance Portal (`/`)

The Executive Portal provides unified organizational risk visibility, automated compliance auditing, sensitive data exposure mapping, and AI-assisted investigation.

### 2.1 Autonomous SOC Threat Copilot & 30-Minute Posture Reports
Grounded in real-time SQLite telemetry, quarantine records, and BDI beliefs. Features one-click pre-prompt investigation chips, purpose-specific LLM provider routing, and segmented filtering between scheduled 30-minute posture assessments and automated host containment plans.

![SOC Copilot & Reports](screenshots/16_portal_copilot_reports_separated.png)

### 2.2 POLARIS · Continuous Compliance & Governance
Automated control evaluation continuously fed by telemetry integrity checks and data discovery signals. Supports dynamic framework mapping across **Baseline-8**, **ISO/IEC 27001**, and **NIST CSF 2.0**, with customizable profile inheritance (`enterprise`, `healthcare`, `soc_heavy`, `generic`).

### 2.3 SENTRA · Sensitive Data Asset Discovery (RADAR)
Classifies sensitive enterprise data patterns across 6 categories: **PII**, **Health / PHI**, **Financial**, **Intellectual Property**, **Credentials & Secrets**, and **Custom Organizational Identifiers**. Tracks public versus private exposure status with unencrypted storage warnings.

### 2.4 Real-Time Executive PDF Generation
On-demand and scheduled PDF reporting featuring a two-pass `NumberedCanvas` with running headers (`SENTRYSCAN // AUTONOMOUS CYBER SOC PLATFORM`), running footers (`AUTONOMOUS AGENTIC CYBER PLATFORM · VIGIL · SENTRA · POLARIS · Page X of Y`), official classification banners, and formatted markdown tables.

![Real-Time PDF Modal](screenshots/15_pdf_modal_enhanced_header_footer.png)

---

## 3. Product 2: Master Cyber Console (`/master`)

The Master Cyber Console is a high-density, real-time command cockpit designed for deep technical investigation, agent introspection, and controlled adversarial testing.

### 3.1 VIGIL · Agentic SOC Collective & Live Topology Graph
An interactive SVG visualization mapping the live multi-agent hierarchy:
* `fleet_sensor` $\to$ `scanner_worker` $\to$ `supervisor-agent`
* Contract-Net negotiation fan-out between `scout-agent` (coverage maximization) and `analyst-l1-triage` (risk prioritization)
* 3-tier BDI Analyst escalation: L1 Triage $\to$ L2 Incident $\to$ L3 Containment
* `remediator-agent`: Generates verified dry-run containment rules (`iptables` and `nftables`) upon quarantine approval.

![Master Cyber Console](screenshots/10_master_console_active_pipeline.png)

### 3.2 Interactive Threat Injection & Simulation Toolbox
Allows security operators to inject synthetic adversary attacks and telemetry corruptions into the running fleet in real time:
* **Service Banner Mismatch**: Injects conflicting software banners to test reflex detection.
* **TLS Claim Contradiction**: Simulates cleartext ports falsely reporting SSL encryption.
* **Stale Timestamp & Clock Skew**: Tests time-drift detection and replay defense gates.
* **Prompt Injection Banner**: Adversarial text designed to test LLM copilot jailbreak resilience.
* **Replay Floods & Traffic Bursts**: High-frequency telemetry bursts to stress agent negotiation.
* **Simulation Speed & Fleet Pace**: Adjustable live pace slider and profile switching.

![Threat Injection Toolbox](screenshots/11_master_console_toolbox.png)

### 3.3 Streamlined Agent Operations View
Cleaned viewport eliminating redundant headers and button overlaps, providing zero-distraction monitoring of live agent message exchanges, BDI beliefs, and quarantine triggers.

![Live Agent Operations](screenshots/17_agents_page_overlap_fixed.png)

---

## 4. Multi-Provider LLM Intelligence Architecture

SentryScan supports **purpose-specific LLM routing**, allowing operators to direct different subsystems to independent providers, models, or API keys:

```ini
# ==============================================================================
# Purpose-Specific Provider Routing (Configured in .env)
# ==============================================================================

# 1. Executive Posture Reports (e.g. NVIDIA Cloud, OpenAI GPT-4o, Claude)
SENTRYSCAN_REPORT_LLM_PROVIDER=nvidia
SENTRYSCAN_REPORT_LLM_MODEL=openai/gpt-oss-20b
NVIDIA_API_KEY=nvapi-...

# 2. Interactive SOC Copilot Q&A (e.g. Local Self-Hosted Ollama)
SENTRYSCAN_COPILOT_LLM_PROVIDER=ollama
SENTRYSCAN_COPILOT_LLM_MODEL=beam:cloud
OLLAMA_BASE_URL=http://127.0.0.1:11434

# 3. Agent Task Bidding (Deterministic rule-based or lightweight models)
SENTRYSCAN_AGENT_LLM_PROVIDER=deterministic
```

* **Zero-Crash Resilience:** All LLM integrations feature automatic fallback to deterministic, rule-based responses if an external API key is missing, times out, or encounters rate limits.
* **Dual Persistent Sinks:** Every report, message, event, and telemetry packet is written simultaneously to an indexed **SQLite Database** (`run.db`) and an authoritative, monotonic **JSONL Event Stream** (`trace.jsonl`).

---

## 5. Quickstart & Installation

### Prerequisites
- Python 3.11 or 3.12
- Node.js 18+ (for frontend console build)
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

# Install Python package and core dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# Compile Frontend Dashboard (Pre-built bundle included in dist/)
cd frontend
npm install
npm run build
cd ..
```

---

## 6. Launching SentryScan

### 1. Launch Continuous Live SOC (Both Products Active)
Runs continuous enterprise fleet telemetry (100+ devices), multi-agent deliberation, compliance scoring, and both web interfaces on port 8000:
```bash
python main.py --live --devices 100 --profile enterprise --pace 0.5
```
* **Product 1 (Executive & Compliance Portal):** [http://127.0.0.1:8000/](http://127.0.0.1:8000/)  
  * SOC Threat Copilot & Reports: [http://127.0.0.1:8000/#/copilot](http://127.0.0.1:8000/#/copilot)
  * VIGIL Agentic SOC: [http://127.0.0.1:8000/#/vigil](http://127.0.0.1:8000/#/vigil)
  * SENTRA Data Discovery: [http://127.0.0.1:8000/#/sentra](http://127.0.0.1:8000/#/sentra)
  * POLARIS Compliance: [http://127.0.0.1:8000/#/polaris](http://127.0.0.1:8000/#/polaris)
* **Product 2 (Master Cyber Console):** [http://127.0.0.1:8000/master](http://127.0.0.1:8000/master)

### 2. Deterministic Capstone Demonstration
Executes a fixed multi-cycle scenario with Rich CLI terminal graphics and dual-sink parity verification:
```bash
python main.py --demo
```

### 3. High-Frequency Human Workstation Test
Simulates realistic Windows and Linux user workstation traffic (browsing, file collaboration, administrative bursts):
```bash
python main.py --test-human
```

### 4. Running the Test Suite
```bash
pytest -v tests/
```

---

## 7. Repository Layout

```text
sentryscan/
├── config/                        # Runtime configurations and templates
├── docs/                          # Architectural documentation & HLD
│   └── hld/SentryScan_HLD_v1.2.md # Complete architectural reference
├── fixtures/                      # Deterministic test fixtures & profiles
│   ├── knowledge/                 # Vulnerability ontology and CVE maps
│   ├── profiles/                  # Compliance profiles (enterprise, healthcare, generic)
│   └── telemetry/                 # Seeded synthetic telemetry
├── frontend/                      # React + Vite Cyber Console SPA
│   ├── src/                       # Master console, Copilot, Toolbox & Views
│   └── dist/                      # Pre-compiled production bundle
├── screenshots/                   # Platform captures & visual audit assets
├── src/sentryscan/                # Production package
│   ├── actuators/                 # Finding publishers & reporting tools
│   ├── agents/                    # Reflex, Scout, Triage, and Remediator agents
│   ├── analysis/                  # Executive posture report generator & PDF builder
│   ├── bdi/                       # Epistemic beliefs, desires, intentions & deliberator
│   ├── common/                    # Clock, ID generators, utilities
│   ├── contracts/                 # Strongly typed Pydantic models & events
│   ├── dashboard_gateway/         # FastAPI REST & WebSocket server
│   ├── graphs/                    # LangGraph supervisor workflow & typed state
│   ├── integrity/                 # Statistical and structural telemetry checkers
│   ├── knowledge/                 # Vulnerability ontology & NVD adapter
│   ├── live.py                    # Continuous live SOC simulation loop
│   ├── llm/                       # Provider-switchable advisory LLM layer
│   ├── negotiation/               # Contract-Net negotiation & bid scoring
│   ├── observability/             # Event bus, JSONL & SQLite recorders
│   ├── optimizer/                 # Multi-attribute utility engine & constraint filter
│   ├── platform/                  # Core, RADAR, and Pulse compliance engines
│   ├── rules/                     # Deterministic condition-action rule tables
│   ├── security/                  # Cryptographic Ed25519 identity & security gate
│   ├── sensors/                   # Stream parsers & telemetry normalizers
│   ├── simulation/                # Synthetic fleet, human activity & threat mutators
│   ├── storage/                   # Relational SQLite run store & parity verifier
│   └── transport/                 # Binary framing & socket transport
├── tests/                         # Comprehensive unit & integration tests
├── main.py                        # Central CLI & executable runner
├── pyproject.toml                 # Packaging & tool configurations
└── README.md                      # Platform documentation & overview
```

---

## 8. License & Credits

- **Author:** R Ganesh ([@drgeekg](https://github.com/drgeekg))
- **License:** MIT License. See [LICENSE](LICENSE) for details.
