# SentryScan: Comprehensive Project Resume Dossier & Technical Portfolio

> **Project Name:** SentryScan  
> **Tagline:** Autonomous Agentic SOC Collective & Enterprise Cyber Risk Platform  
> **Repository:** [github.com/drgeekg/SentryScan](https://github.com/drgeekg/SentryScan)  
> **Architecture:** Dual-Product Full-Stack System (FastAPI + React 19 / Vite + BDI Multi-Agent Engine + ReportLab PDF Generator)

---

## 1. Executive Summary & One-Liners

Choose one of these depending on the job title you are targeting:

- **For AI / Agentic Systems Roles:**  
  *"Architected and built **SentryScan**, an autonomous multi-agent Security Operations Center (SOC) running 8 distributed agents coordinated via Contract-Net Protocol (CNP) auctions and Belief-Desire-Intention (BDI) reasoning loops, featuring dual-LLM integration for threat correlation and executive audit reporting."*

- **For Cybersecurity / SOC Automation Roles:**  
  *"Developed **SentryScan**, a dual-interface cyber defense platform combining an automated Agentic SOC for real-time threat detection and mitigation with an Executive Cyber Portal delivering POLARIS compliance tracking, SENTRA data discovery, and automated PDF posture reports."*

- **For Full-Stack / Backend Roles:**  
  *"Engineered a high-throughput enterprise cybersecurity platform with a FastAPI async backend, real-time WebSocket dual-sink streaming, 164 automated tests, and a modern React 19 frontend with interactive SVG topology visualization and browser-native PDF generation."*

---

## 2. Core Architecture & Product Breakdown

SentryScan was designed as a **Dual-Product Platform** sharing a unified telemetry and agentic orchestration engine:

```
                                  ┌────────────────────────────────────────────────────────┐
                                  │               SentryScan Core Engine                   │
                                  │      (FastAPI Async Gateway, State Store, Bus)         │
                                  └──────────────────────────┬─────────────────────────────┘
                                                             │
                             ┌───────────────────────────────┴───────────────────────────────┐
                             ▼                                                               ▼
        ┌─────────────────────────────────────────┐                     ┌─────────────────────────────────────────┐
        │  Product 1: Executive Cyber Portal (/)  │                     │ Product 2: Master Cyber Console (/master│
        ├─────────────────────────────────────────┤                     ├─────────────────────────────────────────┤
        │ • POLARIS Compliance Framework          │                     │ • 8-Agent VIGIL Autonomous SOC          │
        │ • SENTRA Sensitive Data Discovery       │                     │ • Contract-Net Protocol (CNP) Auctions  │
        │ • Interactive AI Threat Copilot         │                     │ • BDI Cognitive Deliberation Inspector  │
        │ • 30-Minute Posture Report Scheduler    │                     │ • Live Interactive SVG Topology Graph   │
        │ • Dynamic ReportLab PDF Generator       │                     │ • Real-Time Threat Injection Toolbox    │
        └─────────────────────────────────────────┘                     └─────────────────────────────────────────┘
```

### Product 1: Executive Cyber & Compliance Portal (`/`)
- **Target Audience:** CISOs, Compliance Officers, Risk Auditors, Security Executives.
- **Key Modules:**
  - **POLARIS Risk & Compliance Engine:** Continuous evaluation of NIST, ISO 27001, SOC2, and CIS benchmarks with weighted scoring algorithms.
  - **SENTRA Data Discovery:** Automated discovery and categorization of structured/unstructured sensitive data (PII, PCI, secrets) across fleet endpoints.
  - **Executive Threat Copilot:** Interactive natural language interface allowing executives to query real-time organizational risk, threat surface, and incident logs.
  - **Automated Posture Reports (30-Minute Cycle):** Background worker that aggregates incident metrics, posture deltas, and compliance trends into structured reports with automated PDF generation.
  - **In-Browser PDF Viewer & Exporter:** Interactive modal with instant binary blob streaming, custom pagination, headers, footers, and executive sign-off blocks.

### Product 2: Master Cyber Console (`/master`)
- **Target Audience:** SOC Analysts, Incident Responders, Threat Hunters, AI Engineers.
- **Key Modules:**
  - **VIGIL 8-Agent Collective:** Fully decentralized multi-agent system executing specialized detection, enrichment, and mitigation pipelines.
  - **Live Interactive SVG Network Topology:** Real-time visual canvas tracking node health, active agent links, packet transmissions, and infection states.
  - **Interactive Threat Injection Toolbox:** Built-in attack simulation suite allowing one-click execution of Port Scans, Ransomware outbreaks, Exfiltration pipelines, and Credential Stuffing to test agent response latency.
  - **Contract-Net Protocol Auction Stream:** Real-time visual inspection of CFP (Call for Proposals), task bids, contract awards, and SLA verifications.
  - **BDI Reasoning Inspector:** Deep introspection into agent Beliefs, Desires, Intentions, and execution states.

---

## 3. Deep-Dive: Key Technical Modules & Innovations

### A. Autonomous Multi-Agent Collective (VIGIL Engine)
- **8 Domain Agents:**
  1. `Gateway Agent`: Ingests raw telemetry, performs initial rate limiting and schema validation.
  2. `Ingestion Agent`: Normalizes logs from syslog, cloud trails, and endpoint daemons.
  3. `Analysis Agent`: Performs statistical anomaly detection and signature correlation.
  4. `ThreatIntel Agent`: Enriches indicators with external threat feeds and CVE databases.
  5. `Correlation Agent`: Correlates multi-stage attacks across disparate network segments.
  6. `Response Agent`: Orchestrates autonomous containment (firewall rule updates, process termination, quarantine).
  7. `Audit Agent`: Maintains an append-only verifiable cryptographic ledger of agent actions.
  8. `Coordinator Agent`: Chairs task auctions and enforces global security policies.
- **Contract-Net Protocol (CNP):**
  - Implemented formal FIPA-compliant negotiation protocol.
  - Tasks broadcasted via `Call for Proposals` (CFP); agents evaluate local compute load, confidence score, and specialty before submitting bids.
  - Coordinator awards contracts dynamically, preventing bottlenecks and single points of failure.
- **BDI (Belief-Desire-Intention) Cognitive Cycle:**
  - Real-time internal state modeling (`Beliefs` = environmental observations; `Desires` = operational goals; `Intentions` = committed action plans).

### B. Dual-LLM & Isolated AI Pipeline
- **Problem Solved:** Prevents rate-limit contention and ensures prompt isolation between fast, interactive user queries and heavy batch reporting.
- **Architecture:**
  - **Interactive Copilot LLM:** Dedicated endpoint tuned for low-latency reasoning and immediate user dialogue.
  - **Reporting LLM:** Independent worker endpoint responsible for summarizing multi-incident narratives and generating executive compliance synopses every 30 minutes.
- **Deterministic Fallbacks:** Built-in template and statistical heuristic fallbacks guarantee 100% uptime for reports even during upstream LLM outages or quota exhaustion.

### C. Enterprise ReportLab PDF Engine
- **Engine:** Programmatic, pixel-perfect PDF document generation using ReportLab.
- **Features:**
  - Dynamic Two-Pass Page Numbering (`Page X of Y`).
  - Professional running headers with security classification banners (`CONFIDENTIAL // STRICT AUDIT`).
  - Running footers with generation timestamps, SHA-256 report verification hashes, and legal notices.
  - Data tables, executive summary cards, and risk severity matrices with adaptive styling.
  - Instant backend base64/binary streaming with in-browser preview modal.

### D. Threat Injection & Traffic Simulation Toolbox
- **Simulation Capabilities:**
  - Simulates 50-100+ concurrent network endpoints (workstations, database servers, IoT gateways, edge routers).
  - Configurable attack scenarios:
    - *Port Scan / Reconnaissance*: Rapid SYN/ACK sweeps across simulated IP subnets.
    - *Ransomware Outbreak*: Mass encrypted file creation alerts, canary file trips, and volume shadow copy deletion attempts.
    - *Data Exfiltration*: Covert DNS tunneling and outbound spikes over non-standard ports.
    - *Credential Stuffing*: Distributed brute-force login attempts against authentication gateways.
  - Dual-event dispatch: Telemetry feeds into both the real-time WebSocket bus and the backend audit trail simultaneously.

---

## 4. Engineering Standards, Testing & CI/CD

- **Test Suite:** **164 automated tests** with 100% pass rate (`pytest -v tests/`).
  - End-to-end integration tests covering REST endpoints, WebSockets, BDI cycles, and CNP negotiations.
  - Mocked LLM clients verifying deterministic response parsing and fallback behaviors.
  - Threat scenario execution tests confirming telemetry ingestion and scoring accuracy.
- **Security & Secret Scanning:**
  - Automated `Gitleaks` integration in CI.
  - Sanitized all test fixtures and mock profile keys; implemented `.gitleaks.toml` configuration for compliant build gates.
- **Code Quality & Linting:**
  - Automated `Ruff` enforcement: 0 errors, 0 warnings.
  - Clean modular architecture under `src/sentryscan/`.
- **Frontend Build:**
  - Modern React 19 + Vite frontend.
  - Zero-bundle error production build with CSS grid/flexbox responsiveness.

---

## 5. Tailored Resume Bullet Points (Copy & Paste Ready)

Select 3-5 bullet points matching your target role:

### Option 1: AI / Agentic Systems / LLM Engineer
- Designed and implemented **VIGIL**, an autonomous multi-agent SOC collective comprising 8 specialized agents utilizing **Contract-Net Protocol (CNP)** task auctions and **Belief-Desire-Intention (BDI)** cognitive reasoning loops.
- Architected a **Dual-LLM orchestration pipeline** separating interactive SOC copilot interactions from 30-minute scheduled executive posture syntheses, ensuring zero-latency contention and prompt isolation.
- Integrated structured LLM output parsing with deterministic fallback heuristics, achieving 100% document generation reliability across upstream API failures.
- Built real-time state introspection tools allowing analysts to inspect agent deliberation cycles, active bids, and decision logic in a live React dashboard.

### Option 2: Cybersecurity / SOC Automation / Security Engineer
- Engineered **SentryScan**, an enterprise cybersecurity platform featuring an autonomous SOC collective, real-time threat detection, and an executive compliance suite (POLARIS / SENTRA).
- Created a **Threat Injection Toolbox** supporting on-demand simulation of multi-vector cyber attacks (Ransomware, Port Scans, DNS Exfiltration, Credential Stuffing) across a simulated 100-endpoint network fleet.
- Built an automated **Executive Posture & Compliance Engine** that audits security posture against NIST, ISO 27001, and SOC2 benchmarks, producing automated PDF audit reports every 30 minutes.
- Implemented an immutable cryptographic audit ledger tracking all autonomous containment and remediation actions executed by agents.

### Option 3: Full-Stack / Distributed Backend Engineer
- Developed a high-performance asynchronous **FastAPI** backend supporting bidirectional WebSocket streaming, event-driven task distribution, and REST APIs.
- Engineered a programmatic **ReportLab PDF generation microservice** featuring running headers/footers, dynamic two-pass pagination (`Page X of Y`), and direct in-browser streaming via binary blobs.
- Built a responsive **React 19 / Vite** single-page application featuring an interactive SVG network topology visualizer with real-time packet animation and link tension physics.
- Established rigorous CI/CD standards with **164 automated pytest tests** (100% pass rate), Gitleaks secret scanning, and Ruff linting, eliminating technical debt and regression risks.

---

## 6. Technical Stack Summary Table

| Category | Technologies / Tools |
| :--- | :--- |
| **Backend & Runtime** | Python 3.11+, FastAPI (Async/Await), Uvicorn, asyncio, Pydantic v2 |
| **Multi-Agent Systems** | FIPA Contract-Net Protocol (CNP), BDI (Belief-Desire-Intention) Cognitive Architecture |
| **AI & LLM Services** | OpenAI / Gemini API Integration, Dual-LLM Pipeline, Isolated Prompting, Structured JSON Parsing |
| **Document Engineering**| ReportLab 4.x (Canvas, PlatyPus, TableStyles, Two-Pass Flowables), In-Browser Blob Streaming |
| **Frontend & UI** | React 19, Vite, Lucide Icons, Pure CSS3 (Flexbox/Grid, Dark Mode Cyber Aesthetics), Interactive SVG |
| **Testing & CI/CD** | Pytest (164 tests), Gitleaks (Secret Scanning), Ruff (Linter/Formatter), GitHub Actions |
| **Simulation & SecOps** | Synthetic Network Traffic Generator, Multi-Vector Attack Simulator, POLARIS / SENTRA Compliance |

---

## 7. System Design & Interview Defense Q&A

When interviewers ask about this project, use these structured answers:

### Q1: "Why did you use Contract-Net Protocol (CNP) instead of a simple message queue or round-robin?"
> *"In a cybersecurity operations environment, agents have distinct competencies (e.g., ThreatIntel vs. Ingestion vs. Response) and variable workloads. Round-robin can assign a critical containment task to an agent currently saturated with log ingestion. CNP allows agents to bid based on their real-time compute capacity, specialized capabilities, and historical confidence scores. The Coordinator agent acts as an auctioneer, awarding tasks to the optimal agent while maintaining strict SLAs."*

### Q2: "How did you solve LLM rate limits and reliability in production?"
> *"I implemented a dual-LLM architecture. Real-time Copilot chat queries use a low-latency endpoint, while scheduled 30-minute posture reports use an isolated batch endpoint. Furthermore, all LLM calls are wrapped in deterministic fallback heuristics: if an upstream API times out or exceeds quotas, the system automatically falls back to algorithmic rule-based summaries and mathematical aggregation, ensuring zero downtime."*

### Q3: "How does the dual-product architecture work without duplicating code?"
> *"Both the Executive Portal (`/`) and the Master Cyber Console (`/master`) share a single unified FastAPI backend and WebSocket bus. The Executive Portal subscribes to high-level compliance metrics, posture deltas, and PDF endpoints, while the Master Console subscribes to raw telemetry, agent auction streams, and BDI cognitive states. This decoupled frontend-backend design provides high data reuse without cluttering the executive experience."*
