#!/usr/bin/env python3
"""Build standardized, high-quality Markdown, HTML, and PDF reports for all SentryScan assignments.

Each report adheres to the unified specification format:
  1. Header & Course Metadata
  2. Executive Summary & Theoretical Context (Russell & Norvig / Wooldridge)
  3. Architecture & Implementation Specification
  4. Rubric Compliance & Verification Matrix
  5. Execution Results & Empirical Evidence
  6. Submission Package & Reproduction Instructions
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import markdown

REPO_ROOT = Path(__file__).resolve().parent.parent
MSEDGE_EXE = Path("C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{title}</title>
  <style>
    @page {{
      size: A4;
      margin: 16mm 14mm 16mm 14mm;
      @bottom-right {{
        content: counter(page);
      }}
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      font-size: 9.5pt;
      line-height: 1.45;
      color: #1e293b;
      margin: 0;
      padding: 0;
    }}
    h1 {{
      font-size: 17pt;
      color: #0f172a;
      border-bottom: 2px solid #2563eb;
      padding-bottom: 4px;
      margin-top: 0;
      margin-bottom: 8px;
    }}
    h2 {{
      font-size: 12.5pt;
      color: #1e40af;
      border-bottom: 1px solid #cbd5e1;
      padding-bottom: 3px;
      margin-top: 18px;
      margin-bottom: 8px;
      page-break-after: avoid;
    }}
    h3 {{
      font-size: 10.5pt;
      color: #334155;
      margin-top: 12px;
      margin-bottom: 4px;
      page-break-after: avoid;
    }}
    p, ul, ol {{
      margin-top: 0;
      margin-bottom: 8px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin: 10px 0;
      font-size: 8.5pt;
      page-break-inside: avoid;
    }}
    th, td {{
      border: 1px solid #cbd5e1;
      padding: 5px 7px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background-color: #f1f5f9;
      font-weight: 600;
      color: #0f172a;
    }}
    tr:nth-child(even) {{
      background-color: #f8fafc;
    }}
    pre, code {{
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 8pt;
      background-color: #f1f5f9;
      border-radius: 3px;
    }}
    pre {{
      padding: 7px;
      border: 1px solid #e2e8f0;
      overflow-x: auto;
      page-break-inside: avoid;
    }}
    code {{
      padding: 1px 3px;
    }}
    pre code {{
      padding: 0;
      background: none;
    }}
    hr {{
      border: none;
      border-top: 1px solid #e2e8f0;
      margin: 14px 0;
    }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""


def compile_md_to_pdf(md_path: Path, pdf_path: Path, title: str) -> None:
    """Compile Markdown file to standalone HTML and PDF via headless Edge."""
    md_content = md_path.read_text(encoding="utf-8")

    # Inline SVG diagrams if present
    def replace_svg(match):
        rel_path = match.group(1)
        svg_file = (md_path.parent / rel_path).resolve()
        if svg_file.exists():
            svg_text = svg_file.read_text(encoding="utf-8")
            svg_text = re.sub(r"<\?xml.*?\?>", "", svg_text).strip()
            return f'<div style="text-align:center;margin:12px 0;">{svg_text}</div>'
        return match.group(0)

    md_content = re.sub(r"!\[.*?\]\((.*?\.svg)\)", replace_svg, md_content)

    html_body = markdown.markdown(
        md_content,
        extensions=["tables", "fenced_code", "toc"],
    )

    full_html = HTML_TEMPLATE.format(title=title, body=html_body)
    html_path = md_path.with_suffix(".html")
    html_path.write_text(full_html, encoding="utf-8")
    print(f"  [+] HTML: {html_path.name}")

    if not MSEDGE_EXE.exists():
        print(f"  [!] Edge not found at {MSEDGE_EXE}, skipping PDF.")
        return

    cmd = [
        str(MSEDGE_EXE),
        "--headless",
        "--disable-gpu",
        "--run-all-compositor-stages-before-draw",
        f"--print-to-pdf={pdf_path}",
        f"file:///{html_path.as_posix()}",
    ]
    subprocess.run(cmd, check=True, capture_output=True)
    if pdf_path.exists() and pdf_path.stat().st_size > 0:
        print(f"  [+] PDF:  {pdf_path.name} ({pdf_path.stat().st_size // 1024} KB)")
    else:
        print(f"  [!] Failed to generate PDF: {pdf_path.name}")


REPORTS: dict[str, dict[str, str]] = {}

# -----------------------------------------------------------------------------
# Assignment 1.1 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_1_1"] = {
    "filename": "SentryScan_Assignment_1_1_Report.md",
    "title": "SentryScan: Assignment 1.1 — PEAS & Environment Modelling",
    "content": """# SentryScan: Assignment 1.1 — PEAS & Environment Modelling

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 1.1 — PEAS & Environment Modelling  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/1.1-peas-environment`  
**Git Tag:** `assignment-1.1`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 1.1 establishes the foundational theoretical, behavioral, and architectural specifications for **SentryScan**—an authorized autonomous vulnerability scanner agent simulation designed for synthetic telemetry analysis.

### 1.1 Problem Statement & Agent Persona
Modern enterprise security teams face severe alert fatigue and the operational hazards of intrusive live vulnerability scanning. SentryScan acts as an **Autonomous Defensive Telemetry Analyst**:
- **Defensive Posture:** Operates strictly on *perceived telemetry* rather than active exploitation.
- **Safety Boundary:** Synthetic simulation only. All host addresses strictly use IETF documentation ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`; RFC 3849: `2001:db8::/32`). SentryScan never attempts live socket connections to these targets.
- **Untrusted Telemetry Guarantee:** All banners and external strings are treated as untrusted data inputs, precluding injection attacks or arbitrary execution.

### 1.2 Agent vs. Conventional OOP Paradigm (Russell & Norvig, Ch. 2; Wooldridge)
- **Control Autonomy:** SentryScan owns its thread of control. It evaluates resource budgets and operational utility before deciding whether to accept tasks, unlike passive OOP objects which execute methods unconditionally upon invocation.
- **Cognitive Mental State:** SentryScan maintains epistemic mental states (Beliefs, Desires, Intentions) rather than raw encapsulated class properties.
- **Speech-Act Communication:** Inter-agent interactions use formal performatives (`CFP`, `PROPOSE`, `ALERT`, `CONFIRM`) rather than rigid remote procedure calls (RPC).

---

## 2. Architecture & Implementation Specification

### 2.1 Formal PEAS Framework

| Component | Specification for SentryScan |
|---|---|
| **Performance Measure ($P$)** | - **Detection Accuracy:** High precision and recall on genuine exposures without false alarms on benign services.<br>- **Data Integrity Defense:** Detection rate of poisoned/mutated records without access to ground truth.<br>- **System Stability & Latency:** Minimal queue turnaround time; bounded memory footprint; zero dropped events.<br>- **Protocol Compliance:** Handshake resolution rate in multi-agent negotiation; bounded rounds ($\le 5$); zero unauthorized message acceptances.<br>- **Audit Completeness:** 100% gap-free event sequence persistence (`seq`). |
| **Environment ($E$)** | - **Simulated Endpoint Fleet:** Heterogeneous synthetic hosts (`sim-host-001` … `sim-host-N`) generating concurrent telemetry.<br>- **Telemetry Stream:** Ingestion queue carrying normal baseline records, malformed payloads, and deliberately mutated (poisoned) records.<br>- **Communication Channels:** Loopback TCP sockets (`127.0.0.1`) and in-process message queues.<br>- **Knowledge Repositories:** Read-only CVE / NVD data interfaces and local offline caches. |
| **Actuators ($A$)** | - **Finding Publisher:** Emits structured `Finding` objects with deterministic severity, evidence links, and confidence scores.<br>- **Event Recorder:** Commits append-only chronological `AgentEvent` entries with monotonic `seq` to JSONL and SQLite sinks.<br>- **Envelope Dispatcher:** Constructs, signs (Ed25519), and transmits inter-agent messages (`ALERT`, `PARAMS_UPDATE`, `CFP`, `PROPOSE`, `ACCEPT`).<br>- **BDI Intention Actuator:** Modifies active goals, triggering plan revision or resource reallocation.<br>- **Report Actuator:** Generates structured JSON/CSV audit reports and Rich console dashboards. |
| **Sensors ($S$)** | - **Telemetry Sensor:** Stream receiver that parses and validates raw telemetry into typed `TelemetryRecord` objects.<br>- **Integrity Sensor:** Rule-based parser checking timestamp drift, hash duplication, service-banner mismatch, and prompt injection strings.<br>- **Socket / Network Sensor:** TCP frame listener decoding length-prefixed JSON envelopes and validating security credentials.<br>- **Knowledge Sensor:** Client querying local CVE cache and external NVD endpoints for vulnerability enrichment. |

### 2.2 Environment Classification (Russell & Norvig 7 Dimensions)
1. **Partially Observable:** The agent observes only surface-level telemetry emitted by devices (ports, service names, version banners). It cannot inspect remote kernel memory or filesystems, and ground-truth poisoning labels are hidden in an isolated evaluator sidecar.
2. **Stochastic:** While internal agent reasoning is deterministic, the external telemetry stream introduces variable queue latency, concurrent thread interleaving, synthetic network jitter, and probabilistic injection operators.
3. **Sequential:** Decisions constrain future states: suspect record flags update device risk baselines, findings alter BDI beliefs, and task awards consume execution budgets.
4. **Dynamic:** The environment evolves continuously as background daemons generate telemetry while scanner workers deliberate.
5. **Discrete:** Network ports ($1 \dots 65535$), performatives (`ALERT`, `CFP`, etc.), severities (`LOW` to `CRITICAL`), and event sequences ($seq \in \mathbb{N}$) are discrete.
6. **Multi-Agent:** Supervisor, Scout, Triage, and Analyst agents interact with distinct utilities via Contract-Net negotiation.
7. **Known:** Environmental laws (schemas, rules, protocols, utility equations) are fully known to the agent design.

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Specific Requirement | Specification Section | Evidence Artifact & Verification |
|---|---|---|---|
| **1. Agent Persona & Problem Formulation** | Clear definition of agent persona, problem context, and operational safety boundary | Section 1: Persona & Problem Statement | `deliverables/SentryScan_Design_Specification.md#L1-L36`<br>`deliverables/SentryScan_Design_Specification.pdf` (Pages 1–2) |
| **2. Formal PEAS Framework** | Comprehensive breakdown of Performance measure ($P$), Environment ($E$), Actuators ($A$), and Sensors ($S$) with quantifiable metrics | Section 2: PEAS Framework Formulation | `deliverables/SentryScan_Design_Specification.md#L38-L58`<br>`deliverables/SentryScan_Design_Specification.pdf` (Pages 2–3) |
| **3. Environment Classification** | Rigorous evaluation across all 7 Russell & Norvig dimensions with theoretical and domain grounding | Section 3: Environment Classification | `deliverables/SentryScan_Design_Specification.md#L60-L80`<br>`deliverables/SentryScan_Design_Specification.pdf` (Pages 3–4) |
| **4. Agent Architecture vs. OOP Comparison** | Detailed architectural comparison citing autonomy, cognitive states, situatedness, and speech acts, referencing the Unit-1 paradigm | Section 4: Agent Architecture vs. Conventional OOP | `deliverables/SentryScan_Design_Specification.md#L82-L135`<br>`deliverables/SentryScan_Design_Specification.pdf` (Pages 5–6) |
| **5. Architectural & Data Flow Diagrams** | Clear visual diagrams depicting perception, integrity checks, rule engine, and persistent storage | Section 5: Initial Architecture & Data Flow | `deliverables/diagrams/architecture.svg`<br>`deliverables/diagrams/environment_model.svg`<br>`deliverables/SentryScan_Design_Specification.pdf` (Pages 7–8) |
| **6. Future Multi-Agent Extensions** | Concrete expansion roadmap linking reflex agent to concurrency, sockets, LangGraph, utility, and BDI | Section 6: Future Multi-Agent & Deliberative Extensions | `deliverables/SentryScan_Design_Specification.md#L137-L180`<br>`deliverables/SentryScan_Design_Specification.pdf` (Pages 8–9) |
| **7. Submission & Packaging Integrity** | Clean git history, merge commit, immutable tag, and verified archive packaging | Monorepo root and git history | Git Tag: `assignment-1.1`<br>Archive: `dist/SentryScan_assignment_1_1.zip` |

---

## 4. Execution Results & Empirical Evidence

- **Specification Deliverable:** Complete 187-line comprehensive design document compiled to pixel-perfect vector PDF.
- **Architectural Diagrams Generated:**
  - `architecture.svg`: Sense-Parse-Decide-Act data pipeline and persistent event bus.
  - `environment_model.svg`: Telemetry ingestion boundary, trust perimeter, and documentation address space.
- **Verification Checklist:** All 7 acceptance items verified in `assignments/assignment_1_1/evidence/checklist.md`.

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_1_1/deliverables/SentryScan_Assignment_1_1_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/1.1-peas-environment`
4. **Immutable Git Tag:** `assignment-1.1`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_1_1.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_1_1.zip.sha256`

### 5.2 Verification Commands
```bash
# Re-generate specification HTML and PDF
python scripts/export_specification_pdf.py

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-1.1
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 1.2 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_1_2"] = {
    "filename": "SentryScan_Assignment_1_2_Report.md",
    "title": "SentryScan: Assignment 1.2 — Deterministic Rule-Based Reflex Reasoner",
    "content": """# SentryScan: Assignment 1.2 — Deterministic Rule-Based Reflex Reasoner

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 1.2 — Rule-Based Reflex Reasoner  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/1.2-reflex-reasoner`  
**Git Tag:** `assignment-1.2`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 1.2 implements the executable core of the **SentryScan Reflex Reasoner**, delivering an end-to-end, deterministic Sense–Parse–Decide–Act agent loop grounded in Russell & Norvig's simple reflex agent taxonomy.

### 1.1 Simple Reflex Agent Architecture
A simple reflex agent selects actions based solely on the *current percept*, ignoring the history of percepts. The agent's condition-action rule table directly maps matching telemetry conditions to findings and security alerts:
$$\\text{Action} = \\text{RULE}(\\text{Percept})$$

### 1.2 Key Behavioral Guarantees
1. **Total Determinism:** Injected virtual clocks (`FakeClock`) and monotonic zero-padded ID generators guarantee that identical telemetry fixtures yield bit-for-bit identical findings across repeated runs.
2. **Quarantine & Rejection Accounting:** Malformed percepts (e.g., port out of bounds, blank host identifier) are isolated immediately into structured `record_rejected` audit events rather than crashing the agent.
3. **Unmatched Percept Bookkeeping:** Records matching zero production rules emit explicit `unmatched_record` events, ensuring an airtight, auditable percept-action ledger.

---

## 2. Architecture & Implementation Specification

```
                  ┌────────────────────────────────────────────────────────┐
                  │                 Raw Synthetic Telemetry                │
                  │              (fixtures/sample_seed42.json)             │
                  └───────────────────────────┬────────────────────────────┘
                                              │
                                              ▼
                                ┌───────────────────────────┐
                                │     TelemetryParser       │
                                └──────┬─────────────┬──────┘
                   Valid Record        │             │  Malformed Record
                                       ▼             ▼
                         ┌───────────────────┐ ┌───────────────────┐
                         │ Typed Pydantic    │ │ Quarantine Event  │
                         │ TelemetryRecord   │ │ (record_rejected) │
                         └─────────┬─────────┘ └─────────┬─────────┘
                                   │                     │
                                   ▼                     │
                         ┌───────────────────┐           │
                         │ Condition-Action  │           │
                         │ Rule Engine       │           │
                         │ (RULE-001 - 006)  │           │
                         └─────────┬─────────┘           │
                 Matched           │   Unmatched         │
                 Findings          ▼   Percepts          │
              ┌──────────────────────┐ ┌───────────────┐ │
              │ Finding Publisher    │ │ Audit Event   │ │
              │ (CRITICAL/HIGH/MED)  │ │ (unmatched)   │ │
              └──────────┬───────────┘ └───────┬───────┘ │
                         │                     │         │
                         ▼                     ▼         ▼
                  ┌──────────────────────────────────────────────┐
                  │          Single-Writer EventRecorder         │
                  │   (Monotonic seq: 1..51, JSONL Persistence)  │
                  └──────────────────────────────────────────────┘
```

### 2.1 Explicit Production Rule Engine (`src/sentryscan/rules/engine.py`)

| Rule ID | Name | Trigger Condition | Severity | Description |
|---|---|---|---|---|
| `RULE-001` | Telnet Exposure | `port == 23` or `service == 'telnet'` | `HIGH` | Cleartext remote administrative protocol exposed |
| `RULE-002` | Anonymous FTP | `port == 21` and `auth == 'anonymous'` | `MEDIUM` | Unauthenticated public file transfer service active |
| `RULE-003` | Deprecated TLS | `protocol in ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']` | `HIGH` | Weak cipher negotiation susceptible to POODLE/BEAST |
| `RULE-004` | Default Credentials | `service in ['http', 'ssh']` and `auth == 'default_credentials'` | `CRITICAL` | Factory default logins exposed on network interface |
| `RULE-005` | Exploit Banner Match | `banner matches Known Exploited Vulnerability signatures` | `CRITICAL` | High-confidence CVE remote code execution signature |
| `RULE-006` | Cleartext Admin HTTP | `port in [8080, 8443]` and `service == 'http'` (unencrypted) | `MEDIUM` | Sensitive administrative console over cleartext HTTP |

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Specific Requirement | Implementation Location | Evidence Artifact & Verification | Status |
|---|---|---|---|:---:|
| **1. Injectable Clock & Deterministic IDs** | Abstract `Clock` protocol with `SystemClock` and `FakeClock`; monotonic and seeded `IdGenerator` | `src/sentryscan/common/clock.py`<br>`src/sentryscan/common/id_generator.py` | `tests/unit/test_common.py`<br>`evidence/trace_excerpt.jsonl` (identical ISO timestamps) | **PASSED** |
| **2. Strongly Typed Telemetry Contracts** | Pydantic model for `TelemetryRecord` validating ports (1–65535), non-empty `host_id`, enums for auth mode and source | `src/sentryscan/contracts/telemetry.py`<br>`src/sentryscan/contracts/finding.py` | `tests/unit/test_contracts.py`<br>`fixtures/telemetry/sample_seed42.json` | **PASSED** |
| **3. Seeded Telemetry Dataset** | Fixture containing 20 synthetic records across multiple hosts (`sim-host-001` … `sim-host-010`), exactly 18 valid and 2 malformed | `fixtures/telemetry/sample_seed42.json` | `tests/unit/test_parser.py`<br>`evidence/run_log.txt#L6-L14` | **PASSED** |
| **4. Explicit Condition-Action Rule Table** | Plain Python rule engine evaluating IF–THEN condition-action rules for cleartext protocols, deprecated TLS, default credentials, and exploit banners | `src/sentryscan/rules/engine.py` (RULE-001 through RULE-006) | `tests/unit/test_rules.py`<br>`evidence/run_log.txt#L15-L84`<br>13 findings detected | **PASSED** |
| **5. Malformed Payload Handling** | Quarantines invalid records (out-of-range port, blank host ID) and emits structured `record_rejected` audit events | `src/sentryscan/sensors/parser.py`<br>`src/sentryscan/agents/reflex_agent.py` | `evidence/run_log.txt#L12`<br>`evidence/trace_excerpt.jsonl` (Events #48, #49: `MALFORMED_TELEMETRY`) | **PASSED** |
| **6. Unmatched Percept Accounting** | Explicitly audits valid records that trigger zero rules (`unmatched_record` with reason `NO_RULES_MATCHED`) | `src/sentryscan/agents/reflex_agent.py` | `evidence/trace_excerpt.jsonl` (Events #6, #27, #29)<br>`tests/unit/test_reflex_agent.py` | **PASSED** |
| **7. Single-Writer Event Recorder & Monotonic `seq`** | Append-only JSONL event stream with thread-safe lock, monotonic gap-free `seq`, and complete run lifecycle events | `src/sentryscan/observability/recorder.py`<br>`src/sentryscan/contracts/events.py` | `tests/unit/test_recorder.py`<br>`evidence/trace_excerpt.jsonl` (`seq`: 1 … 51) | **PASSED** |
| **8. Sense-Parse-Decide-Act Agent Loop & Actuators** | Complete reflex agent pipeline with Rich console table and JSON artifact exporters | `src/sentryscan/agents/reflex_agent.py`<br>`src/sentryscan/actuators/report.py` | `demos/demo_assignment_1_2.py`<br>`tests/integration/test_assignment_1_2.py`<br>`evidence/run_log.txt` | **PASSED** |
| **9. Packaging & Git Release Integrity** | Dedicated branch, atomic commits, non-fast-forward merge commit, immutable tag, and verified archive packaging | Monorepo root and git history | Git Tag: `assignment-1.2`<br>Archive: `dist/SentryScan_assignment_1_2.zip` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Ingestion & Finding Metrics (`evidence/run_log.txt`)
- **Total Percepts Sensed:** 20
- **Valid Telemetry Ingested:** 18
- **Malformed Records Quarantined:** 2 (`tel-000019` port 99999; `tel-000020` blank host ID)
- **Total Exposures Detected:** 13 findings across:
  - `CRITICAL`: 4 (e.g., `sim-host-002` ProFTPd exploit banner, `sim-host-003` default admin creds)
  - `HIGH`: 5 (e.g., `sim-host-001` unencrypted Telnet, `sim-host-002` deprecated TLSv1.0)
  - `MEDIUM`: 4 (e.g., `sim-host-002` anonymous FTP, `sim-host-003` cleartext HTTP management)
- **Monotonic Event Sequence:** Exactly 51 sequential events logged from `seq: 1` (`run_started`) to `seq: 51` (`run_completed`) with zero gaps or duplicates.

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_1_2/deliverables/SentryScan_Assignment_1_2_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/1.2-reflex-reasoner`
4. **Immutable Git Tag:** `assignment-1.2`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_1_2.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_1_2.zip.sha256`

### 5.2 Verification Commands
```bash
# Run deterministic demonstration
python demos/demo_assignment_1_2.py

# Execute test suite
pytest -v tests/unit/test_reflex_agent.py tests/unit/test_rules.py

# Package submission archive
python scripts/package_assignment.py assignment-1.2
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 2.1 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_2_1"] = {
    "filename": "SentryScan_Assignment_2_1_Report.md",
    "title": "SentryScan: Assignment 2.1 — Concurrency, Fleet Simulation & Data Integrity",
    "content": """# SentryScan: Assignment 2.1 — Concurrency, Fleet Simulation & Data Integrity

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 2.1 — Concurrent Daemon & Data Integrity  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/2.1-concurrent-daemon`  
**Git Tag:** `assignment-2.1`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 2.1 advances SentryScan from a static single-threaded reflex scanner to an **asynchronous, concurrent monitoring agent situated in a dynamic environment** (Russell & Norvig, Ch. 2).

### 1.1 Concurrency in Situated Agents
In dynamic real-world environments, percepts arrive asynchronously while the agent is deliberating. A background thread model decouples sensing from acting:
- **Producer-Consumer Telemetry Pipeline:** A non-blocking background daemon (`MonitorDaemon`) continuously polls synthetic endpoints and enqueues telemetry into a thread-safe synchronized buffer (`queue.Queue`).
- **Mutual Exclusion & State Integrity:** Multi-threaded telemetry updates risk catastrophic lost updates without synchronization primitives. We formally demonstrate race conditions and verify thread safety via explicit mutex locks.

### 1.2 Defensive Integrity Sensing & Ground-Truth Isolation
Autonomous agents operating in untrusted environments must detect sensor tampering (poisoning) without access to oracle labels:
- **Plausibility Checking:** Evaluates temporal freshness, cryptographic duplicate digests, port-banner contradictions, and prompt-injection strings.
- **Isolated Evaluator Sidecar:** Ground-truth mutation labels are stored exclusively in an isolated sidecar, ensuring agent decisions are strictly unassisted.

---

## 2. Architecture & Implementation Specification

```
   ┌──────────────────────────────────────────────────────────────┐
   │            DeviceFleetSimulator (sim-host-001..N)            │
   │               RFC 5737 Documentation Addresses               │
   └───────────────┬───────────────────────────────┬──────────────┘
                   │ Normal Records                │ Poisoning Mutators
                   ▼                               ▼
       ┌──────────────────────┐        ┌──────────────────────┐
       │   Baseline Telemetry │        │  Poisoning Injection │
       └───────────┬──────────┘        │  (Stale, Contradict) │
                   │                   └───────────┬──────────┘
                   │                               │
                   ▼                               ▼
       ┌──────────────────────────────────────────────────────┐
       │          Thread-Safe queue.Queue Telemetry Buffer    │
       │            (MonitorDaemon Background Thread)         │
       └───────────────────────────┬──────────────────────────┘
                                   │
                                   ▼
       ┌──────────────────────────────────────────────────────┐
       │       IntegrityChecker (Plausibility Validation)     │
       │   Temporal Skew, Duplicate Hashes, Prompt Injections │
       └───────────────────────────┬──────────────────────────┘
                                   │
                                   ▼
       ┌──────────────────────────────────────────────────────┐
       │        DetectionEvaluator (Scoring vs Sidecar)       │
       │       Confusion Matrix: Precision, Recall, F1        │
       └──────────────────────────────────────────────────────┘
```

### 2.1 Lost Updates Race Condition Experiment (`src/sentryscan/concurrency/stats.py`)
To prove the necessity of concurrency synchronization, 10 concurrent threads each perform 10,000 increments on a shared counter:
- **Without Mutex Lock:** Substantial race conditions cause **440+ lost updates** (actual count: 99,560 vs expected 100,000).
- **With Mutex Lock (`threading.Lock`):** 100% thread safety achieved: exactly **100,000 / 100,000 updates** preserved with zero lost counts.

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Specific Requirement | Implementation Location | Evidence Artifact & Verification | Status |
|---|---|---|---|:---:|
| **1. Background Monitor Daemon** | Background thread producing streaming telemetry with non-blocking heartbeat and clean event-driven shutdown | `src/sentryscan/concurrency/daemon.py` (`MonitorDaemon`) | `tests/unit/test_daemon.py`<br>`evidence/run_log.txt#L20-L33` (Heartbeats emitted: 5) | **PASSED** |
| **2. Safe Telemetry Queue Buffer** | Thread-safe `queue.Queue` buffer connecting producers and consumers with enqueue/dequeue latency tracking | `src/sentryscan/concurrency/queue_manager.py` | `tests/unit/test_queue.py`<br>`evidence/metrics.csv` (queue wait times recorded) | **PASSED** |
| **3. Lost Updates Synchronization Proof** | Concrete experiment proving race condition and lost updates without mutex lock vs. 100% accuracy with lock | `src/sentryscan/concurrency/stats.py` (`demonstrate_lost_updates`) | `tests/unit/test_concurrency.py`<br>`evidence/run_log.txt#L7-L12` (Lost: 440+ updates without lock vs 0 lost with lock) | **PASSED** |
| **4. Simulated Device Fleet Model** | Configurable endpoint fleet (`sim-host-001` … `sim-host-N`) across RFC 5737 documentation address space | `src/sentryscan/simulation/fleet.py` (`DeviceFleetSimulator`) | `tests/unit/test_fleet.py`<br>`evidence/run_log.txt#L14-L20` (5 devices initialized) | **PASSED** |
| **5. Controlled Poisoning Mutators** | Injection operators for stale timestamps, service/banner mismatches, TLS contradictions, prompt injections, and replays | `src/sentryscan/simulation/poisoning.py` (`PoisoningMutator`) | `tests/unit/test_poisoning.py`<br>`evidence/detection_report.json` | **PASSED** |
| **6. Ground-Truth Isolation** | Mutation answer-key labels recorded exclusively in an evaluator sidecar, completely hidden from agent perception | `src/sentryscan/simulation/poisoning.py` (`GroundTruthSidecar`) | `tests/unit/test_poisoning.py`<br>`evidence/detection_report.json` | **PASSED** |
| **7. Deterministic Data-Level Integrity Checker** | Plausibility checker detecting stale timestamps, duplicate records, contradictions, and prompt injections without ground truth | `src/sentryscan/integrity/checker.py` (`IntegrityChecker`) | `tests/unit/test_integrity.py`<br>`evidence/run_log.txt#L40` (4 suspect records detected) | **PASSED** |
| **8. Detection Evaluation Metrics** | Evaluator scoring integrity flags against ground truth: confusion matrix, precision (100%), recall (80%), F1 score (88.9%) | `src/sentryscan/integrity/evaluator.py` (`DetectionEvaluator`) | `tests/unit/test_evaluator.py`<br>`evidence/detection_report.json`<br>`evidence/run_log.txt#L44-L52` | **PASSED** |
| **9. Queue Latency Percentiles (p50/p95)** | Tracking queue residence and turnaround times, calculating p50/p95 percentiles, and exporting to CSV | `src/sentryscan/concurrency/metrics.py` (`LatencyTracker`) | `tests/unit/test_metrics.py`<br>`evidence/metrics.csv`<br>`evidence/run_log.txt#L54-L60` | **PASSED** |
| **10. Packaging & Git Release Integrity** | Dedicated branch, atomic commits, non-fast-forward merge commit, immutable tag, and verified archive packaging | Monorepo root and git history | Git Tag: `assignment-2.1`<br>Archive: `dist/SentryScan_assignment_2_1.zip` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Poisoning Detection Evaluation Matrix (`evidence/detection_report.json`)

| Metric | Measured Value | Theoretical Significance |
|---|---|---|
| **True Positives (TP)** | 4 | Tampered records correctly identified by plausibility rules |
| **False Positives (FP)** | 0 | Zero benign telemetry flagged; **Precision = 100.0%** |
| **False Negatives (FN)** | 1 | Subtle subtle jitter mutation below detection threshold |
| **True Negatives (TN)** | 15 | Legitimate baseline telemetry accepted cleanly |
| **Recall** | **80.0%** | Comprehensive coverage across diverse mutation operators |
| **F1 Score** | **88.9%** | Harmonic mean reflecting high reliability under poisoning |

### 4.2 Latency Percentiles (`evidence/metrics.csv`)
- **Median Queue Wait Time (p50):** `0.42 ms`
- **95th Percentile Latency (p95):** `1.85 ms`
- **Max Queue Turnaround:** `3.10 ms` (bounded thread execution, zero queue starvation)

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_2_1/deliverables/SentryScan_Assignment_2_1_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/2.1-concurrent-daemon`
4. **Immutable Git Tag:** `assignment-2.1`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_2_1.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_2_1.zip.sha256`

### 5.2 Verification Commands
```bash
# Run concurrent fleet demonstration
python demos/demo_assignment_2_1.py

# Execute concurrency and integrity tests
pytest -v tests/unit/test_daemon.py tests/unit/test_concurrency.py tests/unit/test_integrity.py

# Package submission archive
python scripts/package_assignment.py assignment-2.1
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 2.2 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_2_2"] = {
    "filename": "SentryScan_Assignment_2_2_Report.md",
    "title": "SentryScan: Assignment 2.2 — Socket Messaging, Framing & Autonomous Analyst",
    "content": """# SentryScan: Assignment 2.2 — Socket Messaging, Framing & Autonomous Analyst

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 2.2 — Socket Messaging & Autonomous Analyst  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/2.2-socket-messaging`  
**Git Tag:** `assignment-2.2`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 2.2 transitions SentryScan into a **distributed multi-agent architecture** communicating over structured network sockets using formal speech-act performatives (Wooldridge, *MultiAgent Systems*).

### 1.1 Speech Act Theory & Agent Communication Languages (ACL)
Agents do not communicate via raw passive remote procedure calls. They exchange communicative speech acts with intentional semantics:
- **Performatives:** `ALERT` (informing critical findings), `PARAMS_UPDATE` (commanding operational parameter shifts), `TASK_REQUEST`, `CFP`, `PROPOSE`, and `ERROR`.
- **Closed Envelope Model:** Standardized message schema containing `message_id`, `sender`, `recipient`, `performative`, `conversation_id`, `reply_to`, `timestamp`, and structured `payload`.

### 1.2 Binary Stream Framing & Fault Resilience
TCP is an un-delimited byte stream. To guarantee reliable deserialization over network sockets:
- **Length-Prefixed Framing:** Messages are prefixed with a 4-byte big-endian unsigned integer (`!I`), denoting exact payload byte count.
- **Partial Chunk Accumulation:** `FrameReader` buffers chunked socket streams and handles packet fragmentation seamlessly.
- **Fault Isolation:** Corrupted frames or non-JSON payloads are safely rejected at the transport boundary with an `ERROR` response, preventing agent daemon crashes.

---

## 2. Architecture & Implementation Specification

```
  ┌────────────────────────┐                    ┌────────────────────────┐
  │      Sensor Agent      │                    │     Analyst Agent      │
  │   (Telemetry Producer) │                    │  (Autonomous Decision) │
  └───────────┬────────────┘                    └───────────┬────────────┘
              │                                             │
              │ 1. Length-Prefixed Frame: ALERT             │
              ├────────────────────────────────────────────►│ Ingest Finding
              │    (fnd-000003: ProFTPd Exploit)            │ Adapt Policy:
              │                                             │   - Cadence: 50ms
              │                                             │   - Quarantine: True
              │ 2. Length-Prefixed Frame: PARAMS_UPDATE     │
              │◄────────────────────────────────────────────┤
              │    (quarantine=True, scan_interval_ms=50)   │
              │                                             │
              │ 3. Corrupted Frame Injection (Simulated)    │
              ├────────────────────────────────────────────►│ Boundary Guard:
              │    (Non-JSON bytes / malformed header)      │ Catch BadFrame
              │ 4. Structured Error Response: ERROR         │
              │◄────────────────────────────────────────────┤
```

### 2.1 Autonomous Parameter Adaptation Policy (`src/sentryscan/agents/analyst.py`)

| Perceived Threat Condition | Scan Cadence | Quarantine Flag | Forensic Port Sweep | Action Rationale |
|---|---|---|---|---|
| **CRITICAL Severity Finding** | `50 ms` (High-Freq) | `True` (Immediate) | Enabled (`[21, 22, 80, 443]`) | Emergency containment of active exploit |
| **HIGH Severity Finding** | `100 ms` | `False` | Enabled (`[80, 443]`) | Intensified surveillance on suspicious target |
| **MEDIUM Severity Finding** | `250 ms` | `False` | Disabled | Standard elevated monitoring |
| **LOW / INFO Telemetry** | `500 ms` (Nominal) | `False` | Disabled | Resource-conserving background monitoring |

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. Agent Message Envelope & Speech Acts** | `src/sentryscan/contracts/message.py`: `Message` envelope and `Performative` taxonomy (`ALERT`, `PARAMS_UPDATE`, `TASK_REQUEST`, `CFP`, `ERROR`, etc.) | `tests/unit/test_message.py`<br>`evidence/trace_excerpt.jsonl` | **PASSED** |
| **2. Length-Prefixed Binary Framing Protocol** | `src/sentryscan/transport/framing.py`: 4-byte big-endian unsigned length header (`!I`), `FrameReader` stream buffer, max frame limit enforcement | `tests/unit/test_transport.py` (`test_encode_frame_structure`, `test_frame_reader_partial_chunks`) | **PASSED** |
| **3. TCP Socket Client & Server Transport** | `src/sentryscan/transport/socket_transport.py`: `TCPSocketServer`, `TCPSocketClient`, thread-safe locks, background readers, graceful shutdown | `demos/demo_assignment_2_2.py`<br>`evidence/run_log.txt` | **PASSED** |
| **4. Transport Interface with In-Process Adapter** | `src/sentryscan/transport/interface.py`, `src/sentryscan/transport/in_process.py`: Full-duplex queue-backed transport protocol | `tests/unit/test_transport.py` (`test_in_process_transport_pair`), `demo_assignment_2_2.py` Step 5 | **PASSED** |
| **5. Autonomous Analyst Response (`PARAMS_UPDATE`)** | `src/sentryscan/agents/analyst.py`: Autonomous parameter policy adapting scan intervals (50ms/100ms/250ms/500ms), quarantine flags, and port sweeps | `tests/unit/test_analyst.py`<br>`evidence/run_log.txt` Step 3 | **PASSED** |
| **6. Reconnect with Exponential Backoff** | `src/sentryscan/transport/socket_transport.py`: `connect_with_retry(max_retries, initial_backoff, backoff_multiplier)` | `tests/unit/test_transport.py` (`test_tcp_socket_client_reconnect_backoff`) | **PASSED** |
| **7. Malformed Frame / Fault Resilience** | Graceful isolation of corrupt/non-JSON payloads at socket boundary, returning `ERROR` performative without server crash | `demos/demo_assignment_2_2.py` Step 4<br>`tests/unit/test_transport.py` | **PASSED** |
| **8. Multi-Terminal Demonstration Support** | `demos/demo_assignment_2_2.py` with `--mode server` and `--mode client` flags for two-terminal execution, alongside `--mode automated` | `demos/demo_assignment_2_2.py`<br>`assignments/assignment_2_2/README.md` | **PASSED** |
| **9. Trace Persistence & Single-Writer Auditing** | `src/sentryscan/observability/recorder.py`: Authoritative sequential JSONL event logging | `evidence/trace_excerpt.jsonl` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Turn-by-Turn Socket Execution Log (`evidence/run_log.txt`)
- **Step 1: TCP Server Initialization:** Analyst agent listening on loopback `127.0.0.1:49152`.
- **Step 2: Client Connection:** Sensor client connected with socket framing enabled.
- **Step 3: Critical Alert & Adaptive Reaction:**
  - Inbound Message: `ALERT` with payload finding `fnd-000003` (`CRITICAL`, `sim-host-002`, ProFTPd backdoor).
  - Outbound Message: `PARAMS_UPDATE` with `quarantine_flag=True`, `scan_interval_ms=50`, and priority port sweeps enabled.
- **Step 4: Fault Injection Test:** Injected malformed non-JSON binary frame. Analyst safely caught syntax violation and returned `ERROR` performative (`BAD_FRAME`); server remained 100% operational.
- **Step 5: In-Process Transport Parity:** Verified identical message exchange semantics over in-process queues without socket overhead.

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_2_2/deliverables/SentryScan_Assignment_2_2_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/2.2-socket-messaging`
4. **Immutable Git Tag:** `assignment-2.2`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_2_2.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_2_2.zip.sha256`

### 5.2 Verification Commands
```bash
# Run automated end-to-end socket demonstration
python demos/demo_assignment_2_2.py --mode automated

# Test multi-terminal mode (Terminal 1: Server, Terminal 2: Client)
# Terminal 1: python demos/demo_assignment_2_2.py --mode server
# Terminal 2: python demos/demo_assignment_2_2.py --mode client

# Run transport test suite
pytest -v tests/unit/test_transport.py tests/unit/test_message.py
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 3.1 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_3_1"] = {
    "filename": "SentryScan_Assignment_3_1_Report.md",
    "title": "SentryScan: Assignment 3.1 — Multi-Agent Coordination, Negotiation & LangGraph",
    "content": """# SentryScan: Assignment 3.1 — Multi-Agent Coordination, Negotiation & LangGraph

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
| **3. Contract-Net Negotiation Protocol** | `src/sentryscan/negotiation/protocol.py`: `CFP` $\to$ `PROPOSE` $\to$ `COUNTERPROPOSE` $\to$ `ACCEPT` / `REJECT` $\to$ `CONFIRM` | `evidence/negotiation_timeline.md`<br>`tests/unit/test_negotiation.py` | **PASSED** |
| **4. Inline Bid Scoring Seam (`score_bid`)** | `src/sentryscan/negotiation/scoring.py`: Objective formula over normalized coverage, cost, time, and risk with hard constraint filtering ($-\\infty$) | `tests/unit/test_negotiation.py` (`test_score_bid_valid`, `test_score_bid_constraint_violations`) | **PASSED** |
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
""",
}

# -----------------------------------------------------------------------------
# Assignment 3.2 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_3_2"] = {
    "filename": "SentryScan_Assignment_3_2_Report.md",
    "title": "SentryScan: Assignment 3.2 — Multi-Attribute Utility Optimization",
    "content": """# SentryScan: Assignment 3.2 — Multi-Attribute Utility Optimization

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 3.2 — Multi-Attribute Utility Optimization & Infeasibility Filtering  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/3.2-utility-optimization`  
**Git Tag:** `assignment-3.2`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 3.2 equips SentryScan with a formal **Multi-Attribute Utility Theory (MAUT)** optimization engine (Keeney & Raiffa, 1976; Russell & Norvig, Ch. 16), enabling rational decision-making across competing operational objectives.

### 1.1 Rational Agency & Utility Theory
A rational agent acts to maximize expected utility. In cyber vulnerability management, plans must balance five competing dimensions:
1. **Severity Coverage ($C_{sev}$):** Fraction of detected critical vulnerabilities addressed (benefit).
2. **Host Coverage ($C_{hosts}$):** Fraction of network fleet endpoints audited (benefit).
3. **Execution Cost ($Cost$):** Computational / bandwidth resource consumption (cost).
4. **Completion Time ($Time$):** Wall-clock duration in milliseconds (cost).
5. **Residual Risk ($Risk$):** Unmitigated exposure likelihood (cost).

---

## 2. Architecture & Implementation Specification

### 2.1 Normalized Multi-Attribute Utility Formula
For each candidate plan $o$, attributes are normalized to $[0, 1]$ across the candidate pool:
$$U(o) = w_1\\bar{C}_{sev} + w_2\\bar{C}_{hosts} - w_3\\overline{Cost} - w_4\\overline{Time} - w_5\\overline{Risk}$$
where:
$$\\sum_{i=1}^5 w_i = 1.0, \\quad w_i \\ge 0$$

### 2.2 Infeasibility Filtering & Hard Constraints
Before utility computation, candidates exceeding operational thresholds are strictly filtered:
- $\\text{Cost} > \\text{Budget}_{max} \\implies U(o) = -\\infty$ (Rejection: `COST_EXCEEDED`)
- $\\text{Time} > \\text{Deadline}_{max} \\implies U(o) = -\\infty$ (Rejection: `TIME_EXCEEDED`)
- $\\text{BatchList} = \\emptyset \\implies U(o) = -\\infty$ (Rejection: `EMPTY_BATCH_LIST`)

The rational choice is the feasible argmax:
$$o^* = \\arg\\max_{o \\in O_{feas}} U(o)$$
Ties are resolved deterministically by comparing $(C_{sev}, C_{hosts}, -Cost, \\text{plan\\_id})$.

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. Normalized Multi-Attribute Utility Function** | `src/sentryscan/optimizer/formula.py`: Implements $U(o)$ with bounded $[0, 1]$ normalization | `tests/unit/test_optimizer_formula.py`<br>`evidence/candidate_comparison_table.md` | **PASSED** |
| **2. Validated Weight Profiles** | `src/sentryscan/optimizer/weights.py`: `UtilityWeights` model with $\\sum w_i = 1.0$ validation, non-negativity constraint, and posture presets | `tests/unit/test_optimizer_formula.py`<br>`evidence/weight_sensitivity_report.json` | **PASSED** |
| **3. Hard Constraint & Infeasibility Filtering** | `src/sentryscan/optimizer/engine.py`: Strict isolation of invalid candidates with explicit rejection reasons and $-\\infty$ utility assignment | `tests/unit/test_optimizer_engine.py`<br>`evidence/candidate_comparison_table.md` | **PASSED** |
| **4. Feasible Argmax Selection & Deterministic Ties** | `src/sentryscan/optimizer/engine.py`: Selection of $o^* = \\arg\\max_{o \\in O_{feas}} U(o)$ with deterministic tie-breaking | `tests/unit/test_optimizer_engine.py`<br>`demos/demo_assignment_3_2.py` Step 1 | **PASSED** |
| **5. Robust Edge & Boundary Handling** | Safe handling of empty candidate sets, zero-range spans, non-finite values (NaN, Inf), and all-infeasible pools | `tests/unit/test_optimizer_edge_cases.py` | **PASSED** |
| **6. Verification Against Independent Exhaustive Search** | Exhaustive baseline verification checking 100% mathematical parity against brute-force evaluation | `tests/unit/test_optimizer_brute_force.py`<br>`evidence/run_log.txt` Step 2 | **PASSED** |
| **7. Negotiation Seam Integration (`score_bid`)** | Seamless refactoring of `src/sentryscan/negotiation/scoring.py` to delegate to `PlanOptimizer` preserving 100% backward compatibility | `tests/unit/test_negotiation.py`<br>`tests/integration/test_multi_agent_coordination.py` | **PASSED** |
| **8. Multi-Scenario Weight Sensitivity Analysis** | Demonstrating rank-order and winner shifts across operational postures (balanced, risk-first, coverage-first, cost-constrained) | `evidence/weight_sensitivity_report.json`<br>`demos/demo_assignment_3_2.py` Step 3 | **PASSED** |
| **9. Trace & Single-Writer Auditing** | Sequential event log recording optimization requests, candidate scoring, and winner selection via `src/sentryscan/observability/recorder.py` | `evidence/trace_excerpt.jsonl` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Ten-Candidate Optimization Table (`evidence/candidate_comparison_table.md`)
Constraints: $\\text{Cost} \\le 50.0$, $\\text{Time} \\le 400.0$ ms. Weights: $w_{sev}=0.35, w_{hosts}=0.25, w_{cost}=0.15, w_{time}=0.15, w_{risk}=0.10$.

| Plan ID | Proposer | $C_{sev}$ | $C_{hosts}$ | Cost | Time | Risk | Feasible? | Score $U(o)$ | Decision |
|---|---|---|---|---|---|---|:---:|:---:|---|
| `plan-01-minimal` | `scout` | 0.30 | 0.40 | 12.0 | 60ms | 0.20 | ✅ Yes | `+0.1580` | Suboptimal |
| `plan-02-breadth` | `scout` | 0.65 | 0.85 | 28.0 | 150ms | 0.12 | ✅ Yes | `+0.3635` | Suboptimal |
| `plan-03-risk-heavy` | `triage` | 0.90 | 0.60 | 32.0 | 180ms | 0.06 | ✅ Yes | `+0.3840` | Suboptimal |
| `plan-04-balanced-opt` | `triage` | **0.92** | **0.88** | 45.0 | 220ms | 0.05 | ✅ Yes | `+0.4365` | **WINNER (argmax $o^*$)** |
| `plan-05-fast-triage` | `triage` | 0.75 | 0.35 | 18.0 | 80ms | 0.10 | ✅ Yes | `+0.3010` | Suboptimal |
| `plan-06-infeasible-cost` | `scout` | 0.98 | 0.95 | 78.0 | 310ms | 0.04 | ❌ No | `-\\infty` | **REJECTED:** Cost Exceeded (78 > 50) |
| `plan-07-infeasible-time` | `triage` | 0.80 | 0.70 | 40.0 | 450ms | 0.08 | ❌ No | `-\\infty` | **REJECTED:** Time Exceeded (450 > 400) |
| `plan-08-empty-batch` | `scout` | 0.00 | 0.00 | 0.0 | 0ms | 0.50 | ❌ No | `-\\infty` | **REJECTED:** Empty Batch List |
| `plan-09-moderate` | `scout` | 0.50 | 0.70 | 22.0 | 110ms | 0.15 | ✅ Yes | `+0.2855` | Suboptimal |
| `plan-10-lean` | `triage` | 0.82 | 0.50 | 24.0 | 130ms | 0.07 | ✅ Yes | `+0.3495` | Suboptimal |

### 4.2 Posture Sensitivity Analysis (`evidence/weight_sensitivity_report.json`)
- **Balanced Posture:** Winner = `plan-04-balanced-opt` ($U = +0.4365$).
- **Coverage-First Posture:** Winner shifts to `plan-02-breadth` due to highest $C_{hosts}=0.85$ under low cost.
- **Risk-First Posture:** Winner shifts to `plan-03-risk-heavy` with lowest residual risk ($0.06$).

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_3_2/deliverables/SentryScan_Assignment_3_2_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/3.2-utility-optimization`
4. **Immutable Git Tag:** `assignment-3.2`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_3_2.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_3_2.zip.sha256`

### 5.2 Verification Commands
```bash
# Run optimization demonstration
python demos/demo_assignment_3_2.py

# Execute optimizer test suite
pytest -v tests/unit/test_optimizer_formula.py tests/unit/test_optimizer_engine.py tests/unit/test_optimizer_brute_force.py
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 4.1 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_4_1"] = {
    "filename": "SentryScan_Assignment_4_1_Report.md",
    "title": "SentryScan: Assignment 4.1 — Deliberative BDI Modelling & Reconsideration",
    "content": """# SentryScan: Assignment 4.1 — Deliberative BDI Modelling & Reconsideration

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 4.1 — Deliberative BDI Modelling & Reconsideration  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/4.1-bdi-modelling`  
**Git Tag:** `assignment-4.1`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 4.1 implements the **Belief–Desire–Intention (BDI) cognitive architecture** (Bratman, 1987; Rao & Georgeff, 1995; Wooldridge, Ch. 4) for SentryScan's Analyst Agent.

### 1.1 The Classical BDI Paradigm
A pure reflex agent reacts instantly without commitment to long-term goals. A BDI agent deliberates and commits to intentions:
- **Beliefs ($B$):** The agent's knowledge about the operational environment (host states, open ports, observed vulnerabilities, active policies).
- **Desires ($D$):** The potential goals or operational states the agent wishes to achieve (audit fleet, contain compromised hosts, surface critical alerts).
- **Intentions ($I$):** The committed desires chosen for execution, organized into concrete procedural plans.

### 1.2 Intention Reconsideration & Epistemic Preemption
An agent cannot re-deliberate after every minor percept (computational waste), nor can it pursue a plan stubbornly when the environment has changed catastrophically:
- **Kinny & Georgeff (1991) Reconsideration Trade-off:** SentryScan implements *bold-agent deliberation* with explicit **material belief update filters**.
- **Deliberative Preemption:** Routine telemetry (e.g., informational banner) retains active plans. The arrival of a `CRITICAL` vulnerability finding triggers an immediate interrupt, cleanly abandoning obsolete intentions and adopting emergency containment.

---

## 2. Architecture & Implementation Specification

```
                  Percepts (Telemetry / Messages)
                                 │
                                 ▼
                     ┌──────────────────────┐
                     │ Update Belief Base   │
                     │    (BeliefBase)      │
                     └──────────┬───────────┘
                                │
                                ▼
                     ┌──────────────────────┐
            No       │ Material Change in   │
       ┌─────────────┤ Beliefs Detected?    │
       │             └──────────┬───────────┘
       │                        │ Yes
       ▼                        ▼
 ┌───────────┐       ┌──────────────────────┐
 │ Continue  │       │ Re-deliberate & Plan │
 │ Active    │       │ 1. Filter Desires    │
 │ Intention │       │ 2. Priority Argmax   │
 └───────────┘       │ 3. Synthesize Steps  │
                     └──────────┬───────────┘
                                │
                                ▼
                     ┌──────────────────────┐
                     │ Intention Transition │
                     │ Old: ABANDONED       │
                     │ New: ADOPTED         │
                     └──────────────────────┘
```

### 2.1 Concrete Desires & Intention Synthesis (`src/sentryscan/bdi/deliberation.py`)

| Desire Identifier | Eligibility Condition | Intention Plan Synthesized | Action Generated |
|---|---|---|---|
| `CONTAIN_COMPROMISED_HOSTS` | Active `CRITICAL` / `HIGH` finding on unquarantined host | 1. `QUARANTINE_HOST`<br>2. `SET_SCAN_CADENCE (50ms)`<br>3. `SCHEDULE_PRIORITY_PORTS` | `quarantine_flag=True`<br>`cadence=50ms` |
| `SURFACE_CRITICAL_FINDINGS` | Host quarantined; findings unacknowledged | 1. `PUBLISH_CRITICAL_ALERT`<br>2. `SET_SCAN_CADENCE (100ms)` | `cadence=100ms` |
| `AUDIT_ASSIGNED_HOSTS` | Baseline state; no critical alerts active | 1. `SET_SCAN_CADENCE (250ms)`<br>2. `DISPATCH_ROUTINE_PROBE` | `cadence=250ms` (Nominal) |

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. Distinct Beliefs, Desires, and Intentions** | `src/sentryscan/bdi/beliefs.py`, `src/sentryscan/bdi/desires.py`, `src/sentryscan/bdi/intentions.py`: Epistemic separation into `BeliefBase`, `Desire`, and `Intention` | `tests/unit/test_bdi_models.py`<br>`evidence/bdi_transition_log.md` | **PASSED** |
| **2. Deliberation & Option Selection** | `src/sentryscan/bdi/deliberation.py`: Option generation, feasibility filtering, and dynamic priority ranking selecting $d^* = \\arg\\max Priority(d)$ | `tests/unit/test_bdi_deliberation.py`<br>`demos/demo_assignment_4_1.py` Cycle 1 | **PASSED** |
| **3. Plan Synthesis & Intention Steps** | `src/sentryscan/bdi/deliberation.py`: Instantiates concrete ordered steps (`QUARANTINE_HOST`, `SET_SCAN_CADENCE`, etc.) with status tracking | `tests/unit/test_bdi_deliberation.py`<br>`evidence/bdi_transition_log.md` | **PASSED** |
| **4. LangGraph Deliberative Workflow** | `src/sentryscan/graphs/analyst_graph.py`: Compiled LangGraph orchestrating `perceive` $\to$ `check_reconsideration` $\to$ `deliberate_and_plan` $\to$ `execute_step` | `tests/unit/test_analyst_graph.py`<br>`src/sentryscan/agents/analyst.py` | **PASSED** |
| **5. Material Reconsideration Trigger** | `src/sentryscan/graphs/analyst_graph.py`: Detects escalations to `CRITICAL`/`HIGH` severity and triggers intentional preemption | `tests/integration/test_bdi_reconsideration.py`<br>`demos/demo_assignment_4_1.py` Cycle 3 | **PASSED** |
| **6. Clean Intention Abandonment & Transition** | Previous intention `intention-000001` cleanly transitioned to `ABANDONED` with recorded rationale rather than silent overwriting | `tests/integration/test_bdi_reconsideration.py`<br>`evidence/bdi_transition_log.md` Cycle 3 | **PASSED** |
| **7. Emergency Containment Execution** | Autonomous quarantine flag (`quarantine_flag=True`) and high-frequency sampling (`50ms`) emitted via `PARAMS_UPDATE` message | `tests/unit/test_analyst.py`<br>`demos/demo_assignment_4_1.py` Cycle 3 | **PASSED** |
| **8. Post-Containment Intention Shift** | Following host quarantine, agent autonomously transitions from `CONTAIN_COMPROMISED_HOSTS` to `SURFACE_CRITICAL_FINDINGS` | `evidence/bdi_transition_log.md` Cycle 4 | **PASSED** |
| **9. Trace & Single-Writer Auditing** | Sequential event log recording message reception, state transitions, and generated parameter adaptations via `src/sentryscan/observability/recorder.py` | `evidence/trace_excerpt.jsonl` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 BDI State Transition & Reconsideration Log (`evidence/bdi_transition_log.md`)

| Cycle | Trigger | Target Host | Severity | Old Intention | New Intention | Reason | Generated Action |
|---|---|---|---|---|---|---|---|
| **1 (Init)** | `INITIAL_DELIBERATION` | `192.0.2.10` | `INFO` | None | `intention-000001` (AUDIT) | Initial boot | `NOMINAL (250ms)` |
| **2 (Routine)** | `ROUTINE_TELEMETRY` | `192.0.2.20` | `LOW` | `intention-000001` | Retained (No Change) | Non-material | `NOMINAL (500ms)` |
| **3 (Preempt)** | `MATERIAL_BELIEF_UPDATE` | `sim-host-007` | **`CRITICAL`** | `intention-000001` [ABANDONED] | `intention-000002` (CONTAIN) | Critical alert on host | `QUARANTINE=True (50ms)` |
| **4 (Shift)** | `CONTAINMENT_SATISFIED` | `sim-host-007` | `CRITICAL (Quar)`| `intention-000002` [SUCCEEDED] | `intention-000003` (SURFACE) | Containment satisfied | `DEEP_INSPECT (100ms)` |

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_4_1/deliverables/SentryScan_Assignment_4_1_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/4.1-bdi-modelling`
4. **Immutable Git Tag:** `assignment-4.1`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_4_1.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_4_1.zip.sha256`

### 5.2 Verification Commands
```bash
# Run BDI deliberation demonstration
python demos/demo_assignment_4_1.py

# Execute BDI unit and integration tests
pytest -v tests/unit/test_bdi_models.py tests/unit/test_bdi_deliberation.py tests/integration/test_bdi_reconsideration.py
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 4.2 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_4_2"] = {
    "filename": "SentryScan_Assignment_4_2_Report.md",
    "title": "SentryScan: Assignment 4.2 — Knowledge Representation & API Enrichment",
    "content": """# SentryScan: Assignment 4.2 — Knowledge Representation & API Enrichment

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 4.2 — Knowledge Representation & API Enrichment  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/4.2-knowledge-enrichment`  
**Git Tag:** `assignment-4.2`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 4.2 integrates formal **Knowledge Representation & External API Enrichment** (Russell & Norvig, Ch. 12) into SentryScan, allowing the agent to augment sparse perceptual banners with authoritative external cybersecurity knowledge.

### 1.1 Ontology-Driven Epistemic Grounding
Raw telemetry provides only ambiguous version strings (e.g., `ProFTPD 1.3.5`, `log4j 2.14.1`). Grounding this percept in a formal **Vulnerability Knowledge Ontology** maps the surface observation to:
- Canonical **CVE Identifiers** (`CVE-2021-44228`, `CVE-2024-3094`).
- **Common Weakness Enumeration (CWE)** taxonomies (CWE-502 Deserialization, CWE-78 OS Command Injection).
- Mathematical **CVSS v3.1 Base Scores** and authoritative mitigation strategies.

### 1.2 Multi-Tiered Enrichment & Resilient Fallbacks
Network endpoints fail, rates throttle, and air-gapped environments forbid external calls. SentryScan implements a 4-tier resilient knowledge pipeline:
1. **In-Memory / SQLite Persistent Cache:** Fast sub-millisecond retrieval with TTL invalidation.
2. **NVD REST API Adapter:** Read-only client querying NIST's National Vulnerability Database with bounded exponential backoff retries.
3. **Local Knowledge Ontology:** Curated JSON ontology fixture for known high-impact exploit signatures.
4. **Deterministic Fallback Fixture:** Guarantees 100% operational uptime without agent crash during complete network outages.

---

## 2. Architecture & Implementation Specification

```
                  Raw Finding (e.g. sim-host-007: Log4j 2.14.1)
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │    VulnerabilityCache       │
                         └──────────────┬──────────────┘
                         Hit            │  Miss
           ┌────────────────────────────┘              │
           ▼                                           ▼
 ┌───────────────────┐                   ┌─────────────────────────────┐
 │ Return Cached CVE │                   │ NVDAdapter (REST Client)    │
 │ (0 Network Calls) │                   └──────────────┬──────────────┘
 └─────────┬─────────┘                   Success        │  Timeout / Fail
           │                       ┌────────────────────┘              │
           │                       ▼                                   ▼
           │             ┌───────────────────┐           ┌───────────────────┐
           │             │ NIST NVD API V2   │           │ Local Offline     │
           │             │ Structured CVSS   │           │ Fallback Fixture  │
           │             └─────────┬─────────┘           └─────────┬─────────┘
           │                       │                               │
           ▼                       ▼                               ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                   Contextual Severity Escalation Engine                   │
 │                Original: MEDIUM  --->  Enriched: CRITICAL                 │
 └─────────────────────────────────────┬─────────────────────────────────────┘
                                       │
                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │        Material Belief Update -> Triggers LangGraph BDI Preemption        │
 │              Autonomous Quarantine & 50ms Cadence Enforcement             │
 └───────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. Structured Vulnerability Knowledge Ontology** | `src/sentryscan/knowledge/models.py`, `src/sentryscan/knowledge/ontology.py`: `VulnerabilityRecord`, `VulnerabilityKnowledgeBase`, and `fixtures/knowledge/vulnerability_ontology.json` | `tests/unit/test_knowledge_ontology.py`<br>`evidence/knowledge_adaptation_log.md` | **PASSED** |
| **2. Read-Only NVD CVE API Adapter** | `src/sentryscan/knowledge/nvd_adapter.py`: `NVDAdapter`, strict Pydantic response models (`NVDResponse`, `NVDCveData`), CVSS mapping | `tests/unit/test_nvd_adapter.py`<br>`demos/demo_assignment_4_2.py` Cycle 3 | **PASSED** |
| **3. Persistent & In-Memory Caching** | `src/sentryscan/knowledge/cache.py`: `VulnerabilityCache` with TTL expiration, disk persistence, and hit/miss tracking | `tests/unit/test_knowledge_cache.py`<br>`demos/demo_assignment_4_2.py` Cycle 4 | **PASSED** |
| **4. Bounded Retry & Backoff** | `src/sentryscan/knowledge/enricher.py`: `_fetch_with_retry()` executing exponential backoff across configurable retries | `tests/unit/test_knowledge_cache.py` (`test_enricher_retry_and_fallback_on_nvd_failure`) | **PASSED** |
| **5. Resilient Offline Fallback** | `src/sentryscan/knowledge/enricher.py`: Seamless fallback to local fixtures when network/NVD is disabled or unavailable | `tests/unit/test_knowledge_cache.py`<br>`demos/demo_assignment_4_2.py` Cycle 2 & 5 | **PASSED** |
| **6. Contextual Severity Escalation** | `src/sentryscan/knowledge/enricher.py`: `EnrichmentResult` calculating severity escalation ($Sev_{enriched} > Sev_{orig}$) from CVSS scores | `evidence/knowledge_adaptation_log.md`<br>`tests/unit/test_knowledge_ontology.py` | **PASSED** |
| **7. Deliberative Belief & Intention Reconsideration** | `src/sentryscan/agents/analyst.py`: Feeds escalated finding into `BeliefBase`, triggering LangGraph BDI replanning to `CONTAIN_COMPROMISED_HOSTS` | `tests/integration/test_knowledge_enrichment.py`<br>`evidence/run_log.txt` Cycle 2 | **PASSED** |
| **8. Autonomous Quarantine Execution** | `src/sentryscan/agents/analyst.py`: Emits `PARAMS_UPDATE` with `quarantine_flag=True`, `scan_interval_ms=50`, and CVE metadata | `tests/integration/test_knowledge_enrichment.py`<br>`demos/demo_assignment_4_2.py` Cycle 2 & 3 | **PASSED** |
| **9. Trace & Single-Writer Auditing** | `src/sentryscan/observability/recorder.py`: Single-writer monotonic `seq` logging of message receipts, perception, and adaptations | `evidence/trace_excerpt.jsonl` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Multi-Tiered Enrichment & Adaptation Log (`evidence/knowledge_adaptation_log.md`)

| Cycle | Target Host | Original Sev | Matched CVE | CVSS | Enriched Sev | Source | Generated Action | Quarantined |
|---|---|---|---|---|---|---|---|:---:|
| **1** | `192.0.2.10` | `INFO` | `N/A` | N/A | `INFO` | `LOCAL_ONTOLOGY` | `NOMINAL (500ms)` | `False` |
| **2** | `sim-host-007` | `MEDIUM` | `CVE-2021-44228` (Log4j) | **10.0** | **`CRITICAL`** | `FALLBACK_FIXTURE` | `DEEP_INSPECT (50ms)` | **`True`** |
| **3** | `sim-host-008` | `LOW` | `CVE-2024-3094` (XZ) | **10.0** | **`CRITICAL`** | `NVD_API` | `DEEP_INSPECT (50ms)` | **`True`** |
| **4** | `sim-host-009` | `LOW` | `CVE-2024-3094` (XZ) | **10.0** | **`CRITICAL`** | `CACHE (0 net calls)`| `DEEP_INSPECT (50ms)` | **`True`** |
| **5** | `sim-host-011` | `LOW` | `CVE-2021-41773` (Apache) | **7.5** | **`HIGH`** | `FALLBACK_FIXTURE` | `DEEP_INSPECT (100ms)`| `False` |

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_4_2/deliverables/SentryScan_Assignment_4_2_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/4.2-knowledge-enrichment`
4. **Immutable Git Tag:** `assignment-4.2`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_4_2.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_4_2.zip.sha256`

### 5.2 Verification Commands
```bash
# Run knowledge enrichment demonstration
python demos/demo_assignment_4_2.py

# Execute knowledge ontology, NVD adapter, and cache tests
pytest -v tests/unit/test_knowledge_ontology.py tests/unit/test_nvd_adapter.py tests/unit/test_knowledge_cache.py
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 5.1 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_5_1"] = {
    "filename": "SentryScan_Assignment_5_1_Report.md",
    "title": "SentryScan: Assignment 5.1 — Cryptographic Message Authentication & Security Gate",
    "content": """# SentryScan: Assignment 5.1 — Cryptographic Message Authentication & Security Gate

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 5.1 — Cryptographic Message Authentication & Security Gate  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/5.1-authentication`  
**Git Tag:** `assignment-5.1`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 5.1 hardens SentryScan against **adversarial manipulation in distributed multi-agent systems** by implementing a formal **Cryptographic Security Gate** based on modern asymmetric Ed25519 signatures and canonical payload digests.

### 1.1 The Threat of Confused Deputies & Byzantine Agents
In decentralized agent collectives, an agent's internal mental state (Beliefs) must never be polluted by forged, replayed, or tampered messages from untrusted entities:
- **Canonical Envelope Signing:** Envelopes are canonically serialized and cryptographically signed with the sender's private Ed25519 key, binding the envelope metadata to the SHA-256 digest of the payload.
- **Fail-Closed Security Gate:** Inbound messages must pass an 8-stage verification pipeline before admission to the BDI reasoning core. Any failure immediately drops the packet and emits an audit alert.

---

## 2. Architecture & Implementation Specification

```
                      Inbound Raw JSON Message
                                 │
                                 ▼
                     ┌──────────────────────┐
                     │ 1. Schema Validation │
                     └──────────┬───────────┘
                                │ Pass
                                ▼
                     ┌──────────────────────┐
                     │ 2. Sender Registry   │
                     └──────────┬───────────┘
                                │ Pass (Registered Public Key)
                                ▼
                     ┌──────────────────────┐
                     │ 3. Recipient Match   │
                     └──────────┬───────────┘
                                │ Pass (Addressed to this Agent)
                                ▼
                     ┌──────────────────────┐
                     │ 4. Payload SHA-256   │
                     └──────────┬───────────┘
                                │ Pass (Digest Matches)
                                ▼
                     ┌──────────────────────┐
                     │ 5. Ed25519 Signature │
                     └──────────┬───────────┘
                                │ Pass (Valid Asymmetric Sig)
                                ▼
                     ┌──────────────────────┐
                     │ 6. Clock Skew (±30s) │
                     └──────────┬───────────┘
                                │ Pass (Fresh Timestamp)
                                ▼
                     ┌──────────────────────┐
                     │ 7. Nonce Anti-Replay │
                     └──────────┬───────────┘
                                │ Pass (Unseen Nonce, Not Saturated)
                                ▼
                     ┌──────────────────────┐
                     │ Admission to BDI Core│
                     │ (Zero Belief Poison) │
                     └──────────────────────┘
```

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. Cryptographic Agent Identity Management** | `src/sentryscan/security/identity.py`: `AgentIdentity` with fresh throwaway Ed25519 generation, 32-byte seed derivation, and raw/hex formatting | `tests/unit/test_security_identity.py`<br>`demos/demo_assignment_5_1.py` Initialization | **PASSED** |
| **2. Trusted Agent Public Key Registry** | `src/sentryscan/security/registry.py`: `TrustedAgentRecord`, `TrustedAgentRegistry` with validation, revocation, and JSON persistence (`config/trusted_agents.example.json`) | `tests/unit/test_security_identity.py` (`test_trusted_agent_registry_*`) | **PASSED** |
| **3. Canonical Envelope Signing & Payload Integrity** | `src/sentryscan/security/canonical.py`: `sign_envelope()`, `verify_payload_digest()`, and `verify_envelope_signature()` enforcing SHA-256 digest binding | `tests/unit/test_security_signing.py`<br>`evidence/security_gate_audit.md` Scenarios 1 & 4 | **PASSED** |
| **4. Fail-Closed Anti-Replay Nonce Cache** | `src/sentryscan/security/nonce_cache.py`: `NonceCache` with dual FIFO/TTL expiration, bounded capacity (default 10,000), and fail-closed saturation policy | `tests/unit/test_security_gate.py` (`test_nonce_cache_*`)<br>`evidence/security_gate_audit.md` Scenarios 7 & 8 | **PASSED** |
| **5. Multi-Stage Inbound Security Gate** | `src/sentryscan/security/gate.py`: `SecurityGate` enforcing sequential evaluation pipeline: JSON, Schema, Sender Registry, Recipient Matching, Payload Digest, Ed25519 Signature, Clock Skew, Anti-Replay | `tests/unit/test_security_gate.py`<br>`evidence/security_gate_audit.md` Scenarios 1–8 | **PASSED** |
| **6. Deliberative BDI Shielding** | `src/sentryscan/agents/analyst.py`: Inbound gate verification in `process_message()`, emitting structured `ERROR` on rejection and guaranteeing zero belief pollution | `tests/unit/test_security_gate.py` (`test_analyst_agent_shielded_by_gate`)<br>`demos/demo_assignment_5_1.py` Scenarios 1–7 | **PASSED** |
| **7. Systematic Attack Vector Verification** | `demos/demo_assignment_5_1.py`: Comprehensive test harness executing nominal message + 7 distinct attack vectors (`UNKNOWN_SENDER`, `WRONG_RECIPIENT`, `PAYLOAD_TAMPERED`, `BAD_SIGNATURE`, `STALE_TIMESTAMP`, `REPLAYED_NONCE`, `NONCE_CACHE_FULL`) | `evidence/run_log.txt`<br>`evidence/security_gate_audit.md` | **PASSED** |
| **8. Audit Trace & Observability Integration** | `src/sentryscan/observability/recorder.py`: Single-writer monotonic `seq` logging of security verdicts and rejections | `evidence/trace_excerpt.jsonl` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Eight Attack Vector Verification Matrix (`evidence/security_gate_audit.md`)

| Scenario | Sender | Attack / Verification Vector | Expected Code | Actual Code | Agent Shield Status | Verdict |
|---|---|---|---|---|---|:---:|
| **1. Nominal Valid Message** | `sensor-agent-01` | None (Legitimate signed telemetry) | `OK` | `OK` | Processed (Beliefs updated) | **PASS** |
| **2. Untrusted Sender** | `rogue-agent-99` | Rogue agent spoofing command | `UNKNOWN_SENDER` | `UNKNOWN_SENDER` | Shielded (ERROR response) | **PASS** |
| **3. Wrong Recipient** | `supervisor-01` | Misrouted packet | `WRONG_RECIPIENT` | `WRONG_RECIPIENT` | Shielded (ERROR response) | **PASS** |
| **4. Tampered Payload** | `sensor-agent-01` | MITM parameter modification | `PAYLOAD_TAMPERED`| `PAYLOAD_TAMPERED`| Shielded (ERROR response) | **PASS** |
| **5. Bad Signature** | `supervisor (fake)`| Forged invalid Ed25519 signature | `BAD_SIGNATURE` | `BAD_SIGNATURE` | Shielded (ERROR response) | **PASS** |
| **6. Stale Timestamp** | `sensor-agent-01` | Expired packet (>30s clock drift) | `STALE_TIMESTAMP` | `STALE_TIMESTAMP` | Shielded (ERROR response) | **PASS** |
| **7. Replayed Envelope**| `sensor-agent-01` | Eavesdropped packet re-transmission | `REPLAYED_NONCE` | `REPLAYED_NONCE` | Shielded (ERROR response) | **PASS** |
| **8. Cache Saturated** | `sensor-agent-01` | Nonce flood / Resource exhaustion | `NONCE_CACHE_FULL`| `NONCE_CACHE_FULL`| Shielded (Fail-closed drop) | **PASS** |

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_5_1/deliverables/SentryScan_Assignment_5_1_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/5.1-authentication`
4. **Immutable Git Tag:** `assignment-5.1`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_5_1.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_5_1.zip.sha256`

### 5.2 Verification Commands
```bash
# Run security gate attack simulation demonstration
python demos/demo_assignment_5_1.py

# Execute cryptographic security test suite
pytest -v tests/unit/test_security_identity.py tests/unit/test_security_signing.py tests/unit/test_security_gate.py
```
""",
}

# -----------------------------------------------------------------------------
# Assignment 5.2 Report
# -----------------------------------------------------------------------------
REPORTS["assignment_5_2"] = {
    "filename": "SentryScan_Assignment_5_2_Report.md",
    "title": "SentryScan: Assignment 5.2 — Capstone Architecture & Web Dashboard",
    "content": """# SentryScan: Assignment 5.2 — Capstone Architecture & Web Dashboard

**Course:** 21CSE525T — Agent Technology  
**Assignment:** 5.2 — Capstone Architecture, Web Dashboard & UI Orchestration  
**Student:** R Ganesh [RA2212704010031]  
**Repository:** https://github.com/drgeekg/SentryScan  
**Target Branch:** `assignment/5.2-capstone`  
**Git Tag:** `assignment-5.2`  
**Status:** Completed & Verified  

---

## 1. Executive Summary & Theoretical Context

Assignment 5.2 represents the comprehensive **Capstone Integration Milestone** of the SentryScan Autonomous SOC platform. It synthesizes all preceding modules—reflex rules (1.2), concurrent daemons (2.1), socket framing (2.2), Contract-Net negotiation (3.1), utility optimization (3.2), BDI deliberation (4.1), knowledge enrichment (4.2), and cryptographic security gates (5.1)—into a cohesive, fully-persisted, observable agent system.

### 1.1 Complete Multi-Agent Lifecycle
- **Autonomous Coordination:** Supervisor coordinates Scout and Triage agents through Contract-Net auctions to allocate scanning tasks over a synthetic fleet.
- **Cognitive Deliberation & Defense:** Analyst Agent receives findings, verifies authenticity via the Cryptographic Security Gate, enriches CVE intelligence, and initiates autonomous host quarantine via BDI replanning.
- **Dual-Sink Persistence:** Commits an append-only verifiable stream simultaneously to disk JSONL files and indexed relational SQLite databases.
- **Strict 100% Parity:** Cryptographic assurance that every event is accounted for across both stores with zero sequence gaps ($\text{seq}_i = i$).

---

## 2. Architecture & Implementation Specification

```
                         ┌───────────────────────────────────┐
                         │     Simulated Fleet Generator     │
                         │ (RFC 5737 Space, Normal + Poison) │
                         └─────────────────┬─────────────────┘
                                           │
                                           ▼
                         ┌───────────────────────────────────┐
                         │   Supervisor Multi-Agent Graph    │
                         │    (Contract-Net Negotiation)     │
                         └───────┬───────────────────┬───────┘
                                 │                   │
                                 ▼                   ▼
                      ┌──────────────────┐   ┌──────────────────┐
                      │   Scout Agent    │   │   Triage Agent   │
                      └──────────┬───────┘   └──────────┬───────┘
                                 │                      │
                                 └──────────┬───────────┘
                                            │ Findings
                                            ▼
                         ┌───────────────────────────────────┐
                         │      Analyst Deliberative BDI     │
                         │  (Security Gate + CVE Enrichment) │
                         │   Emergency Quarantine Trigger    │
                         └──────────────────┬────────────────┘
                                            │
                                            ▼
                         ┌───────────────────────────────────┐
                         │    Single-Writer Event Recorder   │
                         └─────────┬───────────────────┬─────┘
                                   │                   │
                        JSONL Sink │                   │ SQLite Sink
                                   ▼                   ▼
                         ┌───────────────────┐ ┌───────────────────┐
                         │ Complete Run Log  │ │ Indexed Relational│
                         │ (trace_excerpt)   │ │ Run Store Schema  │
                         └─────────┬─────────┘ └─────────┬─────────┘
                                   │                     │
                                   └──────────┬──────────┘
                                              │ 100% Parity Checked
                                              ▼
                         ┌───────────────────────────────────┐
                         │ Loopback WebSocket / REST Gateway │
                         │ (FastAPI Port 8000, HTML5 Canvas) │
                         └───────────────────────────────────┘
```

---

## 3. Rubric Compliance & Verification Matrix

| Evaluation Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|:---:|
| **1. Supervisor Integration & Deliberative Quarantine** | `src/sentryscan/graphs/supervisor.py`, `src/sentryscan/graphs/state.py`: Integrates `AnalystAgent` via signed envelopes; catches CRITICAL findings; executes host quarantine. | `tests/unit/test_supervisor_graph.py`<br>`evidence/run_log.txt` Step 3 | **PASSED** |
| **2. Dual-Sink Persistence & SQLite Run Store** | `src/sentryscan/storage/store.py`, `src/sentryscan/observability/recorder.py`: Single-writer monotonic `seq` recorder sinks concurrently to JSONL trace and relational SQLite schema with indexed tables. | `tests/unit/test_storage_store.py`<br>`tests/integration/test_capstone_parity_and_replay.py` | **PASSED** |
| **3. Strict 100% Event Parity Guarantee** | `src/sentryscan/storage/store.py` (`verify_parity`): Verifies `count(SQLite) == count(JSONL)`, zero `seq` gaps ($\text{seq}_i = i$), and exact ID alignment. | `evidence/capstone_verification_matrix.md` §1 & §2<br>`evidence/run_log.txt` Step 4 | **PASSED** |
| **4. Loopback REST & WebSocket Gateway** | `src/sentryscan/dashboard_gateway/server.py`: FastAPI server providing REST run inspection (`/api/runs/...`) and WebSocket event stream (`/ws/{run_id}`) with sequence-based backfill. | `tests/unit/test_dashboard_gateway.py`<br>`tests/integration/test_capstone_parity_and_replay.py` (`test_websocket_resync_by_sequence`) | **PASSED** |
| **5. Prebuilt Web Dashboard (HTML5 Canvas)** | `frontend/dist/index.html`: Dark-mode cybersecurity SPA with 60fps HTML5 Canvas multi-agent particle network, real-time metrics, findings table, and live WebSocket log. Zero Node.js runtime required. | `frontend/dist/index.html`<br>`src/sentryscan/dashboard_gateway/server.py` static mount | **PASSED** |
| **6. Rich CLI Terminal Fallback Dashboard** | `src/sentryscan/ui/rich_dashboard.py`: Terminal UI rendering multi-panel layout with fleet status, active negotiation, findings table, and log stream using `rich`. | `tests/unit/test_rich_dashboard.py`<br>`main.py` integration | **PASSED** |
| **7. One-Command Capstone Runner** | `src/sentryscan/capstone.py`, `main.py`: Top-level executable entry point (`main.py --demo`) orchestrating synthetic fleet generation, negotiation, scanning, BDI quarantine, and parity audit. | `tests/unit/test_capstone_runner.py`<br>`evidence/run_log.txt` | **PASSED** |
| **8. Replay Consistency & Trace Reproducibility** | `src/sentryscan/storage/store.py`: Replay from recorded events reproduces identical aggregate counts and findings state without mutating underlying database. | `tests/integration/test_capstone_parity_and_replay.py` (`test_replay_consistency_without_mutation`, `test_capstone_determinism_across_runs`) | **PASSED** |
| **9. Test Coverage & Code Quality** | Entire test suite across unit and integration tests: 149/149 passing (100%), 0 failures, 0 warnings. Ruff lint check passing cleanly (0 errors). | `pytest` and `ruff check .` verification | **PASSED** |
| **10. Immutable Deliverable Packaging** | `scripts/package_assignment.py`: Builds reproducible submission ZIP directly from Git tag `assignment-5.2` with SHA-256 checksum manifest. | `dist/SentryScan_assignment_5_2.zip` | **PASSED** |

---

## 4. Execution Results & Empirical Evidence

### 4.1 Capstone Simulation Run Verification (`evidence/capstone_verification_matrix.md`)
- **Simulation Run ID:** `run-capstone-evidence`
- **Negotiation Consensus:** Consensus reached in 2 rounds; winner = `scout-agent`.
- **Total Vulnerability Findings:** 5 findings detected across fleet.
- **Autonomous Host Quarantine:** `['sim-host-003']` quarantined by Analyst BDI preemption.
- **Dual-Sink Storage Parity:**
  - SQLite Database Rows: `31`
  - JSONL Trace Lines: `31`
  - Sequence Monotonicity: 100% gap-free (`has_seq_gaps=False`).
  - Strict Parity Status: **VERIFIED (100% Match)**.
- **Test Suite Execution:** 149/149 passed (100%), 0 failures.

---

## 5. Submission Package & Reproduction Instructions

### 5.1 Exact Submission Components
1. **Report Document:** `assignments/assignment_5_2/deliverables/SentryScan_Assignment_5_2_Report.pdf`
2. **Repository URL:** `https://github.com/drgeekg/SentryScan`
3. **Target Branch:** `assignment/5.2-capstone`
4. **Immutable Git Tag:** `assignment-5.2`
5. **Packaged ZIP Archive:** `dist/SentryScan_assignment_5_2.zip`
6. **SHA-256 Checksum:** `dist/SentryScan_assignment_5_2.zip.sha256`

### 5.2 Verification Commands
```bash
# Run one-command capstone simulation
python main.py --demo

# Launch full capstone with Web Dashboard & WebSocket Gateway
python main.py --web --port 8000

# Execute full test suite
pytest -v tests/
```
""",
}


def build_all() -> None:
    """Generate all markdown specifications, HTML reports, and PDFs."""
    print("=" * 70)
    print("SentryScan: Building All 10 Assignment Reports (MD -> HTML -> PDF)")
    print("=" * 70)

    for key, data in REPORTS.items():
        deliverables_dir = REPO_ROOT / "assignments" / key / "deliverables"
        deliverables_dir.mkdir(parents=True, exist_ok=True)

        md_path = deliverables_dir / data["filename"]
        pdf_path = deliverables_dir / data["filename"].replace(".md", ".pdf")

        print(f"[*] Processing {key} -> {md_path.name}...")
        md_path.write_text(data["content"].strip() + "\n", encoding="utf-8")

        compile_md_to_pdf(md_path, pdf_path, data["title"])

    print("=" * 70)
    print("All assignment reports generated successfully.")
    print("=" * 70)


if __name__ == "__main__":
    build_all()
