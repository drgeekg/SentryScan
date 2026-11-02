# SentryScan: Assignment 1.2 — Deterministic Rule-Based Reflex Reasoner

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
$$\text{Action} = \text{RULE}(\text{Percept})$$

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
