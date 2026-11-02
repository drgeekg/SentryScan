# SentryScan: Assignment 4.2 — Knowledge Representation & API Enrichment

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
