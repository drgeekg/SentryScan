# Assignment 4.2 — Knowledge Representation & External API Enrichment

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-4.2`  

---

## 1. Architectural Increment Overview

Assignment 4.2 integrates external contextual vulnerability intelligence into SentryScan through structured ontology modeling, read-only NVD CVE API integration, persistent caching, bounded exponential retry, offline fallback, and autonomous BDI intention escalation:

1. **Structured Vulnerability Knowledge Ontology:**
   - [`src/sentryscan/knowledge/models.py`](../../src/sentryscan/knowledge/models.py): Defines `VulnerabilityRecord`, `EnrichmentResult`, and `KnowledgeSource` (`LOCAL_ONTOLOGY`, `NVD_API`, `CACHE`, `FALLBACK_FIXTURE`).
   - [`src/sentryscan/knowledge/ontology.py`](../../src/sentryscan/knowledge/ontology.py): `VulnerabilityKnowledgeBase` provides indexed lookup by CVE identifier and fuzzy service/banner keywords.
   - [`fixtures/knowledge/vulnerability_ontology.json`](../../fixtures/knowledge/vulnerability_ontology.json): Seeded local repository of high-profile vulnerability definitions (Log4Shell, Rapid Reset, XZ Backdoor, Apache Path Traversal, EternalBlue, Zerologon, Spring4Shell, BlueKeep).
2. **Read-Only NVD CVE API Adapter:**
   - [`src/sentryscan/knowledge/nvd_adapter.py`](../../src/sentryscan/knowledge/nvd_adapter.py): Implements `NVDAdapter` for querying NIST NVD API 2.0. Enforces strict Pydantic response validation (`NVDResponse`, `NVDCveData`, `NVDCvssData`), extracts CVSS metrics, and derives categorical severities.
   - **Safety Boundary:** The adapter operates strictly as a read-only metadata provider. It never executes probes against target hosts, never interprets raw banners as instructions, and never breaches the simulation sandbox.
3. **Persistent & Memory-Backed Caching:**
   - [`src/sentryscan/knowledge/cache.py`](../../src/sentryscan/knowledge/cache.py): `VulnerabilityCache` supports TTL-based expiration, disk persistence, and hit/miss metrics tracking to eliminate redundant network queries.
4. **Resilient Multi-Tiered Enrichment Pipeline:**
   - [`src/sentryscan/knowledge/enricher.py`](../../src/sentryscan/knowledge/enricher.py): Coordinates tiered resolution:
     $$\text{Finding} \longrightarrow \text{Cache} \overset{\text{miss}}{\longrightarrow} \text{NVD API (with 2 retries)} \overset{\text{error / disabled}}{\longrightarrow} \text{Local Ontology Fixture}$$
   - Guarantees 100% offline testability with zero network dependencies.
5. **Belief Revision & Autonomous BDI Intention Escalation:**
   - [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py): Seamlessly integrates `KnowledgeEnricher`. When a finding's severity escalates via knowledge enrichment (e.g. `MEDIUM` to `CRITICAL` via CVSS 10.0), `BeliefBase` marks a `MATERIAL_BELIEF_UPDATE`. The compiled LangGraph deliberation workflow immediately preempts nominal auditing (`AUDIT_ASSIGNED_HOSTS`), adopts `CONTAIN_COMPROMISED_HOSTS`, quarantines the host, accelerates sampling to 50ms, and emits an enriched `PARAMS_UPDATE` referencing the CVE.

---

## 2. Benchmark Evidence & Deliverables

Demonstration artifacts generated from execution:
- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Knowledge Adaptation Log:** [`evidence/knowledge_adaptation_log.md`](evidence/knowledge_adaptation_log.md)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **Baseline Handling:** Routine `INFO` alerts retain nominal 250ms cadence and `AUDIT_ASSIGNED_HOSTS` intention without replanning.
- **Offline Context Escalation:** Log4j alert on `sim-host-007` escalates from `MEDIUM` to `CRITICAL` via `CVE-2021-44228`, triggering immediate BDI intention preemption and host quarantine.
- **Online Resolution & Caching:** Simulated NVD 2.0 query for `CVE-2024-3094` successfully validates schema, extracts CVSS 10.0, escalates severity, and caches the entry.
- **Zero-Network Cache Verification:** Second query for `CVE-2024-3094` is served directly from cache with 0 network calls and verified `cache_hit=True`.
- **Fault Resilience:** Under simulated NVD endpoint outage (503), the enricher completes 2 exponential retries and cleanly falls back to local fixtures without raising exceptions or interrupting the agent.
- **Unit & Integration Suite:** 120 passed across all test suites with 0 warnings and 0 failures.

---

## 3. Reproduction Instructions

```bash
# Run deterministic knowledge enrichment demonstration
python demos/demo_assignment_4_2.py

# Run unit and integration tests
pytest -v tests/

# Verify code style and linter
ruff check .

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-4.2
```
