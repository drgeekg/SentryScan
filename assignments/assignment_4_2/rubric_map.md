# Assignment 4.2 — Rubric to Evidence Mapping

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** Assignment 4.2 (Knowledge Representation & API Enrichment)  
**Date:** 2026-10-21  

---

## Evaluation Criteria & Implementation Evidence

| Rubric Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|---|
| **1. Structured Vulnerability Knowledge Ontology** | [`src/sentryscan/knowledge/models.py`](../../src/sentryscan/knowledge/models.py), [`src/sentryscan/knowledge/ontology.py`](../../src/sentryscan/knowledge/ontology.py): `VulnerabilityRecord`, `VulnerabilityKnowledgeBase`, and [`fixtures/knowledge/vulnerability_ontology.json`](../../fixtures/knowledge/vulnerability_ontology.json) | [`tests/unit/test_knowledge_ontology.py`](../../tests/unit/test_knowledge_ontology.py), [`evidence/knowledge_adaptation_log.md`](evidence/knowledge_adaptation_log.md) | **PASSED** |
| **2. Read-Only NVD CVE API Adapter** | [`src/sentryscan/knowledge/nvd_adapter.py`](../../src/sentryscan/knowledge/nvd_adapter.py): `NVDAdapter`, strict Pydantic response models (`NVDResponse`, `NVDCveData`, `NVDCvssData`), CVSS mapping | [`tests/unit/test_nvd_adapter.py`](../../tests/unit/test_nvd_adapter.py), [`demos/demo_assignment_4_2.py`](../../demos/demo_assignment_4_2.py) Cycle 3 | **PASSED** |
| **3. Persistent & In-Memory Caching** | [`src/sentryscan/knowledge/cache.py`](../../src/sentryscan/knowledge/cache.py): `VulnerabilityCache` with TTL expiration, disk persistence, and hit/miss tracking | [`tests/unit/test_knowledge_cache.py`](../../tests/unit/test_knowledge_cache.py), [`demos/demo_assignment_4_2.py`](../../demos/demo_assignment_4_2.py) Cycle 4 | **PASSED** |
| **4. Bounded Retry & Backoff** | [`src/sentryscan/knowledge/enricher.py`](../../src/sentryscan/knowledge/enricher.py): `_fetch_with_retry()` executing exponential backoff across configurable retries | [`tests/unit/test_knowledge_cache.py`](../../tests/unit/test_knowledge_cache.py) (`test_enricher_retry_and_fallback_on_nvd_failure`), Cycle 5 log | **PASSED** |
| **5. Resilient Offline Fallback** | [`src/sentryscan/knowledge/enricher.py`](../../src/sentryscan/knowledge/enricher.py): Seamless fallback to local fixtures when network/NVD is disabled or unavailable | [`tests/unit/test_knowledge_cache.py`](../../tests/unit/test_knowledge_cache.py), [`demos/demo_assignment_4_2.py`](../../demos/demo_assignment_4_2.py) Cycle 2 & 5 | **PASSED** |
| **6. Contextual Severity Escalation** | [`src/sentryscan/knowledge/enricher.py`](../../src/sentryscan/knowledge/enricher.py): `EnrichmentResult` calculating severity escalation ($Sev_{enriched} > Sev_{orig}$) from CVSS scores | [`evidence/knowledge_adaptation_log.md`](evidence/knowledge_adaptation_log.md), [`tests/unit/test_knowledge_ontology.py`](../../tests/unit/test_knowledge_ontology.py) | **PASSED** |
| **7. Deliberative Belief & Intention Reconsideration** | [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py): Feeds escalated finding into `BeliefBase`, triggering LangGraph BDI replanning to `CONTAIN_COMPROMISED_HOSTS` | [`tests/integration/test_knowledge_enrichment.py`](../../tests/integration/test_knowledge_enrichment.py), [`evidence/run_log.txt`](evidence/run_log.txt) Cycle 2 | **PASSED** |
| **8. Autonomous Quarantine Execution** | [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py): Emits `PARAMS_UPDATE` with `quarantine_flag=True`, `scan_interval_ms=50`, and CVE metadata | [`tests/integration/test_knowledge_enrichment.py`](../../tests/integration/test_knowledge_enrichment.py), [`demos/demo_assignment_4_2.py`](../../demos/demo_assignment_4_2.py) Cycle 2 & 3 | **PASSED** |
| **9. Trace & Single-Writer Auditing** | [`src/sentryscan/observability/recorder.py`](../../src/sentryscan/observability/recorder.py): Single-writer monotonic `seq` logging of message receipts, perception, and adaptations | [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl) | **PASSED** |
