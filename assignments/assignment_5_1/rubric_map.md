# Assignment 5.1 — Rubric to Evidence Mapping

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** Assignment 5.1 (Cryptographic Message Authentication & Security Gate)  
**Date:** 2026-10-21  

---

## Evaluation Criteria & Implementation Evidence

| Rubric Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|---|
| **1. Cryptographic Agent Identity Management** | [`src/sentryscan/security/identity.py`](../../src/sentryscan/security/identity.py): `AgentIdentity` with fresh throwaway Ed25519 generation, 32-byte seed derivation, and raw/hex formatting | [`tests/unit/test_security_identity.py`](../../tests/unit/test_security_identity.py), [`demos/demo_assignment_5_1.py`](../../demos/demo_assignment_5_1.py) Initialization | **PASSED** |
| **2. Trusted Agent Public Key Registry** | [`src/sentryscan/security/registry.py`](../../src/sentryscan/security/registry.py): `TrustedAgentRecord`, `TrustedAgentRegistry` with validation, revocation, and JSON persistence ([`config/trusted_agents.example.json`](../../config/trusted_agents.example.json)) | [`tests/unit/test_security_identity.py`](../../tests/unit/test_security_identity.py) (`test_trusted_agent_registry_*`) | **PASSED** |
| **3. Canonical Envelope Signing & Payload Integrity** | [`src/sentryscan/security/canonical.py`](../../src/sentryscan/security/canonical.py): `sign_envelope()`, `verify_payload_digest()`, and `verify_envelope_signature()` enforcing SHA-256 digest binding | [`tests/unit/test_security_signing.py`](../../tests/unit/test_security_signing.py), [`evidence/security_gate_audit.md`](evidence/security_gate_audit.md) Scenarios 1 & 4 | **PASSED** |
| **4. Fail-Closed Anti-Replay Nonce Cache** | [`src/sentryscan/security/nonce_cache.py`](../../src/sentryscan/security/nonce_cache.py): `NonceCache` with dual FIFO/TTL expiration, bounded capacity (default 10,000), and fail-closed saturation policy | [`tests/unit/test_security_gate.py`](../../tests/unit/test_security_gate.py) (`test_nonce_cache_*`), [`evidence/security_gate_audit.md`](evidence/security_gate_audit.md) Scenarios 7 & 8 | **PASSED** |
| **5. Multi-Stage Inbound Security Gate** | [`src/sentryscan/security/gate.py`](../../src/sentryscan/security/gate.py): `SecurityGate` enforcing HLD §12.3 sequential evaluation pipeline: JSON, Schema, Sender Registry, Recipient Matching, Payload Digest, Ed25519 Signature, Clock Skew ($\pm 30$s), Anti-Replay | [`tests/unit/test_security_gate.py`](../../tests/unit/test_security_gate.py), [`evidence/security_gate_audit.md`](evidence/security_gate_audit.md) Scenarios 1–8 | **PASSED** |
| **6. Deliberative BDI Shielding** | [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py): Inbound gate verification in `process_message()`, emitting structured `ERROR` on rejection and guaranteeing zero belief pollution | [`tests/unit/test_security_gate.py`](../../tests/unit/test_security_gate.py) (`test_analyst_agent_shielded_by_gate`), [`demos/demo_assignment_5_1.py`](../../demos/demo_assignment_5_1.py) Scenarios 1–7 | **PASSED** |
| **7. Systematic Attack Vector Verification** | [`demos/demo_assignment_5_1.py`](../../demos/demo_assignment_5_1.py): Comprehensive test harness executing nominal message + 7 distinct attack vectors (`UNKNOWN_SENDER`, `WRONG_RECIPIENT`, `PAYLOAD_TAMPERED`, `BAD_SIGNATURE`, `STALE_TIMESTAMP`, `REPLAYED_NONCE`, `NONCE_CACHE_FULL`) | [`evidence/run_log.txt`](evidence/run_log.txt), [`evidence/security_gate_audit.md`](evidence/security_gate_audit.md) | **PASSED** |
| **8. Audit Trace & Observability Integration** | [`src/sentryscan/observability/recorder.py`](../../src/sentryscan/observability/recorder.py): Single-writer monotonic `seq` logging of security verdicts and rejections | [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl) | **PASSED** |
