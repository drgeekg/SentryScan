# Assignment 5.1 — Cryptographic Message Authentication & Security Gate

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-5.1`  

---

## 1. Architectural Increment Overview

Assignment 5.1 hardens the SentryScan multi-agent architecture against spoofing, eavesdropping, payload manipulation, out-of-order injection, and replay attacks by introducing an end-to-end cryptographic security perimeter following HLD §12:

1. **Cryptographic Agent Identity Management:**
   - [`src/sentryscan/security/identity.py`](../../src/sentryscan/security/identity.py): Implements `AgentIdentity` utilizing Ed25519 high-speed elliptic curve digital signatures (`cryptography>=42.0.0`).
   - Supports ephemeral generation and deterministic seed derivation for reproducible test suites.
   - **Safety Boundary:** Private keys are strictly retained in memory and are never written to disk, committed to version control, or serialized in audit traces.
2. **Trusted Agent Public Key Registry:**
   - [`src/sentryscan/security/registry.py`](../../src/sentryscan/security/registry.py): Implements `TrustedAgentRegistry` maintaining a directory of verified public keys, roles, and lifecycle statuses (`ACTIVE`, `REVOKED`).
   - Supports file-backed persistence (`load_from_file`, `save_to_file`) with sample configuration in [`config/trusted_agents.example.json`](../../config/trusted_agents.example.json).
3. **Canonical Envelope Signing & Payload Integrity:**
   - [`src/sentryscan/security/canonical.py`](../../src/sentryscan/security/canonical.py): Enforces deterministic canonical JSON serialization (UTF-8, sorted keys, compact separators).
   - Binds the sender, receiver, UTC timestamp, performative, message ID, and SHA-256 payload digest into canonical signing bytes.
   - Prevents parameter tampering in transit; any modification to payload attributes invalidates the digest prior to signature verification.
4. **Bounded Fail-Closed Anti-Replay Nonce Cache:**
   - [`src/sentryscan/security/nonce_cache.py`](../../src/sentryscan/security/nonce_cache.py): Implements `NonceCache` combining FIFO ring indexing with TTL time-to-live eviction (default 60 seconds).
   - Isolates nonces per sender to prevent cross-agent collisions.
   - Bounded to a strict maximum capacity (default 10,000 entries). Under flooding or resource exhaustion, the cache **fails closed**, returning `NONCE_CACHE_FULL` rather than allowing un-tracked messages through.
5. **Inbound Security Gate:**
   - [`src/sentryscan/security/gate.py`](../../src/sentryscan/security/gate.py): Implements `SecurityGate` executing the multi-stage evaluation pipeline specified in HLD §12.3:
     $$\text{JSON Parse} \to \text{Schema Validation} \to \text{Sender Registry} \to \text{Recipient Match} \to \text{Payload Digest} \to \text{Ed25519 Signature} \to \text{Freshness Window} \to \text{Nonce Cache}$$
   - Generates structured `SecurityVerdict` objects with machine-readable `SecurityReasonCode` classifications.
6. **Deliberative BDI Shielding:**
   - [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py): Seamlessly integrates `SecurityGate`. Unvetted or malicious envelopes are intercepted before reaching the agent's core `BeliefBase` or triggering LangGraph deliberation. Rejection emits an explicit `ERROR` performative containing the diagnostic reason code.

---

## 2. Benchmark Evidence & Deliverables

Demonstration artifacts generated from execution:
- **Execution Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Security Gate Audit Matrix:** [`evidence/security_gate_audit.md`](evidence/security_gate_audit.md)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **Scenario 1 (Nominal):** Legitimate signed alert accepted (`OK`), processed by AnalystAgent, emitting `PARAMS_UPDATE`.
- **Scenario 2 (Untrusted Sender):** Rogue agent message rejected with `UNKNOWN_SENDER`.
- **Scenario 3 (Wrong Recipient):** Misrouted envelope rejected with `WRONG_RECIPIENT`.
- **Scenario 4 (Tampered Payload):** In-transit payload alteration rejected with `PAYLOAD_TAMPERED`.
- **Scenario 5 (Bad Signature):** Forged / corrupted signature bytes rejected with `BAD_SIGNATURE`.
- **Scenario 6 (Stale Timestamp):** Clock skew exceeding $\pm 30$s rejected with `STALE_TIMESTAMP`.
- **Scenario 7 (Replayed Nonce):** Duplicate message transmission caught and rejected with `REPLAYED_NONCE`.
- **Scenario 8 (Cache Saturation):** Saturated cache cleanly fails closed with `NONCE_CACHE_FULL`.
- **Test Suite Status:** 137 passed across all unit and integration test suites with 0 failures and 0 warnings.

---

## 3. Reproduction Instructions

```bash
# Run deterministic security gate demonstration
python demos/demo_assignment_5_1.py

# Run unit and integration tests
pytest -v tests/

# Verify code style and linter
ruff check .

# Package submission archive from immutable tag
python scripts/package_assignment.py assignment-5.1
```
