# Assignment 5.1 Acceptance Checklist

- [x] Cryptographic dependencies and configuration:
  - Pinned `cryptography>=42.0.0` in `requirements.txt` and `pyproject.toml`.
  - Installed and verified in virtual environment (`.venv`).
  - Strict security boundary: throwaway in-memory keys, private keys never logged, dumped, or committed.
- [x] Per-agent Ed25519 identity management implemented in `src/sentryscan/security/identity.py`:
  - `AgentIdentity` with fresh keypair generation and deterministic 32-byte seed derivation.
  - Raw public key bytes and 64-character lowercase hexadecimal formatting.
  - Signing and verification methods.
- [x] Trusted Agent Public Key Registry implemented in `src/sentryscan/security/registry.py`:
  - `TrustedAgentRecord` and `TrustedAgentRegistry`.
  - Agent lookup, revocation status checking, and public key deserialization.
  - JSON serialization and deserialization (`load_from_file`, `save_to_file`).
  - Example registry configuration provided in `config/trusted_agents.example.json`.
- [x] Canonical envelope signing and payload integrity in `src/sentryscan/security/canonical.py`:
  - SHA-256 payload digest calculation over canonical UTF-8 JSON.
  - Canonical signing byte format binding `sender`, `receiver`, `timestamp_utc`, `performative`, `message_id`, and `payload_sha256`.
  - Ed25519 digital signature generation and verification.
- [x] Anti-replay nonce cache implemented in `src/sentryscan/security/nonce_cache.py`:
  - Dual FIFO/TTL expiration tracking.
  - Per-sender nonce isolation preventing replay within the temporal window.
  - Strictly bounded maximum capacity (default 10,000 entries).
  - Explicit fail-closed behavior returning `NONCE_CACHE_FULL` when saturated.
- [x] Multi-stage Inbound Security Gate implemented in `src/sentryscan/security/gate.py`:
  - Strict validation pipeline following HLD §12.3:
    1. JSON decoding (`BAD_JSON`)
    2. Envelope schema validation (`BAD_SCHEMA`)
    3. Sender registry lookup (`UNKNOWN_SENDER`)
    4. Recipient matching (`WRONG_RECIPIENT`)
    5. Payload digest verification (`PAYLOAD_TAMPERED`)
    6. Ed25519 signature verification (`BAD_SIGNATURE`)
    7. Clock skew freshness window $\pm 30$s (`STALE_TIMESTAMP`)
    8. Anti-replay nonce cache check (`REPLAYED_NONCE`, `NONCE_CACHE_FULL`)
  - Structured decision artifacts: `SecurityVerdict` with `SecurityReasonCode`.
- [x] Deliberative BDI Shielding integrated in `src/sentryscan/agents/analyst.py`:
  - Intercepts raw messages before BDI reasoning.
  - Rejects untrusted or compromised messages, emitting structured `ERROR` responses without modifying beliefs or intentions.
  - Allows verified messages to proceed to belief update and LangGraph deliberation.
- [x] Unit test suites implemented and passing:
  - Identity tests in `tests/unit/test_security_identity.py` (4/4 passing).
  - Canonical signing tests in `tests/unit/test_security_signing.py` (4/4 passing).
  - Security gate tests in `tests/unit/test_security_gate.py` (9/9 passing).
- [x] Multi-scenario demonstration script implemented in `demos/demo_assignment_5_1.py`:
  - Verifies nominal valid message acceptance.
  - Systematically tests all 7 rejection vectors (`UNKNOWN_SENDER`, `WRONG_RECIPIENT`, `PAYLOAD_TAMPERED`, `BAD_SIGNATURE`, `STALE_TIMESTAMP`, `REPLAYED_NONCE`, `NONCE_CACHE_FULL`).
  - Generates evidence artifacts: `evidence/run_log.txt`, `evidence/security_gate_audit.md`, and `evidence/trace_excerpt.jsonl`.
- [x] Repository quality checks:
  - 137/137 tests passing across entire repository.
  - Ruff check passing cleanly with 0 errors.
