# Assignment 2.2 — Rubric to Evidence Mapping

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Assignment:** Assignment 2.2 (Socket Messaging & Autonomous Analyst)  
**Date:** 2026-10-21  

---

## Evaluation Criteria & Implementation Evidence

| Rubric Criterion | Implementation Component | Evidence Artifact | Status |
|---|---|---|---|
| **1. Agent Message Envelope & Speech Acts** | [`src/sentryscan/contracts/message.py`](../../src/sentryscan/contracts/message.py): `Message` envelope and `Performative` taxonomy (`ALERT`, `PARAMS_UPDATE`, `TASK_REQUEST`, `TASK_RESULT`, `STATE_SYNC`, `CFP`, `ERROR`, etc.) | [`tests/unit/test_message.py`](../../tests/unit/test_message.py), [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl) | **PASSED** |
| **2. Length-Prefixed Binary Framing Protocol** | [`src/sentryscan/transport/framing.py`](../../src/sentryscan/transport/framing.py): 4-byte big-endian unsigned length header (`!I`), `FrameReader` stream buffer, max frame limit enforcement | [`tests/unit/test_transport.py`](../../tests/unit/test_transport.py) (tests `test_encode_frame_structure`, `test_frame_reader_partial_chunks`) | **PASSED** |
| **3. TCP Socket Client & Server Transport** | [`src/sentryscan/transport/socket_transport.py`](../../src/sentryscan/transport/socket_transport.py): `TCPSocketServer`, `TCPSocketClient`, thread-safe locks, background readers, graceful shutdown | [`demos/demo_assignment_2_2.py`](../../demos/demo_assignment_2_2.py), [`evidence/run_log.txt`](evidence/run_log.txt) | **PASSED** |
| **4. Transport Interface with In-Process Adapter** | [`src/sentryscan/transport/interface.py`](../../src/sentryscan/transport/interface.py), [`src/sentryscan/transport/in_process.py`](../../src/sentryscan/transport/in_process.py): Full-duplex queue-backed transport protocol | [`tests/unit/test_transport.py`](../../tests/unit/test_transport.py) (tests `test_in_process_transport_pair`), `demo_assignment_2_2.py` Step 5 | **PASSED** |
| **5. Autonomous Analyst Response (`PARAMS_UPDATE`)** | [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py): Autonomous parameter policy adapting scan intervals (50ms/100ms/250ms/500ms), quarantine flags, and port sweeps | [`tests/unit/test_analyst.py`](../../tests/unit/test_analyst.py), [`evidence/run_log.txt`](evidence/run_log.txt) Step 3 | **PASSED** |
| **6. Reconnect with Exponential Backoff** | [`src/sentryscan/transport/socket_transport.py`](../../src/sentryscan/transport/socket_transport.py): `connect_with_retry(max_retries, initial_backoff, backoff_multiplier)` | [`tests/unit/test_transport.py`](../../tests/unit/test_transport.py) (`test_tcp_socket_client_reconnect_backoff`) | **PASSED** |
| **7. Malformed Frame / Fault Resilience** | Graceful isolation of corrupt/non-JSON payloads at socket boundary, returning `ERROR` performative without server crash | [`demos/demo_assignment_2_2.py`](../../demos/demo_assignment_2_2.py) Step 4, [`tests/unit/test_transport.py`](../../tests/unit/test_transport.py) | **PASSED** |
| **8. Multi-Terminal Demonstration Support** | `demos/demo_assignment_2_2.py` with `--mode server` and `--mode client` flags for two-terminal execution, alongside `--mode automated` | [`demos/demo_assignment_2_2.py`](../../demos/demo_assignment_2_2.py), [`assignments/assignment_2_2/README.md`](README.md) | **PASSED** |
| **9. Trace Persistence & Single-Writer Auditing** | [`src/sentryscan/observability/recorder.py`](../../src/sentryscan/observability/recorder.py): Authoritative sequential JSONL event logging | [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl) | **PASSED** |
