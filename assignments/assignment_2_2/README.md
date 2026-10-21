# Assignment 2.2 — Socket Messaging, Framing & Autonomous Analyst

**Course:** 21CSE525T — Agent Technology  
**Student:** R Ganesh [RA2212704010031]  
**Status:** Completed & Verified  
**Git Tag:** `assignment-2.2`  

---

## 1. Architectural Increment Overview

Assignment 2.2 establishes inter-agent network communication, message framing, process-level decoupling, and autonomous reactive parameter adjustments:

1. **Shared Message Envelope & Performative Taxonomy:**
   - [`src/sentryscan/contracts/message.py`](../../src/sentryscan/contracts/message.py): Defines the canonical typed `Message` envelope model with strict fields (`message_id`, `run_id`, `sender`, `receiver`, `performative`, `timestamp_utc`, `nonce`, `payload`, `task_id`, `payload_sha256`, `signature`). Introduces standard speech-act communicative performatives: `ALERT`, `PARAMS_UPDATE`, `TASK_REQUEST`, `TASK_RESULT`, `STATE_SYNC`, `CFP`, `PROPOSE`, `COUNTERPROPOSE`, `ACCEPT`, `REJECT`, `CONFIRM`, `EVENT`, `ERROR`. Includes canonical serialization methods for deterministic signing and payload digest hashing (`canonical_payload_bytes()`, `compute_payload_sha256()`).
2. **Length-Prefixed Binary Framing Protocol:**
   - [`src/sentryscan/transport/framing.py`](../../src/sentryscan/transport/framing.py): 4-byte big-endian unsigned length prefix header framing (`!I`). Features `FrameReader` for robust stream buffering, handling partial byte chunks across socket reads, parsing multi-frame streams, and enforcing a strict 1 MB maximum frame size (`FrameTooLargeError`) to safeguard against buffer exhaustion.
3. **Robust TCP Socket Transport:**
   - [`src/sentryscan/transport/socket_transport.py`](../../src/sentryscan/transport/socket_transport.py): Implements `TCPSocketServer` and `TCPSocketClient` on `127.0.0.1`. Features background listener and reader threads, thread-safe message transmission with mutex locks, client reconnect with exponential backoff, and graceful socket shutdown.
4. **Transport Interface & In-Process Adapter:**
   - [`src/sentryscan/transport/interface.py`](../../src/sentryscan/transport/interface.py): Abstract `Transport` protocol defining `send()`, `receive()`, and `close()`.
   - [`src/sentryscan/transport/in_process.py`](../../src/sentryscan/transport/in_process.py): Thread-safe queue-backed `InProcessTransport` allowing fast, reliable in-memory multi-agent testing and zero-overhead execution without network sockets.
5. **Autonomous Analyst Agent:**
   - [`src/sentryscan/agents/analyst.py`](../../src/sentryscan/agents/analyst.py): Represents Process B in the system architecture. Receives `ALERT` messages over transport, parses severity levels, maintains internal beliefs, and autonomously decides adaptive scan policies:
     - `CRITICAL`: Emits `PARAMS_UPDATE` requesting immediate high-frequency deep inspection (50 ms cadence), port sweep, and quarantine enforcement.
     - `HIGH`: Emits `PARAMS_UPDATE` with tightened 100 ms monitoring and core port priority.
     - `MEDIUM`: Emits `PARAMS_UPDATE` with 250 ms standard targeted cadence.
     - `LOW`: Emits `PARAMS_UPDATE` retaining nominal 500 ms baseline cadence.
6. **Fault Tolerance & Malformed Frame Resilience:**
   - Ingesting corrupt or non-JSON payloads across the socket boundary does not crash the server; the exception is trapped and safely returned as an `ERROR` performative.

---

## 2. Multi-Terminal Execution & Demonstration

The demonstration supports both automated single-command execution and interactive two-terminal multi-process execution:

### Mode A: Automated End-to-End Verification
```bash
python demos/demo_assignment_2_2.py --mode automated
```
Spins up the Analyst server on an ephemeral port, establishes client connection with backoff, executes full bidirectional message exchanges across four severity tiers, verifies malformed frame resilience, confirms in-process transport parity, logs trace events, and performs clean shutdown.

### Mode B: Two-Terminal Execution (Rubric Demonstration)

**Terminal 1 (Analyst Server — Process B):**
```bash
python demos/demo_assignment_2_2.py --mode server --port 8765
```

**Terminal 2 (Supervisor Client — Process A):**
```bash
python demos/demo_assignment_2_2.py --mode client --port 8765
```

---

## 3. Evidence & Acceptance Verification

All execution artifacts have been captured and verified:
- **Run Log:** [`evidence/run_log.txt`](evidence/run_log.txt)
- **Trace Excerpt (JSONL):** [`evidence/trace_excerpt.jsonl`](evidence/trace_excerpt.jsonl)
- **Rubric Mapping:** [`rubric_map.md`](rubric_map.md)
- **Acceptance Checklist:** [`evidence/checklist.md`](evidence/checklist.md)

### Verification Summary
- **Unit & Integration Tests:** 61 passed across all suites (`tests/unit/test_transport.py`, `tests/unit/test_analyst.py`, `tests/unit/test_message.py`).
- **Framing Invariant:** Verified 4-byte big-endian framing with partial stream assembly and max size enforcement.
- **Autonomous Reasoning:** Verified CRITICAL alert triggers quarantine and 50 ms cadence; HIGH triggers 100 ms cadence; LOW retains 500 ms nominal cadence.
- **Fault Resilience:** Malformed payload safely caught and responded with `ERROR` performative without process termination.
