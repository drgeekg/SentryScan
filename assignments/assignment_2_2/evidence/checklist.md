# Assignment 2.2 Acceptance Checklist

- [x] Canonical `Message` envelope defined with typed fields (`message_id`, `run_id`, `sender`, `receiver`, `performative`, `timestamp_utc`, `nonce`, `payload`).
- [x] Standard performative taxonomy implemented including `ALERT`, `PARAMS_UPDATE`, `TASK_REQUEST`, `TASK_RESULT`, `STATE_SYNC`, `ERROR`.
- [x] Deterministic canonical bytes serialization and SHA-256 payload digest methods provided.
- [x] Binary length prefix framing implemented (4-byte unsigned big-endian prefix `!I`).
- [x] Stream chunk reader (`FrameReader`) handles partial frames and multi-frame packets.
- [x] Maximum frame length boundary (1 MB) enforced to prevent memory exhaustion attacks.
- [x] `TCPSocketServer` and `TCPSocketClient` implemented with thread-safe send and background receive loops.
- [x] Reconnection logic with exponential backoff implemented on client.
- [x] Abstract `Transport` protocol defined with `send`, `receive`, and `close`.
- [x] `InProcessTransport` implemented using thread-safe synchronous queues for unit tests.
- [x] `AnalystAgent` implemented responding autonomously to `ALERT` messages with `PARAMS_UPDATE`.
- [x] Severity-based parameter tuning verified (50ms + quarantine for CRITICAL, 100ms for HIGH, 250ms for MEDIUM, 500ms for LOW).
- [x] Socket boundary fault tolerance verified (corrupt JSON safely isolated into `ERROR` reply).
- [x] Two-terminal execution supported via `--mode server` and `--mode client`.
- [x] Automated demo generates [`run_log.txt`](run_log.txt) and [`trace_excerpt.jsonl`](trace_excerpt.jsonl).
- [x] All 61 pytest tests pass cleanly with 0 failures and 0 warnings.
- [x] Ruff lint checks pass cleanly with 0 errors across entire repository.
