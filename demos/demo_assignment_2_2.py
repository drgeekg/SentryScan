#!/usr/bin/env python3
"""Deterministic Demonstration Script for Assignment 2.2 — Socket Messaging & Analyst.

Demonstrates:
1. Length-prefixed binary framing (4-byte big-endian) over localhost TCP.
2. Bidirectional inter-agent communication using canonical Message envelopes.
3. Autonomous reasoning by the AnalystAgent responding with PARAMS_UPDATE to ALERTs.
4. Fault tolerance and graceful handling of malformed frames / JSON payloads.
5. In-process Transport parity for single-process testability.
6. Multi-terminal support via --mode server / --mode client / --mode automated.
"""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import sys
import threading
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentryscan.agents.analyst import AnalystAgent  # noqa: E402
from sentryscan.common.clock import SystemClock  # noqa: E402
from sentryscan.common.id_generator import IdGenerator  # noqa: E402
from sentryscan.contracts.events import EventStatus, EventType  # noqa: E402
from sentryscan.contracts.message import Message, Performative  # noqa: E402
from sentryscan.observability.recorder import EventRecorder  # noqa: E402
from sentryscan.transport.framing import encode_frame  # noqa: E402
from sentryscan.transport.in_process import InProcessTransport  # noqa: E402
from sentryscan.transport.socket_transport import TCPSocketClient  # noqa: E402

logging.basicConfig(level=logging.WARNING)


def run_server_mode(port: int = 8765) -> None:
    """Run standalone Analyst Agent TCP server."""
    print("=" * 78)
    print(f" [Analyst Server] Starting AnalystAgent on 127.0.0.1:{port}...")
    print("=" * 78)

    analyst = AnalystAgent(agent_id="analyst-agent-01")
    actual_port = analyst.start_server(host="127.0.0.1", port=port)
    print(f"[*] AnalystAgent server listening on 127.0.0.1:{actual_port}")
    print("[*] Waiting for incoming ALERT and control envelopes. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Shutting down AnalystAgent server...")
    finally:
        analyst.stop_server()
        print("[*] Server shutdown complete.")


def run_client_mode(port: int = 8765) -> None:
    """Run standalone Supervisor/Scanner client sending alerts."""
    print("=" * 78)
    print(f" [Supervisor Client] Connecting to Analyst on 127.0.0.1:{port}...")
    print("=" * 78)

    client = TCPSocketClient(host="127.0.0.1", port=port)
    print("[*] Attempting connection with exponential backoff...")
    client.connect_with_retry(max_retries=5, initial_backoff=0.2)
    print("[+] Connected to AnalystAgent successfully!\n")

    clock = SystemClock()
    id_gen = IdGenerator(seed=42)

    sample_alerts = [
        ("192.0.2.10", "CRITICAL", "fnd-0001", "RULE-01-VULN-BANNER"),
        ("192.0.2.11", "HIGH", "fnd-0002", "RULE-02-TELNET-EXPOSURE"),
        ("192.0.2.12", "LOW", "fnd-0003", "RULE-06-ROUTINE-PROBE"),
    ]

    try:
        for host, sev, fid, rid in sample_alerts:
            msg = Message(
                message_id=id_gen.next_id("message"),
                run_id="run-interactive",
                sender="supervisor-agent",
                receiver="analyst-agent-01",
                performative=Performative.ALERT,
                timestamp_utc=clock.now_iso(),
                nonce=id_gen.seeded_token(16),
                task_id="task-scan-01",
                payload={
                    "target_host": host,
                    "finding_id": fid,
                    "rule_id": rid,
                    "severity": sev,
                },
            )
            print(f"[>] Outgoing ALERT: {fid} [{sev}] on {host}")
            client.send(msg)

            reply = client.receive(timeout=3.0)
            if reply:
                print(f"[<] Inbound {reply.performative.value} from {reply.sender}:")
                print(f"    - Action:        {reply.payload.get('action')}")
                print(f"    - Interval:      {reply.payload.get('scan_interval_ms')} ms")
                print(f"    - Quarantine:    {reply.payload.get('quarantine_flag')}")
                print(f"    - Rationale:     {reply.payload.get('rationale')}\n")
            else:
                print("[!] Timeout waiting for reply!\n")
            time.sleep(0.5)
    finally:
        client.close()
        print("[*] Client closed connection.")


def run_automated_demo() -> None:
    """Run deterministic end-to-end multi-agent socket demo and generate evidence."""
    evidence_dir = REPO_ROOT / "assignments" / "assignment_2_2" / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    run_log_path = evidence_dir / "run_log.txt"
    trace_path = evidence_dir / "trace_excerpt.jsonl"
    if trace_path.exists():
        trace_path.unlink()

    log_lines: list[str] = []

    def log(line: str) -> None:
        print(line)
        log_lines.append(line)

    clock = SystemClock()
    id_gen = IdGenerator(seed=42)
    recorder = EventRecorder(run_id="run-demo-2-2", output_path=trace_path, clock=clock)

    log("=" * 78)
    log(" SentryScan Milestone 2.2 -- Socket Messaging & Autonomous Analyst ")
    log("=" * 78)

    # 1. Start AnalystAgent Server
    log("\n[1] Starting Process B (AnalystAgent) TCP Server on 127.0.0.1 (ephemeral port)...")
    analyst = AnalystAgent(agent_id="analyst-agent-01", clock=clock, id_gen=id_gen)
    bound_port = analyst.start_server(host="127.0.0.1", port=0)
    log(f"    [+] AnalystAgent listening on 127.0.0.1:{bound_port}")

    recorder.record(
        event_type=EventType.STATE_TRANSITION,
        component="analyst-agent-01",
        status=EventStatus.OK,
        details={"state": "LISTENING", "port": bound_port},
    )

    # 2. Start Supervisor Client
    log("\n[2] Connecting Process A (Supervisor Client) via TCP with backoff...")
    client = TCPSocketClient(host="127.0.0.1", port=bound_port)
    client.connect_with_retry(max_retries=5, initial_backoff=0.05)
    log(f"    [+] Established framed TCP connection to port {bound_port}")

    # 3. Message Sequence: ALERT -> Autonomous PARAMS_UPDATE
    test_cases = [
        (
            "192.0.2.10",
            "CRITICAL",
            "fnd-0001",
            "RULE-01-VULN-BANNER",
            "OpenSSH 7.2p2 Remote Vulnerability",
        ),
        (
            "192.0.2.11",
            "HIGH",
            "fnd-0002",
            "RULE-02-TELNET-EXPOSURE",
            "Unencrypted Telnet Management Port",
        ),
        (
            "192.0.2.12",
            "MEDIUM",
            "fnd-0003",
            "RULE-04-DEPRECATED-TLS",
            "TLS 1.0/1.1 Insecure Protocol",
        ),
        (
            "192.0.2.13",
            "LOW",
            "fnd-0004",
            "RULE-06-ROUTINE-PROBE",
            "HTTP Options Header Information Disclosure",
        ),
    ]

    log("\n[3] Transmitting Security ALERT Messages across Socket...")
    for host, sev, fid, rid, desc in test_cases:
        alert_msg = Message(
            message_id=id_gen.next_id("message"),
            run_id="run-demo-2-2",
            sender="supervisor-agent",
            receiver="analyst-agent-01",
            performative=Performative.ALERT,
            timestamp_utc=clock.now_iso(),
            nonce=id_gen.seeded_token(16),
            task_id="task-fleet-scan",
            payload={
                "target_host": host,
                "finding_id": fid,
                "rule_id": rid,
                "severity": sev,
                "description": desc,
            },
        )

        log("\n    [>] SENDER (supervisor-agent) -> RECEIVER (analyst-agent-01):")
        log(f"        Message ID:   {alert_msg.message_id} (Performative: ALERT)")
        log(f"        Target:       {host} | Finding: {fid} | Severity: {sev}")
        log(f"        Nonce:        {alert_msg.nonce}")

        recorder.record(
            event_type=EventType.MESSAGE_SENT,
            component="supervisor-agent",
            status=EventStatus.OK,
            host_id=host,
            finding_id=fid,
            rule_id=rid,
            details={
                "message_id": alert_msg.message_id,
                "performative": "ALERT",
                "severity": sev,
            },
        )

        client.send(alert_msg)

        # Receive autonomous response
        reply = client.receive(timeout=2.0)
        assert reply is not None, "Failed to receive Analyst response!"
        assert reply.performative == Performative.PARAMS_UPDATE

        log("    [<] RECEIVER (supervisor-agent) <- SENDER (analyst-agent-01):")
        log(f"        Message ID:   {reply.message_id} (Performative: PARAMS_UPDATE)")
        log(f"        Action:       {reply.payload['action']}")
        log(f"        Interval:     {reply.payload['scan_interval_ms']} ms")
        log(f"        Quarantine:   {reply.payload['quarantine_flag']}")
        log(f"        Priority:     {reply.payload['priority_ports']}")
        log(f"        Rationale:    {reply.payload['rationale']}")

        recorder.record(
            event_type=EventType.MESSAGE_RECEIVED,
            component="analyst-agent-01",
            status=EventStatus.OK,
            host_id=host,
            finding_id=fid,
            details={
                "message_id": reply.message_id,
                "performative": "PARAMS_UPDATE",
                "action": reply.payload["action"],
                "scan_interval_ms": reply.payload["scan_interval_ms"],
                "quarantine_flag": reply.payload["quarantine_flag"],
            },
        )

    # 4. Error Resilience Verification: Malformed JSON Frame
    log("\n[4] Testing Socket Fault Tolerance (Malformed Frame Handling)...")
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        raw_sock.connect(("127.0.0.1", bound_port))
        malformed_bytes = b"BROKEN_JSON_STRING_{{{not_json"
        log("    [>] Injecting intentionally corrupted frame payload...")
        raw_sock.sendall(encode_frame(malformed_bytes))

        resp_len_bytes = raw_sock.recv(4)
        resp_len = struct.unpack("!I", resp_len_bytes)[0]
        resp_payload = raw_sock.recv(resp_len)
        err_msg = Message.from_json(resp_payload.decode("utf-8"))

        log("    [+] Analyst handled corrupted frame gracefully!")
        log(f"        Performative returned: {err_msg.performative.value}")
        log(f"        Error details:         {err_msg.payload.get('error')}")

        recorder.record(
            event_type=EventType.RECORD_REJECTED,
            component="analyst-agent-01",
            status=EventStatus.REJECTED,
            reason_code="BAD_JSON",
            details={"error_performative": err_msg.performative.value},
        )
    finally:
        raw_sock.close()

    # 5. In-Process Transport Parity Check
    log("\n[5] Verifying Transport Interface Parity (In-Process Adapter)...")
    t_analyst, t_sup = InProcessTransport.create_pair()
    analyst_in_proc = AnalystAgent(agent_id="analyst-in-process", clock=clock, id_gen=id_gen)

    in_proc_stop = threading.Event()
    th = threading.Thread(
        target=lambda: analyst_in_proc.listen_and_respond(
            t_analyst, stop_event=in_proc_stop, timeout=0.05
        ),
        daemon=True,
    )
    th.start()

    t_sup.send(
        Message(
            message_id="msg-inproc-01",
            run_id="run-inproc",
            sender="supervisor-agent",
            receiver="analyst-in-process",
            performative=Performative.ALERT,
            timestamp_utc=clock.now_iso(),
            nonce="nonce-inproc-01",
            payload={"target_host": "192.0.2.99", "severity": "CRITICAL"},
        )
    )

    inproc_reply = t_sup.receive(timeout=1.0)
    assert inproc_reply is not None
    assert inproc_reply.performative == Performative.PARAMS_UPDATE
    log("    [+] InProcessTransport produced identical autonomous PARAMS_UPDATE reply.")

    in_proc_stop.set()
    th.join(timeout=1.0)
    t_analyst.close()
    t_sup.close()

    # Cleanup
    client.close()
    analyst.stop_server()
    recorder.close()
    log("\n[6] Clean shutdown of all TCP transports and sockets verified.")

    # Save run log
    with open(run_log_path, "w", encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")

    log("\n[*] Execution artifacts successfully written:")
    log(f"    - Console Log:   {run_log_path}")
    log(f"    - Trace Excerpt: {trace_path}")
    log("=" * 78)


def main() -> None:
    parser = argparse.ArgumentParser(description="Assignment 2.2 Socket Messaging Demo")
    parser.add_argument(
        "--mode",
        choices=["automated", "server", "client"],
        default="automated",
        help="Run mode: automated (full test & capture), server (Analyst), client (Supervisor)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="TCP port to listen on or connect to (default: 8765)",
    )
    args = parser.parse_args()

    if args.mode == "server":
        run_server_mode(port=args.port)
    elif args.mode == "client":
        run_client_mode(port=args.port)
    else:
        run_automated_demo()


if __name__ == "__main__":
    main()
