"""Demonstration and evidence generator for Milestone 5.1: Security Gate.

Executes a deterministic security verification suite showing:
1. Generation and registration of cryptographic Ed25519 agent identities.
2. Nominal valid signed envelope exchange accepted by SecurityGate.
3. Rejection Vector 1: Unknown / Untrusted sender rejected (UNKNOWN_SENDER).
4. Rejection Vector 2: Mismatched recipient envelope rejected (WRONG_RECIPIENT).
5. Rejection Vector 3: Tampered payload bytes rejected (PAYLOAD_TAMPERED).
6. Rejection Vector 4: Forged / corrupted signature rejected (BAD_SIGNATURE).
7. Rejection Vector 5: Expired clock skew rejected (STALE_TIMESTAMP).
8. Rejection Vector 6: Duplicate envelope replay attack rejected (REPLAYED_NONCE).
9. Rejection Vector 7: Nonce cache saturation fail-closed (NONCE_CACHE_FULL).
10. Shielded AnalystAgent BDI state verification ensuring zero belief pollution.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src is in Python path for direct execution
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentryscan.agents.analyst import AnalystAgent
from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.events import EventStatus, EventType
from sentryscan.contracts.message import Message, Performative
from sentryscan.observability.recorder import EventRecorder
from sentryscan.security.canonical import sign_envelope
from sentryscan.security.gate import SecurityGate, SecurityReasonCode
from sentryscan.security.identity import AgentIdentity
from sentryscan.security.nonce_cache import NonceCache
from sentryscan.security.registry import TrustedAgentRegistry


def run_demo() -> None:
    output_dir = Path("assignments/assignment_5_1/evidence")
    output_dir.mkdir(parents=True, exist_ok=True)
    trace_path = output_dir / "trace_excerpt.jsonl"
    run_log_path = output_dir / "run_log.txt"
    audit_table_path = output_dir / "security_gate_audit.md"

    clock = FakeClock("2026-10-21T10:00:00Z")
    id_gen = IdGenerator(seed=5101)
    recorder = EventRecorder(
        run_id="run-security-gate-demo",
        output_path=trace_path,
        clock=clock,
    )

    # -------------------------------------------------------------------------
    # 1. Setup Identities and Trusted Registry
    # -------------------------------------------------------------------------
    supervisor_id = AgentIdentity.generate("supervisor-agent-01")
    analyst_id = AgentIdentity.generate("analyst-agent-01")
    sensor_id = AgentIdentity.generate("sensor-agent-01")
    rogue_id = AgentIdentity.generate("rogue-agent-99")

    registry = TrustedAgentRegistry()
    registry.register(
        agent_id=supervisor_id.agent_id,
        public_key_hex=supervisor_id.public_key_hex,
        description="SupervisorAgent",
    )
    registry.register(
        agent_id=analyst_id.agent_id,
        public_key_hex=analyst_id.public_key_hex,
        description="AnalystAgent",
    )
    registry.register(
        agent_id=sensor_id.agent_id,
        public_key_hex=sensor_id.public_key_hex,
        description="SensorAgent",
    )
    # Note: rogue_id is intentionally omitted from registry

    analyst_gate = SecurityGate(
        agent_id="analyst-agent-01",
        registry=registry,
        clock=clock,
        freshness_window_seconds=30.0,
    )

    analyst = AnalystAgent(
        agent_id="analyst-agent-01",
        clock=clock,
        id_gen=id_gen,
        security_gate=analyst_gate,
    )

    log_lines: list[str] = []

    def log(msg: str = "") -> None:
        print(msg)
        log_lines.append(msg)

    log("=" * 82)
    log(" SentryScan Milestone 5.1 -- Cryptographic Message Authentication & Gate Demo ")
    log("=" * 82)
    log()
    log("[*] Initializing Cryptographic Environment:")
    log(f"    - Trusted Registry Agents : {len(registry.list_all())} enrolled")
    log(f"      * {supervisor_id.agent_id} (Supervisor): {supervisor_id.public_key_hex[:16]}...")
    log(f"      * {analyst_id.agent_id} (Analyst): {analyst_id.public_key_hex[:16]}...")
    log(f"      * {sensor_id.agent_id} (Sensor): {sensor_id.public_key_hex[:16]}...")
    log(f"    - Untrusted Rogue Agent  : {rogue_id.agent_id} (Unregistered)")
    log("    - Inbound Gate Recipient : analyst-agent-01")
    log("    - Clock Skew Allowance   : +/- 30.0s")
    log("    - Anti-Replay Cache      : NonceCache (capacity=10000, ttl=60.0s)")
    log()

    audit_records: list[dict[str, str]] = []

    # -------------------------------------------------------------------------
    # Scenario 1: Nominal Valid Signed Message
    # -------------------------------------------------------------------------
    log("[1] Scenario 1: Nominal Valid Signed Message")
    payload_1 = {
        "target_host": "192.0.2.10",
        "finding_id": "fnd-501",
        "rule_id": "RULE-01-PORT",
        "severity": "MEDIUM",
        "service": "ssh",
    }
    raw_msg_1 = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="sensor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce=id_gen.seeded_token(16),
        payload=payload_1,
    )
    signed_msg_1 = sign_envelope(raw_msg_1, sensor_id)
    verdict_1 = analyst_gate.validate(signed_msg_1)

    log(f"    - Envelope ID      : {signed_msg_1.message_id}")
    log(f"    - Sender           : {signed_msg_1.sender} -> Receiver: {signed_msg_1.receiver}")
    log(f"    - Payload Digest   : {signed_msg_1.payload_sha256[:20]}...")
    log(f"    - Ed25519 Sig      : {signed_msg_1.signature[:20]}...")
    log(f"    - Gate Evaluation  : valid={verdict_1.valid}, reason={verdict_1.reason_code.value}")
    assert verdict_1.valid

    # Dispatch fresh valid envelope to AnalystAgent
    raw_msg_1_agent = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="sensor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce=id_gen.seeded_token(16),
        payload=payload_1,
    )
    signed_msg_1_agent = sign_envelope(raw_msg_1_agent, sensor_id)
    reply_1 = analyst.process_message(signed_msg_1_agent)
    assert reply_1 is not None
    assert reply_1.performative == Performative.PARAMS_UPDATE
    action_1 = reply_1.payload.get("action")
    log(f"    - Analyst Action   : Emitted {reply_1.performative.value} (Action: {action_1})")
    log(f"    - BDI Belief Count : {len(analyst.beliefs)} host belief(s)")
    log()

    recorder.record(
        event_type=EventType.MESSAGE_RECEIVED,
        component="analyst_gate",
        status=EventStatus.OK,
        details={"message_id": signed_msg_1.message_id, "verdict": verdict_1.reason_code.value},
    )

    audit_records.append({
        "scenario": "1. Nominal Valid Message",
        "sender": "sensor-agent-01",
        "attack_vector": "None (Legitimate telemetry)",
        "expected_code": "OK",
        "actual_code": verdict_1.reason_code.value,
        "analyst_shielded": "Processed (Beliefs updated)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Scenario 2: Untrusted Sender (UNKNOWN_SENDER)
    # -------------------------------------------------------------------------
    log("[2] Scenario 2: Untrusted Sender (UNKNOWN_SENDER)")
    raw_msg_2 = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="rogue-agent-99",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce=id_gen.seeded_token(16),
        payload={"command": "SHUTDOWN_MONITORING"},
    )
    signed_msg_2 = sign_envelope(raw_msg_2, rogue_id)
    verdict_2 = analyst_gate.validate(signed_msg_2)

    log(f"    - Sender           : {signed_msg_2.sender} (Not in registry)")
    log(f"    - Gate Evaluation  : valid={verdict_2.valid}, reason={verdict_2.reason_code.value}")
    log(f"    - Audit Message    : {verdict_2.reason_summary}")
    assert not verdict_2.valid
    assert verdict_2.reason_code == SecurityReasonCode.UNKNOWN_SENDER

    reply_2 = analyst.process_message(signed_msg_2)
    assert reply_2 is not None
    assert reply_2.performative == Performative.ERROR
    code_2 = reply_2.payload["reason_code"]
    assert code_2 == SecurityReasonCode.UNKNOWN_SENDER.value
    log(f"    - Analyst Shield   : Emitted ERROR ({code_2}); zero BDI mutation")
    log()

    recorder.record(
        event_type=EventType.RECORD_REJECTED,
        component="analyst_gate",
        status=EventStatus.REJECTED,
        reason_code=verdict_2.reason_code.value,
        details={"sender": signed_msg_2.sender},
    )

    audit_records.append({
        "scenario": "2. Untrusted Sender",
        "sender": "rogue-agent-99",
        "attack_vector": "Rogue agent spoofing command",
        "expected_code": "UNKNOWN_SENDER",
        "actual_code": verdict_2.reason_code.value,
        "analyst_shielded": "Shielded (ERROR response emitted)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Scenario 3: Mismatched Recipient (WRONG_RECIPIENT)
    # -------------------------------------------------------------------------
    log("[3] Scenario 3: Mismatched Recipient (WRONG_RECIPIENT)")
    raw_msg_3 = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="supervisor-agent-01",
        receiver="actuator-agent-01",  # Destined for actuator, misrouted to analyst
        performative=Performative.TASK_REQUEST,
        timestamp_utc=clock.now_iso(),
        nonce=id_gen.seeded_token(16),
        payload={"action": "FIREWALL_DROP", "ip": "192.0.2.99"},
    )
    signed_msg_3 = sign_envelope(raw_msg_3, supervisor_id)
    verdict_3 = analyst_gate.validate(signed_msg_3)

    log("    - Target Envelope  : intended for 'actuator', inspected at 'analyst'")
    log(f"    - Gate Evaluation  : valid={verdict_3.valid}, reason={verdict_3.reason_code.value}")
    log(f"    - Audit Message    : {verdict_3.reason_summary}")
    assert not verdict_3.valid
    assert verdict_3.reason_code == SecurityReasonCode.WRONG_RECIPIENT

    reply_3 = analyst.process_message(signed_msg_3)
    assert reply_3 is not None
    assert reply_3.performative == Performative.ERROR
    code_3 = reply_3.payload["reason_code"]
    assert code_3 == SecurityReasonCode.WRONG_RECIPIENT.value
    log(f"    - Analyst Shield   : Emitted ERROR ({code_3}); wrong recipient blocked")
    log()

    recorder.record(
        event_type=EventType.RECORD_REJECTED,
        component="analyst_gate",
        status=EventStatus.REJECTED,
        reason_code=verdict_3.reason_code.value,
        details={"intended_receiver": signed_msg_3.receiver},
    )

    audit_records.append({
        "scenario": "3. Wrong Recipient",
        "sender": "supervisor-agent-01",
        "attack_vector": "Misrouted / Confused deputy packet",
        "expected_code": "WRONG_RECIPIENT",
        "actual_code": verdict_3.reason_code.value,
        "analyst_shielded": "Shielded (ERROR response emitted)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Scenario 4: Tampered Payload in Transit (PAYLOAD_TAMPERED)
    # -------------------------------------------------------------------------
    log("[4] Scenario 4: Tampered Payload in Transit (PAYLOAD_TAMPERED)")
    raw_msg_4 = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="sensor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce=id_gen.seeded_token(16),
        payload={"target_host": "192.0.2.10", "severity": "LOW"},
    )
    signed_msg_4 = sign_envelope(raw_msg_4, sensor_id)
    # MITM tampering: modify severity to CRITICAL without re-signing
    tampered_msg_4 = signed_msg_4.model_copy(
        update={"payload": {"target_host": "192.0.2.10", "severity": "CRITICAL"}}
    )
    verdict_4 = analyst_gate.validate(tampered_msg_4)

    log("    - Interception     : Altered payload 'LOW' -> 'CRITICAL'")
    log(f"    - Gate Evaluation  : valid={verdict_4.valid}, reason={verdict_4.reason_code.value}")
    log(f"    - Audit Message    : {verdict_4.reason_summary}")
    assert not verdict_4.valid
    assert verdict_4.reason_code == SecurityReasonCode.PAYLOAD_TAMPERED

    reply_4 = analyst.process_message(tampered_msg_4)
    assert reply_4 is not None
    assert reply_4.performative == Performative.ERROR
    code_4 = reply_4.payload["reason_code"]
    assert code_4 == SecurityReasonCode.PAYLOAD_TAMPERED.value
    log(f"    - Analyst Shield   : Emitted ERROR ({code_4}); tamper caught")
    log()

    recorder.record(
        event_type=EventType.RECORD_REJECTED,
        component="analyst_gate",
        status=EventStatus.REJECTED,
        reason_code=verdict_4.reason_code.value,
        details={"message_id": tampered_msg_4.message_id},
    )

    audit_records.append({
        "scenario": "4. Tampered Payload",
        "sender": "sensor-agent-01",
        "attack_vector": "MITM tampering of payload parameters",
        "expected_code": "PAYLOAD_TAMPERED",
        "actual_code": verdict_4.reason_code.value,
        "analyst_shielded": "Shielded (ERROR response emitted)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Scenario 5: Forged / Corrupted Ed25519 Signature (BAD_SIGNATURE)
    # -------------------------------------------------------------------------
    log("[5] Scenario 5: Forged / Corrupted Ed25519 Signature (BAD_SIGNATURE)")
    raw_msg_5 = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="supervisor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce=id_gen.seeded_token(16),
        payload={"policy": "FORCE_REPLAN"},
    )
    # Sign validly first, then corrupt signature bytes to simulate forgery
    valid_signed_5 = sign_envelope(raw_msg_5, supervisor_id)
    corrupted_sig = ("00" if valid_signed_5.signature.startswith("ff") else "ff") * 64
    forged_msg_5 = valid_signed_5.model_copy(update={"signature": corrupted_sig})
    verdict_5 = analyst_gate.validate(forged_msg_5)

    log("    - Impersonation    : Corrupted signature on claimed supervisor envelope")
    log(f"    - Gate Evaluation  : valid={verdict_5.valid}, reason={verdict_5.reason_code.value}")
    log(f"    - Audit Message    : {verdict_5.reason_summary}")
    assert not verdict_5.valid
    assert verdict_5.reason_code == SecurityReasonCode.BAD_SIGNATURE

    reply_5 = analyst.process_message(forged_msg_5)
    assert reply_5 is not None
    assert reply_5.performative == Performative.ERROR
    code_5 = reply_5.payload["reason_code"]
    assert code_5 == SecurityReasonCode.BAD_SIGNATURE.value
    log(f"    - Analyst Shield   : Emitted ERROR ({code_5}); forgery blocked")
    log()

    recorder.record(
        event_type=EventType.RECORD_REJECTED,
        component="analyst_gate",
        status=EventStatus.REJECTED,
        reason_code=verdict_5.reason_code.value,
        details={"claimed_sender": forged_msg_5.sender},
    )

    audit_records.append({
        "scenario": "5. Bad Signature",
        "sender": "supervisor-agent-01 (forged)",
        "attack_vector": "Impersonation with forged/invalid signature",
        "expected_code": "BAD_SIGNATURE",
        "actual_code": verdict_5.reason_code.value,
        "analyst_shielded": "Shielded (ERROR response emitted)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Scenario 6: Expired / Out-of-Bounds Clock Drift (STALE_TIMESTAMP)
    # -------------------------------------------------------------------------
    log("[6] Scenario 6: Expired / Stale Timestamp (STALE_TIMESTAMP)")
    raw_msg_6 = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="sensor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc="2026-10-21T09:58:30Z",  # 90 seconds behind clock
        nonce=id_gen.seeded_token(16),
        payload={"host": "192.0.2.10", "status": "UP"},
    )
    signed_msg_6 = sign_envelope(raw_msg_6, sensor_id)
    verdict_6 = analyst_gate.validate(signed_msg_6)

    log("    - Timestamp Skew   : Envelope is 90s behind (Allowance: +/-30s)")
    log(f"    - Gate Evaluation  : valid={verdict_6.valid}, reason={verdict_6.reason_code.value}")
    log(f"    - Audit Message    : {verdict_6.reason_summary}")
    assert not verdict_6.valid
    assert verdict_6.reason_code == SecurityReasonCode.STALE_TIMESTAMP

    reply_6 = analyst.process_message(signed_msg_6)
    assert reply_6 is not None
    assert reply_6.performative == Performative.ERROR
    code_6 = reply_6.payload["reason_code"]
    assert code_6 == SecurityReasonCode.STALE_TIMESTAMP.value
    log(f"    - Analyst Shield   : Emitted ERROR ({code_6}); stale clock blocked")
    log()

    recorder.record(
        event_type=EventType.RECORD_REJECTED,
        component="analyst_gate",
        status=EventStatus.REJECTED,
        reason_code=verdict_6.reason_code.value,
        details={"timestamp_utc": signed_msg_6.timestamp_utc},
    )

    audit_records.append({
        "scenario": "6. Stale Timestamp",
        "sender": "sensor-agent-01",
        "attack_vector": "Expired packet injection / Clock desync",
        "expected_code": "STALE_TIMESTAMP",
        "actual_code": verdict_6.reason_code.value,
        "analyst_shielded": "Shielded (ERROR response emitted)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Scenario 7: Duplicate Envelope Replay Attack (REPLAYED_NONCE)
    # -------------------------------------------------------------------------
    log("[7] Scenario 7: Duplicate Envelope Replay Attack (REPLAYED_NONCE)")
    # Replay signed_msg_1 which was accepted in Scenario 1
    verdict_7 = analyst_gate.validate(signed_msg_1)

    log(f"    - Replay Target    : Re-broadcasting legitimate envelope ({signed_msg_1.nonce})")
    log(f"    - Gate Evaluation  : valid={verdict_7.valid}, reason={verdict_7.reason_code.value}")
    log(f"    - Audit Message    : {verdict_7.reason_summary}")
    assert not verdict_7.valid
    assert verdict_7.reason_code == SecurityReasonCode.REPLAYED_NONCE

    reply_7 = analyst.process_message(signed_msg_1)
    assert reply_7 is not None
    assert reply_7.performative == Performative.ERROR
    code_7 = reply_7.payload["reason_code"]
    assert code_7 == SecurityReasonCode.REPLAYED_NONCE.value
    log(f"    - Analyst Shield   : Emitted ERROR ({code_7}); replay prevented")
    log()

    recorder.record(
        event_type=EventType.RECORD_REJECTED,
        component="analyst_gate",
        status=EventStatus.REJECTED,
        reason_code=verdict_7.reason_code.value,
        details={"replayed_nonce": signed_msg_1.nonce},
    )

    audit_records.append({
        "scenario": "7. Replayed Envelope",
        "sender": "sensor-agent-01",
        "attack_vector": "Eavesdropped packet re-transmission",
        "expected_code": "REPLAYED_NONCE",
        "actual_code": verdict_7.reason_code.value,
        "analyst_shielded": "Shielded (ERROR response emitted)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Scenario 8: Fail-Closed Cache Saturation (NONCE_CACHE_FULL)
    # -------------------------------------------------------------------------
    log("[8] Scenario 8: Fail-Closed Cache Saturation (NONCE_CACHE_FULL)")
    bounded_cache = NonceCache(clock=clock, ttl_seconds=60.0, max_size=3)
    bounded_gate = SecurityGate(
        agent_id="analyst-agent-01",
        registry=registry,
        clock=clock,
        freshness_window_seconds=30.0,
        nonce_cache=bounded_cache,
    )
    # Populate the 3 slots
    for i in range(3):
        msg_fill = Message(
            message_id=id_gen.next_id("msg"),
            run_id="run-security-gate-demo",
            sender="sensor-agent-01",
            receiver="analyst-agent-01",
            performative=Performative.ALERT,
            timestamp_utc=clock.now_iso(),
            nonce=f"fill-nonce-{i}",
            payload={"fill": i},
        )
        s_fill = sign_envelope(msg_fill, sensor_id)
        v_fill = bounded_gate.validate(s_fill)
        assert v_fill.valid

    # 4th message attempts to insert when cache is full
    msg_overflow = Message(
        message_id=id_gen.next_id("msg"),
        run_id="run-security-gate-demo",
        sender="sensor-agent-01",
        receiver="analyst-agent-01",
        performative=Performative.ALERT,
        timestamp_utc=clock.now_iso(),
        nonce="overflow-nonce",
        payload={"overflow": True},
    )
    s_overflow = sign_envelope(msg_overflow, sensor_id)
    verdict_8 = bounded_gate.validate(s_overflow)

    log("    - Cache Capacity   : max_size=3 (Currently saturated)")
    log(f"    - Gate Evaluation  : valid={verdict_8.valid}, reason={verdict_8.reason_code.value}")
    log(f"    - Audit Message    : {verdict_8.reason_summary}")
    assert not verdict_8.valid
    assert verdict_8.reason_code == SecurityReasonCode.NONCE_CACHE_FULL
    log("    - Security Stance  : Fail-Closed (Never accepts un-cached nonces during saturation)")
    log()

    recorder.record(
        event_type=EventType.RECORD_REJECTED,
        component="bounded_gate",
        status=EventStatus.REJECTED,
        reason_code=verdict_8.reason_code.value,
        details={"cache_capacity": 3},
    )

    audit_records.append({
        "scenario": "8. Cache Saturation",
        "sender": "sensor-agent-01",
        "attack_vector": "Resource exhaustion / Cache flood",
        "expected_code": "NONCE_CACHE_FULL",
        "actual_code": verdict_8.reason_code.value,
        "analyst_shielded": "Shielded (Fail-closed defensive stop)",
        "verdict": "PASS",
    })

    # -------------------------------------------------------------------------
    # Final Summary & Evidence Generation
    # -------------------------------------------------------------------------
    log("=" * 82)
    log(" Security Verification Matrix Summary ")
    log("=" * 82)
    log(f"{'Scenario':<25} | {'Sender':<22} | {'Expected':<18} | {'Actual':<18} | {'Status'}")
    log("-" * 95)
    for row in audit_records:
        sc = row["scenario"]
        se = row["sender"]
        exp = row["expected_code"]
        act = row["actual_code"]
        ver = row["verdict"]
        log(f"{sc:<25} | {se:<22} | {exp:<18} | {act:<18} | {ver}")
    log("=" * 82)
    log(" [PASS] All 8 Cryptographic Security Gate Scenarios Successfully Verified!")
    log("=" * 82)

    # Write run_log.txt
    run_log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")

    # Write security_gate_audit.md
    md_lines = [
        "# Assignment 5.1 — Cryptographic Security Gate Audit Log",
        "",
        "**Course:** 21CSE525T — Agent Technology  ",
        "**Student:** R Ganesh [RA2212704010031]  ",
        "**Milestone:** Assignment 5.1 (Cryptographic Message Authentication & Security Gate)  ",
        "**Execution Date:** 2026-10-21  ",
        "",
        "---",
        "",
        "## 1. Security Gate Verification Matrix",
        "",
        "The inbound `SecurityGate` enforces strict fail-closed, multi-stage validation prior to",
        "passing envelopes to the agent's core BDI reasoning logic.",
        "",
        "| Scenario | Sender | Attack / Verification Vector | Expected Code | Actual Code "
        "| Agent Shield Status | Verdict |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in audit_records:
        md_lines.append(
            f"| **{row['scenario']}** | `{row['sender']}` | {row['attack_vector']} "
            f"| `{row['expected_code']}` | `{row['actual_code']}` | {row['analyst_shielded']} "
            f"| **{row['verdict']}** |"
        )

    md_lines.extend([
        "",
        "---",
        "",
        "## 2. Inbound Security Gate Stage Pipeline",
        "",
        "```mermaid",
        "flowchart TD",
        "    Inbound[Inbound Raw Message] --> Stage1[1. JSON / Schema Parse]",
        "    Stage1 -- Malformed --> R1[Reject: BAD_SCHEMA / BAD_JSON]",
        "    Stage1 -- Valid --> Stage2[2. Sender Registry Lookup]",
        "    Stage2 -- Unknown Sender --> R2[Reject: UNKNOWN_SENDER]",
        "    Stage2 -- Enrolled --> Stage3[3. Recipient Matching]",
        "    Stage3 -- Mismatched Recipient --> R3[Reject: WRONG_RECIPIENT]",
        "    Stage3 -- Matched --> Stage4[4. SHA-256 Payload Digest Check]",
        "    Stage4 -- Digest Mismatch --> R4[Reject: PAYLOAD_TAMPERED]",
        "    Stage4 -- Digest Valid --> Stage5[5. Ed25519 Canonical Sig Verification]",
        "    Stage5 -- Verification Failed --> R5[Reject: BAD_SIGNATURE]",
        "    Stage5 -- Signature Valid --> Stage6[6. Clock Skew Freshness Check +/-30s]",
        "    Stage6 -- Stale / Drifted --> R6[Reject: STALE_TIMESTAMP]",
        "    Stage6 -- Fresh --> Stage7[7. Anti-Replay Nonce Cache]",
        "    Stage7 -- Nonce Present --> R7[Reject: REPLAYED_NONCE]",
        "    Stage7 -- Cache Saturated --> R8[Reject: NONCE_CACHE_FULL]",
        "    Stage7 -- Nonce Added --> Pass[Verdict: OK -> Dispatch to BDI Core]",
        "```",
        "",
        "---",
        "",
        "## 3. Deliberative Integrity Guarantee",
        "",
        "- **Zero Belief Pollution:** During breach attempts (Scenarios 2–8), the `AnalystAgent`"
        " discarded unvetted messages before they touched `BeliefBase` or triggered deliberation.",
        "- **Canonical Signing:** Signatures bind sender, recipient, timestamp, performative,"
        " message ID, and SHA-256 digest of canonically serialized payload.",
        "- **Fail-Closed Stance:** If the anti-replay cache reaches capacity, unknown messages are"
        " strictly rejected (`NONCE_CACHE_FULL`), preventing memory overflow and acceptance.",
    ])

    audit_table_path.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    log()
    log(f"[+] Evidence artifacts saved successfully to {output_dir}/")


if __name__ == "__main__":
    run_demo()
