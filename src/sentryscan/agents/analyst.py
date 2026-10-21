"""Analyst Agent: Autonomous reasoning entity receiving alerts and adjusting scanning parameters."""

from __future__ import annotations

import logging
import threading
from typing import Any

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Message, Performative
from sentryscan.transport.interface import Transport
from sentryscan.transport.socket_transport import TCPSocketServer

logger = logging.getLogger(__name__)


class AnalystAgent:
    """Analyst agent evaluating incoming alerts and autonomously replying with parameter updates."""

    def __init__(
        self,
        agent_id: str = "analyst-agent-01",
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator()
        self.server: TCPSocketServer | None = None
        self.beliefs: dict[str, dict[str, Any]] = {}

    def process_message(self, msg: Message) -> Message | None:
        """Process incoming Message envelope and return an autonomous response Message."""
        if msg.performative == Performative.ALERT:
            return self._handle_alert(msg)
        if msg.performative == Performative.STATE_SYNC:
            return self._handle_state_sync(msg)
        if msg.performative == Performative.EVENT:
            logger.info("[%s] Observed event from %s: %s", self.agent_id, msg.sender, msg.payload)
            return None

        # Return error performative for unsupported performatives
        return Message(
            message_id=self.id_gen.next_id("message"),
            run_id=msg.run_id,
            sender=self.agent_id,
            receiver=msg.sender,
            performative=Performative.ERROR,
            timestamp_utc=self.clock.now_iso(),
            nonce=self.id_gen.seeded_token(16),
            task_id=msg.task_id,
            payload={
                "error": f"Unsupported performative {msg.performative.value} for AnalystAgent",
                "original_message_id": msg.message_id,
            },
        )

    def _handle_alert(self, msg: Message) -> Message:
        """Analyze security finding alert and synthesize an autonomous PARAMS_UPDATE response."""
        payload = msg.payload
        target_host = payload.get("target_host") or payload.get("host_id") or "unknown-host"
        severity = str(payload.get("severity", "LOW")).upper()
        finding_id = payload.get("finding_id", "unknown-finding")
        rule_id = payload.get("rule_id", "unknown-rule")

        # Update persistent beliefs about this host
        self.beliefs[target_host] = {
            "severity": severity,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "last_assessed": self.clock.now_iso(),
        }

        # Autonomous parameter decision policy
        if severity == "CRITICAL":
            action = "DEEP_INSPECTION"
            scan_interval_ms = 50
            priority_ports = [80, 443, 22, 23, 3389, 8080]
            quarantine_flag = True
            rationale = (
                f"Critical finding on {target_host} ({finding_id}). "
                "Escalating to immediate high-frequency deep inspection with host quarantine."
            )
        elif severity == "HIGH":
            action = "DEEP_INSPECTION"
            scan_interval_ms = 100
            priority_ports = [80, 443, 22]
            quarantine_flag = False
            rationale = (
                f"High-severity finding on {target_host} ({finding_id}). "
                "Tightening sampling window and monitoring core exposure ports."
            )
        elif severity == "MEDIUM":
            action = "NOMINAL_MONITORING"
            scan_interval_ms = 250
            priority_ports = []
            quarantine_flag = False
            rationale = (
                f"Medium risk finding on {target_host} ({finding_id}). "
                "Applying standard targeted observation cadence."
            )
        else:
            action = "NOMINAL_MONITORING"
            scan_interval_ms = 500
            priority_ports = []
            quarantine_flag = False
            rationale = (
                f"Low or informational finding on {target_host}. "
                "Retaining baseline telemetry cadence."
            )

        return Message(
            message_id=self.id_gen.next_id("message"),
            run_id=msg.run_id,
            sender=self.agent_id,
            receiver=msg.sender,
            performative=Performative.PARAMS_UPDATE,
            timestamp_utc=self.clock.now_iso(),
            nonce=self.id_gen.seeded_token(16),
            task_id=msg.task_id,
            payload={
                "target_host": target_host,
                "correlated_finding_id": finding_id,
                "action": action,
                "scan_interval_ms": scan_interval_ms,
                "priority_ports": priority_ports,
                "quarantine_flag": quarantine_flag,
                "rationale": rationale,
            },
        )

    def _handle_state_sync(self, msg: Message) -> Message:
        """Acknowledge a state sync message."""
        return Message(
            message_id=self.id_gen.next_id("message"),
            run_id=msg.run_id,
            sender=self.agent_id,
            receiver=msg.sender,
            performative=Performative.CONFIRM,
            timestamp_utc=self.clock.now_iso(),
            nonce=self.id_gen.seeded_token(16),
            task_id=msg.task_id,
            payload={"status": "STATE_ACKNOWLEDGED", "agent_id": self.agent_id},
        )

    def start_server(self, host: str = "127.0.0.1", port: int = 8765) -> int:
        """Start socket server listening for inbound agent messages."""
        if self.server is not None:
            return self.server.bound_port

        self.server = TCPSocketServer(
            host=host,
            port=port,
            message_handler=self.process_message,
        )
        self.server.start()
        return self.server.bound_port

    def stop_server(self) -> None:
        """Stop socket server."""
        if self.server is not None:
            self.server.stop()
            self.server = None

    def listen_and_respond(
        self,
        transport: Transport,
        stop_event: threading.Event | None = None,
        timeout: float = 0.5,
    ) -> None:
        """Run loop receiving messages from a Transport and replying over it."""
        while stop_event is None or not stop_event.is_set():
            msg = transport.receive(timeout=timeout)
            if msg is None:
                continue
            reply = self.process_message(msg)
            if reply is not None:
                transport.send(reply)
