"""Analyst Agent: Deliberative reasoning entity hosting the BDI LangGraph workflow."""

from __future__ import annotations

import logging
import threading
from typing import Any

from sentryscan.bdi.beliefs import BeliefBase
from sentryscan.bdi.intentions import Intention
from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.message import Message, Performative
from sentryscan.graphs.analyst_graph import build_analyst_graph
from sentryscan.graphs.analyst_state import AnalystGraphState, ReconsiderationRecord
from sentryscan.knowledge.enricher import KnowledgeEnricher
from sentryscan.knowledge.models import EnrichmentResult
from sentryscan.security.gate import SecurityGate
from sentryscan.transport.interface import Transport
from sentryscan.transport.socket_transport import TCPSocketServer

logger = logging.getLogger(__name__)


class AnalystAgent:
    """Analyst agent hosting BDI deliberative reasoning and LangGraph replanning."""

    def __init__(
        self,
        agent_id: str = "analyst-agent-01",
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
        enricher: KnowledgeEnricher | None = None,
        security_gate: SecurityGate | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator()
        self.enricher = enricher if enricher is not None else KnowledgeEnricher()
        self.security_gate = security_gate
        self.server: TCPSocketServer | None = None

        # BDI State
        self.belief_base = BeliefBase()
        self.active_intention: Intention | None = None
        self.reconsideration_history: list[ReconsiderationRecord] = []
        self._beliefs_compat: dict[str, dict[str, Any]] = {}

        # Knowledge enrichment tracking
        self.last_enrichment: EnrichmentResult | None = None
        self.enrichment_history: list[EnrichmentResult] = []

        # Deliberative LangGraph workflow
        self.graph = build_analyst_graph(clock=self.clock, id_gen=self.id_gen)

    @property
    def beliefs(self) -> dict[str, dict[str, Any]]:
        """Dictionary view over host beliefs for backward compatibility."""
        return self._beliefs_compat

    def process_message(self, msg: Message) -> Message | None:
        """Process incoming Message envelope and return an autonomous response Message."""
        # Inbound Security Gate validation
        if self.security_gate is not None:
            verdict = self.security_gate.validate(msg)
            if not verdict.valid:
                logger.warning(
                    "[%s] Security Gate rejected message %s from %s: %s",
                    self.agent_id,
                    msg.message_id,
                    msg.sender,
                    verdict.reason_summary,
                )
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
                        "error": f"Security verification rejected: {verdict.reason_code.value}",
                        "reason_code": verdict.reason_code.value,
                        "reason_summary": verdict.reason_summary,
                        "original_message_id": msg.message_id,
                    },
                )

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
        """Analyze alert, route through BDI Analyst graph, and emit PARAMS_UPDATE."""
        payload = msg.payload
        target_host = payload.get("target_host") or payload.get("host_id") or "unknown-host"
        orig_severity = str(payload.get("severity", "LOW")).upper()
        severity = orig_severity
        finding_id = payload.get("finding_id", "unknown-finding")
        rule_id = payload.get("rule_id", "unknown-rule")
        service = payload.get("service")
        banner = payload.get("banner")
        cve_id = payload.get("cve_id")

        # 1. External Knowledge Enrichment
        enrichment: EnrichmentResult | None = None
        if self.enricher is not None:
            enrichment = self.enricher.enrich_finding(
                finding_id=finding_id,
                target_host=target_host,
                original_severity=orig_severity,
                service=service,
                banner=banner,
                cve_id=cve_id,
                extra_details=payload,
            )
            self.last_enrichment = enrichment
            self.enrichment_history.append(enrichment)
            if enrichment.escalated:
                logger.info(
                    "[%s] Knowledge enrichment escalated %s (%s) from %s to %s (CVSS %.1f)",
                    self.agent_id,
                    target_host,
                    enrichment.cve_id,
                    orig_severity,
                    enrichment.enriched_severity,
                    enrichment.cvss_score or 0.0,
                )
                severity = enrichment.enriched_severity

        # 2. Route through the deliberative BDI LangGraph workflow
        initial_state: AnalystGraphState = {
            "beliefs": self.belief_base,
            "active_intention": self.active_intention,
            "reconsideration_history": self.reconsideration_history,
            "incoming_percept": {
                "target_host": target_host,
                "finding_id": finding_id,
                "rule_id": rule_id,
                "severity": severity,
                "priority_ports": payload.get("priority_ports"),
                "cve_id": enrichment.cve_id if enrichment else cve_id,
                "cvss_score": enrichment.cvss_score if enrichment else None,
                "enrichment_source": (
                    enrichment.source.value if enrichment else None
                ),
            },
        }

        final_state = self.graph.invoke(initial_state)

        # Synchronize agent state from compiled graph execution
        self.belief_base = final_state.get("beliefs", self.belief_base)
        self.active_intention = final_state.get("active_intention", self.active_intention)
        self.reconsideration_history = final_state.get(
            "reconsideration_history", self.reconsideration_history
        )

        action_data = final_state.get("generated_action") or {}
        action = action_data.get("action", "NOMINAL_MONITORING")
        scan_interval_ms = action_data.get("scan_interval_ms", 500)
        priority_ports = action_data.get("priority_ports", [])
        quarantine_flag = action_data.get("quarantine_flag", False)
        rationale = action_data.get("rationale", "")

        # Fallback rationale formatting
        if not rationale:
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

        if enrichment and enrichment.escalated and enrichment.cve_id:
            rationale = (
                f"Knowledge escalated ({enrichment.cve_id}, "
                f"CVSS {enrichment.cvss_score}): {rationale}"
            )

        # Update backwards-compatible dictionary view
        self._beliefs_compat[target_host] = {
            "severity": severity,
            "finding_id": finding_id,
            "rule_id": rule_id,
            "cve_id": enrichment.cve_id if enrichment else cve_id,
            "cvss_score": enrichment.cvss_score if enrichment else None,
            "last_assessed": self.clock.now_iso(),
            "quarantined": quarantine_flag,
        }

        reply_payload: dict[str, Any] = {
            "target_host": target_host,
            "correlated_finding_id": finding_id,
            "action": action,
            "scan_interval_ms": scan_interval_ms,
            "priority_ports": priority_ports,
            "quarantine_flag": quarantine_flag,
            "rationale": rationale,
        }

        if enrichment and enrichment.cve_id:
            reply_payload["cve_id"] = enrichment.cve_id
            reply_payload["cvss_score"] = enrichment.cvss_score
            reply_payload["enriched_severity"] = enrichment.enriched_severity
            reply_payload["escalated"] = enrichment.escalated
            reply_payload["knowledge_source"] = enrichment.source.value

        return Message(
            message_id=self.id_gen.next_id("message"),
            run_id=msg.run_id,
            sender=self.agent_id,
            receiver=msg.sender,
            performative=Performative.PARAMS_UPDATE,
            timestamp_utc=self.clock.now_iso(),
            nonce=self.id_gen.seeded_token(16),
            task_id=msg.task_id,
            payload=reply_payload,
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
