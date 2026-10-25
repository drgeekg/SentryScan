"""Dry-run Remediator Agent: generates iptables and nftables rule text after L3 quarantine approval."""

from __future__ import annotations

import json
from typing import Any

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.finding import Finding
from sentryscan.contracts.message import Message, Performative

RULE_PORT_DEFAULTS: dict[str, int] = {
    "RULE-001": 23,
    "RULE-002": 21,
    "RULE-003": 443,
    "RULE-004": 23,
    "RULE-005": 80,
    "RULE-006": 80,
}


class RemediatorAgent:
    """Dry-run remediator that emits iptables and nftables containment rule text without executing anything."""

    def __init__(
        self,
        agent_id: str = "remediator-agent",
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator()

    def generate_remediation(
        self,
        run_id: str,
        host_id: str,
        findings: list[Finding | dict[str, Any]],
        host_ip: str | None = None,
    ) -> dict[str, Any]:
        """Generate dry-run iptables and nftables rule text and rationale for a quarantined host."""
        ports: set[int] = set()
        rule_ids: list[str] = []
        finding_ids: list[str] = []
        resolved_ip = host_ip

        for f in findings:
            if isinstance(f, Finding):
                f_host = f.host_id
                f_id = f.finding_id
                r_id = f.rule_id
                ev = f.evidence or {}
            else:
                f_host = str(f.get("host_id", ""))
                f_id = str(f.get("finding_id", ""))
                r_id = str(f.get("rule_id", ""))
                ev = f.get("evidence") or {}

            if f_host and f_host != host_id:
                continue

            if f_id and f_id not in finding_ids:
                finding_ids.append(f_id)
            if r_id and r_id not in rule_ids:
                rule_ids.append(r_id)

            port = ev.get("port") or RULE_PORT_DEFAULTS.get(r_id)
            if port is not None:
                ports.add(int(port))
            if not resolved_ip and ev.get("ip"):
                resolved_ip = str(ev["ip"])

        if not ports:
            ports = {22, 23, 80, 443}
        sorted_ports = sorted(ports)
        target_addr = resolved_ip or host_id
        rules_str = ", ".join(sorted(rule_ids)) if rule_ids else "L3-CONTAINMENT"
        ports_csv = ", ".join(str(p) for p in sorted_ports)

        iptables_lines = [
            f"# Dry-Run iptables containment plan for {host_id} ({target_addr})",
            f"iptables -A INPUT -s {target_addr} -j DROP",
            f"iptables -A OUTPUT -d {target_addr} -j DROP",
        ]
        for p in sorted_ports:
            iptables_lines.append(
                f"iptables -A FORWARD -s {target_addr} -p tcp --dport {p} -j DROP"
            )
            iptables_lines.append(
                f"iptables -A FORWARD -d {target_addr} -p tcp --dport {p} -j DROP"
            )
        iptables_text = "\n".join(iptables_lines)

        nftables_lines = [
            f"# Dry-Run nftables containment plan for {host_id} ({target_addr})",
            "table inet sentryscan_quarantine {",
            "    chain quarantine_filter {",
            "        type filter hook forward priority 0; policy accept;",
            f"        ip saddr {target_addr} tcp dport {{ {ports_csv} }} drop",
            f"        ip daddr {target_addr} tcp sport {{ {ports_csv} }} drop",
            f"        ip saddr {target_addr} drop",
            f"        ip daddr {target_addr} drop",
            "    }",
            "}",
        ]
        nftables_text = "\n".join(nftables_lines)

        rationale = (
            f"Dry-run containment generated for quarantined host {host_id} ({target_addr}) "
            f"triggered by {rules_str} across port(s) [{ports_csv}]. "
            "Rules isolate inbound, outbound, and lateral forwarding traffic without executing "
            "any host or kernel commands (HLD §2.2 compliant)."
        )

        report_id = f"{self.id_gen.next_id('remed')}-{host_id}"
        created_at = self.clock.now_iso()
        summary_md = (
            f"# Dry-Run Remediation Plan: {host_id}\n"
            f"**Target Host:** `{host_id}` (`{target_addr}`) · **Triggered Rules:** `{rules_str}`\n\n"
            f"## Rationale\n{rationale}\n\n"
            f"## iptables Rules (Dry-Run Text Only)\n```bash\n{iptables_text}\n```\n\n"
            f"## nftables Rules (Dry-Run Text Only)\n```nft\n{nftables_text}\n```"
        )
        data = {
            "type": "remediation_plan",
            "report_type": "remediation_plan",
            "dry_run": True,
            "host_id": host_id,
            "target_addr": target_addr,
            "finding_ids": finding_ids,
            "rule_ids": rule_ids,
            "ports": sorted_ports,
            "iptables": iptables_text,
            "nftables": nftables_text,
            "rationale": rationale,
        }
        return {
            "report_id": report_id,
            "run_id": run_id,
            "created_at": created_at,
            "window_name": f"Remediation Plan: {host_id}",
            "posture_score": 95,
            "threat_level": "CONTAINED",
            "summary_md": summary_md,
            "data_json": json.dumps(data),
            "data": data,
        }

    def remediate_and_store(
        self,
        store: Any,
        run_id: str,
        host_id: str,
        findings: list[Finding | dict[str, Any]],
        recorder: Any | None = None,
        host_ip: str | None = None,
    ) -> dict[str, Any]:
        """Generate remediation plan, persist to SQLite reports, and optionally log REPORT_WRITTEN."""
        from sentryscan.contracts.events import EventStatus, EventType

        plan = self.generate_remediation(
            run_id=run_id,
            host_id=host_id,
            findings=findings,
            host_ip=host_ip,
        )
        store.save_report(
            report_id=plan["report_id"],
            run_id=run_id,
            created_at=plan["created_at"],
            window_name=plan["window_name"],
            posture_score=plan["posture_score"],
            threat_level=plan["threat_level"],
            summary_md=plan["summary_md"],
            data_json=plan["data_json"],
        )
        if recorder is not None and not getattr(recorder._file, "closed", True):
            recorder.record(
                event_type=EventType.REPORT_WRITTEN,
                component=self.agent_id,
                status=EventStatus.OK,
                host_id=host_id,
                details={
                    "report_id": plan["report_id"],
                    "host_id": host_id,
                    "dry_run": True,
                    "ports": plan["data"]["ports"],
                },
            )
        return plan

    def build_message(self, run_id: str, plan: dict[str, Any], task_id: str | None = None) -> Message:
        """Build a signed-ready TASK_RESULT message summarizing the dry-run remediation plan."""
        return Message(
            message_id=self.id_gen.next_id("message"),
            run_id=run_id,
            sender=self.agent_id,
            receiver="supervisor-agent",
            performative=Performative.TASK_RESULT,
            timestamp_utc=self.clock.now_iso(),
            nonce=self.id_gen.seeded_token(16),
            task_id=task_id,
            payload={
                "report_id": plan["report_id"],
                "host_id": plan["data"]["host_id"],
                "iptables": plan["data"]["iptables"],
                "nftables": plan["data"]["nftables"],
                "rationale": plan["data"]["rationale"],
                "dry_run": True,
            },
        )
