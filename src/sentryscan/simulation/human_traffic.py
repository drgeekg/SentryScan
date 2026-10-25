"""Realistic human workstation traffic and interactive session generator for Windows and Linux.

Simulates the telemetry log cadence and burst patterns generated when average human users
interact with enterprise Windows 11/10 workstations and Ubuntu/Debian Linux systems.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord, TelemetrySource
from sentryscan.simulation.fleet import DeviceProfile, ServiceConfig
from sentryscan.simulation.poisoning import GroundTruthSidecar, InjectionOperator, PoisoningMutator


class HumanActionType(str, Enum):
    """Categorical interactive actions performed by an average human user."""

    WEB_BROWSING = "web_browsing"              # Opening browser tabs, SaaS apps, intranet portals
    FILE_COLLABORATION = "file_collaboration"  # Reading/writing documents on SMB/NFS network shares
    DEVELOPER_WORKFLOW = "developer_workflow"  # SSH sessions, local dev servers, database queries
    REMOTE_ADMIN = "remote_administration"    # RDP, WinRM, terminal router management
    AMBIENT_HEARTBEAT = "ambient_heartbeat"    # Periodic OS daemon keepalives, NTP, telemetry
    MAJOR_BURST = "major_burst"                # Heavy traffic spike (large file sync, security update scan, app batch)
    ATTACK_ANOMALY = "attack_anomaly"          # Malicious injection, prompt exploit, or flood


@dataclass
class HumanWorkstationTemplate:
    """Template modeling a specific human user's computer and service footprint."""

    host_id: str
    label: str
    os_family: str  # "windows" or "linux"
    persona: str    # e.g. "finance_analyst", "software_engineer", "it_admin"
    ip: str
    services: list[ServiceConfig]
    primary_workflow: HumanActionType
    typical_active_ports: list[int]
    typical_idle_ports: list[int]


HUMAN_WORKSTATION_TEMPLATES: list[HumanWorkstationTemplate] = [
    HumanWorkstationTemplate(
        host_id="win11-finance-01",
        label="Win11 Workstation (Alice - Finance Analyst)",
        os_family="windows",
        persona="finance_analyst",
        ip="192.0.2.11",
        services=[
            ServiceConfig(445, "smb", "Microsoft Windows SMBv3 (Corporate Finance Share)", None, AuthMode.REQUIRED),
            ServiceConfig(443, "https", "Microsoft Edge / SAP Intranet Portal", "TLSv1.3", AuthMode.REQUIRED),
            ServiceConfig(3389, "rdp", "Microsoft Remote Desktop (NLA Enforced)", "TLSv1.3", AuthMode.REQUIRED),
            ServiceConfig(5985, "winrm", "Microsoft WinRM 2.0 (Kerberos)", None, AuthMode.REQUIRED),
        ],
        primary_workflow=HumanActionType.FILE_COLLABORATION,
        typical_active_ports=[443, 445, 5985],
        typical_idle_ports=[445],
    ),
    HumanWorkstationTemplate(
        host_id="ubuntu-dev-01",
        label="Ubuntu 24.04 Dev (Bob - Backend Lead)",
        os_family="linux",
        persona="software_engineer",
        ip="192.0.2.12",
        services=[
            ServiceConfig(22, "ssh", "OpenSSH 9.6p1 Ubuntu-3ubuntu13", None, AuthMode.REQUIRED),
            ServiceConfig(8080, "http", "Local Node.js Microservice (Dev Environment)", None, AuthMode.ANONYMOUS),
            ServiceConfig(5432, "postgresql", "PostgreSQL 16.2 Local Database", "TLSv1.3", AuthMode.REQUIRED),
            ServiceConfig(443, "https", "Internal GitLab & Container Registry", "TLSv1.3", AuthMode.REQUIRED),
        ],
        primary_workflow=HumanActionType.DEVELOPER_WORKFLOW,
        typical_active_ports=[22, 8080, 5432, 443],
        typical_idle_ports=[22],
    ),
    HumanWorkstationTemplate(
        host_id="win10-support-01",
        label="Win10 Admin Laptop (Charlie - IT Support)",
        os_family="windows",
        persona="it_support_admin",
        ip="192.0.2.13",
        services=[
            ServiceConfig(445, "smb", "Microsoft Windows SMBv3", None, AuthMode.REQUIRED),
            ServiceConfig(3389, "rdp", "Microsoft Remote Desktop (NLA Enforced)", "TLSv1.2", AuthMode.REQUIRED),
            ServiceConfig(
                8080,
                "http",
                "Legacy Switch Web Management (Apache-Coyote/1.1)",
                None,
                AuthMode.DEFAULT,
                True,
                ["RULE-004", "RULE-006"],
            ),
            ServiceConfig(
                23,
                "telnet",
                "Core Switch Telnet Console (Linux telnetd)",
                None,
                AuthMode.UNKNOWN,
                True,
                ["RULE-001"],
            ),
        ],
        primary_workflow=HumanActionType.REMOTE_ADMIN,
        typical_active_ports=[3389, 8080, 23, 445],
        typical_idle_ports=[445],
    ),
    HumanWorkstationTemplate(
        host_id="debian-bastion-01",
        label="Debian 12 Bastion (Dana - DevOps Gateway)",
        os_family="linux",
        persona="devops_engineer",
        ip="192.0.2.14",
        services=[
            ServiceConfig(22, "ssh", "OpenSSH 9.2p1 Debian-2+deb12u2", None, AuthMode.REQUIRED),
            ServiceConfig(443, "https", "Production Reverse Proxy (Nginx 1.24.0)", "TLSv1.3", AuthMode.REQUIRED),
            ServiceConfig(
                21,
                "ftp",
                "vsftpd 2.3.4 (Anonymous Access)",
                None,
                AuthMode.ANONYMOUS,
                True,
                ["RULE-002", "RULE-005"],
            ),
        ],
        primary_workflow=HumanActionType.WEB_BROWSING,
        typical_active_ports=[22, 443, 21],
        typical_idle_ports=[22],
    ),
    HumanWorkstationTemplate(
        host_id="fedora-ml-01",
        label="Fedora 40 Workstation (Eve - ML Scientist)",
        os_family="linux",
        persona="data_scientist",
        ip="192.0.2.15",
        services=[
            ServiceConfig(22, "ssh", "OpenSSH 9.3p1", None, AuthMode.REQUIRED),
            ServiceConfig(8888, "http", "JupyterLab Analytics Server (Python 3.12)", None, AuthMode.REQUIRED),
            ServiceConfig(443, "https", "Internal S3 Storage Proxy (MinIO)", "TLSv1.3", AuthMode.REQUIRED),
        ],
        primary_workflow=HumanActionType.DEVELOPER_WORKFLOW,
        typical_active_ports=[22, 8888, 443],
        typical_idle_ports=[22],
    ),
]


@dataclass
class HumanInteractionBurst:
    """A discrete flurry of telemetry logs emitted when a human user interacts with their system."""

    host_id: str
    action: HumanActionType
    record_count: int
    intra_event_delay_ms: float   # Milliseconds between events in this interactive burst (e.g. 20-50ms)
    post_burst_pause_s: float     # Seconds of human cognitive think-time before next action (e.g. 1.0-3.0s)
    is_anomaly: bool = False
    target_ports: list[int] = field(default_factory=list)


class HumanTrafficGenerator:
    """Orchestrates realistic high-frequency log generation for Windows & Linux human workstations."""

    def __init__(
        self,
        templates: list[HumanWorkstationTemplate] | None = None,
        device_count: int = 4,
        seed: int = 42,
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
        poison_ratio: float = 0.2,
    ) -> None:
        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator(seed=seed)
        self.seed = seed
        self._rng = random.Random(seed)
        self.poison_ratio = poison_ratio

        base_templates = templates or HUMAN_WORKSTATION_TEMPLATES
        # Select or cycle templates to meet device_count
        self.workstations: list[HumanWorkstationTemplate] = []
        for i in range(device_count):
            tpl = base_templates[i % len(base_templates)]
            # If cycling beyond base length, create indexed host
            if i >= len(base_templates):
                suffix = f"-{i + 1:02d}"
                host_id = f"{tpl.host_id.rsplit('-', 1)[0]}{suffix}"
                ip = f"192.0.2.{20 + i}"
                new_tpl = HumanWorkstationTemplate(
                    host_id=host_id,
                    label=f"{tpl.label} #{i + 1}",
                    os_family=tpl.os_family,
                    persona=tpl.persona,
                    ip=ip,
                    services=list(tpl.services),
                    primary_workflow=tpl.primary_workflow,
                    typical_active_ports=list(tpl.typical_active_ports),
                    typical_idle_ports=list(tpl.typical_idle_ports),
                )
                self.workstations.append(new_tpl)
            else:
                self.workstations.append(tpl)

        # Build DeviceProfiles compatible with DeviceFleetSimulator
        self.devices: list[DeviceProfile] = [
            DeviceProfile(
                device_id=w.host_id,
                host_id=w.host_id,
                label=w.label,
                ip=w.ip,
                services=list(w.services),
                event_rate=2.5,
                os_family=w.os_family,
            )
            for w in self.workstations
        ]
        self.device_map: dict[str, DeviceProfile] = {d.host_id: d for d in self.devices}
        self.workstation_map: dict[str, HumanWorkstationTemplate] = {w.host_id: w for w in self.workstations}

        self.mutator = PoisoningMutator(sidecar=GroundTruthSidecar(), seed=seed)
        self.poison_ops = [
            op for op in InjectionOperator
            if op not in (InjectionOperator.REPLAYED_RECORD,)  # Handled distinctly
        ]

    def plan_next_human_burst(
        self,
        active_host_ids: list[str] | None = None,
        force_anomaly: bool = False,
    ) -> HumanInteractionBurst:
        """Calculate the next human interaction burst across available workstations."""
        candidates = [w for w in self.workstations if not active_host_ids or w.host_id in active_host_ids]
        if not candidates:
            candidates = self.workstations

        # Pick workstation for this action
        ws = self._rng.choice(candidates)

        roll = self._rng.random()
        if force_anomaly or roll < (self.poison_ratio * 0.7):
            # Suspicious flurry: untrusted link, prompt injection, or exploit banner scan
            action = HumanActionType.ATTACK_ANOMALY
            size = self._rng.randint(12, 28)
            intra_delay_ms = self._rng.uniform(10.0, 30.0)    # Rapid automated or exploit burst
            pause_s = self._rng.uniform(0.5, 1.5)
            is_anomaly = True
            target_ports = ws.typical_active_ports
        elif roll < 0.22:
            # Major Burst: random sudden surge (batch backup, large download, security scanner, automated build)
            action = HumanActionType.MAJOR_BURST
            size = self._rng.randint(35, 75)                  # High-volume burst
            intra_delay_ms = self._rng.uniform(8.0, 20.0)     # High packet rate
            pause_s = self._rng.uniform(0.8, 2.0)
            is_anomaly = False
            target_ports = ws.typical_active_ports
        elif roll < 0.75:
            # Active interactive human task: web browsing, file edits, compiling, terminal
            action = ws.primary_workflow
            size = self._rng.randint(8, 22)                  # 8-22 events in one human task
            intra_delay_ms = self._rng.uniform(20.0, 50.0)   # 20-50ms between human actions/connections
            pause_s = self._rng.uniform(1.0, 2.5)            # Human pauses to read/think for 1-2.5s
            is_anomaly = False
            target_ports = ws.typical_active_ports
        elif roll < 0.90:
            # Secondary interactive action (e.g. user checks web browser or RDP)
            action = HumanActionType.WEB_BROWSING if ws.os_family == "windows" else HumanActionType.DEVELOPER_WORKFLOW
            size = self._rng.randint(5, 14)
            intra_delay_ms = self._rng.uniform(30.0, 60.0)
            pause_s = self._rng.uniform(1.2, 3.0)
            is_anomaly = False
            target_ports = ws.typical_active_ports
        else:
            # Ambient heartbeat (OS keepalive while human is away)
            action = HumanActionType.AMBIENT_HEARTBEAT
            size = self._rng.randint(2, 4)
            intra_delay_ms = self._rng.uniform(80.0, 150.0)
            pause_s = self._rng.uniform(2.0, 4.0)
            is_anomaly = False
            target_ports = ws.typical_idle_ports

        return HumanInteractionBurst(
            host_id=ws.host_id,
            action=action,
            record_count=size,
            intra_event_delay_ms=intra_delay_ms,
            post_burst_pause_s=pause_s,
            is_anomaly=is_anomaly,
            target_ports=target_ports,
        )

    def generate_burst_records(
        self,
        burst: HumanInteractionBurst,
    ) -> list[tuple[TelemetryRecord, dict[str, Any], bool, str | None]]:
        """Emit telemetry records for an interactive burst with ground truth metadata.

        Returns:
            List of (record, truth_dict, is_poisoned, injection_type).
        """
        ws = self.workstation_map[burst.host_id]
        dev = self.device_map[burst.host_id]

        records: list[tuple[TelemetryRecord, dict[str, Any], bool, str | None]] = []

        # Find available service configs matching target ports or fallback
        matching_services = [s for s in dev.services if s.port in burst.target_ports]
        if not matching_services:
            matching_services = dev.services

        for _ in range(burst.record_count):
            svc = self._rng.choice(matching_services)
            record_id = self.id_gen.next_id("record")

            # Base telemetry record
            rec = TelemetryRecord(
                record_id=record_id,
                host_id=dev.host_id,
                ip=dev.ip,
                port=svc.port,
                service=svc.service,
                banner=svc.banner,
                tls_version=svc.tls_version,
                auth_mode=svc.auth_mode,
                generated_at=self.clock.now_iso(),
                source=TelemetrySource.SYNTHETIC_SIMULATOR,
            )

            truth = {
                "record_id": rec.record_id,
                "host_id": dev.host_id,
                "is_vulnerable": svc.is_vulnerable,
                "expected_rules": list(svc.expected_rules),
                "is_poisoned": False,
                "injection_type": None,
                "user_action": burst.action.value,
                "os_family": ws.os_family,
                "persona": ws.persona,
            }

            is_p = False
            inj_type: str | None = None

            # Apply poisoning / integrity corruption if this is an anomaly burst
            if burst.is_anomaly and (self._rng.random() < 0.65):
                op = self._rng.choice(self.poison_ops)
                rec = self.mutator.mutate(baseline=rec, operator=op, new_record_id=self.id_gen.next_id("record"))
                is_p = True
                inj_type = op.value
                truth["is_poisoned"] = True
                truth["injection_type"] = inj_type

            records.append((rec, truth, is_p, inj_type))

        return records
