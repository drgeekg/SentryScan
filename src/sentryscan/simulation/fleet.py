"""Configurable simulated endpoint device fleet model."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.telemetry import AuthMode, TelemetryRecord, TelemetrySource


@dataclass
class ServiceConfig:
    """Configuration template for an endpoint network service."""

    port: int
    service: str
    banner: str
    tls_version: str | None = None
    auth_mode: AuthMode = AuthMode.REQUIRED


@dataclass
class DeviceProfile:
    """Model representing a simulated endpoint in the enterprise fleet."""

    device_id: str
    host_id: str  # host_id == device_id by default
    label: str
    ip: str
    services: list[ServiceConfig] = field(default_factory=list)
    event_rate: float = 1.0  # Events per second
    os_family: str = "linux"


class DeviceFleetSimulator:
    """Simulator managing a heterogeneous fleet of simulated endpoint devices.

    Generates realistic, repeatable synthetic telemetry records without live network probing.
    """

    _STANDARD_TEMPLATES: list[dict[str, Any]] = [
        {
            "label": "Web Gateway",
            "os_family": "linux",
            "services": [
                ServiceConfig(80, "http", "nginx/1.24.0 (Ubuntu)", None, AuthMode.ANONYMOUS),
                ServiceConfig(443, "https", "nginx/1.24.0 (Ubuntu)", "TLSv1.3", AuthMode.REQUIRED),
                ServiceConfig(22, "ssh", "OpenSSH 9.2p1", None, AuthMode.REQUIRED),
            ],
        },
        {
            "label": "Database Server",
            "os_family": "linux",
            "services": [
                ServiceConfig(5432, "postgresql", "PostgreSQL 15.4", "TLSv1.3", AuthMode.REQUIRED),
                ServiceConfig(22, "ssh", "OpenSSH 9.2p1", None, AuthMode.REQUIRED),
            ],
        },
        {
            "label": "Legacy App Server",
            "os_family": "linux",
            "services": [
                ServiceConfig(8080, "http", "Apache-Coyote/1.1", None, AuthMode.DEFAULT),
                ServiceConfig(
                    21, "ftp", "vsftpd 2.3.4 (Anonymous Access)", None, AuthMode.ANONYMOUS
                ),
                ServiceConfig(23, "telnet", "Linux telnetd", None, AuthMode.UNKNOWN),
            ],
        },
        {
            "label": "Corporate Workstation",
            "os_family": "windows",
            "services": [
                ServiceConfig(
                    3389, "rdp", "Microsoft RDP (NLA Enforced)", "TLSv1.2", AuthMode.REQUIRED
                ),
                ServiceConfig(445, "smb", "Microsoft SMBv3", None, AuthMode.REQUIRED),
            ],
        },
        {
            "label": "IoT Controller",
            "os_family": "embedded",
            "services": [
                ServiceConfig(8443, "https", "Embedded Web Interface", "SSLv3", AuthMode.REQUIRED),
                ServiceConfig(23, "telnet", "BusyBox telnetd", None, AuthMode.DEFAULT),
            ],
        },
    ]

    def __init__(
        self,
        device_count: int = 10,
        seed: int = 42,
        clock: Clock | None = None,
        id_gen: IdGenerator | None = None,
    ) -> None:
        self.device_count = device_count
        self.seed = seed
        self.clock = clock if clock is not None else SystemClock()
        self.id_gen = id_gen if id_gen is not None else IdGenerator(seed=seed)
        self._rng = random.Random(seed)

        self.devices: list[DeviceProfile] = []
        self._initialize_fleet()

    def _initialize_fleet(self) -> None:
        """Create deterministic device profiles across RFC 5737 IP space."""
        # Use RFC 5737 test prefixes: 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2)
        for i in range(1, self.device_count + 1):
            device_id = f"sim-host-{i:03d}"
            template = self._STANDARD_TEMPLATES[(i - 1) % len(self._STANDARD_TEMPLATES)]

            if i <= 250:
                ip = f"192.0.2.{i}"
            else:
                ip = f"198.51.100.{i - 250}"

            profile = DeviceProfile(
                device_id=device_id,
                host_id=device_id,
                label=f"{template['label']} {i:03d}",
                ip=ip,
                services=list(template["services"]),
                event_rate=1.0 + (self._rng.random() * 0.5),
                os_family=template["os_family"],
            )
            self.devices.append(profile)

    def generate_record_for_device(
        self,
        device: DeviceProfile,
        service_index: int | None = None,
    ) -> TelemetryRecord:
        """Emit a clean baseline telemetry record for a specific device and service."""
        if not device.services:
            raise ValueError(f"Device {device.device_id} has no configured services")

        if service_index is None:
            svc = self._rng.choice(device.services)
        else:
            svc = device.services[service_index % len(device.services)]

        return TelemetryRecord(
            record_id=self.id_gen.next_id("record"),
            host_id=device.host_id,
            ip=device.ip,
            port=svc.port,
            service=svc.service,
            banner=svc.banner,
            tls_version=svc.tls_version,
            auth_mode=svc.auth_mode,
            generated_at=self.clock.now_iso(),
            source=TelemetrySource.SYNTHETIC_SIMULATOR,
        )

    def generate_fleet_cycle(self) -> list[TelemetryRecord]:
        """Generate one round of baseline telemetry records across all fleet devices."""
        records: list[TelemetryRecord] = []
        for dev in self.devices:
            for idx in range(len(dev.services)):
                records.append(self.generate_record_for_device(dev, service_index=idx))
        return records
