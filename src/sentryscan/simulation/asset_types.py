"""Heterogeneous enterprise asset catalogue and per-type fleet resolver (all data is simulated)."""

from __future__ import annotations

import random
from dataclasses import dataclass, field

from sentryscan.contracts.telemetry import AuthMode
from sentryscan.simulation.fleet import ServiceConfig
from sentryscan.simulation.human_traffic import HumanActionType, HumanWorkstationTemplate

A = AuthMode


@dataclass(frozen=True)
class AssetType:
    key: str
    label: str
    category: str  # endpoint | network | cloud | saas | server | iot
    os_family: str
    provider: str
    services: tuple[ServiceConfig, ...]
    workflow: HumanActionType
    weight: int = 1  # relative likelihood when counts are randomly assigned
    data_sources: tuple[str, ...] = field(default_factory=tuple)


ASSET_TYPES: dict[str, AssetType] = {t.key: t for t in [
    AssetType("windows_workstation", "Windows 11 Workstation", "endpoint", "windows", "on-prem", (
        ServiceConfig(445, "smb", "Microsoft Windows SMBv3", None, A.REQUIRED),
        ServiceConfig(443, "https", "Microsoft Edge / Intranet Portal", "TLSv1.3", A.REQUIRED),
        ServiceConfig(3389, "rdp", "Microsoft Remote Desktop (NLA Enforced)", "TLSv1.3", A.REQUIRED),
    ), HumanActionType.FILE_COLLABORATION, 4, ("SMB share: Team Documents", "Local Documents folder")),
    AssetType("linux_workstation", "Ubuntu 24.04 Workstation", "endpoint", "linux", "on-prem", (
        ServiceConfig(22, "ssh", "OpenSSH 9.6p1 Ubuntu", None, A.REQUIRED),
        ServiceConfig(8080, "http", "Local Node.js Dev Server", None, A.REQUIRED),
        ServiceConfig(443, "https", "Internal GitLab", "TLSv1.3", A.REQUIRED),
    ), HumanActionType.DEVELOPER_WORKFLOW, 2, ("Home directory ~/projects",)),
    AssetType("linux_server", "Debian 12 Server", "server", "linux", "on-prem", (
        ServiceConfig(22, "ssh", "OpenSSH 9.2p1 Debian", None, A.REQUIRED),
        ServiceConfig(443, "https", "Nginx 1.24.0 Reverse Proxy", "TLSv1.3", A.REQUIRED),
        ServiceConfig(21, "ftp", "vsftpd 2.3.4 (Anonymous Access)", None, A.ANONYMOUS, True, ["RULE-002", "RULE-005"]),
    ), HumanActionType.WEB_BROWSING, 2, ("/var/backups",)),
    AssetType("cisco_router", "Cisco IOS-XE Router", "network", "network-os", "cisco", (
        ServiceConfig(22, "ssh", "Cisco IOS-XE SSH 2.0", None, A.REQUIRED),
        ServiceConfig(23, "telnet", "Cisco VTY Console", None, A.DEFAULT, True, ["RULE-001", "RULE-004"]),
        ServiceConfig(8443, "https", "Cisco RESTCONF Gateway", "TLSv1.2", A.REQUIRED),
    ), HumanActionType.REMOTE_ADMIN, 1, ("running-config backup",)),
    AssetType("firewall", "Next-Gen Firewall", "network", "network-os", "generic-vendor", (
        ServiceConfig(443, "https", "Firewall Management UI", "TLSv1.3", A.REQUIRED),
        ServiceConfig(22, "ssh", "OpenSSH 8.9 (appliance)", None, A.REQUIRED),
    ), HumanActionType.REMOTE_ADMIN, 1, ("policy export",)),
    AssetType("aws_account", "AWS Cloud Account", "cloud", "cloud", "aws", (
        ServiceConfig(443, "https", "AWS Application Load Balancer", "TLSv1.3", A.REQUIRED),
        ServiceConfig(8080, "http", "Container Admin Console (cleartext)", None, A.ANONYMOUS, True, ["RULE-006"]),
        ServiceConfig(5432, "postgresql", "Amazon Aurora PostgreSQL 15", "TLSv1.3", A.REQUIRED),
    ), HumanActionType.WEB_BROWSING, 1, ("S3 bucket: app-uploads", "RDS snapshot: customers")),
    AssetType("azure_tenant", "Azure Tenant", "cloud", "cloud", "azure", (
        ServiceConfig(443, "https", "Azure Front Door", "TLSv1.3", A.REQUIRED),
        ServiceConfig(8443, "https", "Legacy App Service Endpoint", "TLSv1.0", A.REQUIRED, True, ["RULE-003"]),
    ), HumanActionType.WEB_BROWSING, 1, ("Blob container: exports", "Key Vault: app-secrets")),
    AssetType("m365_tenant", "Microsoft 365 Tenant", "saas", "saas", "microsoft", (
        ServiceConfig(443, "https", "Microsoft Graph API Proxy", "TLSv1.3", A.REQUIRED),
        ServiceConfig(587, "smtp", "Exchange Online SMTP Submission", "TLSv1.2", A.REQUIRED),
    ), HumanActionType.WEB_BROWSING, 1, ("SharePoint site: HR", "Exchange mailbox: shared", "OneDrive: exec")),
    AssetType("database_server", "PostgreSQL Server", "server", "linux", "on-prem", (
        ServiceConfig(5432, "postgresql", "PostgreSQL 15.4", "TLSv1.3", A.REQUIRED),
        ServiceConfig(22, "ssh", "OpenSSH 9.2p1", None, A.REQUIRED),
    ), HumanActionType.DEVELOPER_WORKFLOW, 1, ("table: customers", "table: orders")),
    AssetType("iot_device", "IoT Controller", "iot", "embedded", "generic-vendor", (
        ServiceConfig(8443, "https", "Embedded Web Interface", "SSLv3", A.REQUIRED, True, ["RULE-003"]),
        ServiceConfig(23, "telnet", "BusyBox telnetd", None, A.DEFAULT, True, ["RULE-001", "RULE-004"]),
    ), HumanActionType.AMBIENT_HEARTBEAT, 1, ()),
    AssetType("saas_app", "Business SaaS App", "saas", "saas", "third-party", (
        ServiceConfig(443, "https", "SaaS API Gateway", "TLSv1.3", A.REQUIRED),
    ), HumanActionType.WEB_BROWSING, 1, ("Exported CSV reports", "Team wiki")),
]}

_CLOUDISH = {"aws_account", "azure_tenant", "m365_tenant", "saas_app"}
_NETWORK = {"cisco_router", "firewall"}


def parse_fleet_spec(spec: str | None) -> dict[str, int]:
    """Parse 'windows_workstation=2,cisco_router=1' (prefix aliases such as windows/linux allowed)."""
    out: dict[str, int] = {}
    for part in (spec or "").split(","):
        if not part.strip():
            continue
        name, _, num = part.partition("=")
        name = name.strip().lower()
        keys = [k for k in ASSET_TYPES if k == name] or [k for k in ASSET_TYPES if k.startswith(name)]
        if not keys or not num.strip().isdigit():
            raise ValueError(f"Bad fleet entry '{part}'. Types: {', '.join(ASSET_TYPES)}")
        out[keys[0]] = out.get(keys[0], 0) + int(num)
    return out


def resolve_fleet(spec: str | None = None, total: int | None = None, seed: int = 42) -> list[str]:
    """Explicit counts are honoured; the rest is filled by seeded, weighted, capped random choice."""
    counts = parse_fleet_spec(spec)
    explicit = sum(counts.values())
    total = max(total or (explicit if explicit else 8), explicit)
    rng = random.Random(seed)
    caps = {k: (max(1, total // 5) if k in _CLOUDISH else max(1, total // 6) if k in _NETWORK else total)
            for k in ASSET_TYPES}
    free = [k for k in ASSET_TYPES if k not in counts] or list(ASSET_TYPES)
    if total >= 6 and not (_NETWORK & set(counts)) and explicit < total:
        counts["cisco_router"] = counts.get("cisco_router", 0) + 1  # realistic: bigger fleets have an edge router
    while sum(counts.values()) < total:
        open_ = [k for k in free if counts.get(k, 0) < caps[k]] or free
        k = rng.choices(open_, weights=[ASSET_TYPES[x].weight for x in open_])[0]
        counts[k] = counts.get(k, 0) + 1
    return [k for k in ASSET_TYPES for _ in range(counts.get(k, 0))]


def build_templates(types: list[str]) -> list[HumanWorkstationTemplate]:
    """One unique-hosted template per fleet member (RFC 5737 addresses)."""
    seen: dict[str, int] = {}
    out: list[HumanWorkstationTemplate] = []
    for i, key in enumerate(types, start=1):
        t = ASSET_TYPES[key]
        seen[key] = seen.get(key, 0) + 1
        ports = [s.port for s in t.services]
        ip = f"192.0.2.{i}" if i <= 250 else f"198.51.100.{i - 250}"
        out.append(HumanWorkstationTemplate(
            host_id=f"{key.replace('_', '-')}-{seen[key]:02d}", label=f"{t.label} {seen[key]:02d}",
            os_family=t.os_family, persona=key, ip=ip, services=list(t.services),
            primary_workflow=t.workflow, typical_active_ports=ports, typical_idle_ports=ports[:1],
        ))
    return out
