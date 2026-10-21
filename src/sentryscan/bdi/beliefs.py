"""BDI BeliefBase and epistemic belief structures for SentryScan."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class HostStatus(str, Enum):
    """Epistemic operational status of a monitored host."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    QUARANTINED = "QUARANTINED"


class HostBelief(BaseModel):
    """Epistemic state and known security facts about a specific synthetic host."""

    host_id: str
    ip_address: str | None = None
    status: HostStatus = HostStatus.CLEAN
    highest_severity: str = "INFO"
    finding_ids: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    scan_cadence_ms: int = 500
    quarantined: bool = False
    last_updated_iso: str = ""

    def is_critical(self) -> bool:
        """Return True if this host has an active critical finding."""
        return self.highest_severity.upper() == "CRITICAL"

    def requires_quarantine(self) -> bool:
        """Return True if the host is compromised/critical but not yet quarantined."""
        return self.is_critical() and not self.quarantined


class FleetBelief(BaseModel):
    """Aggregate fleet-wide belief metrics and operational constraints."""

    total_hosts: int = 0
    scanned_host_ids: list[str] = Field(default_factory=list)
    remaining_budget: float = 100.0
    allocated_scans: int = 0
    quarantined_hosts: list[str] = Field(default_factory=list)


class BeliefBase(BaseModel):
    """Validated, single-source belief state held by the agent."""

    hosts: dict[str, HostBelief] = Field(default_factory=dict)
    fleet: FleetBelief = Field(default_factory=FleetBelief)
    api_available: bool = True
    cache_available: bool = True
    trusted_communication: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)

    def get_or_create_host(self, host_id: str, ip_address: str | None = None) -> HostBelief:
        """Retrieve existing host belief or initialize a clean host record."""
        if host_id not in self.hosts:
            self.hosts[host_id] = HostBelief(host_id=host_id, ip_address=ip_address)
        return self.hosts[host_id]

    def update_host_finding(
        self,
        host_id: str,
        finding_id: str,
        severity: str,
        timestamp_iso: str = "",
        open_ports: list[int] | None = None,
    ) -> bool:
        """Update host belief with a newly observed finding.

        Returns:
            True if this update represents a material belief change (escalation to HIGH/CRITICAL).
        """
        host = self.get_or_create_host(host_id)
        prev_severity = host.highest_severity

        if finding_id not in host.finding_ids:
            host.finding_ids.append(finding_id)

        if open_ports:
            for p in open_ports:
                if p not in host.open_ports:
                    host.open_ports.append(p)

        norm_sev = severity.upper()
        severity_ranks = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        curr_rank = severity_ranks.get(norm_sev, 0)
        prev_rank = severity_ranks.get(prev_severity, 0)

        if curr_rank > prev_rank:
            host.highest_severity = norm_sev
            if norm_sev == "CRITICAL":
                host.status = HostStatus.COMPROMISED
            elif norm_sev == "HIGH":
                host.status = HostStatus.SUSPICIOUS

        if timestamp_iso:
            host.last_updated_iso = timestamp_iso

        # Material change if severity escalated to HIGH or CRITICAL
        material = curr_rank > prev_rank and curr_rank >= severity_ranks["HIGH"]
        return material

    def quarantine_host(self, host_id: str) -> bool:
        """Set host state to QUARANTINED and register in fleet belief."""
        host = self.get_or_create_host(host_id)
        if not host.quarantined:
            host.quarantined = True
            host.status = HostStatus.QUARANTINED
            if host_id not in self.fleet.quarantined_hosts:
                self.fleet.quarantined_hosts.append(host_id)
            return True
        return False

    def deduct_budget(self, amount: float) -> bool:
        """Deduct resource expenditure from remaining budget. Returns False if budget exhausted."""
        if self.fleet.remaining_budget < amount:
            return False
        self.fleet.remaining_budget -= amount
        self.fleet.allocated_scans += 1
        return True

    def record_scan_completed(self, host_id: str) -> None:
        """Record completed scan for a host."""
        if host_id not in self.fleet.scanned_host_ids:
            self.fleet.scanned_host_ids.append(host_id)

    def get_uncontained_critical_hosts(self) -> list[HostBelief]:
        """Return list of hosts with critical severity that are not yet quarantined."""
        return [h for h in self.hosts.values() if h.requires_quarantine()]

    def get_unscanned_hosts(self, candidate_host_ids: list[str]) -> list[str]:
        """Return subset of candidate hosts not yet scanned."""
        scanned = set(self.fleet.scanned_host_ids)
        return [h for h in candidate_host_ids if h not in scanned]
