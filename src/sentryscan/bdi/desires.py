"""BDI Desires and goal models for SentryScan."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from sentryscan.bdi.beliefs import BeliefBase


class DesireType(str, Enum):
    """Ranked high-level goals pursued by the deliberative agent."""

    SURFACE_CRITICAL_FINDINGS = "SURFACE_CRITICAL_FINDINGS"
    CONTAIN_COMPROMISED_HOSTS = "CONTAIN_COMPROMISED_HOSTS"
    AUDIT_ASSIGNED_HOSTS = "AUDIT_ASSIGNED_HOSTS"
    CONSERVE_BUDGET = "CONSERVE_BUDGET"
    MAINTAIN_AUDIT_TRAIL = "MAINTAIN_AUDIT_TRAIL"


class Desire(BaseModel):
    """Goal pursued by the agent, eligible for selection during deliberation."""

    desire_id: str
    desire_type: DesireType
    priority: float = 50.0
    target_host: str | None = None
    description: str = ""
    created_at_iso: str = ""
    parameters: dict[str, str | int | float | bool] = Field(default_factory=dict)

    def is_eligible(self, beliefs: BeliefBase) -> bool:
        """Evaluate whether this desire remains valid and achievable under current beliefs."""
        if self.desire_type == DesireType.CONTAIN_COMPROMISED_HOSTS:
            if not self.target_host:
                return len(beliefs.get_uncontained_critical_hosts()) > 0
            host = beliefs.hosts.get(self.target_host)
            return host is not None and host.requires_quarantine()

        if self.desire_type == DesireType.SURFACE_CRITICAL_FINDINGS:
            if not self.target_host:
                return any(h.is_critical() for h in beliefs.hosts.values())
            host = beliefs.hosts.get(self.target_host)
            return host is not None and host.is_critical()

        if self.desire_type == DesireType.AUDIT_ASSIGNED_HOSTS:
            return beliefs.fleet.remaining_budget >= 5.0

        if self.desire_type == DesireType.CONSERVE_BUDGET:
            return beliefs.fleet.remaining_budget < 25.0

        if self.desire_type == DesireType.MAINTAIN_AUDIT_TRAIL:
            return True

        return True
