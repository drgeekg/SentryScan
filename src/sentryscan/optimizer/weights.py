"""Configurable and validated multi-attribute utility weights."""

from __future__ import annotations

from pydantic import BaseModel, Field, model_validator


class UtilityWeights(BaseModel):
    """Normalized multi-attribute weights for security plan optimization.

    Formula:
        U(o) = w_sev * C_sev + w_hosts * C_hosts - w_cost * Cost - w_time * Time - w_risk * Risk
    """

    w_severity: float = Field(0.35, ge=0.0, le=1.0, description="Weight for severity coverage")
    w_hosts: float = Field(0.25, ge=0.0, le=1.0, description="Weight for endpoint host coverage")
    w_cost: float = Field(0.15, ge=0.0, le=1.0, description="Penalty weight for resource cost")
    w_time: float = Field(0.15, ge=0.0, le=1.0, description="Penalty weight for scan latency")
    w_risk: float = Field(0.10, ge=0.0, le=1.0, description="Penalty weight for residual risk")

    @model_validator(mode="after")
    def validate_sum_to_one(self) -> UtilityWeights:
        total = self.w_severity + self.w_hosts + self.w_cost + self.w_time + self.w_risk
        if not (0.99 <= total <= 1.01):
            raise ValueError(f"Utility weights must sum to 1.0 (got {total:.4f})")
        return self

    @classmethod
    def default(cls) -> UtilityWeights:
        """Return the standard baseline balanced weights."""
        return cls()

    @classmethod
    def risk_first(cls) -> UtilityWeights:
        """Preset favoring critical risk containment."""
        return cls(w_severity=0.55, w_hosts=0.15, w_cost=0.10, w_time=0.10, w_risk=0.10)

    @classmethod
    def coverage_first(cls) -> UtilityWeights:
        """Preset favoring wide fleet subnet enumeration."""
        return cls(w_severity=0.15, w_hosts=0.55, w_cost=0.10, w_time=0.10, w_risk=0.10)
