"""Trusted Agent Public Key Registry for SentryScan."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class TrustedAgentRecord(BaseModel):
    """Entry in the trusted agent public key registry."""

    agent_id: str
    public_key_hex: str = Field(..., min_length=64, max_length=64)
    status: str = "ACTIVE"
    description: str = ""


class TrustedAgentRegistry:
    """Registry maintaining verified Ed25519 public keys for known agent identities."""

    def __init__(self, records: list[TrustedAgentRecord] | None = None) -> None:
        self._records: dict[str, TrustedAgentRecord] = {}
        if records:
            for rec in records:
                self.register_record(rec)

    def register(
        self,
        agent_id: str,
        public_key_hex: str,
        status: str = "ACTIVE",
        description: str = "",
    ) -> None:
        """Register or update an agent public key in the registry."""
        rec = TrustedAgentRecord(
            agent_id=agent_id,
            public_key_hex=public_key_hex.lower(),
            status=status.upper(),
            description=description,
        )
        self.register_record(rec)

    def register_record(self, record: TrustedAgentRecord) -> None:
        """Register a validated TrustedAgentRecord."""
        self._records[record.agent_id] = record

    def get_record(self, agent_id: str) -> TrustedAgentRecord | None:
        """Get record for agent_id if registered."""
        return self._records.get(agent_id)

    def is_trusted(self, agent_id: str) -> bool:
        """Return True if agent_id is registered and status is ACTIVE."""
        rec = self.get_record(agent_id)
        if rec is None:
            return False
        return rec.status == "ACTIVE"

    def revoke(self, agent_id: str) -> None:
        """Mark an agent identity as REVOKED."""
        rec = self.get_record(agent_id)
        if rec:
            rec.status = "REVOKED"
            logger.warning("Revoked trust for agent %s", agent_id)

    def get_public_key(self, agent_id: str) -> Ed25519PublicKey | None:
        """Return the cryptography Ed25519PublicKey object for the trusted agent."""
        if not self.is_trusted(agent_id):
            return None
        rec = self.get_record(agent_id)
        if not rec:
            return None
        try:
            pub_bytes = bytes.fromhex(rec.public_key_hex)
            return Ed25519PublicKey.from_public_bytes(pub_bytes)
        except Exception as e:
            logger.error("Failed to parse public key for agent %s: %s", agent_id, e)
            return None

    @classmethod
    def load_from_file(cls, path: str | Path) -> TrustedAgentRegistry:
        """Load registry from JSON file."""
        target_path = Path(path)
        if not target_path.exists():
            logger.warning("Registry file not found at %s. Returning empty registry.", target_path)
            return cls([])

        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            records = [TrustedAgentRecord(**item) for item in data]
            return cls(records)
        except Exception as e:
            logger.error("Failed to parse trusted agents registry from %s: %s", target_path, e)
            return cls([])

    def save_to_file(self, path: str | Path) -> None:
        """Persist registry records to JSON file."""
        target_path = Path(path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        data = [rec.model_dump() for rec in self._records.values()]
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def list_all(self) -> list[TrustedAgentRecord]:
        """Return list of all registered TrustedAgentRecords."""
        return list(self._records.values())

    def to_list(self) -> list[dict[str, Any]]:
        """Return list of dictionary representations of registered agents."""
        return [rec.model_dump() for rec in self._records.values()]
