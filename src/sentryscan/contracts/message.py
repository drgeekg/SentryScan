"""Canonical agent message envelope and performative taxonomy."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Performative(str, Enum):
    """Speech-act communicative performatives for inter-agent messaging."""

    # Operational & State Performatives
    TASK_REQUEST = "TASK_REQUEST"
    TASK_RESULT = "TASK_RESULT"
    STATE_SYNC = "STATE_SYNC"
    ALERT = "ALERT"
    PARAMS_UPDATE = "PARAMS_UPDATE"

    # Multi-Agent Contract-Net Negotiation
    CFP = "CFP"
    PROPOSE = "PROPOSE"
    COUNTERPROPOSE = "COUNTERPROPOSE"
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    CONFIRM = "CONFIRM"

    # Observability & Errors
    EVENT = "EVENT"
    ERROR = "ERROR"


class Message(BaseModel):
    """Canonical typed envelope for inter-agent communication."""

    message_id: str = Field(..., description="Unique message identifier")
    run_id: str = Field(..., description="Correlated simulation run ID")
    sender: str = Field(..., min_length=1, description="Originating agent identity")
    receiver: str = Field(..., min_length=1, description="Target recipient agent identity")
    performative: Performative = Field(..., description="Communicative intent")
    timestamp_utc: str = Field(..., description="ISO-8601 UTC creation timestamp")
    nonce: str = Field(..., min_length=1, description="Unique anti-replay nonce")
    payload: dict[str, Any] = Field(default_factory=dict, description="Structured message content")
    task_id: str | None = Field(None, description="Correlated task identifier")
    payload_sha256: str | None = Field(None, description="SHA-256 digest of canonical payload")
    signature: str | None = Field(None, description="Cryptographic signature (Ed25519)")

    def to_json(self) -> str:
        """Serialize envelope to JSON string with sorted keys."""
        return self.model_dump_json()

    @classmethod
    def from_json(cls, json_str: str) -> Message:
        """Parse JSON string into a validated Message envelope."""
        return cls.model_validate_json(json_str)

    def canonical_payload_bytes(self) -> bytes:
        """Return canonical UTF-8 bytes of the payload for hashing and signing."""
        return json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_payload_sha256(self) -> str:
        """Calculate the SHA-256 hex digest of the canonical payload bytes."""
        return hashlib.sha256(self.canonical_payload_bytes()).hexdigest()

    def canonical_envelope_bytes(self) -> bytes:
        """Return canonical UTF-8 bytes of envelope without signature."""
        envelope_dict = {
            "domain_prefix": "sentryscan/v1/envelope",
            "message_id": self.message_id,
            "nonce": self.nonce,
            "payload": self.payload,
            "payload_sha256": self.payload_sha256 or self.compute_payload_sha256(),
            "performative": self.performative.value,
            "receiver": self.receiver,
            "run_id": self.run_id,
            "sender": self.sender,
            "task_id": self.task_id,
            "timestamp_utc": self.timestamp_utc,
        }
        return json.dumps(envelope_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
