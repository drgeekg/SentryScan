"""Inbound Security Gate enforcing authentication, recipient binding, freshness, and anti-replay."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.contracts.message import Message
from sentryscan.security.canonical import (
    verify_envelope_signature,
    verify_payload_digest,
)
from sentryscan.security.nonce_cache import NonceCache
from sentryscan.security.registry import TrustedAgentRegistry

logger = logging.getLogger(__name__)


class SecurityReasonCode(str, Enum):
    """Reason codes for security gate verdicts."""

    OK = "OK"
    BAD_FRAME = "BAD_FRAME"
    BAD_JSON = "BAD_JSON"
    BAD_SCHEMA = "BAD_SCHEMA"
    UNKNOWN_SENDER = "UNKNOWN_SENDER"
    WRONG_RECIPIENT = "WRONG_RECIPIENT"
    PAYLOAD_TAMPERED = "PAYLOAD_TAMPERED"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    STALE_TIMESTAMP = "STALE_TIMESTAMP"
    REPLAYED_NONCE = "REPLAYED_NONCE"
    NONCE_CACHE_FULL = "NONCE_CACHE_FULL"


class SecurityVerdict(BaseModel):
    """Comprehensive decision artifact from inbound security gate validation."""

    valid: bool
    reason_code: SecurityReasonCode
    reason_summary: str
    message_id: str | None = None
    sender: str | None = None
    receiver: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class SecurityGate:
    """Security boundary gate inspecting and validating incoming inter-agent messages."""

    def __init__(
        self,
        agent_id: str,
        registry: TrustedAgentRegistry,
        clock: Clock | None = None,
        freshness_window_seconds: float = 30.0,
        nonce_cache: NonceCache | None = None,
    ) -> None:
        self.agent_id = agent_id
        self.registry = registry
        self.clock = clock if clock is not None else SystemClock()
        self.freshness_window_seconds = freshness_window_seconds
        self.nonce_cache = (
            nonce_cache
            if nonce_cache is not None
            else NonceCache(clock=self.clock, ttl_seconds=freshness_window_seconds * 2.0)
        )

        # Audit stats
        self.accepted_count: int = 0
        self.rejected_count: int = 0
        self.rejections_by_code: dict[str, int] = {}

    def validate(self, raw_input: Message | dict[str, Any] | str | bytes) -> SecurityVerdict:
        """Validate an inbound message envelope following the strict order in HLD §12.3."""
        # 1 & 2. JSON Decoding
        msg_dict: dict[str, Any]
        if isinstance(raw_input, (str, bytes)):
            try:
                msg_dict = json.loads(raw_input)
            except Exception as e:
                return self._reject(
                    SecurityReasonCode.BAD_JSON,
                    f"Message payload is not valid JSON: {e}",
                )
        elif isinstance(raw_input, dict):
            msg_dict = raw_input
        elif isinstance(raw_input, Message):
            msg_dict = raw_input.model_dump()
        else:
            return self._reject(
                SecurityReasonCode.BAD_SCHEMA,
                f"Unsupported message input type: {type(raw_input).__name__}",
            )

        # 3. Envelope Schema Validation
        message: Message
        try:
            message = Message(**msg_dict)
        except Exception as e:
            return self._reject(
                SecurityReasonCode.BAD_SCHEMA,
                f"Envelope failed schema validation: {e}",
                message_id=msg_dict.get("message_id"),
                sender=msg_dict.get("sender"),
                receiver=msg_dict.get("receiver"),
            )

        msg_id = message.message_id
        sender = message.sender
        receiver = message.receiver

        # 4. Confirm sender exists and is trusted in registry
        if not self.registry.is_trusted(sender):
            return self._reject(
                SecurityReasonCode.UNKNOWN_SENDER,
                f"Sender agent {sender!r} is not registered or is revoked.",
                message_id=msg_id,
                sender=sender,
                receiver=receiver,
            )

        # 5. Confirm receiver equals this agent's ID
        if receiver != self.agent_id:
            return self._reject(
                SecurityReasonCode.WRONG_RECIPIENT,
                f"Recipient mismatch: expected {self.agent_id!r}, message specifies {receiver!r}.",
                message_id=msg_id,
                sender=sender,
                receiver=receiver,
            )

        # 6. Recompute payload digest and compare with payload_sha256
        if not verify_payload_digest(message):
            return self._reject(
                SecurityReasonCode.PAYLOAD_TAMPERED,
                "Payload SHA-256 digest mismatch. Content has been tampered in transit.",
                message_id=msg_id,
                sender=sender,
                receiver=receiver,
            )

        # 7. Rebuild canonical bytes and verify Ed25519 signature
        pub_key = self.registry.get_public_key(sender)
        if pub_key is None or not verify_envelope_signature(message, pub_key):
            return self._reject(
                SecurityReasonCode.BAD_SIGNATURE,
                f"Ed25519 cryptographic signature verification failed for sender {sender!r}.",
                message_id=msg_id,
                sender=sender,
                receiver=receiver,
            )

        # 8. Check timestamp freshness within ±30s using injected Clock
        now_dt = self.clock.now_utc()
        try:
            clean_ts = message.timestamp_utc.replace("Z", "+00:00")
            msg_dt = datetime.fromisoformat(clean_ts).astimezone(timezone.utc)
            delta_seconds = abs((now_dt - msg_dt).total_seconds())
            if delta_seconds > self.freshness_window_seconds:
                return self._reject(
                    SecurityReasonCode.STALE_TIMESTAMP,
                    f"Timestamp {message.timestamp_utc} outside freshness window "
                    f"(skew={delta_seconds:.1f}s, max={self.freshness_window_seconds}s).",
                    message_id=msg_id,
                    sender=sender,
                    receiver=receiver,
                )
        except Exception as e:
            return self._reject(
                SecurityReasonCode.STALE_TIMESTAMP,
                f"Failed to parse timestamp {message.timestamp_utc!r}: {e}",
                message_id=msg_id,
                sender=sender,
                receiver=receiver,
            )

        # 9 & 10. Anti-replay and bounded nonce cache check
        nonce_valid, nonce_code = self.nonce_cache.check_and_add(sender, message.nonce)
        if not nonce_valid:
            reason = (
                SecurityReasonCode.REPLAYED_NONCE
                if nonce_code == "REPLAYED_NONCE"
                else SecurityReasonCode.NONCE_CACHE_FULL
            )
            summary = (
                f"Nonce {message.nonce!r} from sender {sender!r} was previously seen within window."
                if reason == SecurityReasonCode.REPLAYED_NONCE
                else "Nonce cache capacity exhausted. Gate failing closed."
            )
            return self._reject(
                reason,
                summary,
                message_id=msg_id,
                sender=sender,
                receiver=receiver,
            )

        # All checks passed
        self.accepted_count += 1
        return SecurityVerdict(
            valid=True,
            reason_code=SecurityReasonCode.OK,
            reason_summary=(
                "Cryptographic signature, recipient binding, freshness, and nonce verified."
            ),
            message_id=msg_id,
            sender=sender,
            receiver=receiver,
        )

    def _reject(
        self,
        reason: SecurityReasonCode,
        summary: str,
        message_id: str | None = None,
        sender: str | None = None,
        receiver: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> SecurityVerdict:
        """Record rejection audit metrics and return SecurityVerdict."""
        self.rejected_count += 1
        code_str = reason.value
        self.rejections_by_code[code_str] = self.rejections_by_code.get(code_str, 0) + 1

        logger.warning(
            "[%s] Security Gate REJECT [%s]: %s (message_id=%s, sender=%s)",
            self.agent_id,
            code_str,
            summary,
            message_id,
            sender,
        )

        return SecurityVerdict(
            valid=False,
            reason_code=reason,
            reason_summary=summary,
            message_id=message_id,
            sender=sender,
            receiver=receiver,
            details=details or {},
        )

    def stats(self) -> dict[str, Any]:
        """Return operational security gate metrics."""
        return {
            "agent_id": self.agent_id,
            "accepted": self.accepted_count,
            "rejected": self.rejected_count,
            "rejections_by_code": dict(self.rejections_by_code),
            "nonce_cache": self.nonce_cache.stats(),
        }
