"""Security package: Cryptographic identities, registries, signing, and security gate."""

from sentryscan.security.canonical import (
    sign_envelope,
    verify_envelope_signature,
    verify_payload_digest,
)
from sentryscan.security.gate import SecurityGate, SecurityReasonCode, SecurityVerdict
from sentryscan.security.identity import AgentIdentity
from sentryscan.security.nonce_cache import NonceCache
from sentryscan.security.registry import TrustedAgentRecord, TrustedAgentRegistry

__all__ = [
    "AgentIdentity",
    "NonceCache",
    "SecurityGate",
    "SecurityReasonCode",
    "SecurityVerdict",
    "TrustedAgentRecord",
    "TrustedAgentRegistry",
    "sign_envelope",
    "verify_envelope_signature",
    "verify_payload_digest",
]
