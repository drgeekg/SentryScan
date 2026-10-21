"""Knowledge representation, ontology models, and external enrichment adapters."""

from sentryscan.knowledge.models import EnrichmentResult, KnowledgeSource, VulnerabilityRecord
from sentryscan.knowledge.nvd_adapter import (
    NVDAdapter,
    NVDConnectionError,
    NVDError,
    NVDValidationError,
)
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase

__all__ = [
    "EnrichmentResult",
    "KnowledgeSource",
    "NVDAdapter",
    "NVDConnectionError",
    "NVDError",
    "NVDValidationError",
    "VulnerabilityKnowledgeBase",
    "VulnerabilityRecord",
]
