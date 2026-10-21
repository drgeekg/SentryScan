"""Knowledge representation, ontology models, and external enrichment adapters."""

from sentryscan.knowledge.cache import VulnerabilityCache
from sentryscan.knowledge.enricher import KnowledgeEnricher
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
    "KnowledgeEnricher",
    "KnowledgeSource",
    "NVDAdapter",
    "NVDConnectionError",
    "NVDError",
    "NVDValidationError",
    "VulnerabilityCache",
    "VulnerabilityKnowledgeBase",
    "VulnerabilityRecord",
]
