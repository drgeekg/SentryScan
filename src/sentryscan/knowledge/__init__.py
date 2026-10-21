"""Knowledge representation, ontology models, and external enrichment adapters."""

from sentryscan.knowledge.models import EnrichmentResult, KnowledgeSource, VulnerabilityRecord
from sentryscan.knowledge.ontology import VulnerabilityKnowledgeBase

__all__ = [
    "EnrichmentResult",
    "KnowledgeSource",
    "VulnerabilityKnowledgeBase",
    "VulnerabilityRecord",
]
