"""Persistent and memory-backed cache for vulnerability knowledge records."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from sentryscan.common.clock import Clock, SystemClock
from sentryscan.knowledge.models import KnowledgeSource, VulnerabilityRecord

logger = logging.getLogger(__name__)


class VulnerabilityCache:
    """Cache for external CVE records with TTL and persistence support."""

    def __init__(
        self,
        cache_path: str | Path | None = None,
        clock: Clock | None = None,
        default_ttl_seconds: float = 3600.0,
    ) -> None:
        self.cache_path = Path(cache_path) if cache_path else None
        self.clock = clock if clock is not None else SystemClock()
        self.default_ttl_seconds = default_ttl_seconds

        self._store: dict[str, dict[str, Any]] = {}
        self.hits: int = 0
        self.misses: int = 0

        if self.cache_path and self.cache_path.exists():
            self.load()

    def get(self, cve_id: str) -> VulnerabilityRecord | None:
        """Retrieve record by CVE ID if present and not expired."""
        norm_key = cve_id.strip().upper()
        entry = self._store.get(norm_key)
        if not entry:
            self.misses += 1
            return None

        cached_at = entry.get("cached_at", 0.0)
        ttl = entry.get("ttl_seconds", self.default_ttl_seconds)
        now_ts = self.clock.now_utc().timestamp()

        if (now_ts - cached_at) > ttl:
            logger.debug(
                "Cache entry for %s expired (age=%.1fs, ttl=%.1fs)",
                norm_key,
                (now_ts - cached_at),
                ttl,
            )
            del self._store[norm_key]
            self.misses += 1
            return None

        self.hits += 1
        raw_record = entry.get("record", {})
        # Tag record as CACHE source
        rec_data = dict(raw_record)
        rec_data["source"] = KnowledgeSource.CACHE
        return VulnerabilityRecord(**rec_data)

    def set(
        self,
        cve_id: str,
        record: VulnerabilityRecord,
        ttl_seconds: float | None = None,
    ) -> None:
        """Store record in cache with current timestamp and TTL."""
        norm_key = cve_id.strip().upper()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        now_ts = self.clock.now_utc().timestamp()

        self._store[norm_key] = {
            "cached_at": now_ts,
            "ttl_seconds": ttl,
            "record": record.model_dump(),
        }

        if self.cache_path:
            self.save()

    def clear(self) -> None:
        """Clear all entries and reset metrics."""
        self._store.clear()
        self.hits = 0
        self.misses = 0

    def save(self) -> None:
        """Persist cache entries to disk."""
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._store, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save cache to %s: %s", self.cache_path, e)

    def load(self) -> None:
        """Load cache entries from disk."""
        if not self.cache_path or not self.cache_path.exists():
            return
        try:
            with open(self.cache_path, "r", encoding="utf-8") as f:
                self._store = json.load(f)
        except Exception as e:
            logger.warning("Failed to load cache from %s: %s", self.cache_path, e)
            self._store = {}

    def stats(self) -> dict[str, Any]:
        """Return operational cache metrics."""
        total_requests = self.hits + self.misses
        hit_ratio = (self.hits / total_requests) if total_requests > 0 else 0.0
        return {
            "size": len(self._store),
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio": round(hit_ratio, 4),
        }
