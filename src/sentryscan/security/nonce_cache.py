"""Anti-replay nonce cache with TTL eviction and fail-closed capacity limits."""

from __future__ import annotations

import logging
from typing import Any

from sentryscan.common.clock import Clock, SystemClock

logger = logging.getLogger(__name__)


class NonceCache:
    """Tracks seen (sender, nonce) tuples with TTL eviction and fail-closed bounds."""

    def __init__(
        self,
        clock: Clock | None = None,
        ttl_seconds: float = 60.0,
        max_size: int = 1000,
    ) -> None:
        self.clock = clock if clock is not None else SystemClock()
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size

        # Map: (sender, nonce) -> timestamp_utc_float
        self._store: dict[tuple[str, str], float] = {}

        # Operational metrics
        self.replays_detected: int = 0
        self.cache_full_events: int = 0
        self.total_recorded: int = 0

    def purge_expired(self, now_ts: float | None = None) -> int:
        """Evict nonces whose age exceeds ttl_seconds. Returns count of evicted entries."""
        now = now_ts if now_ts is not None else self.clock.now_utc().timestamp()
        expired_keys = [
            k for k, seen_ts in self._store.items() if (now - seen_ts) > self.ttl_seconds
        ]
        for k in expired_keys:
            del self._store[k]
        return len(expired_keys)

    def check_and_add(self, sender: str, nonce: str) -> tuple[bool, str]:
        """Check if (sender, nonce) is replay or if cache is full; record if valid.

        Returns:
            (is_valid, reason_code) where reason_code is "OK", "REPLAYED_NONCE",
            or "NONCE_CACHE_FULL".
        """
        now = self.clock.now_utc().timestamp()
        self.purge_expired(now)

        key = (sender.strip(), nonce.strip())

        # Check for replay
        if key in self._store:
            self.replays_detected += 1
            logger.warning("Replayed nonce detected for sender %s: %s", sender, nonce)
            return False, "REPLAYED_NONCE"

        # Check capacity bound (Fail-closed)
        if len(self._store) >= self.max_size:
            self.cache_full_events += 1
            logger.critical(
                "Nonce cache reached max capacity (%d entries). Failing closed.",
                self.max_size,
            )
            return False, "NONCE_CACHE_FULL"

        # Record valid nonce
        self._store[key] = now
        self.total_recorded += 1
        return True, "OK"

    def clear(self) -> None:
        """Clear all stored nonces."""
        self._store.clear()

    def stats(self) -> dict[str, Any]:
        """Return operational cache metrics."""
        return {
            "size": len(self._store),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds,
            "replays_detected": self.replays_detected,
            "cache_full_events": self.cache_full_events,
            "total_recorded": self.total_recorded,
        }
