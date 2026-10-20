"""Deterministic ID generation utilities for reproducible runs."""

from __future__ import annotations

import random
from typing import ClassVar


class IdGenerator:
    """Deterministic sequence and seeded ID generator.

    Generates stable, zero-padded IDs for records, findings, tasks, events, and runs.
    """

    _DEFAULT_PREFIXES: ClassVar[dict[str, str]] = {
        "record": "tel",
        "finding": "fnd",
        "event": "evt",
        "task": "tsk",
        "run": "run",
        "proposal": "prop",
        "message": "msg",
    }

    def __init__(self, seed: int | None = 42) -> None:
        self.seed = seed
        self._counters: dict[str, int] = {}
        self._rng = random.Random(seed) if seed is not None else random.Random()

    def next_id(self, entity_type: str, pad_width: int = 6) -> str:
        """Return the next zero-padded monotonic ID for a given entity type."""
        prefix = self._DEFAULT_PREFIXES.get(entity_type, entity_type)
        current = self._counters.get(entity_type, 0) + 1
        self._counters[entity_type] = current
        return f"{prefix}-{current:0{pad_width}d}"

    def seeded_token(self, length: int = 12) -> str:
        """Generate a deterministic hex token using the seeded PRNG."""
        chars = "0123456789abcdef"
        return "".join(self._rng.choice(chars) for _ in range(length))

    def reset(self) -> None:
        """Reset internal counters and re-seed the PRNG."""
        self._counters.clear()
        if self.seed is not None:
            self._rng.seed(self.seed)
