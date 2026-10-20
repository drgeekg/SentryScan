"""Tests for common utilities (Clock and IdGenerator)."""

from datetime import datetime, timezone

from sentryscan.common.clock import FakeClock, SystemClock
from sentryscan.common.id_generator import IdGenerator


def test_system_clock():
    """Verify system clock returns valid UTC datetime and ISO string."""
    clock = SystemClock()
    now_utc = clock.now_utc()
    assert isinstance(now_utc, datetime)
    assert now_utc.tzinfo == timezone.utc
    assert clock.now_iso().endswith("Z")


def test_fake_clock_advance_and_sleep():
    """Verify fake clock deterministic progression without real sleep."""
    clock = FakeClock("2026-10-21T12:00:00Z")
    assert clock.now_iso() == "2026-10-21T12:00:00Z"

    clock.advance(30.0)
    assert clock.now_iso() == "2026-10-21T12:00:30Z"

    clock.sleep(90.0)
    assert clock.now_iso() == "2026-10-21T12:02:00Z"


def test_id_generator_monotonic_sequence():
    """Verify ID generator produces zero-padded sequential IDs."""
    gen = IdGenerator(seed=42)
    assert gen.next_id("record") == "tel-000001"
    assert gen.next_id("record") == "tel-000002"
    assert gen.next_id("finding") == "fnd-000001"
    assert gen.next_id("event") == "evt-000001"


def test_id_generator_seeded_determinism():
    """Verify identical seeds produce identical random tokens."""
    gen1 = IdGenerator(seed=1337)
    gen2 = IdGenerator(seed=1337)

    tokens1 = [gen1.seeded_token() for _ in range(5)]
    tokens2 = [gen2.seeded_token() for _ in range(5)]
    assert tokens1 == tokens2

    gen1.reset()
    tokens1_reset = [gen1.seeded_token() for _ in range(5)]
    assert tokens1_reset == tokens2
