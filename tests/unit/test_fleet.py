"""Unit tests for DeviceFleetSimulator."""

from sentryscan.common.clock import FakeClock
from sentryscan.common.id_generator import IdGenerator
from sentryscan.contracts.telemetry import TelemetrySource
from sentryscan.simulation.fleet import DeviceFleetSimulator


def test_fleet_initialization():
    """Verify fleet simulator initializes requested number of devices in RFC 5737 space."""
    sim = DeviceFleetSimulator(device_count=5, seed=42)
    assert len(sim.devices) == 5
    assert sim.devices[0].device_id == "sim-host-001"
    assert sim.devices[0].ip == "192.0.2.1"
    assert len(sim.devices[0].services) > 0


def test_fleet_telemetry_generation():
    """Verify clean baseline telemetry record generation with monotonic record_ids."""
    clock = FakeClock("2026-10-21T06:00:00Z")
    id_gen = IdGenerator(seed=10)
    sim = DeviceFleetSimulator(device_count=3, seed=10, clock=clock, id_gen=id_gen)

    dev = sim.devices[0]
    rec = sim.generate_record_for_device(dev, service_index=0)

    assert rec.record_id == "tel-000001"
    assert rec.host_id == dev.host_id
    assert rec.source == TelemetrySource.SYNTHETIC_SIMULATOR
    assert rec.generated_at == "2026-10-21T06:00:00Z"


def test_fleet_cycle_determinism():
    """Verify identical seeds produce identical fleet cycle records."""
    sim1 = DeviceFleetSimulator(
        device_count=3, seed=99, clock=FakeClock(), id_gen=IdGenerator(seed=99)
    )
    sim2 = DeviceFleetSimulator(
        device_count=3, seed=99, clock=FakeClock(), id_gen=IdGenerator(seed=99)
    )

    cycle1 = sim1.generate_fleet_cycle()
    cycle2 = sim2.generate_fleet_cycle()

    assert len(cycle1) == len(cycle2)
    for r1, r2 in zip(cycle1, cycle2, strict=False):
        assert r1.record_id == r2.record_id
        assert r1.host_id == r2.host_id
        assert r1.port == r2.port
        assert r1.service == r2.service
        assert r1.banner == r2.banner
