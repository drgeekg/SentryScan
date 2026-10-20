"""Baseline sanity test for SentryScan."""
import sentryscan


def test_package_version():
    """Verify package imports cleanly and reports version."""
    assert sentryscan.__version__ == "0.1.0"
