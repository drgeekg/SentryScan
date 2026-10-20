"""Unit tests for the packaging script."""

import hashlib
import sys
from pathlib import Path

# Add scripts directory to path for testing
SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

import package_assignment  # noqa: E402


def test_compute_sha256(tmp_path: Path):
    """Test SHA-256 calculation matches expected hash."""
    sample_file = tmp_path / "sample.txt"
    payload = b"SentryScan determinism test\n"
    sample_file.write_bytes(payload)

    expected_hash = hashlib.sha256(payload).hexdigest()
    computed_hash = package_assignment.compute_sha256(sample_file)

    assert computed_hash == expected_hash
