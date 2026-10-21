"""Unit tests for DetectionEvaluator scoring against ground truth."""

from sentryscan.integrity.checker import (
    IntegrityFlag,
    IntegrityReasonCode,
)
from sentryscan.integrity.evaluator import DetectionEvaluator
from sentryscan.simulation.poisoning import (
    GroundTruthEntry,
    GroundTruthSidecar,
)


def test_evaluator_metrics_calculation():
    """Verify precision, recall, and confusion matrix calculation."""
    sidecar = GroundTruthSidecar()

    # Entry 1: Mutated & Flagged (TP)
    sidecar.record_ground_truth(
        GroundTruthEntry("tel-001", "sim-001", True, "stale_timestamp", ["time"], "suspect")
    )
    # Entry 2: Mutated & Flagged (TP)
    sidecar.record_ground_truth(
        GroundTruthEntry("tel-002", "sim-001", True, "service_mismatch", ["banner"], "suspect")
    )
    # Entry 3: Clean & Not Flagged (TN)
    sidecar.record_ground_truth(
        GroundTruthEntry("tel-003", "sim-002", False, None, [], "normal")
    )
    # Entry 4: Clean & Not Flagged (TN)
    sidecar.record_ground_truth(
        GroundTruthEntry("tel-004", "sim-002", False, None, [], "normal")
    )

    evaluator = DetectionEvaluator(sidecar)

    flags = {
        "tel-001": [
            IntegrityFlag(
                "tel-001", "INT-002", IntegrityReasonCode.STALE_RECORD, 1.0, {}
            )
        ],
        "tel-002": [
            IntegrityFlag(
                "tel-002", "INT-003", IntegrityReasonCode.FIELD_CONTRADICTION, 1.0, {}
            )
        ],
    }

    metrics = evaluator.evaluate(["tel-001", "tel-002", "tel-003", "tel-004"], flags)

    assert metrics.total_evaluated == 4
    assert metrics.true_positives == 2
    assert metrics.true_negatives == 2
    assert metrics.false_positives == 0
    assert metrics.false_negatives == 0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
