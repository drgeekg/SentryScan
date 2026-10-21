"""Evaluator scoring integrity flags against isolated ground truth."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentryscan.integrity.checker import IntegrityFlag
from sentryscan.simulation.poisoning import GroundTruthSidecar


@dataclass
class DetectionMetrics:
    """Statistical evaluation metrics comparing detected anomalies to ground truth."""

    total_evaluated: int
    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    per_operator_stats: dict[str, dict[str, int]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary representation."""
        return {
            "total_evaluated": self.total_evaluated,
            "confusion_matrix": {
                "true_positives": self.true_positives,
                "true_negatives": self.true_negatives,
                "false_positives": self.false_positives,
                "false_negatives": self.false_negatives,
            },
            "scores": {
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1_score": round(self.f1_score, 4),
            },
            "per_operator_stats": self.per_operator_stats,
        }


class DetectionEvaluator:
    """Evaluates detector accuracy by joining integrity flags with the ground truth sidecar.

    Runs out-of-band as an evaluator-only job; never participates in agent reasoning.
    """

    def __init__(self, ground_truth_sidecar: GroundTruthSidecar) -> None:
        self.sidecar = ground_truth_sidecar

    def evaluate(
        self,
        record_ids: list[str],
        flags_by_record: dict[str, list[IntegrityFlag]],
    ) -> DetectionMetrics:
        """Compute precision, recall, and per-operator detection rates."""
        tp = 0
        tn = 0
        fp = 0
        fn = 0

        operator_stats: dict[str, dict[str, int]] = {}

        for rec_id in record_ids:
            gt_entry = self.sidecar.get_entry(rec_id)
            is_truly_poisoned = gt_entry.is_poisoned if gt_entry else False
            op_type = gt_entry.injection_type if gt_entry else "normal"

            if op_type not in operator_stats:
                operator_stats[op_type] = {"total": 0, "detected": 0}
            operator_stats[op_type]["total"] += 1

            was_flagged = bool(flags_by_record.get(rec_id))

            if was_flagged:
                operator_stats[op_type]["detected"] += 1

            if is_truly_poisoned and was_flagged:
                tp += 1
            elif not is_truly_poisoned and not was_flagged:
                tn += 1
            elif not is_truly_poisoned and was_flagged:
                fp += 1
            elif is_truly_poisoned and not was_flagged:
                fn += 1

        total = len(record_ids)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1 = (
            (2 * precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return DetectionMetrics(
            total_evaluated=total,
            true_positives=tp,
            true_negatives=tn,
            false_positives=fp,
            false_negatives=fn,
            precision=precision,
            recall=recall,
            f1_score=f1,
            per_operator_stats=operator_stats,
        )

    def write_report_json(self, metrics: DetectionMetrics, file_path: Path | str) -> Path:
        """Export metrics report to JSON."""
        target = Path(file_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(metrics.to_dict(), indent=2), encoding="utf-8")
        return target
