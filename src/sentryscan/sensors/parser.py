"""Telemetry parsing and normalization sensor."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from sentryscan.contracts.telemetry import TelemetryRecord


@dataclass(frozen=True)
class ParseResult:
    """Outcome of attempting to parse raw telemetry into a TelemetryRecord."""

    is_valid: bool
    record: TelemetryRecord | None
    raw_payload: dict[str, Any]
    error_message: str | None = None
    record_id: str = "unknown"


class TelemetryParser:
    """Sensor component for ingesting and validating telemetry percepts."""

    def parse_dict(self, raw: dict[str, Any]) -> ParseResult:
        """Parse and validate a dictionary into a TelemetryRecord."""
        record_id = str(raw.get("record_id", "unknown"))
        try:
            record = TelemetryRecord.model_validate(raw)
            return ParseResult(
                is_valid=True,
                record=record,
                raw_payload=raw,
                record_id=record.record_id,
            )
        except (ValidationError, ValueError, TypeError) as err:
            return ParseResult(
                is_valid=False,
                record=None,
                raw_payload=raw,
                error_message=str(err),
                record_id=record_id,
            )

    def parse_json_string(self, raw_str: str) -> ParseResult:
        """Decode a JSON string and parse into a TelemetryRecord."""
        try:
            data = json.loads(raw_str)
            if not isinstance(data, dict):
                return ParseResult(
                    is_valid=False,
                    record=None,
                    raw_payload={"raw": raw_str},
                    error_message="Telemetry JSON root must be an object",
                )
            return self.parse_dict(data)
        except json.JSONDecodeError as err:
            return ParseResult(
                is_valid=False,
                record=None,
                raw_payload={"raw": raw_str},
                error_message=f"JSON decode failure: {err}",
            )

    def parse_file(self, file_path: Path | str) -> list[ParseResult]:
        """Load and parse an array of telemetry records from a JSON file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Telemetry fixture not found at {path}")

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            raise ValueError(f"Expected JSON list of records in {path}, got {type(data).__name__}")

        return [self.parse_dict(item) for item in data]
