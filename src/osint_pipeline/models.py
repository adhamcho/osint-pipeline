from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

ALLOWED_STATUSES = {"found", "not_found", "error"}
ALLOWED_CONFIDENCE = {None, "low", "medium", "high"}


@dataclass(slots=True)
class Finding:
    run_id: str
    input_type: str
    input_value: str
    platform: str
    signal_strength: str
    url: str
    username: str
    source: str
    checked_at_utc: str
    status: str
    confidence: str | None
    raw_data: str
    notes: str

    def __post_init__(self) -> None:
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(f"invalid status: {self.status}")
        if self.confidence not in ALLOWED_CONFIDENCE:
            raise ValueError(f"invalid confidence: {self.confidence}")


@dataclass(slots=True)
class RunRecord:
    run_id: str
    input_type: str
    input_value: str
    full_name: str | None
    source: str
    created_at_utc: str
    finding_count: int


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_json_string(value: dict[str, str] | None) -> str:
    if value is None:
        return "{}"
    return json.dumps(value, sort_keys=True)
