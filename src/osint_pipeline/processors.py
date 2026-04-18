from __future__ import annotations

from osint_pipeline.models import Finding, to_json_string
from osint_pipeline.site_profiles import get_signal_strength


SHERLOCK_STATUS_MAP = {
    "Claimed": "found",
    "Available": "not_found",
    "Illegal": "not_found",
    "Unknown": "error",
    "WAF": "error",
    "Breach": "found",
    "NoBreach": "not_found",
    "RecordFound": "found",
    "NoRecord": "not_found",
    "DNSRecordsFound": "found",
    "NoDNSRecords": "not_found",
    "EmailDomainProfiled": "found",
    "EmailDomainNoRecords": "not_found",
    "EmailProfileFound": "found",
    "NoEmailProfile": "not_found",
    "EmailProfileError": "error",
    "HoleheAccountFound": "found",
    "HoleheNotFound": "not_found",
    "HoleheRateLimited": "error",
    "BuiltWithClassified": "found",
    "NoBuiltWithProfile": "not_found",
    "BuiltWithError": "error",
}


def normalize_username(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("@"):
        normalized = normalized[1:]
    if not normalized:
        raise ValueError("username cannot be empty")
    return normalized


def normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    if not normalized or "@" not in normalized:
        raise ValueError("email must contain @")
    local_part, _, domain = normalized.partition("@")
    if not local_part or not domain:
        raise ValueError("email must be a valid address")
    return normalized


def normalize_domain(value: str) -> str:
    normalized = value.strip().lower()
    if normalized.startswith("http://"):
        normalized = normalized[7:]
    elif normalized.startswith("https://"):
        normalized = normalized[8:]
    normalized = normalized.strip("/").split("/", 1)[0]
    if "." not in normalized or normalized.startswith(".") or normalized.endswith("."):
        raise ValueError("domain must look like example.com")
    return normalized


def map_sherlock_status(raw_status: str) -> str:
    cleaned = raw_status.strip()
    return SHERLOCK_STATUS_MAP.get(cleaned, "error")


def _override_status(
    *,
    platform: str,
    source: str,
    raw_status: str,
    raw_data: dict[str, str] | None,
) -> str | None:
    if raw_data is None:
        return None

    if (
        source.startswith("sherlock")
        and platform.strip().lower() == "academia.edu"
        and raw_status.strip() == "Available"
        and str(raw_data.get("http_status", "")).strip() == "403"
    ):
        # Academia.edu has returned blocked 403 responses that Sherlock labeled as
        # Available. Treat that as an unstable/error state rather than a clean
        # not-found result.
        return "error"

    return None


def normalize_finding(
    *,
    run_id: str,
    input_type: str,
    input_value: str,
    platform: str,
    url: str,
    username: str,
    source: str,
    checked_at_utc: str,
    raw_status: str,
    signal_strength: str | None = None,
    confidence: str | None = None,
    raw_data: dict[str, str] | None = None,
    notes: str = "",
) -> Finding:
    normalized_identity = username.strip()
    if input_type == "username":
        normalized_identity = normalize_username(username)
    elif input_type == "email":
        normalized_identity = normalize_email(username)
    elif input_type == "domain":
        normalized_identity = normalize_domain(username)

    status = _override_status(
        platform=platform,
        source=source,
        raw_status=raw_status,
        raw_data=raw_data,
    ) or map_sherlock_status(raw_status)

    return Finding(
        run_id=run_id,
        input_type=input_type,
        input_value=input_value,
        platform=platform.strip(),
        signal_strength=signal_strength or get_signal_strength(platform),
        url=url.strip(),
        username=normalized_identity,
        source=source.strip(),
        checked_at_utc=checked_at_utc,
        status=status,
        confidence=confidence,
        raw_data=to_json_string(raw_data),
        notes=notes,
    )
