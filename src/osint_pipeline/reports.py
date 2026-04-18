from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
import re

from osint_pipeline.models import Finding, RunRecord
from osint_pipeline.site_profiles import get_collector_weights, get_report_setting


def get_default_reports_dir(base_dir: Path) -> Path:
    return base_dir / "reports"


def get_report_output_dir(reports_dir: Path, run: RunRecord) -> Path:
    return reports_dir / run.input_type


def _local_started_at(run: RunRecord) -> datetime:
    return datetime.fromisoformat(run.created_at_utc.replace("Z", "+00:00")).astimezone()


def _report_filename(run: RunRecord) -> str:
    # Use local time in the filename so scans are easier to read at a glance.
    started_at = _local_started_at(run)
    timestamp = started_at.strftime("%Y-%m-%d_%H%M%S")
    safe_input = re.sub(r"[^A-Za-z0-9_.-]+", "_", run.input_value).strip("_")
    if len(safe_input) > 80:
        safe_input = safe_input[:80].rstrip("_")
    return f"{timestamp}_{run.input_type}_{safe_input}.md"


def _name_tokens(full_name: str) -> set[str]:
    return {token.lower() for token in re.findall(r"[A-Za-z0-9]+", full_name) if len(token) >= 3}


def _linkedin_search_queries(run: RunRecord) -> list[str]:
    if not run.full_name:
        return []

    queries = [
        f'"{run.full_name}" site:linkedin.com/in',
        f'"{run.full_name}" "{run.input_value}" site:linkedin.com/in',
    ]
    return queries


def _linkedin_slug_candidates(run: RunRecord) -> list[str]:
    candidates: list[str] = []
    username = run.input_value.strip().lower()
    if username:
        candidates.append(username)

    if run.full_name:
        tokens = [token.lower() for token in re.findall(r"[A-Za-z0-9]+", run.full_name) if token]
        if tokens:
            full_name_slug = "-".join(tokens)
            candidates.append(full_name_slug)
            if username and username not in tokens:
                candidates.append(f"{full_name_slug}-{username}")

    # Keep the list readable and stable if later rules add duplicates.
    return list(dict.fromkeys(candidates))


def _linkedin_manual_review_targets(run: RunRecord) -> list[str]:
    return [f"https://www.linkedin.com/in/{slug}" for slug in _linkedin_slug_candidates(run)]


def _collector_summary_lines(collector_summary: dict[str, int]) -> list[str]:
    if "username_findings" in collector_summary:
        lines = [
            f"- Username findings: `{collector_summary['username_findings']}`",
            f"- Email findings: `{collector_summary['email_findings']}`",
            f"- Domain findings: `{collector_summary['domain_findings']}`",
        ]
        if "sherlock_sites" in collector_summary:
            lines.extend(
                [
                    f"- Sites checked by Sherlock: `{collector_summary['sherlock_sites']}`",
                    f"- Sites checked by WhatsMyName: `{collector_summary['whatsmyname_sites']}`",
                    f"- Merged username platforms before filtering: `{collector_summary['merged_sites']}`",
                    f"- Disabled username sites skipped: `{collector_summary['disabled_sites']}`",
                ]
            )
        if "hibp_requests" in collector_summary:
            lines.append(f"- Email domain profiles: `{collector_summary.get('email_domain_profiles', 0)}`")
            lines.append(f"- Gravatar checks: `{collector_summary.get('gravatar_checks', 0)}`")
            lines.append(f"- Gravatar profiles found: `{collector_summary.get('gravatar_profiles', 0)}`")
            lines.append(f"- Holehe checks: `{collector_summary.get('holehe_checks', 0)}`")
            lines.append(f"- Holehe accounts found: `{collector_summary.get('holehe_found', 0)}`")
            lines.append(f"- Holehe rate limited: `{collector_summary.get('holehe_rate_limited', 0)}`")
            lines.append(f"- HIBP requests: `{collector_summary['hibp_requests']}`")
            lines.append(f"- HIBP breaches: `{collector_summary.get('hibp_breaches', 0)}`")
        if "rdap_requests" in collector_summary:
            lines.extend(
                [
                    f"- RDAP requests: `{collector_summary['rdap_requests']}`",
                    f"- DNS requests: `{collector_summary['dns_requests']}`",
                    f"- DNS record types found: `{collector_summary['dns_record_types']}`",
                    f"- DNS values found: `{collector_summary['dns_values']}`",
                    f"- BuiltWith requests: `{collector_summary.get('builtwith_requests', 0)}`",
                    f"- BuiltWith classifications: `{collector_summary.get('builtwith_classifications', 0)}`",
                ]
            )
        return lines

    if "sherlock_sites" in collector_summary:
        return [
            f"- Sites checked by Sherlock: `{collector_summary['sherlock_sites']}`",
            f"- Sites checked by WhatsMyName: `{collector_summary['whatsmyname_sites']}`",
            f"- Total collector checks: `{collector_summary['checked_sites']}`",
            f"- Merged platforms before filtering: `{collector_summary['merged_sites']}`",
            f"- Findings kept after filtering: `{collector_summary['kept_findings']}`",
            f"- Disabled sites skipped: `{collector_summary['disabled_sites']}`",
        ]
    if "rdap_requests" in collector_summary:
        return [
            f"- RDAP requests: `{collector_summary['rdap_requests']}`",
            f"- DNS requests: `{collector_summary['dns_requests']}`",
            f"- RDAP records found: `{collector_summary['domain_records']}`",
            f"- DNS record types found: `{collector_summary['dns_record_types']}`",
            f"- DNS values found: `{collector_summary['dns_values']}`",
            f"- BuiltWith requests: `{collector_summary.get('builtwith_requests', 0)}`",
            f"- BuiltWith classifications: `{collector_summary.get('builtwith_classifications', 0)}`",
            f"- Findings kept after filtering: `{collector_summary['kept_findings']}`",
        ]
    if "email_domain_profiles" in collector_summary:
        return [
            f"- Email domain profiles: `{collector_summary['email_domain_profiles']}`",
            f"- Gravatar checks: `{collector_summary.get('gravatar_checks', 0)}`",
            f"- Gravatar profiles found: `{collector_summary.get('gravatar_profiles', 0)}`",
            f"- Holehe checks: `{collector_summary.get('holehe_checks', 0)}`",
            f"- Holehe accounts found: `{collector_summary.get('holehe_found', 0)}`",
            f"- Holehe rate limited: `{collector_summary.get('holehe_rate_limited', 0)}`",
            f"- HIBP requests: `{collector_summary['hibp_requests']}`",
            f"- HIBP breaches: `{collector_summary['hibp_breaches']}`",
            f"- Findings kept after filtering: `{collector_summary['kept_findings']}`",
        ]

    lines: list[str] = []
    for key, value in collector_summary.items():
        label = key.replace("_", " ").capitalize()
        lines.append(f"- {label}: `{value}`")
    return lines


def _review_priority(item: Finding) -> int:
    strength_rank = {"high": 3, "medium": 2, "low": 1}
    return strength_rank.get(item.signal_strength, 0)


def _raw_payload(item: Finding) -> dict:
    try:
        payload = json.loads(item.raw_data)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def source_statuses(item: Finding) -> dict[str, str]:
    payload = _raw_payload(item)
    collector_rows = payload.get("collector_rows")
    statuses: dict[str, str] = {}

    if isinstance(collector_rows, list):
        for row in collector_rows:
            if not isinstance(row, dict):
                continue
            source = str(row.get("source", "")).strip() or "unknown"
            raw_status = str(row.get("exists", "")).strip()
            if raw_status == "Claimed":
                statuses[source] = "found"
            elif raw_status in {"Available", "Illegal"}:
                statuses[source] = "not_found"
            else:
                statuses[source] = "error"

    if statuses:
        preferred_order = ["sherlock", "whatsmyname"]
        ordered = {name: statuses[name] for name in preferred_order if name in statuses}
        for name, status in statuses.items():
            if name not in ordered:
                ordered[name] = status
        return ordered

    # Older stored rows may not have the merged collector payload.
    source = item.source or "unknown"
    return {source: item.status}


def reconciliation_label(item: Finding) -> str:
    statuses = list(source_statuses(item).values())
    if not statuses:
        return "unknown"
    if len(statuses) >= 2 and all(status == "found" for status in statuses):
        return f"{len(statuses)} sources found"
    if "found" in statuses and any(status != "found" for status in statuses):
        return "source conflict"
    if any(status == "error" for status in statuses):
        return "mixed/error"
    if len(statuses) >= 2 and all(status == "not_found" for status in statuses):
        return f"{len(statuses)} sources not found"
    if all(status == "found" for status in statuses):
        return f"{len(statuses)} source found"
    if len(set(statuses)) == 1:
        only_status = statuses[0]
        if only_status == "not_found":
            return "mixed/error"
        if only_status == "error":
            return "mixed/error"
    return "mixed/error"


def source_summary(item: Finding) -> str:
    return ", ".join(f"{source}={status}" for source, status in source_statuses(item).items())


def _email_local_part(value: str | None) -> str | None:
    if not value or "@" not in value:
        return None
    return value.split("@", 1)[0]


def _case_context(findings: list[Finding], run: RunRecord) -> dict[str, object]:
    username = _case_username_value(findings)
    email = _case_email_value(findings)
    email_local_part = _email_local_part(email)
    full_name_tokens = _name_tokens(run.full_name) if run.full_name else set()
    builtwith_finding = next(
        (item for item in findings if item.input_type == "domain" and item.source == "builtwith"),
        None,
    )
    builtwith_classifications = set()
    if builtwith_finding is not None:
        payload = _raw_payload(builtwith_finding)
        builtwith_classifications = {
            str(value).strip().lower()
            for value in (payload.get("classifications") or [])
            if str(value).strip()
        }
    holehe_services = {
        _service_key(str((_raw_payload(item).get("service") or item.platform)))
        for item in findings
        if item.input_type == "email" and item.source == "holehe" and item.status == "found"
    }
    return {
        "username": username,
        "email_local_part": email_local_part,
        "full_name_tokens": full_name_tokens,
        "holehe_services": holehe_services,
        "builtwith_classifications": builtwith_classifications,
    }


def score_details(
    item: Finding,
    *,
    run: RunRecord | None = None,
    findings: list[Finding] | None = None,
) -> tuple[int, list[str]]:
    reasons: list[str] = []
    strength_points = {"high": 8, "medium": 5, "low": 0}.get(item.signal_strength, 0)
    reconciliation = reconciliation_label(item)
    reconciliation_points = {
        "2 sources found": 4,
        "1 source found": 1,
        "source conflict": 0,
        "2 sources not found": -2,
        "mixed/error": -3,
    }.get(reconciliation, 0)
    collector_weights = get_collector_weights()
    statuses = source_statuses(item)
    source_points = sum(collector_weights.get(source, 0) for source in statuses)
    score = strength_points + reconciliation_points + source_points

    if run and findings and item.status == "found" and item.input_type == "username":
        context = _case_context(findings, run) if run.input_type == "case" else {
            "username": run.input_value if run.input_type == "username" else None,
            "email_local_part": None,
            "full_name_tokens": _name_tokens(run.full_name) if run.full_name else set(),
            "holehe_services": set(),
        }
        username = str(context["username"] or "")
        email_local_part = str(context["email_local_part"] or "")
        full_name_tokens = set(context["full_name_tokens"])
        holehe_services = set(context["holehe_services"])
        builtwith_classifications = set(context.get("builtwith_classifications") or set())

        if username and email_local_part and username.lower() == email_local_part.lower():
            score += 2
            reasons.append("email local-part matches username (+2)")
        elif username and email_local_part and (
            username.lower() in email_local_part.lower()
            or email_local_part.lower() in username.lower()
        ):
            score += 1
            reasons.append("email local-part overlaps username (+1)")

        if full_name_tokens:
            overlap = sorted(token for token in full_name_tokens if token in item.url.lower())
            if overlap:
                score += 2
                reasons.append(f"name-token overlap in public URL: {', '.join(overlap)} (+2)")

        if _service_key(item.platform) in holehe_services:
            score += 3
            reasons.append("email workflow found the same service (+3)")

        if builtwith_classifications:
            if "likely e-commerce stack" in builtwith_classifications:
                score -= 1
                reasons.append("domain looks like an e-commerce stack, so username-only linkage is weaker (-1)")
            if "likely CMS-backed site" in builtwith_classifications:
                score -= 1
                reasons.append("domain looks CMS-backed, which lowers uniqueness as a correlation signal (-1)")
            if "low-tech footprint" in builtwith_classifications:
                score -= 1
                reasons.append("domain has a low-tech footprint, so domain context adds limited evidence (-1)")
            if "broad web stack" in builtwith_classifications:
                score += 1
                reasons.append("domain has a broader web stack, adding small business-context value (+1)")

    return score, reasons


def review_score(item: Finding, *, run: RunRecord | None = None, findings: list[Finding] | None = None) -> int:
    return score_details(item, run=run, findings=findings)[0]


def review_summary_lines(
    item: Finding,
    *,
    run: RunRecord | None = None,
    findings: list[Finding] | None = None,
) -> list[str]:
    score, reasons = score_details(item, run=run, findings=findings)
    lines = [
        f"- `{item.platform}` [{item.signal_strength}] ({reconciliation_label(item)}): "
        f"{item.url} | {source_summary(item)} | score={score}"
    ]
    if reasons:
        lines.append(f"  - Why: {'; '.join(reasons)}")
    return lines


def _base_report_header(run: RunRecord) -> list[str]:
    local_started_at = _local_started_at(run)
    return [
        "# OSINT Pipeline Report",
        "",
        f"- Run ID: `{run.run_id}`",
        f"- Input Type: `{run.input_type}`",
        f"- Input Value: `{run.input_value}`",
        f"- Full Name Context: `{run.full_name}`" if run.full_name else "- Full Name Context: `None`",
        f"- Source: `{run.source}`",
        f"- Started At: `{local_started_at.strftime('%Y-%m-%d %H:%M:%S %Z')}`",
        f"- Stored UTC Timestamp: `{run.created_at_utc}`",
        f"- Stored results: `{run.finding_count}`",
        "",
    ]


def _append_signal_summary(lines: list[str], findings: list[Finding], *, run: RunRecord) -> None:
    if run.input_type == "username":
        found = [item for item in findings if item.status == "found"]
        high = len([item for item in found if item.signal_strength == "high"])
        medium = len([item for item in found if item.signal_strength == "medium"])
        low = len([item for item in found if item.signal_strength == "low"])
        not_found = len([item for item in findings if item.status == "not_found"])
        errors = len([item for item in findings if item.status == "error"])
        lines.extend(
            [
                "## Signal Summary",
                "",
                f"- Strong review leads: `{high}`",
                f"- Medium review leads: `{medium}`",
                f"- Low-priority found results: `{low}`",
                f"- Not found: `{not_found}`",
                f"- Errors / unstable results: `{errors}`",
                "",
            ]
        )
        return

    if run.input_type == "email":
        holehe_findings = [item for item in findings if item.source == "holehe"]
        lines.extend(
            [
                "## Signal Summary",
                "",
                f"- Account signals found: `{len([item for item in holehe_findings if item.status == 'found'])}`",
                f"- Public profile signals: `{len([item for item in findings if item.source == 'gravatar' and item.status == 'found'])}`",
                f"- Breach hits: `{len([item for item in findings if item.source == 'haveibeenpwned' and item.status == 'found'])}`",
                f"- Rate limited / unstable checks: `{len([item for item in holehe_findings if item.status == 'error'])}`",
                "",
            ]
        )
        return

    if run.input_type == "domain":
        dns_finding = next((item for item in findings if item.source == "dns"), None)
        dns_records = (_raw_payload(dns_finding).get("records") or {}) if dns_finding else {}
        populated_record_types = len([record_type for record_type, values in dns_records.items() if values])
        lines.extend(
            [
                "## Signal Summary",
                "",
                f"- Registration records found: `{len([item for item in findings if item.source == 'rdap' and item.status == 'found'])}`",
                f"- DNS record types found: `{populated_record_types}`",
                f"- BuiltWith classifications: `{len([item for item in findings if item.source == 'builtwith' and item.status == 'found'])}`",
                f"- Errors / unstable results: `{len([item for item in findings if item.status == 'error'])}`",
                "",
            ]
        )


def _append_collector_summary(lines: list[str], collector_summary: dict[str, int] | None) -> None:
    if not collector_summary:
        return

    lines.extend(["## Collector Summary", ""])
    lines.extend(_collector_summary_lines(collector_summary))
    lines.append("")


def _append_delta_section(lines: list[str], delta_summary: dict | None) -> None:
    lines.extend(["## Delta From Previous Similar Run", ""])
    if not delta_summary:
        lines.append("- None")
        lines.append("")
        return

    lines.append(f"- Previous run: `{delta_summary['previous_run_id']}`")
    lines.append(f"- New findings: `{len(delta_summary['new'])}`")
    lines.append(f"- Removed findings: `{len(delta_summary['removed'])}`")
    lines.append(f"- Changed findings: `{len(delta_summary['changed'])}`")
    lines.append("")

    if delta_summary["new"]:
        lines.append("### New")
        for item in delta_summary["new"][:10]:
            lines.append(f"- `{item['platform']}` [{item['status']}]")
        lines.append("")

    if delta_summary["removed"]:
        lines.append("### Removed")
        for item in delta_summary["removed"][:10]:
            lines.append(f"- `{item['platform']}` [{item['status']}]")
        lines.append("")

    if delta_summary["changed"]:
        lines.append("### Changed")
        for item in delta_summary["changed"][:10]:
            lines.append(f"- `{item['platform']}`: {'; '.join(item['changes'])}")
        lines.append("")

    if lines[-1] == "":
        return
    lines.append("")


def _email_assessment_lines(findings: list[Finding]) -> list[str]:
    domain_profile = next((item for item in findings if item.source == "email-domain"), None)
    gravatar_profile = next((item for item in findings if item.source == "gravatar"), None)
    holehe_findings = [item for item in findings if item.source == "holehe"]
    breach_findings = [item for item in findings if item.source == "haveibeenpwned"]

    found_accounts = [item for item in holehe_findings if item.status == "found"]
    rate_limited = [item for item in holehe_findings if item.status == "error"]
    if found_accounts:
        account_presence = f"`moderate` ({len(found_accounts)} positive account signal(s))"
    elif holehe_findings:
        account_presence = "`limited` (no positive account signals in this run)"
    else:
        account_presence = "`limited` (account-signal checks not run)"

    linkage_detail = "little public identity context"
    linkage_level = "weak"
    if gravatar_profile:
        payload = _raw_payload(gravatar_profile)
        if payload.get("profile_found"):
            display_name = payload.get("display_name") or "Unknown"
            linkage_level = "moderate"
            linkage_detail = f"Gravatar profile found ({display_name})"
        elif payload.get("avatar_found"):
            linkage_level = "limited"
            linkage_detail = "Gravatar avatar found without a full public profile"

    if domain_profile:
        payload = _raw_payload(domain_profile)
        if payload.get("is_common_provider"):
            linkage_detail += "; common provider domain lowers domain-specific value"
        else:
            linkage_detail += "; custom domain adds more contextual value"

    reliability_level = "moderate"
    reliability_detail = "signals are usable as review context"
    if rate_limited:
        reliability_level = "low-moderate"
        reliability_detail = f"{len(rate_limited)} Holehe rate limits/errors reduce confidence in negative results"
    elif holehe_findings:
        reliability_detail = "account-signal checks completed without heavy rate limiting"

    if breach_findings:
        linkage_detail += f"; {len(breach_findings)} HIBP breach hit(s) add historical exposure context"

    return [
        f"Account presence: {account_presence}",
        f"Identity linkage: `{linkage_level}` ({linkage_detail})",
        f"Reliability: `{reliability_level}` ({reliability_detail})",
    ]


def _render_email_report(
    run: RunRecord,
    findings: list[Finding],
    collector_summary: dict[str, int] | None = None,
    delta_summary: dict | None = None,
) -> str:
    lines = _base_report_header(run)
    _append_collector_summary(lines, collector_summary)
    _append_delta_section(lines, delta_summary)
    _append_signal_summary(lines, findings, run=run)
    domain_profile = next((item for item in findings if item.source == "email-domain"), None)
    gravatar_profile = next((item for item in findings if item.source == "gravatar"), None)
    holehe_findings = [item for item in findings if item.source == "holehe"]
    breach_findings = [item for item in findings if item.source == "haveibeenpwned"]

    lines.extend(["## Email Assessment", ""])
    for line in _email_assessment_lines(findings):
        lines.append(f"- {line}")

    lines.extend(["", "## Email Domain Summary", ""])
    if domain_profile:
        payload = _raw_payload(domain_profile)
        lines.extend(
            [
                f"- Domain: `{payload.get('domain') or 'Unknown'}`",
                f"- Common provider: `{payload.get('is_common_provider')}`",
                f"- MX records found: `{len(payload.get('mx_records') or [])}`",
                f"- SPF records found: `{len(payload.get('spf_records') or [])}`",
                f"- DMARC record found: `{'yes' if payload.get('dmarc_record') else 'no'}`",
            ]
        )
    else:
        lines.append("- No email domain profile found.")

    lines.extend(["", "## Email Address Signals", ""])
    if gravatar_profile:
        payload = _raw_payload(gravatar_profile)
        lines.extend(
            [
                "### Gravatar",
                f"- Profile found: `{payload.get('profile_found')}`",
                f"- Avatar found: `{payload.get('avatar_found')}`",
                f"- Profile URL: `{payload.get('url_user') or gravatar_profile.url}`",
                f"- Display name: `{payload.get('display_name') or 'Unknown'}`",
                f"- Preferred username: `{payload.get('preferred_username') or 'Unknown'}`",
            ]
        )
    else:
        lines.append("- No email-address collector result found.")

    lines.extend(["", "## Account Signals", ""])
    if holehe_findings:
        found_accounts = [item for item in holehe_findings if item.status == "found"]
        rate_limited = [item for item in holehe_findings if item.status == "error"]
        not_found = [item for item in holehe_findings if item.status == "not_found"]
        lines.append(f"- Services checked: `{len(holehe_findings)}`")
        lines.append(f"- Account signals found: `{len(found_accounts)}`")
        lines.append(f"- Rate limited/errors: `{len(rate_limited)}`")
        if found_accounts:
            lines.extend(["", "### Found"])
            for item in found_accounts:
                payload = _raw_payload(item)
                details = []
                if payload.get("email_recovery"):
                    details.append(f"recovery_email={payload['email_recovery']}")
                if payload.get("phone_number"):
                    details.append(f"phone={payload['phone_number']}")
                suffix = f" | {', '.join(details)}" if details else ""
                lines.append(f"- `{item.platform}`: {item.url or 'No URL'}{suffix}")
        if rate_limited:
            lines.extend(["", "### Rate Limited / Errors"])
            for item in rate_limited[:20]:
                lines.append(f"- `{item.platform}`")
        lines.append(f"- No-account signals: `{len(not_found)}`")
    else:
        lines.append("- Holehe not run. Use `--include-holehe` for optional account-signal checks.")

    lines.extend(["", "## Mail Records", ""])
    if domain_profile:
        payload = _raw_payload(domain_profile)
        mail_sections = {
            "MX": payload.get("mx_records") or [],
            "SPF": payload.get("spf_records") or [],
            "DMARC": [payload.get("dmarc_record")] if payload.get("dmarc_record") else [],
        }
        for label, values in mail_sections.items():
            lines.append(f"### {label}")
            if values:
                for value in values:
                    lines.append(f"- `{value}`")
            else:
                lines.append("- None")
            lines.append("")
        if lines[-1] == "":
            lines.pop()
    else:
        lines.append("- None")

    lines.extend(["", "## HIBP Breaches", ""])
    if breach_findings:
        lines.append(f"- Breaches found: `{len(breach_findings)}`")
        for item in breach_findings:
            payload = _raw_payload(item)
            data_classes = payload.get("data_classes") or "Unknown"
            breach_date = payload.get("breach_date") or "Unknown"
            domain = payload.get("domain") or "Unknown"
            lines.append(f"- `{item.platform}`: {item.url}")
            lines.append(f"  - Breach date: `{breach_date}`")
            lines.append(f"  - Domain: `{domain}`")
            lines.append(f"  - Data exposed: `{data_classes}`")
    else:
        lines.append("- None. HIBP is optional and requires a paid API key for real email searches.")

    lines.extend(
        [
            "",
            "## Analyst Notes",
            "",
            "- Email domain profiling is free and checks public DNS/mail configuration.",
            "- Gravatar checks are free and use the normalized email hash to look for public Gravatar profile/avatar signals.",
            "- Holehe checks are optional account signals and can be rate-limited or noisy.",
            "- HIBP breach presence is optional and requires a paid API key for real email searches.",
            "- Review exposed data classes before deciding what action matters.",
            "- Raw email-domain, Gravatar, Holehe, and HIBP data is stored for re-checking and debugging.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_domain_report(
    run: RunRecord,
    findings: list[Finding],
    collector_summary: dict[str, int] | None = None,
    delta_summary: dict | None = None,
) -> str:
    lines = _base_report_header(run)
    _append_collector_summary(lines, collector_summary)
    _append_delta_section(lines, delta_summary)
    _append_signal_summary(lines, findings, run=run)
    rdap_finding = next((item for item in findings if item.source == "rdap"), None)
    dns_finding = next((item for item in findings if item.source == "dns"), None)
    builtwith_finding = next((item for item in findings if item.source == "builtwith"), None)

    lines.extend(["## Registration Summary", ""])
    if rdap_finding is None:
        lines.append("- No RDAP record found.")
    else:
        payload = _raw_payload(rdap_finding)
        lines.extend(
            [
                f"- Domain: `{payload.get('domain') or run.input_value}`",
                f"- Registrar: `{payload.get('registrar') or 'Unknown'}`",
                f"- Created: `{payload.get('created') or 'Unknown'}`",
                f"- Updated: `{payload.get('updated') or 'Unknown'}`",
                f"- Expires: `{payload.get('expires') or 'Unknown'}`",
            ]
        )

        nameservers = payload.get("nameservers") or ""
        lines.extend(["", "## Nameservers", ""])
        if nameservers:
            for nameserver in [item.strip() for item in nameservers.split(",") if item.strip()]:
                lines.append(f"- `{nameserver}`")
        else:
            lines.append("- None")

    lines.extend(["", "## DNS Records", ""])
    if dns_finding is None:
        lines.append("- No DNS collector result found.")
    else:
        payload = _raw_payload(dns_finding)
        records = payload.get("records") or {}
        if not records:
            lines.append("- No DNS records found.")
        else:
            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                values = records.get(record_type) or []
                if not values:
                    continue
                lines.append(f"### {record_type}")
                for value in values:
                    lines.append(f"- `{value}`")
                lines.append("")
            if lines[-1] == "":
                lines.pop()

    lines.extend(["", "## Site Classification", ""])
    if builtwith_finding is None:
        lines.append("- BuiltWith not run.")
    else:
        payload = _raw_payload(builtwith_finding)
        classifications = payload.get("classifications") or []
        live_groups = payload.get("live_groups") or []
        lines.append(f"- Status: `{builtwith_finding.status}`")
        lines.append(f"- Live technology groups: `{len(live_groups)}`")
        if classifications:
            lines.append(f"- Classification: `{'; '.join(classifications)}`")
        else:
            lines.append("- Classification: `no strong classification`")
        if live_groups:
            lines.append(f"- Live groups: `{', '.join(live_groups[:8])}`")

    lines.extend(
        [
            "",
            "## Analyst Notes",
            "",
            "- Domain lookups use RDAP for WHOIS-style registration data.",
            "- DNS lookups collect common public records: `A`, `AAAA`, `MX`, `NS`, `TXT`, and `CNAME`.",
            "- BuiltWith free API is optional and is used here as domain classification/context, not a detailed technology inventory.",
            "- Registrant details may be privacy-protected or omitted.",
            "- Raw RDAP and DNS data is stored for re-checking and debugging.",
        ]
    )
    return "\n".join(lines) + "\n"


def _append_case_username_section(lines: list[str], run: RunRecord, findings: list[Finding]) -> None:
    username_findings = [item for item in findings if item.input_type == "username"]
    ranked_found = _case_ranked_username_found(run, findings)
    secondary_found = ranked_found[5:]
    visible_secondary_found = secondary_found[:8]

    lines.extend(["## Username Findings", ""])
    if not username_findings:
        lines.append("- No username input provided.")
    elif visible_secondary_found:
        lines.append("- Top leads are shown above. This section highlights the next tier of username findings.")
        lines.append("")
        for item in visible_secondary_found:
            lines.extend(review_summary_lines(item, run=run, findings=findings))
        hidden_count = max(0, len(secondary_found) - len(visible_secondary_found))
        if hidden_count:
            lines.append(f"- Additional lower-priority username findings summarized: `{hidden_count}`")
    elif ranked_found:
        lines.append("- Top leads already cover the found username results for this case.")
    else:
        lines.append("- No found username results.")


def _case_ranked_username_found(run: RunRecord, findings: list[Finding]) -> list[Finding]:
    username_found = [
        item
        for item in findings
        if item.input_type == "username" and item.status == "found"
    ]
    return sorted(
        username_found,
        key=lambda item: (review_score(item, run=run, findings=findings), _review_priority(item)),
        reverse=True,
    )


def _append_case_top_leads(lines: list[str], run: RunRecord, findings: list[Finding]) -> None:
    username_found = _case_ranked_username_found(run, findings)
    top_leads = username_found[:5]
    correlation_hints: list[str] = []

    username = _case_username_value(findings)
    email = _case_email_value(findings)
    email_local_part = _email_local_part(email)
    if username and email_local_part:
        if username.lower() == email_local_part.lower():
            correlation_hints.append("Email local-part matches the provided username.")
        elif username.lower() in email_local_part.lower() or email_local_part.lower() in username.lower():
            correlation_hints.append("Email local-part partially overlaps with the provided username.")

    holehe_found = [
        item
        for item in findings
        if item.input_type == "email" and item.source == "holehe" and item.status == "found"
    ]
    username_found_by_service = {
        _service_key(item.platform): item
        for item in username_found
    }
    for item in holehe_found[:5]:
        service_key = _service_key(str((_raw_payload(item).get("service") or item.platform)))
        matched = username_found_by_service.get(service_key)
        if matched:
            correlation_hints.append(
                f"{item.platform} lines up across email and username workflows."
            )

    gravatar_profile = next(
        (item for item in findings if item.input_type == "email" and item.source == "gravatar"),
        None,
    )
    if gravatar_profile and run.full_name:
        payload = _raw_payload(gravatar_profile)
        display_name = str(payload.get("display_name") or "")
        if display_name:
            overlap = sorted(_name_tokens(run.full_name) & _name_tokens(display_name))
            if overlap:
                correlation_hints.append(
                    f"Gravatar display name overlaps with full-name context: {', '.join(overlap)}."
                )

    lines.extend(["## Key Findings", "", "### Top Leads", ""])
    if not top_leads and not correlation_hints:
        lines.append("- None")
        lines.append("")
        return

    if top_leads:
        for item in top_leads:
            lines.extend(review_summary_lines(item, run=run, findings=findings))
    else:
        lines.append("- No scored username leads yet.")

    if correlation_hints:
        lines.extend(["", "### Cross-Signal Highlights"])
        for hint in correlation_hints[:5]:
            lines.append(f"- {hint}")
    lines.append("")


def _case_overall_assessment(findings: list[Finding]) -> list[str]:
    username_found = [item for item in findings if item.input_type == "username" and item.status == "found"]
    strong_username = [item for item in username_found if item.signal_strength == "high"]
    medium_username = [item for item in username_found if item.signal_strength == "medium"]
    multi_source = [item for item in username_found if reconciliation_label(item).endswith("sources found")]
    holehe_found = [
        item for item in findings
        if item.input_type == "email" and item.source == "holehe" and item.status == "found"
    ]
    username_services = {_service_key(item.platform) for item in username_found}
    aligned_services = [
        item for item in holehe_found
        if _service_key(str((_raw_payload(item).get("service") or item.platform))) in username_services
    ]

    if aligned_services and (strong_username or len(multi_source) >= 2 or len(medium_username) >= 2):
        correlation = "strong"
    elif strong_username or aligned_services or len(multi_source) >= 2 or len(medium_username) >= 2:
        correlation = "moderate"
    elif username_found or holehe_found:
        correlation = "limited"
    else:
        correlation = "weak"

    if strong_username and aligned_services:
        lead_quality = "strong"
    elif strong_username or len(medium_username) >= 2 or aligned_services:
        lead_quality = "moderate"
    elif username_found or holehe_found:
        lead_quality = "limited"
    else:
        lead_quality = "weak"

    summary = [
        f"- Cross-signal correlation: `{correlation}`",
        f"- Lead quality: `{lead_quality}`",
    ]

    if aligned_services:
        services = ", ".join(item.platform for item in aligned_services[:3])
        summary.append(f"- Strongest overlap right now: `{services}` align across email and username workflows.")
    elif strong_username:
        services = ", ".join(item.platform for item in strong_username[:3])
        summary.append(f"- Strongest visible public leads: `{services}`.")
    elif medium_username:
        services = ", ".join(item.platform for item in medium_username[:3])
        summary.append(f"- Current case is being carried mainly by medium-signal username results such as `{services}`.")
    else:
        summary.append("- This case currently has limited high-value public overlap and may need more context or another run.")

    return summary


def _append_case_email_section(lines: list[str], findings: list[Finding]) -> None:
    email_findings = [item for item in findings if item.input_type == "email"]
    domain_profile = next((item for item in email_findings if item.source == "email-domain"), None)
    gravatar_profile = next((item for item in email_findings if item.source == "gravatar"), None)
    holehe_findings = [item for item in email_findings if item.source == "holehe"]
    breach_findings = [item for item in email_findings if item.source == "haveibeenpwned"]
    username_services = {
        _service_key(item.platform)
        for item in findings
        if item.input_type == "username" and item.status == "found"
    }
    lines.extend(["", "## Email Findings", ""])
    if not email_findings:
        lines.append("- No email input provided.")
        return

    lines.extend(["### Assessment", ""])
    for line in _email_assessment_lines(email_findings):
        lines.append(f"- {line}")
    lines.append("")

    lines.extend(["### Summary", ""])
    if domain_profile:
        payload = _raw_payload(domain_profile)
        lines.extend(
            [
                f"- Domain: `{payload.get('domain') or 'Unknown'}`",
                f"- Common provider: `{payload.get('is_common_provider')}`",
                f"- MX records found: `{len(payload.get('mx_records') or [])}`",
                f"- SPF records found: `{len(payload.get('spf_records') or [])}`",
                f"- DMARC record found: `{'yes' if payload.get('dmarc_record') else 'no'}`",
            ]
        )
    else:
        lines.append("- No email domain profile found.")

    if gravatar_profile:
        payload = _raw_payload(gravatar_profile)
        lines.append(f"- Gravatar profile found: `{payload.get('profile_found')}`")
        if payload.get("display_name"):
            lines.append(f"- Gravatar display name: `{payload.get('display_name')}`")
        elif payload.get("avatar_found"):
            lines.append("- Gravatar avatar found without a public display name.")
    else:
        lines.append("- No Gravatar result found.")

    if breach_findings:
        lines.append(f"- HIBP breaches found: `{len(breach_findings)}`")
    else:
        lines.append("- HIBP breaches found: `0`")

    lines.append("")
    lines.extend(["### Account Signals", ""])
    if holehe_findings:
        found_accounts = [item for item in holehe_findings if item.status == "found"]
        rate_limited = [item for item in holehe_findings if item.status == "error"]
        aligned_accounts = [
            item for item in found_accounts
            if _service_key(str((_raw_payload(item).get("service") or item.platform))) in username_services
        ]
        unaligned_accounts = [
            item for item in found_accounts
            if item not in aligned_accounts
        ]
        lines.append(f"- Holehe services checked: `{len(holehe_findings)}`")
        lines.append(f"- Holehe account signals found: `{len(found_accounts)}`")
        lines.append(f"- Holehe rate limited/errors: `{len(rate_limited)}`")
        lines.append(f"- Cross-signal overlaps with username results: `{len(aligned_accounts)}`")
        if aligned_accounts:
            lines.append("- Strongest aligned services:")
            for item in aligned_accounts[:3]:
                lines.append(f"  - `{item.platform}`")
        if unaligned_accounts:
            lines.append(f"- Additional email-only account signals: `{len(unaligned_accounts)}`")
            for item in unaligned_accounts[:3]:
                lines.append(f"  - `{item.platform}`")
        remaining_found = max(0, len(found_accounts) - min(len(aligned_accounts), 3) - min(len(unaligned_accounts), 3))
        if remaining_found:
            lines.append(f"- Additional account-signal hits summarized: `{remaining_found}`")
    else:
        lines.append("- Holehe not run.")
    if breach_findings:
        lines.extend(["", "### Breaches"])
        for item in breach_findings[:3]:
            payload = _raw_payload(item)
            breach_date = payload.get("breach_date") or "Unknown"
            data_classes = payload.get("data_classes") or "Unknown"
            lines.append(f"- `{item.platform}`: breach date `{breach_date}`, data exposed `{data_classes}`")
        if len(breach_findings) > 3:
            lines.append(f"- Additional breach hits summarized: `{len(breach_findings) - 3}`")


def _append_case_domain_section(lines: list[str], findings: list[Finding]) -> None:
    domain_findings = [item for item in findings if item.input_type == "domain"]
    rdap_finding = next((item for item in domain_findings if item.source == "rdap"), None)
    dns_finding = next((item for item in domain_findings if item.source == "dns"), None)
    builtwith_finding = next((item for item in domain_findings if item.source == "builtwith"), None)

    lines.extend(["", "## Domain Findings", ""])
    if not domain_findings:
        lines.append("- No domain input provided.")
        return

    if rdap_finding:
        payload = _raw_payload(rdap_finding)
        lines.extend(
            [
                "### Registration",
                f"- Domain: `{payload.get('domain') or rdap_finding.input_value}`",
                f"- Registrar: `{payload.get('registrar') or 'Unknown'}`",
                f"- Created: `{payload.get('created') or 'Unknown'}`",
                f"- Updated: `{payload.get('updated') or 'Unknown'}`",
                f"- Expires: `{payload.get('expires') or 'Unknown'}`",
            ]
        )
    else:
        lines.append("- No RDAP record found.")

    if dns_finding:
        payload = _raw_payload(dns_finding)
        records = payload.get("records") or {}
        lines.extend(["", "### DNS"])
        if records:
            for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
                values = records.get(record_type) or []
                if not values:
                    continue
                lines.append(f"- {record_type}: " + ", ".join(f"`{value}`" for value in values))
        else:
            lines.append("- No DNS records found.")
    else:
        lines.append("- No DNS collector result found.")

    lines.extend(["", "### BuiltWith Classification"])
    if builtwith_finding is None:
        lines.append("- BuiltWith not run.")
    else:
        payload = _raw_payload(builtwith_finding)
        classifications = payload.get("classifications") or []
        live_groups = payload.get("live_groups") or []
        if classifications:
            lines.append(f"- Classification: `{'; '.join(classifications)}`")
        else:
            lines.append("- Classification: `no strong classification`")
        lines.append(f"- Live technology groups: `{len(live_groups)}`")
        if live_groups:
            lines.append(f"- Live groups: `{', '.join(live_groups[:8])}`")


SERVICE_USERNAME_TARGETS = {
    "github": ["https://github.com/{username}"],
    "instagram": ["https://www.instagram.com/{username}/"],
    "spotify": ["https://open.spotify.com/user/{username}"],
    "twitter": ["https://twitter.com/{username}", "https://x.com/{username}"],
    "x": ["https://x.com/{username}", "https://twitter.com/{username}"],
}


SERVICE_SEARCH_SITES = {
    "github": "github.com",
    "instagram": "instagram.com",
    "spotify": "open.spotify.com/user",
    "twitter": "twitter.com",
    "x": "x.com",
}


def _service_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _case_username_value(findings: list[Finding]) -> str | None:
    username_finding = next((item for item in findings if item.input_type == "username"), None)
    return username_finding.input_value if username_finding else None


def _case_email_value(findings: list[Finding]) -> str | None:
    email_finding = next((item for item in findings if item.input_type == "email"), None)
    return email_finding.input_value if email_finding else None


def _append_case_cross_signal_section(lines: list[str], run: RunRecord, findings: list[Finding]) -> None:
    username = _case_username_value(findings)
    email = _case_email_value(findings)
    email_local_part = email.split("@", 1)[0] if email and "@" in email else None
    username_findings = [item for item in findings if item.input_type == "username"]
    username_found_by_service = {
        _service_key(item.platform): item
        for item in username_findings
        if item.status == "found"
    }
    holehe_found = [
        item
        for item in findings
        if item.input_type == "email" and item.source == "holehe" and item.status == "found"
    ]
    gravatar_profile = next(
        (item for item in findings if item.input_type == "email" and item.source == "gravatar"),
        None,
    )

    lines.extend(["", "## Cross-Signal Correlation", ""])
    if not any([username, email, holehe_found, gravatar_profile]):
        lines.append("- Not enough case inputs to compare signals.")
        return

    if username and email_local_part:
        if username.lower() == email_local_part.lower():
            lines.append("- Email local-part matches the provided username.")
        elif username.lower() in email_local_part.lower() or email_local_part.lower() in username.lower():
            lines.append("- Email local-part partially overlaps with the provided username.")
        else:
            lines.append("- Email local-part does not directly match the provided username.")

    if gravatar_profile and run.full_name:
        payload = _raw_payload(gravatar_profile)
        display_name = str(payload.get("display_name") or "")
        if display_name:
            full_name_tokens = _name_tokens(run.full_name)
            display_tokens = _name_tokens(display_name)
            overlap = sorted(full_name_tokens & display_tokens)
            if overlap:
                lines.append(f"- Gravatar display name overlaps with full-name context: {', '.join(overlap)}.")
            else:
                lines.append("- Gravatar display name does not overlap with the full-name context.")

    if not holehe_found:
        lines.append("- No Holehe account-signal hits to correlate. Use `--include-holehe` to collect them.")
        return

    for item in sorted(holehe_found, key=lambda finding: finding.platform.lower())[:20]:
        payload = _raw_payload(item)
        service = str(payload.get("service") or item.platform).lower()
        service_key = _service_key(service)
        matched_username_finding = username_found_by_service.get(service_key)
        if matched_username_finding:
            lines.append(
                f"- `{item.platform}`: Holehe found an email account signal and username workflow found `{matched_username_finding.platform}` for the provided username."
            )
        else:
            lines.append(
                f"- `{item.platform}`: Holehe found an email account signal, but username workflow did not find a matching public username result."
            )

        if username:
            for target_template in SERVICE_USERNAME_TARGETS.get(service_key, []):
                lines.append(f"  - Public username review target: `{target_template.format(username=username)}`")
        if run.full_name:
            search_site = SERVICE_SEARCH_SITES.get(service_key)
            if search_site:
                lines.append(f"  - Manual public search query: `\"{run.full_name}\" \"{username or ''}\" site:{search_site}`")


def _render_case_report(
    run: RunRecord,
    findings: list[Finding],
    audit_warnings: list[str] | None = None,
    collector_summary: dict[str, int] | None = None,
    delta_summary: dict | None = None,
) -> str:
    lines = _base_report_header(run)
    _append_collector_summary(lines, collector_summary)
    _append_delta_section(lines, delta_summary)

    counts_by_type = {
        "username": len([item for item in findings if item.input_type == "username"]),
        "email": len([item for item in findings if item.input_type == "email"]),
        "domain": len([item for item in findings if item.input_type == "domain"]),
    }
    username_found = [
        item for item in findings
        if item.input_type == "username" and item.status == "found"
    ]
    signal_summary = {
        "high": len([item for item in username_found if item.signal_strength == "high"]),
        "medium": len([item for item in username_found if item.signal_strength == "medium"]),
        "low": len([item for item in username_found if item.signal_strength == "low"]),
    }
    lines.extend(
        [
            "## Case Summary",
            "",
            f"- Username findings: `{counts_by_type['username']}`",
            f"- Email findings: `{counts_by_type['email']}`",
            f"- Domain findings: `{counts_by_type['domain']}`",
            f"- High-signal username leads: `{signal_summary['high']}`",
            f"- Medium-signal username leads: `{signal_summary['medium']}`",
            f"- Low-signal/noisy username results: `{signal_summary['low']}`",
            "",
        ]
    )

    lines.extend(["## Overall Assessment", ""])
    lines.extend(_case_overall_assessment(findings))
    lines.append("")
    _append_case_top_leads(lines, run, findings)
    _append_case_username_section(lines, run, findings)
    _append_case_email_section(lines, findings)
    _append_case_domain_section(lines, findings)
    _append_case_cross_signal_section(lines, run, findings)

    lines.extend(["", "## Audit Warnings", ""])
    if audit_warnings:
        for warning in audit_warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Analyst Notes",
            "",
            "- This case report combines public-signal workflow results for review.",
            "- Source counts and signal strengths are review aids, not identity proof.",
            "- Raw collector data is stored in the SQLite database for re-checking and debugging.",
        ]
    )
    return "\n".join(lines) + "\n"


def _confidence_hints(run: RunRecord, findings: list[Finding]) -> list[str]:
    found = [item for item in findings if item.status == "found"]
    if not found:
        return []

    hints: list[str] = []
    strong_found = [item for item in found if item.signal_strength == "high"]
    medium_found = [item for item in found if item.signal_strength == "medium"]
    multi_source_found = [item for item in found if reconciliation_label(item).endswith("sources found")]

    if len(multi_source_found) >= 2:
        platforms = ", ".join(item.platform for item in multi_source_found[:4])
        hints.append(f"Multiple platforms were found by more than one source: {platforms}.")
    elif len(strong_found) >= 2:
        platforms = ", ".join(item.platform for item in strong_found[:4])
        hints.append(f"Multiple high-signal accounts were found: {platforms}. Review these first together.")
    elif strong_found and medium_found:
        hints.append(
            f"{strong_found[0].platform} lines up with {len(medium_found)} medium-signal finding(s), which makes the username pattern more worth reviewing."
        )

    if run.full_name:
        tokens = _name_tokens(run.full_name)
        matched = [
            item.platform
            for item in found
            if item.signal_strength in {"high", "medium"}
            and any(token in item.url.lower() for token in tokens)
        ]
        if matched:
            unique_matches = ", ".join(dict.fromkeys(matched))
            hints.append(f"Full-name tokens overlap with review-worthy URLs on: {unique_matches}.")

    linkedin = next((item for item in findings if item.platform == "LinkedIn"), None)
    github = next((item for item in findings if item.platform == "GitHub"), None)
    reddit = next((item for item in findings if item.platform == "Reddit"), None)
    if linkedin and linkedin.status != "found":
        supporting = [item.platform for item in (github, reddit) if item and item.status == "found"]
        if supporting:
            hints.append(
                f"LinkedIn needs manual review, but {', '.join(supporting)} already produced found results for the same username."
            )

    return hints


def _correlation_hints(run: RunRecord, findings: list[Finding]) -> list[str]:
    if not run.full_name:
        return []

    hints: list[str] = []
    tokens = _name_tokens(run.full_name)
    found = [item for item in findings if item.status == "found"]

    for item in found:
        if item.signal_strength not in {"high", "medium"}:
            continue
        token_matches = [token for token in tokens if token in item.url.lower()]
        if token_matches:
            hints.append(
                f"{item.platform} is a {item.signal_strength} signal and its URL contains name token(s): {', '.join(sorted(token_matches))}."
            )
        else:
            hints.append(
                f"Review {item.platform} as a {item.signal_strength} signal against the full-name context `{run.full_name}`."
            )

    linkedin = next((item for item in findings if item.platform == "LinkedIn"), None)
    if linkedin is not None:
        if linkedin.status == "found":
            hints.append("LinkedIn returned a found result. Compare profile naming and public details against the provided full name.")
        elif linkedin.status == "not_found":
            hints.append("LinkedIn username-path checking did not confirm a match. This does not rule out a real LinkedIn profile with a different slug.")
        elif linkedin.status == "error":
            hints.append("LinkedIn returned an error result, so treat this run as incomplete for LinkedIn review.")

        for target in _linkedin_manual_review_targets(run):
            hints.append(f"Suggested LinkedIn review target: `{target}`")
        for query in _linkedin_search_queries(run):
            hints.append(f"Suggested LinkedIn manual review query: `{query}`")

    return hints


def render_markdown_report(
    run: RunRecord,
    findings: list[Finding],
    audit_warnings: list[str] | None = None,
    collector_summary: dict[str, int] | None = None,
    delta_summary: dict | None = None,
) -> str:
    if run.input_type == "email":
        return _render_email_report(run, findings, collector_summary=collector_summary, delta_summary=delta_summary)
    if run.input_type == "domain":
        return _render_domain_report(run, findings, collector_summary=collector_summary, delta_summary=delta_summary)
    if run.input_type == "case":
        return _render_case_report(
            run,
            findings,
            audit_warnings=audit_warnings,
            collector_summary=collector_summary,
            delta_summary=delta_summary,
        )

    # The report keeps review simple by splitting findings into clear buckets.
    confidence_hints = _confidence_hints(run, findings)
    correlation_hints = _correlation_hints(run, findings)
    found = [item for item in findings if item.status == "found"]
    not_found = [item for item in findings if item.status == "not_found"]
    errors = [item for item in findings if item.status == "error"]
    strong_found = [item for item in found if item.signal_strength == "high"]
    medium_found = [item for item in found if item.signal_strength == "medium"]
    weak_found = [item for item in found if item.signal_strength == "low"]
    top_review_limit = get_report_setting("top_review_limit", 12)
    top_review_min_score = get_report_setting("top_review_min_score", 5)
    should_filter_medium = run.input_type == "username"

    lines = _base_report_header(run)
    _append_collector_summary(lines, collector_summary)
    _append_delta_section(lines, delta_summary)
    _append_signal_summary(lines, findings, run=run)

    lines.extend(
        [
        "## Likely Worth Reviewing First",
        "",
        ]
    )

    priority_review_candidates = sorted(
        strong_found + medium_found,
        key=lambda item: (review_score(item, run=run, findings=findings), _review_priority(item)),
        reverse=True,
    )
    priority_review = [
        item for item in priority_review_candidates if review_score(item, run=run, findings=findings) >= top_review_min_score
    ][:top_review_limit]
    if priority_review:
        for item in priority_review:
            lines.extend(review_summary_lines(item, run=run, findings=findings))
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
        "## Found Accounts",
        "",
        "### Strong Signals",
        ]
    )

    if strong_found:
        for item in strong_found:
            lines.extend(review_summary_lines(item, run=run, findings=findings))
    else:
        lines.append("- None")

    lines.extend(["", "### Medium Signals", ""])
    if medium_found:
        visible_medium = [
            item for item in medium_found
            if not should_filter_medium or review_score(item, run=run, findings=findings) >= top_review_min_score
        ]
        if visible_medium:
            for item in visible_medium:
                lines.extend(review_summary_lines(item, run=run, findings=findings))
        else:
            lines.append("- None")
        hidden_medium_count = len(medium_found) - len(visible_medium)
        if should_filter_medium and hidden_medium_count:
            lines.append(f"- Hidden lower-priority medium-signal hits: `{hidden_medium_count}`")
    else:
        lines.append("- None")

    lines.extend(["", "## Not Found", ""])
    if not_found:
        for item in not_found:
            lines.append(f"- `{item.platform}` ({reconciliation_label(item)}): {source_summary(item)}")
    else:
        lines.append("- None")

    lines.extend(["", "## Errors", ""])
    if errors:
        for item in errors:
            lines.append(f"- `{item.platform}` ({reconciliation_label(item)}): {source_summary(item)}")
    else:
        lines.append("- None")

    lines.extend(["", "## Audit Warnings", ""])
    if audit_warnings:
        for warning in audit_warnings:
            lines.append(f"- {warning}")
    else:
        lines.append("- None")

    lines.extend(["", "## Confidence Hints", ""])
    if confidence_hints:
        for hint in confidence_hints:
            lines.append(f"- {hint}")
    else:
        lines.append("- None")

    lines.extend(["", "## Correlation Hints", ""])
    if correlation_hints:
        for hint in correlation_hints:
            lines.append(f"- {hint}")
    else:
        lines.append("- None")

    lines.extend(["", "## Low Signal Accounts", ""])
    if weak_found:
        for item in weak_found:
            lines.extend(review_summary_lines(item, run=run, findings=findings))
    else:
        lines.append("- None")

    lines.extend(
        [
            "",
            "## Analyst Notes",
            "",
            "- Confidence values are: `low`, `medium`, `high`, or unset.",
            "- Signal strength is a review hint, not proof of identity.",
            "- Lead scores are weighted review priorities, not identity scores.",
            "- Raw collector data is stored for re-checking and debugging.",
            "- Review linked accounts before drawing conclusions.",
        ]
    )
    return "\n".join(lines) + "\n"


def write_markdown_report(
    reports_dir: Path,
    run: RunRecord,
    findings: list[Finding],
    audit_warnings: list[str] | None = None,
    collector_summary: dict[str, int] | None = None,
    delta_summary: dict | None = None,
) -> Path:
    report_dir = get_report_output_dir(reports_dir, run)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / _report_filename(run)
    report_path.write_text(
        render_markdown_report(
            run,
            findings,
            audit_warnings=audit_warnings,
            collector_summary=collector_summary,
            delta_summary=delta_summary,
        ),
        encoding="utf-8",
    )
    return report_path
