from __future__ import annotations

import argparse
from datetime import datetime
import os
import sys
import uuid
from pathlib import Path

from dotenv import load_dotenv

from osint_pipeline.audit import find_missing_priority_rows
from osint_pipeline.collectors import (
    run_builtwith_domain_lookup,
    run_dns_domain_lookup,
    run_email_domain_profile,
    run_gravatar_email_lookup,
    run_hibp_email_lookup,
    run_holehe_email_lookup,
    run_rdap_domain_lookup,
    run_sherlock,
    run_whatsmyname,
)
from osint_pipeline.models import RunRecord, utc_now_iso
from osint_pipeline.processors import (
    map_sherlock_status,
    normalize_domain,
    normalize_email,
    normalize_finding,
    normalize_username,
)
from osint_pipeline.reports import (
    _confidence_hints,
    get_default_reports_dir,
    reconciliation_label,
    review_score,
    source_summary,
    write_markdown_report,
)
from osint_pipeline.site_profiles import get_disabled_sites, is_disabled_site
from osint_pipeline.storage import (
    ensure_database,
    get_default_db_path,
    get_latest_run,
    get_previous_run_for,
    insert_findings,
    insert_run,
    list_runs,
    load_run_details,
)


BASE_DIR = Path(__file__).resolve().parents[2]
STATUS_RANK = {"found": 3, "not_found": 2, "error": 1}
HIBP_TEST_DOMAIN = "hibp-integration-tests.com"
HIBP_TEST_KEY = "00000000000000000000000000000000"

load_dotenv(BASE_DIR / ".env")


def _merge_collector_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    merged: dict[str, dict[str, str]] = {}

    for row in rows:
        source = row.get("source", "sherlock")
        platform_key = row["name"].strip().lower()
        current = merged.get(platform_key)
        candidate_status = map_sherlock_status(row["exists"])

        if current is None:
            merged[platform_key] = {
                **row,
                "source": source,
                "collector_sources": [source],
                "collector_rows": [{**row, "source": source}],
            }
            continue

        current_status = map_sherlock_status(current["exists"])
        should_replace = STATUS_RANK[candidate_status] > STATUS_RANK[current_status]
        if STATUS_RANK[candidate_status] == STATUS_RANK[current_status]:
            should_replace = current["source"] != "sherlock" and row["source"] == "sherlock"

        current["collector_sources"] = list(dict.fromkeys(current["collector_sources"] + [source]))
        current["collector_rows"] = current["collector_rows"] + [{**row, "source": source}]

        if should_replace:
            current.update(
                {
                    "username": row["username"],
                    "name": row["name"],
                    "url_main": row["url_main"],
                    "url_user": row["url_user"],
                    "exists": row["exists"],
                    "http_status": row["http_status"],
                    "response_time_s": row["response_time_s"],
                    "source": source,
                }
            )

    final_rows = []
    for row in merged.values():
        row["source"] = "+".join(row["collector_sources"])
        final_rows.append(row)
    return sorted(final_rows, key=lambda item: item["name"].lower())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osint-pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run a collection workflow.")
    run_subparsers = run_parser.add_subparsers(dest="input_type", required=True)

    username_parser = run_subparsers.add_parser("username", help="Run username correlation workflow.")
    username_parser.add_argument("value", help="Username to search for.")
    username_parser.add_argument("--full-name", dest="full_name", default=None, help="Optional analyst context for the person's full name.")
    username_parser.add_argument("--db", dest="db_path", type=Path, default=None, help="SQLite database path.")
    username_parser.add_argument(
        "--reports-dir",
        dest="reports_dir",
        type=Path,
        default=None,
        help="Directory for Markdown reports.",
    )
    username_parser.add_argument("--no-report", action="store_true", help="Skip Markdown report generation.")
    username_parser.add_argument("--timeout", type=int, default=60, help="Sherlock request timeout in seconds.")

    email_parser = run_subparsers.add_parser("email", help="Run free email domain workflow.")
    email_parser.add_argument("value", help="Email address to search for.")
    email_parser.add_argument("--db", dest="db_path", type=Path, default=None, help="SQLite database path.")
    email_parser.add_argument(
        "--reports-dir",
        dest="reports_dir",
        type=Path,
        default=None,
        help="Directory for Markdown reports.",
    )
    email_parser.add_argument("--no-report", action="store_true", help="Skip Markdown report generation.")
    email_parser.add_argument("--include-holehe", action="store_true", help="Also run optional Holehe account-signal checks.")
    email_parser.add_argument("--include-hibp", action="store_true", help="Also run paid HIBP breach lookup.")
    email_parser.add_argument("--hibp-api-key", dest="hibp_api_key", default=None, help="HIBP API key.")
    email_parser.add_argument("--timeout", type=int, default=30, help="Email request timeout in seconds.")

    domain_parser = run_subparsers.add_parser("domain", help="Run domain registration and DNS workflow.")
    domain_parser.add_argument("value", help="Domain to search for.")
    domain_parser.add_argument("--db", dest="db_path", type=Path, default=None, help="SQLite database path.")
    domain_parser.add_argument(
        "--reports-dir",
        dest="reports_dir",
        type=Path,
        default=None,
        help="Directory for Markdown reports.",
    )
    domain_parser.add_argument("--no-report", action="store_true", help="Skip Markdown report generation.")
    domain_parser.add_argument("--include-builtwith", action="store_true", help="Also run optional BuiltWith free domain classification.")
    domain_parser.add_argument("--builtwith-api-key", dest="builtwith_api_key", default=None, help="BuiltWith API key.")
    domain_parser.add_argument("--timeout", type=int, default=30, help="Domain request timeout in seconds.")

    case_parser = subparsers.add_parser("case", help="Run a combined case workflow.")
    case_parser.add_argument("--username", default=None, help="Optional username to search for.")
    case_parser.add_argument("--full-name", dest="full_name", default=None, help="Optional full-name context.")
    case_parser.add_argument("--email", default=None, help="Optional email address to search for.")
    case_parser.add_argument("--domain", default=None, help="Optional domain to inspect.")
    case_parser.add_argument("--db", dest="db_path", type=Path, default=None, help="SQLite database path.")
    case_parser.add_argument(
        "--reports-dir",
        dest="reports_dir",
        type=Path,
        default=None,
        help="Directory for Markdown reports.",
    )
    case_parser.add_argument("--no-report", action="store_true", help="Skip Markdown report generation.")
    case_parser.add_argument("--include-holehe", action="store_true", help="Also run optional Holehe account-signal checks for email input.")
    case_parser.add_argument("--include-hibp", action="store_true", help="Also run paid HIBP breach lookup for email input.")
    case_parser.add_argument("--hibp-api-key", dest="hibp_api_key", default=None, help="HIBP API key.")
    case_parser.add_argument("--include-builtwith", action="store_true", help="Also run optional BuiltWith free domain classification for domain input.")
    case_parser.add_argument("--builtwith-api-key", dest="builtwith_api_key", default=None, help="BuiltWith API key.")
    case_parser.add_argument("--timeout", type=int, default=60, help="Collector request timeout in seconds.")

    list_parser = subparsers.add_parser("list", help="List recent runs.")
    list_parser.add_argument("--db", dest="db_path", type=Path, default=None, help="SQLite database path.")
    list_parser.add_argument("--limit", type=int, default=10, help="Number of recent runs to show.")

    reports_parser = subparsers.add_parser("reports", help="List recent Markdown reports.")
    reports_parser.add_argument(
        "--reports-dir",
        dest="reports_dir",
        type=Path,
        default=None,
        help="Directory containing Markdown reports.",
    )
    reports_parser.add_argument("--limit", type=int, default=10, help="Number of recent reports to show.")
    reports_parser.add_argument(
        "--oldest-first",
        action="store_true",
        help="List reports from oldest to newest instead of newest to oldest.",
    )

    show_parser = subparsers.add_parser("show", help="Show stored run details.")
    show_parser.add_argument("target", choices=["latest", "run"], help="Show the latest run or a specific run id.")
    show_parser.add_argument("run_id", nargs="?", help="Run id to inspect when using `show run`.")
    show_parser.add_argument("--db", dest="db_path", type=Path, default=None, help="SQLite database path.")

    rerun_parser = subparsers.add_parser("rerun", help="Repeat a previous run.")
    rerun_parser.add_argument("target", choices=["latest", "run"], help="Rerun the latest run or a specific run id.")
    rerun_parser.add_argument("run_id", nargs="?", help="Run id to repeat when using `rerun run`.")
    rerun_parser.add_argument("--db", dest="db_path", type=Path, default=None, help="SQLite database path.")
    return parser


def _prompt_required(prompt: str) -> str:
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Please enter a value.")


def _prompt_optional(prompt: str) -> str | None:
    value = input(prompt).strip()
    return value or None


def _prompt_yes_no(prompt: str, *, default: bool = False) -> bool:
    suffix = " [Y/n]: " if default else " [y/N]: "
    value = input(prompt + suffix).strip().lower()
    if not value:
        return default
    return value in {"y", "yes"}


def interactive_menu() -> int:
    print("OSINT Pipeline")
    print("")
    print("1. Username")
    print("2. Username + full name")
    print("3. Email")
    print("4. Case: username + full name + email")
    print("5. Domain")
    print("6. Show latest run")
    print("7. List recent runs")
    print("8. Repeat latest run")
    print("9. List recent reports")
    print("")

    choice = _prompt_required("Choose an option: ")

    if choice == "1":
        username = _prompt_required("Username: ")
        return main(["run", "username", username])
    if choice == "2":
        username = _prompt_required("Username: ")
        full_name = _prompt_required("Full name: ")
        return main(["run", "username", username, "--full-name", full_name])
    if choice == "3":
        email = _prompt_required("Email: ")
        return main(["run", "email", email])
    if choice == "4":
        username = _prompt_required("Username: ")
        full_name = _prompt_required("Full name: ")
        email = _prompt_required("Email: ")
        args = ["case", "--username", username, "--full-name", full_name, "--email", email]
        if _prompt_yes_no("Include Holehe account-signal checks?", default=False):
            args.append("--include-holehe")
        return main(args)
    if choice == "5":
        domain = _prompt_required("Domain: ")
        return main(["run", "domain", domain])
    if choice == "6":
        return main(["show", "latest"])
    if choice == "7":
        limit = _prompt_optional("How many runs? [10]: ") or "10"
        return main(["list", "--limit", limit])
    if choice == "8":
        return main(["rerun", "latest"])
    if choice == "9":
        limit = _prompt_optional("How many reports? [10]: ") or "10"
        return main(["reports", "--limit", limit])

    print(f"Unsupported option: {choice}")
    return 2


def run_username_workflow(args: argparse.Namespace) -> int:
    normalized_username = normalize_username(args.value)
    created_at_utc = utc_now_iso()
    run_id = f"username-{normalized_username}-{uuid.uuid4().hex[:8]}"
    sherlock_rows = run_sherlock(normalized_username, timeout=args.timeout)
    whatsmyname_rows = run_whatsmyname(normalized_username, timeout=args.timeout)
    rows = _merge_collector_rows(sherlock_rows + whatsmyname_rows)
    disabled_sites = get_disabled_sites()
    enabled_rows = [row for row in rows if not is_disabled_site(row["name"])]
    collector_summary = {
        "checked_sites": len(sherlock_rows) + len(whatsmyname_rows),
        "sherlock_sites": len(sherlock_rows),
        "whatsmyname_sites": len(whatsmyname_rows),
        "merged_sites": len(rows),
        "kept_findings": len(enabled_rows),
        "disabled_sites": len(rows) - len(enabled_rows),
    }
    audit_warnings = find_missing_priority_rows(enabled_rows)

    # Every collector result is converted into the same internal finding shape.
    findings = [
        normalize_finding(
            run_id=run_id,
            input_type="username",
            input_value=normalized_username,
            platform=row["name"],
            url=row["url_user"],
            username=row["username"],
            source=row["source"],
            checked_at_utc=created_at_utc,
            raw_status=row["exists"],
            raw_data=row,
        )
        for row in enabled_rows
    ]

    run = RunRecord(
        run_id=run_id,
        input_type="username",
        input_value=normalized_username,
        full_name=args.full_name.strip() if args.full_name else None,
        source="sherlock+whatsmyname",
        created_at_utc=created_at_utc,
        finding_count=len(findings),
    )

    db_path = args.db_path or get_default_db_path(BASE_DIR)
    # Store the run first, then attach all findings to that run id.
    ensure_database(db_path)
    insert_run(db_path, run)
    insert_findings(db_path, findings)
    delta_summary = _build_delta_summary(db_path, run, findings)

    report_path = None
    if not args.no_report:
        reports_dir = args.reports_dir or get_default_reports_dir(BASE_DIR)
        report_path = write_markdown_report(
            reports_dir,
            run,
            findings,
            audit_warnings=audit_warnings,
            collector_summary=collector_summary,
            delta_summary=delta_summary,
        )

    print(f"Run ID: {run_id}")
    print(f"Database: {db_path}")
    print(f"Sherlock checked: {collector_summary['sherlock_sites']} sites")
    print(f"WhatsMyName checked: {collector_summary['whatsmyname_sites']} sites")
    print(f"Merged platforms: {collector_summary['merged_sites']}")
    print(f"Stored findings: {len(findings)}")
    if disabled_sites:
        print(f"Disabled sites skipped: {collector_summary['disabled_sites']}")
    _print_delta_summary(db_path, run, findings)
    if audit_warnings:
        print("Audit warnings:")
        for warning in audit_warnings:
            print(f"- {warning}")
    if report_path is not None:
        print(f"Report: {report_path}")
    return 0


def _resolve_hibp_api_key(email: str, explicit_key: str | None) -> str:
    if explicit_key:
        return explicit_key.strip()

    env_key = os.getenv("HIBP_API_KEY")
    if env_key:
        return env_key.strip()

    if email.endswith(f"@{HIBP_TEST_DOMAIN}"):
        return HIBP_TEST_KEY

    raise SystemExit(
        "HIBP API key required. Set HIBP_API_KEY or pass --hibp-api-key. "
        "Official docs: https://haveibeenpwned.com/API/V3"
    )


def _resolve_builtwith_api_key(explicit_key: str | None) -> str:
    if explicit_key:
        return explicit_key.strip()

    env_key = os.getenv("BUILTWITH_API_KEY")
    if env_key:
        return env_key.strip()

    raise SystemExit(
        "BuiltWith API key required. Set BUILTWITH_API_KEY or pass --builtwith-api-key. "
        "Official docs: https://api.builtwith.com/free-api"
    )


def run_email_workflow(args: argparse.Namespace) -> int:
    normalized_email = normalize_email(args.value)
    created_at_utc = utc_now_iso()
    run_id = f"email-{normalized_email.split('@', 1)[0]}-{uuid.uuid4().hex[:8]}"
    rows = run_email_domain_profile(normalized_email, timeout=args.timeout)
    rows.extend(run_gravatar_email_lookup(normalized_email, timeout=args.timeout))
    if args.include_holehe:
        rows.extend(run_holehe_email_lookup(normalized_email, timeout=args.timeout))
    if args.include_hibp:
        hibp_api_key = _resolve_hibp_api_key(normalized_email, args.hibp_api_key)
        rows.extend(
            run_hibp_email_lookup(
                normalized_email,
                api_key=hibp_api_key,
                timeout=args.timeout,
            )
        )

    hibp_rows = [row for row in rows if row["source"] == "haveibeenpwned"]
    domain_rows = [row for row in rows if row["source"] == "email-domain"]
    gravatar_rows = [row for row in rows if row["source"] == "gravatar"]
    holehe_rows = [row for row in rows if row["source"] == "holehe"]
    collector_summary = {
        "email_domain_profiles": len(domain_rows),
        "gravatar_checks": len(gravatar_rows),
        "gravatar_profiles": len([row for row in gravatar_rows if row["exists"] == "EmailProfileFound"]),
        "holehe_checks": len(holehe_rows),
        "holehe_found": len([row for row in holehe_rows if row["exists"] == "HoleheAccountFound"]),
        "holehe_rate_limited": len([row for row in holehe_rows if row["exists"] == "HoleheRateLimited"]),
        "hibp_requests": 1 if args.include_hibp else 0,
        "hibp_breaches": len(hibp_rows),
        "kept_findings": len(rows),
    }

    findings = [
        normalize_finding(
            run_id=run_id,
            input_type="email",
            input_value=normalized_email,
            platform=row["title"] or row["name"],
            url=row["url_user"],
            username=normalized_email,
            source=row["source"],
            checked_at_utc=created_at_utc,
            raw_status=row["exists"],
            raw_data=row,
            signal_strength="medium",
        )
        for row in rows
    ]

    run = RunRecord(
        run_id=run_id,
        input_type="email",
        input_value=normalized_email,
        full_name=None,
        source="+".join(
            ["email-domain", "gravatar"]
            + (["holehe"] if args.include_holehe else [])
            + (["haveibeenpwned"] if args.include_hibp else [])
        ),
        created_at_utc=created_at_utc,
        finding_count=len(findings),
    )

    db_path = args.db_path or get_default_db_path(BASE_DIR)
    ensure_database(db_path)
    insert_run(db_path, run)
    insert_findings(db_path, findings)
    delta_summary = _build_delta_summary(db_path, run, findings)

    report_path = None
    if not args.no_report:
        reports_dir = args.reports_dir or get_default_reports_dir(BASE_DIR)
        report_path = write_markdown_report(
            reports_dir,
            run,
            findings,
            audit_warnings=None,
            collector_summary=collector_summary,
            delta_summary=delta_summary,
        )

    print(f"Run ID: {run_id}")
    print(f"Database: {db_path}")
    print(f"Email domain profiles: {len(domain_rows)}")
    print(f"Gravatar checks: {len(gravatar_rows)}")
    print(f"Gravatar profiles found: {collector_summary['gravatar_profiles']}")
    print(f"Holehe checks: {collector_summary['holehe_checks']}")
    print(f"Holehe accounts found: {collector_summary['holehe_found']}")
    print(f"Holehe rate limited: {collector_summary['holehe_rate_limited']}")
    print(f"HIBP requests: {collector_summary['hibp_requests']}")
    print(f"Breaches found: {len(hibp_rows)}")
    _print_delta_summary(db_path, run, findings)
    if report_path is not None:
        print(f"Report: {report_path}")
    return 0


def run_domain_workflow(args: argparse.Namespace) -> int:
    normalized_domain = normalize_domain(args.value)
    created_at_utc = utc_now_iso()
    run_id = f"domain-{normalized_domain.split('.', 1)[0]}-{uuid.uuid4().hex[:8]}"
    rdap_rows = run_rdap_domain_lookup(normalized_domain, timeout=args.timeout)
    dns_rows = run_dns_domain_lookup(normalized_domain, timeout=args.timeout)
    rows = rdap_rows + dns_rows
    if args.include_builtwith:
        builtwith_api_key = _resolve_builtwith_api_key(args.builtwith_api_key)
        rows.extend(run_builtwith_domain_lookup(normalized_domain, api_key=builtwith_api_key, timeout=args.timeout))
    dns_records = dns_rows[0].get("records", {}) if dns_rows else {}
    dns_record_types = len(dns_records) if isinstance(dns_records, dict) else 0
    dns_values = (
        sum(len(values) for values in dns_records.values())
        if isinstance(dns_records, dict)
        else 0
    )
    collector_summary = {
        "rdap_requests": 1,
        "dns_requests": 6,
        "domain_records": len(rdap_rows),
        "dns_record_types": dns_record_types,
        "dns_values": dns_values,
        "builtwith_requests": 1 if args.include_builtwith else 0,
        "builtwith_classifications": len([row for row in rows if row.get("source") == "builtwith" and row.get("exists") == "BuiltWithClassified"]),
        "kept_findings": len(rows),
    }

    findings = [
        normalize_finding(
            run_id=run_id,
            input_type="domain",
            input_value=normalized_domain,
            platform=row["title"] or row["name"],
            url=row["url_user"],
            username=normalized_domain,
            source=row["source"],
            checked_at_utc=created_at_utc,
            raw_status=row["exists"],
            raw_data=row,
            signal_strength="medium",
        )
        for row in rows
    ]

    run = RunRecord(
        run_id=run_id,
        input_type="domain",
        input_value=normalized_domain,
        full_name=None,
        source="+".join(["rdap", "dns"] + (["builtwith"] if args.include_builtwith else [])),
        created_at_utc=created_at_utc,
        finding_count=len(findings),
    )

    db_path = args.db_path or get_default_db_path(BASE_DIR)
    ensure_database(db_path)
    insert_run(db_path, run)
    insert_findings(db_path, findings)
    delta_summary = _build_delta_summary(db_path, run, findings)

    report_path = None
    if not args.no_report:
        reports_dir = args.reports_dir or get_default_reports_dir(BASE_DIR)
        report_path = write_markdown_report(
            reports_dir,
            run,
            findings,
            audit_warnings=None,
            collector_summary=collector_summary,
            delta_summary=delta_summary,
        )

    print(f"Run ID: {run_id}")
    print(f"Database: {db_path}")
    print("RDAP requests: 1")
    print("DNS requests: 6")
    print(f"DNS record types found: {dns_record_types}")
    print(f"DNS values found: {dns_values}")
    print(f"BuiltWith requests: {collector_summary['builtwith_requests']}")
    print(f"Records found: {len(findings)}")
    _print_delta_summary(db_path, run, findings)
    if report_path is not None:
        print(f"Report: {report_path}")
    return 0


def run_case_workflow(args: argparse.Namespace) -> int:
    if not any([args.username, args.email, args.domain]):
        raise SystemExit("case requires at least one of --username, --email, or --domain")

    created_at_utc = utc_now_iso()
    case_label = args.username or args.email or args.domain or "case"
    run_id = f"case-{case_label.split('@', 1)[0].split('.', 1)[0]}-{uuid.uuid4().hex[:8]}"
    findings = []
    audit_warnings: list[str] = []
    collector_summary: dict[str, int] = {
        "username_findings": 0,
        "email_findings": 0,
        "domain_findings": 0,
    }
    input_parts: list[str] = []
    source_parts: list[str] = []

    if args.username:
        normalized_username = normalize_username(args.username)
        input_parts.append(f"username={normalized_username}")
        source_parts.append("sherlock+whatsmyname")
        sherlock_rows = run_sherlock(normalized_username, timeout=args.timeout)
        whatsmyname_rows = run_whatsmyname(normalized_username, timeout=args.timeout)
        rows = _merge_collector_rows(sherlock_rows + whatsmyname_rows)
        enabled_rows = [row for row in rows if not is_disabled_site(row["name"])]
        audit_warnings.extend(find_missing_priority_rows(enabled_rows))
        collector_summary.update(
            {
                "sherlock_sites": len(sherlock_rows),
                "whatsmyname_sites": len(whatsmyname_rows),
                "merged_sites": len(rows),
                "disabled_sites": len(rows) - len(enabled_rows),
            }
        )
        username_findings = [
            normalize_finding(
                run_id=run_id,
                input_type="username",
                input_value=normalized_username,
                platform=row["name"],
                url=row["url_user"],
                username=row["username"],
                source=row["source"],
                checked_at_utc=created_at_utc,
                raw_status=row["exists"],
                raw_data=row,
            )
            for row in enabled_rows
        ]
        findings.extend(username_findings)
        collector_summary["username_findings"] = len(username_findings)

    if args.email:
        normalized_email = normalize_email(args.email)
        input_parts.append(f"email={normalized_email}")
        source_parts.append("email-domain")
        source_parts.append("gravatar")
        rows = run_email_domain_profile(normalized_email, timeout=args.timeout)
        rows.extend(run_gravatar_email_lookup(normalized_email, timeout=args.timeout))
        if args.include_holehe:
            source_parts.append("holehe")
            rows.extend(run_holehe_email_lookup(normalized_email, timeout=args.timeout))
        if args.include_hibp:
            source_parts.append("haveibeenpwned")
            hibp_api_key = _resolve_hibp_api_key(normalized_email, args.hibp_api_key)
            rows.extend(
                run_hibp_email_lookup(
                    normalized_email,
                    api_key=hibp_api_key,
                    timeout=args.timeout,
                )
            )
        hibp_rows = [row for row in rows if row["source"] == "haveibeenpwned"]
        domain_rows = [row for row in rows if row["source"] == "email-domain"]
        gravatar_rows = [row for row in rows if row["source"] == "gravatar"]
        holehe_rows = [row for row in rows if row["source"] == "holehe"]
        email_findings = [
            normalize_finding(
                run_id=run_id,
                input_type="email",
                input_value=normalized_email,
                platform=row["title"] or row["name"],
                url=row["url_user"],
                username=normalized_email,
                source=row["source"],
                checked_at_utc=created_at_utc,
                raw_status=row["exists"],
                raw_data=row,
                signal_strength="medium",
            )
            for row in rows
        ]
        findings.extend(email_findings)
        collector_summary["email_domain_profiles"] = len(domain_rows)
        collector_summary["gravatar_checks"] = len(gravatar_rows)
        collector_summary["gravatar_profiles"] = len([row for row in gravatar_rows if row["exists"] == "EmailProfileFound"])
        collector_summary["holehe_checks"] = len(holehe_rows)
        collector_summary["holehe_found"] = len([row for row in holehe_rows if row["exists"] == "HoleheAccountFound"])
        collector_summary["holehe_rate_limited"] = len([row for row in holehe_rows if row["exists"] == "HoleheRateLimited"])
        collector_summary["hibp_requests"] = 1 if args.include_hibp else 0
        collector_summary["hibp_breaches"] = len(hibp_rows)
        collector_summary["email_findings"] = len(email_findings)

    if args.domain:
        normalized_domain = normalize_domain(args.domain)
        input_parts.append(f"domain={normalized_domain}")
        source_parts.append("rdap+dns")
        rdap_rows = run_rdap_domain_lookup(normalized_domain, timeout=args.timeout)
        dns_rows = run_dns_domain_lookup(normalized_domain, timeout=args.timeout)
        rows = rdap_rows + dns_rows
        if args.include_builtwith:
            source_parts.append("builtwith")
            builtwith_api_key = _resolve_builtwith_api_key(args.builtwith_api_key)
            rows.extend(run_builtwith_domain_lookup(normalized_domain, api_key=builtwith_api_key, timeout=args.timeout))
        dns_records = dns_rows[0].get("records", {}) if dns_rows else {}
        dns_record_types = len(dns_records) if isinstance(dns_records, dict) else 0
        dns_values = (
            sum(len(values) for values in dns_records.values())
            if isinstance(dns_records, dict)
            else 0
        )
        domain_findings = [
            normalize_finding(
                run_id=run_id,
                input_type="domain",
                input_value=normalized_domain,
                platform=row["title"] or row["name"],
                url=row["url_user"],
                username=normalized_domain,
                source=row["source"],
                checked_at_utc=created_at_utc,
                raw_status=row["exists"],
                raw_data=row,
                signal_strength="medium",
            )
            for row in rows
        ]
        findings.extend(domain_findings)
        collector_summary.update(
            {
                "rdap_requests": 1,
                "dns_requests": 6,
                "dns_record_types": dns_record_types,
                "dns_values": dns_values,
                "builtwith_requests": 1 if args.include_builtwith else 0,
                "builtwith_classifications": len([row for row in rows if row.get("source") == "builtwith" and row.get("exists") == "BuiltWithClassified"]),
                "domain_findings": len(domain_findings),
            }
        )

    run = RunRecord(
        run_id=run_id,
        input_type="case",
        input_value="; ".join(input_parts),
        full_name=args.full_name.strip() if args.full_name else None,
        source="+".join(dict.fromkeys(source_parts)),
        created_at_utc=created_at_utc,
        finding_count=len(findings),
    )

    db_path = args.db_path or get_default_db_path(BASE_DIR)
    ensure_database(db_path)
    insert_run(db_path, run)
    insert_findings(db_path, findings)
    delta_summary = _build_delta_summary(db_path, run, findings)

    report_path = None
    if not args.no_report:
        reports_dir = args.reports_dir or get_default_reports_dir(BASE_DIR)
        report_path = write_markdown_report(
            reports_dir,
            run,
            findings,
            audit_warnings=audit_warnings,
            collector_summary=collector_summary,
            delta_summary=delta_summary,
        )

    print(f"Case Run ID: {run_id}")
    print(f"Database: {db_path}")
    print(f"Stored findings: {len(findings)}")
    print(f"Username findings: {collector_summary['username_findings']}")
    print(f"Email findings: {collector_summary['email_findings']}")
    print(f"Domain findings: {collector_summary['domain_findings']}")
    _print_delta_summary(db_path, run, findings)
    if audit_warnings:
        print("Audit warnings:")
        for warning in audit_warnings:
            print(f"- {warning}")
    if report_path is not None:
        print(f"Case report: {report_path}")
    return 0


def _local_time_label(timestamp_utc: str) -> str:
    local_dt = datetime.fromisoformat(timestamp_utc.replace("Z", "+00:00")).astimezone()
    return local_dt.strftime("%Y-%m-%d %H:%M:%S %Z")


def _finding_delta_key(item) -> tuple[str, str]:
    return (item.input_type, item.platform)


def _compute_delta_summary(current_findings, previous_findings):
    current_map = {_finding_delta_key(item): item for item in current_findings}
    previous_map = {_finding_delta_key(item): item for item in previous_findings}

    new_items = [
        current_map[key]
        for key in sorted(current_map.keys() - previous_map.keys())
    ]
    removed_items = [
        previous_map[key]
        for key in sorted(previous_map.keys() - current_map.keys())
    ]
    changed_items = []
    for key in sorted(current_map.keys() & previous_map.keys()):
        current = current_map[key]
        previous = previous_map[key]
        changes = []
        if current.status != previous.status:
            changes.append(f"status {previous.status} -> {current.status}")
        if current.signal_strength != previous.signal_strength:
            changes.append(f"signal {previous.signal_strength} -> {current.signal_strength}")
        if current.url != previous.url:
            changes.append("url changed")
        if current.source != previous.source:
            changes.append(f"source {previous.source} -> {current.source}")
        if changes:
            changed_items.append((current, changes))
    return {
        "new": new_items,
        "removed": removed_items,
        "changed": changed_items,
    }


def _build_delta_summary(db_path: Path, run: RunRecord, findings):
    previous_run = get_previous_run_for(db_path, run)
    if previous_run is None:
        return None

    _, previous_findings = load_run_details(db_path, previous_run.run_id)
    delta = _compute_delta_summary(findings, previous_findings)
    return {
        "previous_run_id": previous_run.run_id,
        "new": [
            {"platform": item.platform, "status": item.status}
            for item in delta["new"]
        ],
        "removed": [
            {"platform": item.platform, "status": item.status}
            for item in delta["removed"]
        ],
        "changed": [
            {"platform": item.platform, "changes": changes}
            for item, changes in delta["changed"]
        ],
    }


def _print_delta_summary(db_path: Path, run: RunRecord, findings) -> None:
    delta_summary = _build_delta_summary(db_path, run, findings)
    if delta_summary is None:
        print("Delta vs previous similar run: none")
        return
    print(
        "Delta vs previous similar run: "
        f"{delta_summary['previous_run_id']} | new={len(delta_summary['new'])}, "
        f"removed={len(delta_summary['removed'])}, changed={len(delta_summary['changed'])}"
    )
    for item in delta_summary["new"][:5]:
        print(f"- New: {item['platform']} [{item['status']}]")
    for item in delta_summary["removed"][:5]:
        print(f"- Removed: {item['platform']} [{item['status']}]")
    for item in delta_summary["changed"][:5]:
        print(f"- Changed: {item['platform']} ({'; '.join(item['changes'])})")


def list_runs_workflow(args: argparse.Namespace) -> int:
    db_path = args.db_path or get_default_db_path(BASE_DIR)
    ensure_database(db_path)
    runs = list_runs(db_path, limit=args.limit)
    if not runs:
        print("No runs found.")
        return 0

    for run in runs:
        print(
            f"{run.run_id} | {_local_time_label(run.created_at_utc)} | "
            f"{run.input_type}={run.input_value} | "
            f"full_name={run.full_name or 'None'} | findings={run.finding_count}"
        )
    return 0


def list_reports_workflow(args: argparse.Namespace) -> int:
    reports_dir = args.reports_dir or get_default_reports_dir(BASE_DIR)
    if not reports_dir.exists():
        print(f"No reports directory found: {reports_dir}")
        return 0

    report_files = sorted(
        reports_dir.rglob("*.md"),
        key=lambda path: path.stat().st_mtime,
        reverse=not args.oldest_first,
    )[: args.limit]
    if not report_files:
        print("No reports found.")
        return 0

    for report_path in report_files:
        modified = datetime.fromtimestamp(report_path.stat().st_mtime).astimezone()
        print(f"{modified.strftime('%Y-%m-%d %H:%M:%S %Z')} | {report_path.name} | {report_path}")
    return 0


def show_run_workflow(args: argparse.Namespace) -> int:
    db_path = args.db_path or get_default_db_path(BASE_DIR)
    ensure_database(db_path)

    if args.target == "latest":
        latest = get_latest_run(db_path)
        if latest is None:
            print("No runs found.")
            return 0
        run_id = latest.run_id
    else:
        if not args.run_id:
            raise SystemExit("show run requires a run id")
        run_id = args.run_id

    run, findings = load_run_details(db_path, run_id)
    if run is None:
        print(f"Run not found: {run_id}")
        return 1

    found_count = sum(1 for item in findings if item.status == "found")
    not_found_count = sum(1 for item in findings if item.status == "not_found")
    error_count = sum(1 for item in findings if item.status == "error")

    print(f"Run ID: {run.run_id}")
    print(f"Created: {_local_time_label(run.created_at_utc)}")
    print(f"Input: {run.input_type}={run.input_value}")
    print(f"Full Name Context: {run.full_name or 'None'}")
    print(f"Source: {run.source}")
    print(f"Stored results: {run.finding_count}")
    print(f"Found: {found_count}")
    print(f"Not Found: {not_found_count}")
    print(f"Errors: {error_count}")
    previous_run = get_previous_run_for(db_path, run)
    if previous_run is None:
        print("Delta vs previous similar run: none")
    else:
        _, previous_findings = load_run_details(db_path, previous_run.run_id)
        delta = _compute_delta_summary(findings, previous_findings)
        print(
            "Delta vs previous similar run: "
            f"{previous_run.run_id} | new={len(delta['new'])}, "
            f"removed={len(delta['removed'])}, changed={len(delta['changed'])}"
        )
    print("")
    confidence_hints = _confidence_hints(run, findings)
    print("Confidence hints:")
    if not confidence_hints:
        print("- None")
    else:
        for hint in confidence_hints[:5]:
            print(f"- {hint}")
    print("")
    print("Top found accounts:")

    found_items = sorted(
        [item for item in findings if item.status == "found"],
        key=lambda item: (
            review_score(item, run=run, findings=findings),
            item.signal_strength,
            item.platform.lower(),
        ),
        reverse=True,
    )[:15]
    if not found_items:
        print("- None")
    else:
        for item in found_items:
            print(
                f"- {item.platform} [{item.signal_strength}] ({reconciliation_label(item)}) "
                f"-> {item.url} | {source_summary(item)}"
            )
    return 0


def _parse_case_input_value(input_value: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for part in input_value.split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key and value:
            parsed[key.strip()] = value.strip()
    return parsed


def _rerun_args_for_run(run: RunRecord) -> list[str]:
    if run.input_type == "username":
        args = ["run", "username", run.input_value]
        if run.full_name:
            args.extend(["--full-name", run.full_name])
        return args

    if run.input_type == "email":
        args = ["run", "email", run.input_value]
        if "holehe" in run.source:
            args.append("--include-holehe")
        if "haveibeenpwned" in run.source:
            args.append("--include-hibp")
        return args

    if run.input_type == "domain":
        return ["run", "domain", run.input_value]

    if run.input_type == "case":
        values = _parse_case_input_value(run.input_value)
        args = ["case"]
        if values.get("username"):
            args.extend(["--username", values["username"]])
        if run.full_name:
            args.extend(["--full-name", run.full_name])
        if values.get("email"):
            args.extend(["--email", values["email"]])
        if values.get("domain"):
            args.extend(["--domain", values["domain"]])
        if "holehe" in run.source:
            args.append("--include-holehe")
        if "haveibeenpwned" in run.source:
            args.append("--include-hibp")
        return args

    raise SystemExit(f"Cannot rerun unsupported input type: {run.input_type}")


def rerun_workflow(args: argparse.Namespace) -> int:
    db_path = args.db_path or get_default_db_path(BASE_DIR)
    ensure_database(db_path)

    if args.target == "latest":
        run = get_latest_run(db_path)
        if run is None:
            print("No runs found.")
            return 0
    else:
        if not args.run_id:
            raise SystemExit("rerun run requires a run id")
        run, _ = load_run_details(db_path, args.run_id)
        if run is None:
            print(f"Run not found: {args.run_id}")
            return 1

    rerun_args = _rerun_args_for_run(run)
    if args.db_path is not None:
        rerun_args.extend(["--db", str(args.db_path)])

    print(f"Repeating run: {run.run_id}")
    print(f"Command: {' '.join(rerun_args)}")
    return main(rerun_args)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if argv == []:
        return interactive_menu()

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "run" and args.input_type == "username":
        return run_username_workflow(args)
    if args.command == "run" and args.input_type == "email":
        return run_email_workflow(args)
    if args.command == "run" and args.input_type == "domain":
        return run_domain_workflow(args)
    if args.command == "case":
        return run_case_workflow(args)
    if args.command == "list":
        return list_runs_workflow(args)
    if args.command == "reports":
        return list_reports_workflow(args)
    if args.command == "show":
        return show_run_workflow(args)
    if args.command == "rerun":
        return rerun_workflow(args)

    parser.error("unsupported command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
