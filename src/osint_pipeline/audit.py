from __future__ import annotations

from osint_pipeline.site_profiles import get_priority_sites


def find_missing_priority_rows(rows: list[dict[str, str]]) -> list[str]:
    present_sites = {row["name"] for row in rows}
    return [
        f"Priority site returned no result row: {site}"
        for site in get_priority_sites()
        if site not in present_sites
    ]
