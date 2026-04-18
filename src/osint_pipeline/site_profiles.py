from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SITE_SETTINGS_PATH = PROJECT_ROOT / "config" / "site_settings.json"

DEFAULT_SETTINGS = {
    "signal_strength": {
        "GitHub": "high",
        "GitLab": "high",
        "LinkedIn": "high",
        "Docker Hub": "medium",
        "Instagram": "medium",
        "Reddit": "medium",
        "TikTok": "medium",
        "Twitch": "medium",
        "Twitter": "medium",
        "YouTube": "medium",
    },
    "priority_sites": ["GitHub", "LinkedIn", "Reddit"],
    "collector_weights": {
        "sherlock": 2,
        "whatsmyname": 1,
    },
    "report_settings": {
        "top_review_limit": 12,
        "top_review_min_score": 5,
    },
    "disabled_sites": [],
}


@lru_cache(maxsize=1)
def load_site_settings() -> dict[str, object]:
    if not SITE_SETTINGS_PATH.exists():
        return DEFAULT_SETTINGS

    loaded = json.loads(SITE_SETTINGS_PATH.read_text(encoding="utf-8"))
    return {
        "signal_strength": loaded.get("signal_strength", DEFAULT_SETTINGS["signal_strength"]),
        "priority_sites": loaded.get("priority_sites", DEFAULT_SETTINGS["priority_sites"]),
        "collector_weights": loaded.get("collector_weights", DEFAULT_SETTINGS["collector_weights"]),
        "report_settings": loaded.get("report_settings", DEFAULT_SETTINGS["report_settings"]),
        "disabled_sites": loaded.get("disabled_sites", DEFAULT_SETTINGS["disabled_sites"]),
    }


def get_signal_strength(platform: str) -> str:
    settings = load_site_settings()
    signal_strength = settings["signal_strength"]
    return signal_strength.get(platform.strip(), "low")


def get_priority_sites() -> tuple[str, ...]:
    settings = load_site_settings()
    disabled = {site.lower() for site in get_disabled_sites()}
    return tuple(site for site in settings["priority_sites"] if site.lower() not in disabled)


def get_disabled_sites() -> tuple[str, ...]:
    settings = load_site_settings()
    return tuple(settings["disabled_sites"])


def is_disabled_site(platform: str) -> bool:
    disabled = {site.lower() for site in get_disabled_sites()}
    return platform.strip().lower() in disabled


def get_collector_weights() -> dict[str, int]:
    settings = load_site_settings()
    raw_weights = settings["collector_weights"]
    return {str(name): int(value) for name, value in raw_weights.items()}


def get_report_setting(name: str, default: int) -> int:
    settings = load_site_settings()
    report_settings = settings["report_settings"]
    return int(report_settings.get(name, default))
