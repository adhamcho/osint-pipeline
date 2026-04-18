from __future__ import annotations

import hashlib
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from types import SimpleNamespace

import requests
from sherlock_project.notify import QueryNotify
from sherlock_project.sherlock import sherlock
from sherlock_project.sites import SitesInformation


WMN_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "wmn-data.json"
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
COMMON_EMAIL_PROVIDERS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "ymail.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "tutanota.com",
    "tuta.com",
    "zoho.com",
    "gmx.com",
    "mail.com",
}
BUILTWITH_FREE_API_URL = "https://api.builtwith.com/free1/api.json"


class ProgressNotify(QueryNotify):
    def __init__(self, total_sites: int):
        super().__init__(result=None)
        self.total_sites = total_sites
        self.completed = 0

    def update(self, result) -> None:
        self.result = result
        self.completed += 1
        # Sherlock reports one result per site, so we can show real progress.
        print(
            f"\rChecked {self.completed}/{self.total_sites} sites...",
            end="",
            flush=True,
        )

    def finish(self, message=None):
        print("\r" + " " * 60 + "\r", end="", flush=True)


def _get_sherlock_resource_path() -> Path:
    import sherlock_project

    return Path(sherlock_project.__file__).resolve().parent / "resources" / "data.json"


def _load_site_data(sites: list[str] | None = None) -> dict[str, dict]:
    site_info = SitesInformation(
        str(_get_sherlock_resource_path()),
        honor_exclusions=False,
    )
    site_data_all = {site.name: site.information for site in site_info}

    if not sites:
        return site_data_all

    filtered: dict[str, dict] = {}
    for desired_site in sites:
        for existing_site, info in site_data_all.items():
            if desired_site.lower() == existing_site.lower():
                filtered[existing_site] = info
                break
    if not filtered:
        raise ValueError(f"No supported sites matched: {sites}")
    return filtered


def _results_to_rows(results: dict[str, dict], username: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for site_name in sorted(results):
        item = results[site_name]
        status = item["status"]
        response_time_s = status.query_time if status.query_time is not None else ""
        rows.append(
            {
                "username": username,
                "name": site_name,
                "url_main": item.get("url_main", ""),
                "url_user": item.get("url_user", ""),
                "exists": str(status.status),
                "http_status": str(item.get("http_status", "")),
                "response_time_s": str(response_time_s),
                "source": "sherlock",
            }
        )
    return rows


def run_sherlock(username: str, *, timeout: int = 60, sites: list[str] | None = None) -> list[dict[str, str]]:
    site_data = _load_site_data(sites)
    query_notify = ProgressNotify(total_sites=len(site_data))
    results = sherlock(
        username,
        site_data,
        query_notify,
        timeout=timeout,
    )
    query_notify.finish()
    return _results_to_rows(results, username)


def _load_whatsmyname_sites() -> list[dict]:
    payload = json.loads(WMN_DATA_PATH.read_text(encoding="utf-8"))
    return payload.get("sites", [])


def _check_whatsmyname_site(site: dict, username: str, timeout: int, session: requests.Session) -> dict[str, str]:
    formatted_url = site["uri_check"].replace("{account}", username)
    result = {
        "username": username,
        "name": site["name"],
        "url_main": site["uri_check"],
        "url_user": formatted_url,
        "exists": "Unknown",
        "http_status": "",
        "response_time_s": "",
        "source": "whatsmyname",
    }

    try:
        response = session.get(formatted_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        return result

    html = response.text
    result["http_status"] = str(response.status_code)

    expected_code = site.get("e_code")
    expected_string = site.get("e_string") or ""
    missing_code = site.get("m_code")
    missing_string = site.get("m_string") or ""

    if (
        expected_code == response.status_code
        and expected_string in html
        and missing_string not in html
    ):
        result["exists"] = "Claimed"
        return result

    if missing_code == response.status_code and missing_string in html:
        result["exists"] = "Available"
        return result

    return result


def run_whatsmyname(username: str, *, timeout: int = 30, max_workers: int = 32) -> list[dict[str, str]]:
    sites = _load_whatsmyname_sites()
    rows: list[dict[str, str]] = []
    completed = 0
    headers = {
        "User-Agent": "osint-pipeline/0.1 (+https://github.com)",
    }

    with requests.Session() as session:
        session.headers.update(headers)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(_check_whatsmyname_site, site, username, timeout, session)
                for site in sites
            ]
            total_sites = len(futures)
            for future in as_completed(futures):
                rows.append(future.result())
                completed += 1
                print(
                    f"\rWhatsMyName checked {completed}/{total_sites} sites...",
                    end="",
                    flush=True,
                )

    print("\r" + " " * 60 + "\r", end="", flush=True)
    return sorted(rows, key=lambda item: item["name"].lower())


def run_hibp_email_lookup(
    email: str,
    *,
    api_key: str,
    user_agent: str = "osint-pipeline",
    timeout: int = 30,
) -> list[dict[str, str]]:
    encoded_email = requests.utils.quote(email, safe="")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}"
    headers = {
        "hibp-api-key": api_key,
        "user-agent": user_agent,
    }
    params = {
        "truncateResponse": "false",
    }

    response = requests.get(url, headers=headers, params=params, timeout=timeout)
    if response.status_code == 404:
        return []
    response.raise_for_status()

    breaches = response.json()
    rows: list[dict[str, str]] = []
    for breach in breaches:
        rows.append(
            {
                "username": email,
                "name": breach.get("Name", ""),
                "url_main": breach.get("Domain", ""),
                "url_user": f"https://{breach.get('Domain', '')}" if breach.get("Domain") else "",
                "exists": "Breach",
                "http_status": str(response.status_code),
                "response_time_s": "",
                "source": "haveibeenpwned",
                "title": breach.get("Title", ""),
                "breach_date": breach.get("BreachDate", ""),
                "domain": breach.get("Domain", ""),
                "data_classes": ", ".join(breach.get("DataClasses", [])),
                "raw_breach": breach,
            }
        )
    return rows


def run_rdap_domain_lookup(domain: str, *, timeout: int = 30) -> list[dict[str, str]]:
    url = f"https://rdap.org/domain/{domain}"
    response = requests.get(url, timeout=timeout, headers={"user-agent": "osint-pipeline"})
    if response.status_code == 404:
        return []
    response.raise_for_status()

    payload = response.json()
    events = payload.get("events", [])
    nameservers = payload.get("nameservers", [])
    entities = payload.get("entities", [])

    def event_date(event_action: str) -> str:
        for event in events:
            if event.get("eventAction") == event_action:
                return str(event.get("eventDate", ""))
        return ""

    registrar = ""
    for entity in entities:
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if len(vcard) == 2:
                for item in vcard[1]:
                    if item[0] == "fn":
                        registrar = item[3]
                        break
        if registrar:
            break

    return [
        {
            "username": domain,
            "name": "WHOIS",
            "title": "WHOIS / RDAP",
            "url_main": domain,
            "url_user": f"https://{domain}",
            "exists": "RecordFound",
            "http_status": str(response.status_code),
            "response_time_s": "",
            "source": "rdap",
            "domain": payload.get("ldhName", domain),
            "registrar": registrar,
            "created": event_date("registration"),
            "updated": event_date("last changed"),
            "expires": event_date("expiration"),
            "nameservers": ", ".join(
                item.get("ldhName", "") for item in nameservers if item.get("ldhName")
            ),
            "raw_record": payload,
        }
    ]


def _builtwith_classifications(groups: list[dict]) -> tuple[list[str], list[str], list[str]]:
    live_groups = []
    live_categories = []
    for group in groups:
        if int(group.get("live", 0) or 0) <= 0:
            continue
        group_name = str(group.get("name") or "").strip().lower()
        if group_name:
            live_groups.append(group_name)
        for category in group.get("categories") or []:
            if int(category.get("live", 0) or 0) <= 0:
                continue
            category_name = str(category.get("name") or "").strip().lower()
            if category_name:
                live_categories.append(category_name)

    unique_groups = list(dict.fromkeys(live_groups))
    unique_categories = list(dict.fromkeys(live_categories))
    classifications: list[str] = []

    ecommerce_terms = {"shopping-cart", "ecommerce", "payment-acceptance", "payment-processors"}
    cms_terms = {"cms", "blog", "blogs", "blogging-platforms"}
    if any(term in unique_groups or term in unique_categories for term in ecommerce_terms):
        classifications.append("likely e-commerce stack")
    if any(term in unique_groups or term in unique_categories for term in cms_terms):
        classifications.append("likely CMS-backed site")
    if len(unique_groups) <= 2:
        classifications.append("low-tech footprint")
    elif len(unique_groups) >= 8:
        classifications.append("broad web stack")
    if "analytics" in unique_groups:
        classifications.append("analytics-heavy deployment")

    return list(dict.fromkeys(classifications)), unique_groups, unique_categories


def run_builtwith_domain_lookup(
    domain: str,
    *,
    api_key: str,
    timeout: int = 30,
) -> list[dict[str, str]]:
    response = requests.get(
        BUILTWITH_FREE_API_URL,
        params={"KEY": api_key, "LOOKUP": domain},
        timeout=timeout,
        headers={"user-agent": "osint-pipeline"},
    )
    response.raise_for_status()
    payload = response.json()

    errors = payload.get("Errors") or []
    if errors:
        message = str(errors[0].get("Message") or "BuiltWith error")
        return [
            {
                "username": domain,
                "name": "BuiltWith",
                "title": "BuiltWith Classification",
                "url_main": domain,
                "url_user": f"https://builtwith.com/{domain}",
                "exists": "BuiltWithError",
                "http_status": str(response.status_code),
                "response_time_s": "",
                "source": "builtwith",
                "domain": domain,
                "error": message,
                "raw_record": payload,
            }
        ]

    result = payload.get("Results") or [payload]
    record = result[0] if result else payload
    groups = record.get("groups") or []
    classifications, live_groups, live_categories = _builtwith_classifications(groups)
    exists = "BuiltWithClassified" if groups else "NoBuiltWithProfile"

    return [
        {
            "username": domain,
            "name": "BuiltWith",
            "title": "BuiltWith Classification",
            "url_main": domain,
            "url_user": f"https://builtwith.com/{domain}",
            "exists": exists,
            "http_status": str(response.status_code),
            "response_time_s": "",
            "source": "builtwith",
            "domain": record.get("domain", domain),
            "first_indexed": record.get("first", ""),
            "last_indexed": record.get("last", ""),
            "live_groups": live_groups,
            "live_categories": live_categories,
            "classifications": classifications,
            "raw_record": payload,
        }
    ]


def _clean_dns_answer_data(record_type: str, data: str) -> str:
    cleaned = data.strip()
    if record_type == "TXT":
        return cleaned.replace('" "', "")
    if record_type == "MX":
        parts = cleaned.split(maxsplit=1)
        if len(parts) == 2 and parts[1] == ".":
            return parts[0]
    return cleaned.rstrip(".").strip()


def run_dns_domain_lookup(domain: str, *, timeout: int = 30) -> list[dict[str, str]]:
    records: dict[str, list[str]] = {}
    raw_responses: dict[str, dict] = {}

    for record_type in DNS_RECORD_TYPES:
        response = requests.get(
            "https://dns.google/resolve",
            params={"name": domain, "type": record_type},
            timeout=timeout,
            headers={"user-agent": "osint-pipeline"},
        )
        response.raise_for_status()
        payload = response.json()
        raw_responses[record_type] = payload

        answers = payload.get("Answer", [])
        values = []
        for answer in answers:
            if not isinstance(answer, dict):
                continue
            data = answer.get("data")
            if data:
                values.append(_clean_dns_answer_data(record_type, str(data)))
        if values:
            records[record_type] = values

    exists = "DNSRecordsFound" if records else "NoDNSRecords"
    return [
        {
            "username": domain,
            "name": "DNS",
            "title": "DNS Records",
            "url_main": domain,
            "url_user": f"https://dns.google/resolve?name={domain}",
            "exists": exists,
            "http_status": "200",
            "response_time_s": "",
            "source": "dns",
            "domain": domain,
            "records": records,
            "raw_record": raw_responses,
        }
    ]


def run_email_domain_profile(email: str, *, timeout: int = 30) -> list[dict[str, str]]:
    _, domain = email.rsplit("@", 1)
    dns_rows = run_dns_domain_lookup(domain, timeout=timeout)
    dns_records = dns_rows[0].get("records", {}) if dns_rows else {}
    mx_records = dns_records.get("MX", []) if isinstance(dns_records, dict) else []
    txt_records = dns_records.get("TXT", []) if isinstance(dns_records, dict) else []
    spf_records = [record for record in txt_records if record.lower().startswith("v=spf1")]
    dmarc_rows = run_dns_domain_lookup(f"_dmarc.{domain}", timeout=timeout)
    dmarc_records = dmarc_rows[0].get("records", {}) if dmarc_rows else {}
    dmarc_txt = dmarc_records.get("TXT", []) if isinstance(dmarc_records, dict) else []
    dmarc_policy = next((record for record in dmarc_txt if record.lower().startswith("v=dmarc1")), "")

    exists = "EmailDomainProfiled" if dns_records or dmarc_txt else "EmailDomainNoRecords"
    return [
        {
            "username": email,
            "name": "Email Domain Profile",
            "title": "Email Domain Profile",
            "url_main": domain,
            "url_user": f"https://dns.google/resolve?name={domain}",
            "exists": exists,
            "http_status": "200",
            "response_time_s": "",
            "source": "email-domain",
            "email": email,
            "domain": domain,
            "is_common_provider": domain in COMMON_EMAIL_PROVIDERS,
            "mx_records": mx_records,
            "spf_records": spf_records,
            "dmarc_record": dmarc_policy,
            "dns_records": dns_records,
            "dmarc_dns_records": dmarc_records,
        }
    ]


def run_gravatar_email_lookup(email: str, *, timeout: int = 30) -> list[dict[str, str]]:
    email_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    profile_url = f"https://www.gravatar.com/{email_hash}.json"
    avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    result = {
        "username": email,
        "name": "Gravatar",
        "title": "Gravatar",
        "url_main": "https://www.gravatar.com",
        "url_user": f"https://www.gravatar.com/{email_hash}",
        "exists": "NoEmailProfile",
        "http_status": "",
        "response_time_s": "",
        "source": "gravatar",
        "email": email,
        "email_hash": email_hash,
        "profile_url": profile_url,
        "avatar_url": avatar_url,
        "profile_found": False,
        "avatar_found": False,
        "display_name": "",
        "preferred_username": "",
        "profile_data": {},
    }

    try:
        profile_response = requests.get(
            profile_url,
            timeout=timeout,
            headers={"user-agent": "osint-pipeline"},
        )
        result["http_status"] = str(profile_response.status_code)
        if profile_response.status_code == 200:
            profile_data = profile_response.json()
            entry = (profile_data.get("entry") or [{}])[0]
            result.update(
                {
                    "exists": "EmailProfileFound",
                    "profile_found": True,
                    "display_name": entry.get("displayName", ""),
                    "preferred_username": entry.get("preferredUsername", ""),
                    "profile_data": profile_data,
                }
            )
    except requests.RequestException:
        result["exists"] = "EmailProfileError"
    except (ValueError, IndexError, TypeError):
        result["exists"] = "EmailProfileError"

    try:
        avatar_response = requests.get(
            avatar_url,
            timeout=timeout,
            headers={"user-agent": "osint-pipeline"},
        )
        result["avatar_found"] = avatar_response.status_code == 200
        if result["avatar_found"] and result["exists"] == "NoEmailProfile":
            result["exists"] = "EmailProfileFound"
    except requests.RequestException:
        if result["exists"] == "NoEmailProfile":
            result["exists"] = "EmailProfileError"

    return [result]


def run_holehe_email_lookup(
    email: str,
    *,
    timeout: int = 30,
    no_password_recovery: bool = True,
) -> list[dict[str, str]]:
    try:
        import httpx
        import trio
        from holehe.core import get_functions, import_submodules, launch_module
    except ImportError as exc:
        raise RuntimeError(
            "Holehe is optional and is not installed. Install it with: "
            ".\\.venv\\Scripts\\python -m pip install holehe==1.61"
        ) from exc

    async def run_modules() -> list[dict]:
        modules = import_submodules("holehe.modules")
        args = SimpleNamespace(nopasswordrecovery=no_password_recovery)
        websites = get_functions(modules, args)
        out: list[dict] = []
        client = httpx.AsyncClient(timeout=timeout)
        try:
            async with trio.open_nursery() as nursery:
                for website in websites:
                    nursery.start_soon(launch_module, website, email, client, out)
        finally:
            await client.aclose()
        return sorted(out, key=lambda item: item.get("name", ""))

    results = trio.run(run_modules)
    rows: list[dict[str, str]] = []
    for item in results:
        if item.get("rateLimit"):
            exists = "HoleheRateLimited"
        elif item.get("exists") is True:
            exists = "HoleheAccountFound"
        else:
            exists = "HoleheNotFound"

        service_name = str(item.get("name") or item.get("domain") or "Unknown")
        domain = str(item.get("domain") or "")
        rows.append(
            {
                "username": email,
                "name": service_name,
                "title": f"Holehe / {service_name}",
                "url_main": domain,
                "url_user": f"https://{domain}" if domain else "",
                "exists": exists,
                "http_status": "",
                "response_time_s": "",
                "source": "holehe",
                "email": email,
                "service": service_name,
                "domain": domain,
                "rate_limit": bool(item.get("rateLimit")),
                "email_recovery": item.get("emailrecovery"),
                "phone_number": item.get("phoneNumber"),
                "others": item.get("others"),
                "raw_holehe": item,
            }
        )
    return rows
