from osint_pipeline.models import RunRecord
from osint_pipeline.processors import normalize_finding
from osint_pipeline.reports import render_markdown_report


def test_render_markdown_report_contains_sections():
    run = RunRecord(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        full_name="Test Value",
        source="sherlock",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=2,
    )
    findings = [
        normalize_finding(
            run_id="run-1",
            input_type="username",
            input_value="testvalue",
            platform="GitHub",
            url="https://github.com/testvalue",
            username="testvalue",
            source="sherlock+whatsmyname",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={
                "name": "GitHub",
                "exists": "Claimed",
                "collector_rows": [
                    {"name": "GitHub", "source": "sherlock", "exists": "Claimed"},
                    {"name": "GitHub", "source": "whatsmyname", "exists": "Claimed"},
                ],
            },
        ),
        normalize_finding(
            run_id="run-1",
            input_type="username",
            input_value="testvalue",
            platform="LinkedIn",
            url="https://linkedin.com/in/testvalue",
            username="testvalue",
            source="sherlock+whatsmyname",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Available",
            raw_data={
                "name": "LinkedIn",
                "exists": "Available",
                "collector_rows": [
                    {"name": "LinkedIn", "source": "sherlock", "exists": "Available"},
                    {"name": "LinkedIn", "source": "whatsmyname", "exists": "Claimed"},
                ],
            },
        ),
        normalize_finding(
            run_id="run-1",
            input_type="username",
            input_value="testvalue",
            platform="Instagram",
            url="https://instagram.com/testvalue",
            username="testvalue",
            source="sherlock",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Available",
            raw_data={"name": "Instagram", "exists": "Available"},
        ),
        normalize_finding(
            run_id="run-1",
            input_type="username",
            input_value="testvalue",
            platform="Reddit",
            url="https://www.reddit.com/user/testvalue",
            username="testvalue",
            source="sherlock",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={"name": "Reddit", "exists": "Claimed"},
        ),
    ]

    report = render_markdown_report(
        run,
        findings,
        audit_warnings=["Priority site returned no result row: GitHub"],
        collector_summary={
            "checked_sites": 5,
            "sherlock_sites": 3,
            "whatsmyname_sites": 2,
            "merged_sites": 3,
            "kept_findings": 3,
            "disabled_sites": 0,
        },
    )
    assert "# OSINT Pipeline Report" in report
    assert "## Collector Summary" in report
    assert "Sites checked by Sherlock: `3`" in report
    assert "Sites checked by WhatsMyName: `2`" in report
    assert "## Signal Summary" in report
    assert "Strong review leads:" in report
    assert "Errors / unstable results:" in report
    assert "## Likely Worth Reviewing First" in report
    assert "## Found Accounts" in report
    assert "Full Name Context" in report
    assert "Test Value" in report
    assert "### Strong Signals" in report
    assert "### Medium Signals" in report
    assert "## Not Found" in report
    assert "## Errors" in report
    assert "## Audit Warnings" in report
    assert "## Confidence Hints" in report
    assert "## Correlation Hints" in report
    assert "## Low Signal Accounts" in report
    assert "score=" in report
    assert "GitHub" in report
    assert "LinkedIn needs manual review" in report
    assert "2 sources found" in report
    assert "source conflict" in report
    assert "sherlock=found, whatsmyname=found" in report
    assert "sherlock=not_found, whatsmyname=found" in report
    assert "name token" in report or "Review GitHub as a high signal" in report
    assert "LinkedIn username-path checking did not confirm a match" in report
    assert "Suggested LinkedIn review target" in report
    assert "https://www.linkedin.com/in/testvalue" in report
    assert "https://www.linkedin.com/in/test-value" in report
    assert 'Suggested LinkedIn manual review query' in report
    assert "Priority site returned no result row: GitHub" in report
    assert "## Analyst Notes" in report


def test_render_markdown_report_includes_delta_section():
    run = RunRecord(
        run_id="run-2",
        input_type="username",
        input_value="testvalue",
        full_name=None,
        source="sherlock",
        created_at_utc="2026-04-06T22:30:00Z",
        finding_count=1,
    )
    findings = [
        normalize_finding(
            run_id="run-2",
            input_type="username",
            input_value="testvalue",
            platform="GitHub",
            url="https://github.com/testvalue",
            username="testvalue",
            source="sherlock",
            checked_at_utc="2026-04-06T22:30:00Z",
            raw_status="Claimed",
            raw_data={"name": "GitHub", "exists": "Claimed"},
        ),
    ]

    report = render_markdown_report(
        run,
        findings,
        delta_summary={
            "previous_run_id": "run-1",
            "new": [{"platform": "GitHub", "status": "found"}],
            "removed": [],
            "changed": [{"platform": "LinkedIn", "changes": ["status not_found -> found"]}],
        },
    )

    assert "## Delta From Previous Similar Run" in report
    assert "Previous run: `run-1`" in report
    assert "New findings: `1`" in report
    assert "Changed findings: `1`" in report
    assert "### New" in report
    assert "`GitHub` [found]" in report
    assert "### Changed" in report
    assert "`LinkedIn`: status not_found -> found" in report


def test_email_report_shows_free_domain_profile_and_optional_breaches():
    run = RunRecord(
        run_id="email-1",
        input_type="email",
        input_value="account-exists@hibp-integration-tests.com",
        full_name=None,
        source="email-domain+haveibeenpwned",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=2,
    )
    findings = [
        normalize_finding(
            run_id="email-1",
            input_type="email",
            input_value="account-exists@hibp-integration-tests.com",
            platform="Email Domain Profile",
            url="https://dns.google/resolve?name=hibp-integration-tests.com",
            username="account-exists@hibp-integration-tests.com",
            source="email-domain",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="EmailDomainProfiled",
            raw_data={
                "name": "Email Domain Profile",
                "exists": "EmailDomainProfiled",
                "domain": "hibp-integration-tests.com",
                "is_common_provider": False,
                "mx_records": ["10 mail.example.com"],
                "spf_records": ["v=spf1 -all"],
                "dmarc_record": "v=DMARC1; p=none",
            },
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="email-1",
            input_type="email",
            input_value="account-exists@hibp-integration-tests.com",
            platform="github",
            url="https://github.com",
            username="account-exists@hibp-integration-tests.com",
            source="holehe",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="HoleheAccountFound",
            raw_data={
                "name": "github",
                "exists": "HoleheAccountFound",
                "domain": "github.com",
                "email_recovery": None,
                "phone_number": None,
            },
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="email-1",
            input_type="email",
            input_value="account-exists@hibp-integration-tests.com",
            platform="Gravatar",
            url="https://www.gravatar.com/hash",
            username="account-exists@hibp-integration-tests.com",
            source="gravatar",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="EmailProfileFound",
            raw_data={
                "name": "Gravatar",
                "exists": "EmailProfileFound",
                "url_user": "https://www.gravatar.com/hash",
                "profile_found": True,
                "avatar_found": True,
                "display_name": "Test User",
                "preferred_username": "testuser",
            },
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="email-1",
            input_type="email",
            input_value="account-exists@hibp-integration-tests.com",
            platform="Adobe",
            url="https://adobe.com",
            username="account-exists@hibp-integration-tests.com",
            source="haveibeenpwned",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Breach",
            raw_data={"name": "Adobe", "exists": "Breach"},
            signal_strength="medium",
        )
    ]

    report = render_markdown_report(run, findings)
    assert "## Email Assessment" in report
    assert "## Signal Summary" in report
    assert "Account signals found:" in report
    assert "Public profile signals:" in report
    assert "Account presence:" in report
    assert "Identity linkage:" in report
    assert "Reliability:" in report
    assert "custom domain adds more contextual value" in report
    assert "## Email Domain Summary" in report
    assert "## Email Address Signals" in report
    assert "## Mail Records" in report
    assert "MX records found: `1`" in report
    assert "v=DMARC1; p=none" in report
    assert "Profile found: `True`" in report
    assert "Display name: `Test User`" in report
    assert "## Account Signals" in report
    assert "Account signals found: `1`" in report
    assert "github" in report
    assert "## HIBP Breaches" in report
    assert "Adobe" in report
    assert "Data exposed" in report
    assert "Hidden lower-priority medium-signal hits" not in report
    assert "medium-signal platform" not in report


def test_domain_report_uses_registration_sections():
    run = RunRecord(
        run_id="domain-1",
        input_type="domain",
        input_value="example.com",
        full_name=None,
        source="rdap+dns",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=2,
    )
    findings = [
        normalize_finding(
            run_id="domain-1",
            input_type="domain",
            input_value="example.com",
            platform="WHOIS / RDAP",
            url="https://example.com",
            username="example.com",
            source="rdap",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="RecordFound",
            raw_data={
                "name": "WHOIS",
                "exists": "RecordFound",
                "domain": "example.com",
                "registrar": "Example Registrar",
                "created": "1995-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z",
                "expires": "2027-01-01T00:00:00Z",
                "nameservers": "NS1.EXAMPLE.COM, NS2.EXAMPLE.COM",
            },
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="domain-1",
            input_type="domain",
            input_value="example.com",
            platform="DNS Records",
            url="https://dns.google/resolve?name=example.com",
            username="example.com",
            source="dns",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="DNSRecordsFound",
            raw_data={
                "name": "DNS",
                "exists": "DNSRecordsFound",
                "domain": "example.com",
                "records": {
                    "A": ["93.184.216.34"],
                    "MX": ["10 mail.example.com"],
                    "TXT": ["v=spf1 -all"],
                },
            },
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="domain-1",
            input_type="domain",
            input_value="example.com",
            platform="BuiltWith Classification",
            url="https://builtwith.com/example.com",
            username="example.com",
            source="builtwith",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="BuiltWithClassified",
            raw_data={
                "name": "BuiltWith",
                "exists": "BuiltWithClassified",
                "classifications": ["likely CMS-backed site", "analytics-heavy deployment"],
                "live_groups": ["cms", "analytics"],
            },
            signal_strength="medium",
        ),
    ]

    report = render_markdown_report(run, findings)
    assert "## Signal Summary" in report
    assert "Registration records found:" in report
    assert "DNS record types found:" in report
    assert "## Registration Summary" in report
    assert "## Nameservers" in report
    assert "## DNS Records" in report
    assert "Example Registrar" in report
    assert "NS1.EXAMPLE.COM" in report
    assert "### A" in report
    assert "93.184.216.34" in report
    assert "### MX" in report
    assert "10 mail.example.com" in report
    assert "## Site Classification" in report
    assert "likely CMS-backed site; analytics-heavy deployment" in report
    assert "Hidden lower-priority medium-signal hits" not in report


def test_case_report_correlates_holehe_service_with_username_and_full_name():
    run = RunRecord(
        run_id="case-1",
        input_type="case",
        input_value="username=testuser; email=testuser@example.com",
        full_name="Test User",
        source="sherlock+whatsmyname+email-domain+gravatar+holehe",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=3,
    )
    findings = [
        normalize_finding(
            run_id="case-1",
            input_type="username",
            input_value="testuser",
            platform="Spotify",
            url="https://open.spotify.com/user/testuser",
            username="testuser",
            source="sherlock",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={"name": "Spotify", "exists": "Claimed"},
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="case-1",
            input_type="email",
            input_value="testuser@example.com",
            platform="Gravatar",
            url="https://www.gravatar.com/hash",
            username="testuser@example.com",
            source="gravatar",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="EmailProfileFound",
            raw_data={
                "name": "Gravatar",
                "exists": "EmailProfileFound",
                "display_name": "Test User",
                "profile_found": True,
                "avatar_found": True,
            },
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="case-1",
            input_type="email",
            input_value="testuser@example.com",
            platform="Holehe / spotify",
            url="https://spotify.com",
            username="testuser@example.com",
            source="holehe",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="HoleheAccountFound",
            raw_data={
                "name": "spotify",
                "exists": "HoleheAccountFound",
                "service": "spotify",
                "domain": "spotify.com",
            },
            signal_strength="medium",
        ),
    ]

    report = render_markdown_report(run, findings)

    assert "Stored results:" in report
    assert "## Overall Assessment" in report
    assert "## Key Findings" in report
    assert "### Top Leads" in report
    assert "High-signal username leads" in report
    assert "## Cross-Signal Correlation" in report
    assert "### Assessment" in report
    assert "### Summary" in report
    assert "### Account Signals" in report
    assert "Account presence:" in report
    assert "### Cross-Signal Highlights" in report
    assert "Email local-part matches the provided username" in report
    assert "Gravatar display name overlaps with full-name context" in report
    assert "Holehe found an email account signal and username workflow found `Spotify`" in report
    assert "Cross-signal overlaps with username results: `1`" in report
    assert "Strongest aligned services:" in report
    assert "score=" in report
    assert "email local-part matches username (+2)" in report
    assert "email workflow found the same service (+3)" in report
    assert "https://open.spotify.com/user/testuser" in report
    assert '"Test User" "testuser" site:open.spotify.com/user' in report


def test_case_report_uses_builtwith_domain_context_in_scoring():
    run = RunRecord(
        run_id="case-2",
        input_type="case",
        input_value="username=testshop; domain=example.com",
        full_name=None,
        source="sherlock+rdap+dns+builtwith",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=2,
    )
    findings = [
        normalize_finding(
            run_id="case-2",
            input_type="username",
            input_value="testshop",
            platform="GitHub",
            url="https://github.com/testshop",
            username="testshop",
            source="sherlock",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={"name": "GitHub", "exists": "Claimed"},
            signal_strength="high",
        ),
        normalize_finding(
            run_id="case-2",
            input_type="domain",
            input_value="example.com",
            platform="BuiltWith Classification",
            url="https://builtwith.com/example.com",
            username="example.com",
            source="builtwith",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="BuiltWithClassified",
            raw_data={
                "name": "BuiltWith",
                "exists": "BuiltWithClassified",
                "classifications": ["likely CMS-backed site", "low-tech footprint"],
                "live_groups": ["cms"],
            },
            signal_strength="medium",
        ),
    ]

    report = render_markdown_report(run, findings)

    assert "score=" in report
    assert "domain has a low-tech footprint, so domain context adds limited evidence (-1)" in report
    assert "### BuiltWith Classification" in report
    assert "likely CMS-backed site; low-tech footprint" in report


def test_report_why_line_avoids_repeating_obvious_strength_labels():
    run = RunRecord(
        run_id="run-3",
        input_type="username",
        input_value="testvalue",
        full_name=None,
        source="sherlock",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=1,
    )
    findings = [
        normalize_finding(
            run_id="run-3",
            input_type="username",
            input_value="testvalue",
            platform="GitHub",
            url="https://github.com/testvalue",
            username="testvalue",
            source="sherlock+whatsmyname",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={
                "name": "GitHub",
                "exists": "Claimed",
                "collector_rows": [
                    {"name": "GitHub", "source": "sherlock", "exists": "Claimed"},
                    {"name": "GitHub", "source": "whatsmyname", "exists": "Claimed"},
                ],
            },
        ),
    ]

    report = render_markdown_report(run, findings)

    assert "high-signal platform" not in report
    assert "medium-signal platform" not in report
    assert "collector coverage" not in report


def test_case_report_username_findings_do_not_repeat_top_leads():
    run = RunRecord(
        run_id="case-3",
        input_type="case",
        input_value="username=testuser",
        full_name=None,
        source="sherlock+whatsmyname",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=6,
    )
    findings = [
        normalize_finding(
            run_id="case-3",
            input_type="username",
            input_value="testuser",
            platform=platform,
            url=f"https://example.com/{platform.lower()}",
            username="testuser",
            source="sherlock",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={"name": platform, "exists": "Claimed"},
            signal_strength=strength,
        )
        for platform, strength in [
            ("GitHub", "high"),
            ("Reddit", "medium"),
            ("Spotify", "medium"),
            ("Instagram", "medium"),
            ("Telegram", "medium"),
            ("Snapchat", "medium"),
        ]
    ]

    report = render_markdown_report(run, findings)

    assert report.count("https://example.com/github") == 1
    assert "Top leads are shown above. This section highlights the next tier of username findings." in report
    assert "https://example.com/snapchat" in report


def test_case_overall_assessment_stays_moderate_without_real_cross_signal_overlap():
    run = RunRecord(
        run_id="case-4",
        input_type="case",
        input_value="username=exampleuser; email=exampleuser@gmail.com",
        full_name="Example User",
        source="sherlock+whatsmyname+email-domain+holehe",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=4,
    )
    findings = [
        normalize_finding(
            run_id="case-4",
            input_type="username",
            input_value="exampleuser",
            platform="GitHub",
            url="https://www.github.com/exampleuser",
            username="exampleuser",
            source="sherlock",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={"name": "GitHub", "exists": "Claimed"},
            signal_strength="high",
        ),
        normalize_finding(
            run_id="case-4",
            input_type="username",
            input_value="exampleuser",
            platform="Codecademy",
            url="https://www.codecademy.com/profiles/exampleuser",
            username="exampleuser",
            source="sherlock+whatsmyname",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="Claimed",
            raw_data={
                "name": "Codecademy",
                "exists": "Claimed",
                "collector_rows": [
                    {"name": "Codecademy", "source": "sherlock", "exists": "Claimed"},
                    {"name": "Codecademy", "source": "whatsmyname", "exists": "Claimed"},
                ],
            },
            signal_strength="low",
        ),
        normalize_finding(
            run_id="case-4",
            input_type="email",
            input_value="exampleuser@gmail.com",
            platform="Email Domain Profile",
            url="https://dns.google/resolve?name=gmail.com",
            username="exampleuser@gmail.com",
            source="email-domain",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="EmailDomainProfiled",
            raw_data={
                "name": "Email Domain Profile",
                "exists": "EmailDomainProfiled",
                "domain": "gmail.com",
                "is_common_provider": True,
            },
            signal_strength="medium",
        ),
        normalize_finding(
            run_id="case-4",
            input_type="email",
            input_value="exampleuser@gmail.com",
            platform="Holehe / office365",
            url="https://office365.com",
            username="exampleuser@gmail.com",
            source="holehe",
            checked_at_utc="2026-04-05T22:30:00Z",
            raw_status="HoleheAccountFound",
            raw_data={
                "name": "office365",
                "exists": "HoleheAccountFound",
                "service": "office365",
            },
            signal_strength="medium",
        ),
    ]

    report = render_markdown_report(run, findings)

    assert "- Cross-signal correlation: `moderate`" in report
    assert "- Lead quality: `moderate`" in report
