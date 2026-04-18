from pathlib import Path

from osint_pipeline import cli


def test_cli_run_username_with_mocked_collector(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        cli,
        "run_sherlock",
        lambda username, timeout=60: [
            {
                "username": username,
                "name": "GitHub",
                "url_main": "https://github.com",
                "url_user": f"https://github.com/{username}",
                "exists": "Claimed",
                "http_status": "200",
                "response_time_s": "0.12",
            },
            {
                "username": username,
                "name": "Pornhub",
                "url_main": "https://pornhub.com",
                "url_user": f"https://pornhub.com/users/{username}",
                "exists": "Claimed",
                "http_status": "200",
                "response_time_s": "0.20",
            },
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_whatsmyname",
        lambda username, timeout=60: [
            {
                "username": username,
                "name": "GitHub",
                "url_main": "https://github.com/{account}",
                "url_user": f"https://github.com/{username}",
                "exists": "Claimed",
                "http_status": "200",
                "response_time_s": "",
                "source": "whatsmyname",
            },
            {
                "username": username,
                "name": "Reddit",
                "url_main": "https://www.reddit.com/user/{account}",
                "url_user": f"https://www.reddit.com/user/{username}",
                "exists": "Claimed",
                "http_status": "200",
                "response_time_s": "",
                "source": "whatsmyname",
            },
        ],
    )

    exit_code = cli.main(
        [
            "run",
            "username",
            "testvalue",
            "--db",
            str(tmp_path / "pipeline.db"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Sherlock checked: 2 sites" in captured.out
    assert "WhatsMyName checked: 2 sites" in captured.out
    assert "Merged platforms: 3" in captured.out
    assert "Stored findings: 2" in captured.out
    assert "Disabled sites skipped:" in captured.out
    report_files = list((tmp_path / "reports").rglob("*.md"))
    assert len(report_files) == 1


def test_cli_run_email_with_free_domain_profile(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        cli,
        "run_email_domain_profile",
        lambda email, timeout=30: [
            {
                "username": email,
                "name": "Email Domain Profile",
                "title": "Email Domain Profile",
                "url_main": "hibp-integration-tests.com",
                "url_user": "https://dns.google/resolve?name=hibp-integration-tests.com",
                "exists": "EmailDomainProfiled",
                "http_status": "200",
                "response_time_s": "",
                "source": "email-domain",
                "email": email,
                "domain": "hibp-integration-tests.com",
                "is_common_provider": False,
                "mx_records": ["10 mail.example.com"],
                "spf_records": ["v=spf1 -all"],
                "dmarc_record": "v=DMARC1; p=none",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_gravatar_email_lookup",
        lambda email, timeout=30: [
            {
                "username": email,
                "name": "Gravatar",
                "title": "Gravatar",
                "url_main": "https://www.gravatar.com",
                "url_user": "https://www.gravatar.com/hash",
                "exists": "EmailProfileFound",
                "http_status": "200",
                "response_time_s": "",
                "source": "gravatar",
                "email": email,
                "email_hash": "hash",
                "profile_found": True,
                "avatar_found": True,
                "display_name": "Test User",
                "preferred_username": "testuser",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_holehe_email_lookup",
        lambda email, timeout=60: [
            {
                "username": email,
                "name": "github",
                "title": "Holehe / github",
                "url_main": "github.com",
                "url_user": "https://github.com",
                "exists": "HoleheAccountFound",
                "http_status": "",
                "response_time_s": "",
                "source": "holehe",
                "email": email,
                "service": "github",
                "domain": "github.com",
                "rate_limit": False,
                "email_recovery": None,
                "phone_number": None,
                "others": None,
            }
        ],
    )
    monkeypatch.setattr(cli, "run_holehe_email_lookup", lambda email, timeout=30: [])

    exit_code = cli.main(
        [
            "run",
            "email",
            "account-exists@hibp-integration-tests.com",
            "--db",
            str(tmp_path / "pipeline.db"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Email domain profiles: 1" in captured.out
    assert "Gravatar checks: 1" in captured.out
    assert "Gravatar profiles found: 1" in captured.out
    assert "HIBP requests: 0" in captured.out
    assert "Breaches found: 0" in captured.out
    report_files = list((tmp_path / "reports").rglob("*.md"))
    assert len(report_files) == 1
    report = report_files[0].read_text(encoding="utf-8")
    assert "## Email Domain Summary" in report
    assert "## Email Address Signals" in report
    assert "Gravatar" in report
    assert "## Mail Records" in report


def test_cli_run_domain_with_mocked_rdap(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        cli,
        "run_rdap_domain_lookup",
        lambda domain, timeout=30: [
            {
                "username": domain,
                "name": "WHOIS",
                "title": "WHOIS / RDAP",
                "url_main": domain,
                "url_user": f"https://{domain}",
                "exists": "RecordFound",
                "http_status": "200",
                "response_time_s": "",
                "source": "rdap",
                "domain": domain,
                "registrar": "Example Registrar",
                "created": "1995-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z",
                "expires": "2027-01-01T00:00:00Z",
                "nameservers": "NS1.EXAMPLE.COM, NS2.EXAMPLE.COM",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_dns_domain_lookup",
        lambda domain, timeout=30: [
            {
                "username": domain,
                "name": "DNS",
                "title": "DNS Records",
                "url_main": domain,
                "url_user": f"https://dns.google/resolve?name={domain}",
                "exists": "DNSRecordsFound",
                "http_status": "200",
                "response_time_s": "",
                "source": "dns",
                "domain": domain,
                "records": {
                    "A": ["93.184.216.34"],
                    "MX": ["10 mail.example.com"],
                },
            }
        ],
    )

    exit_code = cli.main(
        [
            "run",
            "domain",
            "https://example.com/path",
            "--db",
            str(tmp_path / "pipeline.db"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "RDAP requests: 1" in captured.out
    assert "DNS requests: 6" in captured.out
    assert "Records found: 2" in captured.out
    report_files = list((tmp_path / "reports").rglob("*.md"))
    assert len(report_files) == 1


def test_cli_run_domain_can_include_builtwith(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        cli,
        "run_rdap_domain_lookup",
        lambda domain, timeout=30: [],
    )
    monkeypatch.setattr(
        cli,
        "run_dns_domain_lookup",
        lambda domain, timeout=30: [],
    )
    monkeypatch.setattr(
        cli,
        "run_builtwith_domain_lookup",
        lambda domain, api_key, timeout=30: [
            {
                "username": domain,
                "name": "BuiltWith",
                "title": "BuiltWith Classification",
                "url_main": domain,
                "url_user": f"https://builtwith.com/{domain}",
                "exists": "BuiltWithClassified",
                "http_status": "200",
                "response_time_s": "",
                "source": "builtwith",
                "domain": domain,
                "classifications": ["likely CMS-backed site"],
                "live_groups": ["cms"],
                "live_categories": ["blogs"],
            }
        ],
    )

    exit_code = cli.main(
        [
            "run",
            "domain",
            "example.com",
            "--include-builtwith",
            "--builtwith-api-key",
            "demo-key",
            "--db",
            str(tmp_path / "pipeline.db"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "BuiltWith requests: 1" in captured.out
    report_files = list((tmp_path / "reports").rglob("*.md"))
    assert len(report_files) == 1
    report = report_files[0].read_text(encoding="utf-8")
    assert "## Site Classification" in report
    assert "likely CMS-backed site" in report


def test_cli_case_creates_combined_report(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(
        cli,
        "run_sherlock",
        lambda username, timeout=60: [
            {
                "username": username,
                "name": "GitHub",
                "url_main": "https://github.com",
                "url_user": f"https://github.com/{username}",
                "exists": "Claimed",
                "http_status": "200",
                "response_time_s": "",
                "source": "sherlock",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_whatsmyname",
        lambda username, timeout=60: [
            {
                "username": username,
                "name": "GitHub",
                "url_main": "https://github.com/{account}",
                "url_user": f"https://github.com/{username}",
                "exists": "Claimed",
                "http_status": "200",
                "response_time_s": "",
                "source": "whatsmyname",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_email_domain_profile",
        lambda email, timeout=60: [
            {
                "username": email,
                "name": "Email Domain Profile",
                "title": "Email Domain Profile",
                "url_main": "hibp-integration-tests.com",
                "url_user": "https://dns.google/resolve?name=hibp-integration-tests.com",
                "exists": "EmailDomainProfiled",
                "http_status": "200",
                "response_time_s": "",
                "source": "email-domain",
                "email": email,
                "domain": "hibp-integration-tests.com",
                "is_common_provider": False,
                "mx_records": ["10 mail.example.com"],
                "spf_records": ["v=spf1 -all"],
                "dmarc_record": "v=DMARC1; p=none",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_gravatar_email_lookup",
        lambda email, timeout=60: [
            {
                "username": email,
                "name": "Gravatar",
                "title": "Gravatar",
                "url_main": "https://www.gravatar.com",
                "url_user": "https://www.gravatar.com/hash",
                "exists": "NoEmailProfile",
                "http_status": "404",
                "response_time_s": "",
                "source": "gravatar",
                "email": email,
                "email_hash": "hash",
                "profile_found": False,
                "avatar_found": False,
                "display_name": "",
                "preferred_username": "",
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_holehe_email_lookup",
        lambda email, timeout=60: [
            {
                "username": email,
                "name": "github",
                "title": "Holehe / github",
                "url_main": "github.com",
                "url_user": "https://github.com",
                "exists": "HoleheAccountFound",
                "http_status": "",
                "response_time_s": "",
                "source": "holehe",
                "email": email,
                "service": "github",
                "domain": "github.com",
                "rate_limit": False,
                "email_recovery": None,
                "phone_number": None,
                "others": None,
            }
        ],
    )
    monkeypatch.setattr(
        cli,
        "run_hibp_email_lookup",
        lambda email, api_key, timeout=60: [
            {
                "username": email,
                "name": "Adobe",
                "title": "Adobe",
                "url_main": "adobe.com",
                "url_user": "https://adobe.com",
                "exists": "Breach",
                "http_status": "200",
                "response_time_s": "",
                "source": "haveibeenpwned",
                "breach_date": "2013-10-04",
                "domain": "adobe.com",
                "data_classes": "Email addresses",
            }
        ],
    )

    exit_code = cli.main(
        [
            "case",
            "--username",
            "testvalue",
            "--full-name",
            "Test Value",
            "--email",
            "account-exists@hibp-integration-tests.com",
            "--include-holehe",
            "--include-hibp",
            "--db",
            str(tmp_path / "pipeline.db"),
            "--reports-dir",
            str(tmp_path / "reports"),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Case Run ID:" in captured.out
    assert "Username findings: 1" in captured.out
    assert "Email findings: 4" in captured.out
    report_files = list((tmp_path / "reports").rglob("*.md"))
    assert len(report_files) == 1
    report = report_files[0].read_text(encoding="utf-8")
    assert "## Case Summary" in report
    assert "## Username Findings" in report
    assert "## Email Findings" in report
    assert "GitHub" in report
    assert "Adobe" in report
    assert "MX records found" in report
    assert "Gravatar profile found" in report
    assert "Holehe account signals found" in report


def test_interactive_menu_can_show_latest(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda prompt="": "6")
    monkeypatch.setattr(cli, "get_latest_run", lambda db_path: None)

    exit_code = cli.main([])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "OSINT Pipeline" in captured.out
    assert "No runs found." in captured.out


def test_interactive_menu_can_repeat_latest(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt="": "8")
    captured_args = []

    def fake_main(argv=None):
        if argv == []:
            return cli.interactive_menu()
        captured_args.append(argv)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)

    exit_code = cli.interactive_menu()

    assert exit_code == 0
    assert captured_args == [["rerun", "latest"]]


def test_interactive_menu_can_list_reports(monkeypatch):
    answers = iter(["9", "5"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    captured_args = []

    def fake_main(argv=None):
        if argv == []:
            return cli.interactive_menu()
        captured_args.append(argv)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)

    exit_code = cli.interactive_menu()

    assert exit_code == 0
    assert captured_args == [["reports", "--limit", "5"]]


def test_interactive_case_can_include_holehe(monkeypatch):
    answers = iter(["4", "testvalue", "Test Value", "test@example.com", "y"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    captured_args = []

    def fake_main(argv=None):
        if argv == []:
            return cli.interactive_menu()
        captured_args.append(argv)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)

    exit_code = cli.interactive_menu()

    assert exit_code == 0
    assert captured_args == [
        [
            "case",
            "--username",
            "testvalue",
            "--full-name",
            "Test Value",
            "--email",
            "test@example.com",
            "--include-holehe",
        ]
    ]


def test_rerun_latest_reconstructs_case_with_optional_collectors(monkeypatch, tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    cli.ensure_database(db_path)
    cli.insert_run(
        db_path,
        cli.RunRecord(
            run_id="case-1",
            input_type="case",
            input_value="username=testvalue; email=test@example.com; domain=example.com",
            full_name="Test Value",
            source="sherlock+whatsmyname+email-domain+gravatar+holehe+haveibeenpwned+rdap+dns",
            created_at_utc="2026-04-06T04:00:00Z",
            finding_count=0,
        ),
    )
    captured_args = []

    def fake_main(argv=None):
        captured_args.append(argv)
        return 0

    monkeypatch.setattr(cli, "main", fake_main)

    exit_code = cli.rerun_workflow(
        cli.build_parser().parse_args(["rerun", "latest", "--db", str(db_path)])
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Repeating run: case-1" in captured.out
    assert captured_args == [
        [
            "case",
            "--username",
            "testvalue",
            "--full-name",
            "Test Value",
            "--email",
            "test@example.com",
            "--domain",
            "example.com",
            "--include-holehe",
            "--include-hibp",
            "--db",
            str(db_path),
        ]
    ]
