from osint_pipeline.processors import normalize_domain, normalize_email, normalize_finding, normalize_username


def test_normalize_username_strips_at_sign_and_whitespace():
    assert normalize_username("  @SomeUser  ") == "SomeUser"


def test_normalize_finding_maps_status():
    finding = normalize_finding(
        run_id="run-1",
        input_type="username",
        input_value="SomeUser",
        platform="GitHub",
        url="https://github.com/SomeUser",
        username="@SomeUser",
        source="sherlock",
        checked_at_utc="2026-04-05T22:30:00Z",
        raw_status="Claimed",
        raw_data={"name": "GitHub", "exists": "Claimed"},
    )
    assert finding.status == "found"
    assert finding.username == "SomeUser"
    assert finding.signal_strength == "high"
    assert '"exists": "Claimed"' in finding.raw_data


def test_normalize_email_lowercases_and_strips():
    assert normalize_email("  Test@Example.com  ") == "test@example.com"


def test_normalize_domain_accepts_url_input():
    assert normalize_domain("https://Example.com/path") == "example.com"


def test_normalize_finding_treats_academia_403_as_error():
    finding = normalize_finding(
        run_id="run-1",
        input_type="username",
        input_value="exampleuser",
        platform="Academia.edu",
        url="https://independent.academia.edu/exampleuser",
        username="exampleuser",
        source="sherlock",
        checked_at_utc="2026-04-09T00:00:00Z",
        raw_status="Available",
        raw_data={
            "name": "Academia.edu",
            "exists": "Available",
            "http_status": "403",
        },
    )
    assert finding.status == "error"
