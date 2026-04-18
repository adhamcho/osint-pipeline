import os

from osint_pipeline import cli
from osint_pipeline.models import RunRecord
from osint_pipeline.processors import normalize_finding
from osint_pipeline.storage import ensure_database, insert_findings, insert_run


def test_list_runs_outputs_recent_runs(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    ensure_database(db_path)
    run = RunRecord(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        full_name=None,
        source="sherlock",
        created_at_utc="2026-04-06T04:00:00Z",
        finding_count=1,
    )
    insert_run(db_path, run)

    exit_code = cli.main(["list", "--db", str(db_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "run-1" in captured.out
    assert "username=testvalue" in captured.out
    assert "full_name=None" in captured.out


def test_show_latest_outputs_summary(tmp_path, capsys):
    db_path = tmp_path / "pipeline.db"
    ensure_database(db_path)
    previous_run = RunRecord(
        run_id="run-0",
        input_type="username",
        input_value="testvalue",
        full_name="Test Value",
        source="sherlock",
        created_at_utc="2026-04-05T04:00:00Z",
        finding_count=1,
    )
    run = RunRecord(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        full_name="Test Value",
        source="sherlock",
        created_at_utc="2026-04-06T04:00:00Z",
        finding_count=1,
    )
    finding = normalize_finding(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        platform="GitHub",
        url="https://github.com/testvalue",
        username="testvalue",
        source="sherlock+whatsmyname",
        checked_at_utc="2026-04-06T04:00:00Z",
        raw_status="Claimed",
        raw_data={
            "name": "GitHub",
            "exists": "Claimed",
            "collector_rows": [
                {"name": "GitHub", "source": "sherlock", "exists": "Claimed"},
                {"name": "GitHub", "source": "whatsmyname", "exists": "Claimed"},
            ],
        },
    )
    reddit_finding = normalize_finding(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        platform="Reddit",
        url="https://www.reddit.com/user/testvalue",
        username="testvalue",
        source="sherlock",
        checked_at_utc="2026-04-06T04:00:00Z",
        raw_status="Claimed",
        raw_data={"name": "Reddit", "exists": "Claimed"},
    )
    linkedin_finding = normalize_finding(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        platform="LinkedIn",
        url="https://www.linkedin.com/in/testvalue",
        username="testvalue",
        source="sherlock+whatsmyname",
        checked_at_utc="2026-04-06T04:00:00Z",
        raw_status="Available",
        raw_data={
            "name": "LinkedIn",
            "exists": "Available",
            "collector_rows": [
                {"name": "LinkedIn", "source": "sherlock", "exists": "Available"},
                {"name": "LinkedIn", "source": "whatsmyname", "exists": "Claimed"},
            ],
        },
    )
    previous_finding = normalize_finding(
        run_id="run-0",
        input_type="username",
        input_value="testvalue",
        platform="GitHub",
        url="https://github.com/testvalue",
        username="testvalue",
        source="sherlock",
        checked_at_utc="2026-04-05T04:00:00Z",
        raw_status="Available",
        raw_data={"name": "GitHub", "exists": "Available"},
    )
    insert_run(db_path, previous_run)
    insert_findings(db_path, [previous_finding])
    insert_run(db_path, run)
    insert_findings(db_path, [finding, reddit_finding, linkedin_finding])

    exit_code = cli.main(["show", "latest", "--db", str(db_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Run ID: run-1" in captured.out
    assert "Full Name Context: Test Value" in captured.out
    assert "Stored results: 1" in captured.out
    assert "Delta vs previous similar run: run-0 | new=2, removed=0, changed=1" in captured.out
    assert "Confidence hints:" in captured.out
    assert "LinkedIn needs manual review" in captured.out
    assert "Top found accounts:" in captured.out
    assert "GitHub [high] (2 sources found)" in captured.out
    assert "sherlock=found, whatsmyname=found" in captured.out


def test_reports_command_lists_recent_report_files(tmp_path, capsys):
    reports_dir = tmp_path / "reports"
    (reports_dir / "username").mkdir(parents=True)
    (reports_dir / "case").mkdir(parents=True)
    first = reports_dir / "username" / "2026-04-08_120000_username_test.md"
    second = reports_dir / "case" / "2026-04-08_121500_case_test.md"
    first.write_text("# first\n", encoding="utf-8")
    second.write_text("# second\n", encoding="utf-8")
    os.utime(first, (1_000_000_000, 1_000_000_000))
    os.utime(second, (1_000_000_100, 1_000_000_100))

    exit_code = cli.main(["reports", "--reports-dir", str(reports_dir), "--limit", "2"])
    captured = capsys.readouterr()

    assert exit_code == 0
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert "2026-04-08_121500_case_test.md" in lines[0]
    assert str(second) in captured.out


def test_reports_command_can_list_oldest_first(tmp_path, capsys):
    reports_dir = tmp_path / "reports"
    (reports_dir / "username").mkdir(parents=True)
    (reports_dir / "case").mkdir(parents=True)
    first = reports_dir / "username" / "2026-04-08_120000_username_test.md"
    second = reports_dir / "case" / "2026-04-08_121500_case_test.md"
    first.write_text("# first\n", encoding="utf-8")
    second.write_text("# second\n", encoding="utf-8")
    os.utime(first, (1_000_000_000, 1_000_000_000))
    os.utime(second, (1_000_000_100, 1_000_000_100))

    exit_code = cli.main(
        ["reports", "--reports-dir", str(reports_dir), "--limit", "2", "--oldest-first"]
    )
    captured = capsys.readouterr()

    assert exit_code == 0
    lines = [line for line in captured.out.splitlines() if line.strip()]
    assert "2026-04-08_120000_username_test.md" in lines[0]
