from osint_pipeline.models import RunRecord
from osint_pipeline.processors import normalize_finding
from osint_pipeline.storage import ensure_database, fetch_run, get_previous_run_for, insert_findings, insert_run


def test_insert_and_fetch_run_and_findings(tmp_path):
    db_path = tmp_path / "pipeline.db"
    ensure_database(db_path)

    run = RunRecord(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        full_name="Test Value",
        source="sherlock",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=1,
    )
    finding = normalize_finding(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        platform="GitHub",
        url="https://github.com/testvalue",
        username="testvalue",
        source="sherlock",
        checked_at_utc="2026-04-05T22:30:00Z",
        raw_status="Claimed",
        raw_data={"name": "GitHub", "exists": "Claimed"},
    )

    insert_run(db_path, run)
    insert_findings(db_path, [finding])

    stored_run, stored_findings = fetch_run(db_path, "run-1")
    assert stored_run[0] == "run-1"
    assert stored_run[3] == "Test Value"
    assert stored_findings[0][3] == "GitHub"
    assert stored_findings[0][4] == "high"
    assert stored_findings[0][9] == "found"
    assert stored_findings[0][11] == '{"exists": "Claimed", "name": "GitHub"}'


def test_get_previous_run_for_same_input(tmp_path):
    db_path = tmp_path / "pipeline.db"
    ensure_database(db_path)

    older = RunRecord(
        run_id="run-1",
        input_type="username",
        input_value="testvalue",
        full_name="Test Value",
        source="sherlock",
        created_at_utc="2026-04-05T22:30:00Z",
        finding_count=1,
    )
    newer = RunRecord(
        run_id="run-2",
        input_type="username",
        input_value="testvalue",
        full_name="Test Value",
        source="sherlock+whatsmyname",
        created_at_utc="2026-04-06T22:30:00Z",
        finding_count=2,
    )

    insert_run(db_path, older)
    insert_run(db_path, newer)

    previous = get_previous_run_for(db_path, newer)
    assert previous is not None
    assert previous.run_id == "run-1"
