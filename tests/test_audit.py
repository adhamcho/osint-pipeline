from osint_pipeline.audit import find_missing_priority_rows


def test_find_missing_priority_rows_flags_missing_sites():
    rows = [
        {"name": "GitHub"},
        {"name": "LinkedIn"},
    ]
    warnings = find_missing_priority_rows(rows)
    assert warnings == ["Priority site returned no result row: Reddit"]
