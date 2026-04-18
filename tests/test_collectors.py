from types import SimpleNamespace

from osint_pipeline.collectors import _builtwith_classifications, _results_to_rows


def test_results_to_rows_converts_sherlock_shape():
    results = {
        "GitHub": {
            "url_main": "https://github.com",
            "url_user": "https://github.com/testvalue",
            "http_status": 200,
            "status": SimpleNamespace(status="Claimed", query_time=0.12),
        }
    }
    rows = _results_to_rows(results, "testvalue")
    assert len(rows) == 1
    assert rows[0]["name"] == "GitHub"
    assert rows[0]["exists"] == "Claimed"


def test_builtwith_classifications_reduce_groups_to_context():
    classifications, live_groups, live_categories = _builtwith_classifications(
        [
            {
                "name": "cms",
                "live": 2,
                "categories": [{"name": "blogs", "live": 1}],
            },
            {
                "name": "analytics",
                "live": 3,
                "categories": [{"name": "social-sdk", "live": 1}],
            },
        ]
    )

    assert "likely CMS-backed site" in classifications
    assert "analytics-heavy deployment" in classifications
    assert "cms" in live_groups
    assert "blogs" in live_categories
