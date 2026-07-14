def test_status_lists_all_pollers_and_enrichers(client):
    resp = client.get("/api/status")
    assert resp.status_code == 200
    names = {s["name"] for s in resp.json()["sources"]}
    assert names == {
        "nvd", "cisa_kev", "github_advisories",  # CONNECTOR_REGISTRY
        "exploitdb", "threat_context", "epss", "github_poc",  # ENRICHER_NAMES
    }


def test_status_reports_never_polled_source_as_none(client):
    resp = client.get("/api/status")
    row = next(s for s in resp.json()["sources"] if s["name"] == "nvd")
    assert row["last_polled_at"] is None
    assert row["last_success_count"] == 0
    assert row["last_new_count"] == 0
    assert row["last_error"] is None


def test_status_reports_fetched_and_new_counts_separately(client, db_session):
    from app.models import SourceState

    db_session.add(SourceState(source_name="epss", last_success_count=347460, last_new_count=5722))
    db_session.commit()

    resp = client.get("/api/status")
    row = next(s for s in resp.json()["sources"] if s["name"] == "epss")
    assert row["last_success_count"] == 347460
    assert row["last_new_count"] == 5722
