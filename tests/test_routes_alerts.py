import pytest

import app.api.routes_alerts as routes_alerts
from app.config import settings
from app.models import AlertLog

_STUB_SUMMARY = [{"source": "stub", "fetched": 0, "new": 0, "alerts_sent": 0, "error": None}]


@pytest.fixture(autouse=True)
def _open_write_endpoints(monkeypatch):
    # cf. tests/test_routes_watchlist.py::_open_write_endpoints - neutralise un API_KEY local.
    monkeypatch.setattr(settings, "api_key", None)


def test_list_alerts_filters_by_acknowledged(client, db_session):
    db_session.add(AlertLog(cve_id="CVE-2026-0001", channel="slack", reasons=["x"], acknowledged=False))
    db_session.add(AlertLog(cve_id="CVE-2026-0002", channel="slack", reasons=["x"], acknowledged=True))
    db_session.commit()

    assert len(client.get("/api/alerts").json()) == 2
    unack = client.get("/api/alerts?acknowledged=false").json()
    assert len(unack) == 1
    assert unack[0]["cve_id"] == "CVE-2026-0001"


def test_acknowledge_alert(client, db_session):
    db_session.add(AlertLog(cve_id="CVE-2026-0003", channel="slack", reasons=["x"]))
    db_session.commit()
    alert_id = db_session.query(AlertLog).filter_by(cve_id="CVE-2026-0003").one().id

    resp = client.post(f"/api/alerts/{alert_id}/ack")
    assert resp.status_code == 200
    assert resp.json()["acknowledged"] is True


def test_acknowledge_unknown_alert_returns_404(client):
    assert client.post("/api/alerts/999999/ack").status_code == 404


def test_poll_now_triggers_ingestion(client, monkeypatch):
    monkeypatch.setattr(routes_alerts, "_last_poll_completed", None)
    monkeypatch.setattr(routes_alerts, "poll_all_sources", lambda db: _STUB_SUMMARY)

    resp = client.post("/api/alerts/poll-now")
    assert resp.status_code == 200
    assert resp.json()["summaries"] == _STUB_SUMMARY


def test_poll_now_cooldown_blocks_immediate_second_call(client, monkeypatch):
    monkeypatch.setattr(routes_alerts, "_last_poll_completed", None)
    monkeypatch.setattr(routes_alerts, "poll_all_sources", lambda db: _STUB_SUMMARY)

    assert client.post("/api/alerts/poll-now").status_code == 200
    assert client.post("/api/alerts/poll-now").status_code == 429
