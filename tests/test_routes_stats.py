from app.config import settings
from app.enrichment.epss import EpssEnricher
from app.models import CVE
from app.rate_limit import reset_rate_limit


def test_stats_computes_new_aggregates(client, db_session):
    db_session.add(CVE(
        cve_id="CVE-2026-8001", severity="CRITICAL", cvss_score=9.8, is_kev=True, has_poc=True,
        epss_score=0.9, cwe_ids=["CWE-79", "CWE-89"], sources=["nvd"],
    ))
    db_session.add(CVE(
        cve_id="CVE-2026-8002", severity="LOW", cvss_score=2.0, is_kev=False, has_poc=False,
        epss_score=0.02, cwe_ids=["CWE-79"], sources=["nvd"],
    ))
    db_session.add(CVE(
        cve_id="CVE-2026-8003", severity=None, sources=["github_poc"],  # stub, non confirmée
    ))
    db_session.commit()

    resp = client.get("/api/cves/stats")
    assert resp.status_code == 200
    body = resp.json()

    assert body["weaponization_risk_count"] == 1  # KEV + has_poc
    assert body["epss_high_risk_count"] == 1  # score >= 0.5
    assert body["unconfirmed_count"] == 1  # seule github_poc, aucune source structurée
    assert body["top_cwe"]["CWE-79"] == 2
    assert body["top_cwe"]["CWE-89"] == 1
    assert body["epss_distribution"]["90-100%"] == 1
    assert body["epss_distribution"]["1-10%"] == 1


def test_stats_are_zero_on_empty_database(client):
    body = client.get("/api/cves/stats").json()
    assert body["weaponization_risk_count"] == 0
    assert body["epss_high_risk_count"] == 0
    assert body["unconfirmed_count"] == 0
    assert body["top_cwe"] == {}
    assert body["epss_distribution"] == {}


def test_list_cves_filters_by_has_poc(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-8101", has_poc=True))
    db_session.add(CVE(cve_id="CVE-2026-8102", has_poc=False))
    db_session.commit()

    resp = client.get("/api/cves?has_poc=true")
    ids = {c["cve_id"] for c in resp.json()}
    assert ids == {"CVE-2026-8101"}


def test_list_cves_filters_by_epss_min(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-8103", epss_score=0.8))
    db_session.add(CVE(cve_id="CVE-2026-8104", epss_score=0.05))
    db_session.commit()

    resp = client.get("/api/cves?epss_min=0.5")
    ids = {c["cve_id"] for c in resp.json()}
    assert ids == {"CVE-2026-8103"}


def test_sync_epss_triggers_enrichment_and_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", None)
    reset_rate_limit("sync:epss")
    monkeypatch.setattr(EpssEnricher, "fetch_index", lambda self: {})

    resp = client.post("/api/cves/sync-epss")
    assert resp.status_code == 200
    assert resp.json()["source"] == "epss"

    # Deuxième appel immédiat : bloqué par le cooldown anti-double-clic.
    assert client.post("/api/cves/sync-epss").status_code == 429


def test_sync_epss_requires_auth_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "secret")
    assert client.post("/api/cves/sync-epss").status_code == 401


def test_stats_kev_by_day_counts_only_kev_cves_in_window(client, db_session):
    from datetime import datetime, timedelta

    today = datetime.utcnow()
    db_session.add(CVE(cve_id="CVE-2026-8201", is_kev=True, kev_date_added=today))
    db_session.add(CVE(cve_id="CVE-2026-8202", is_kev=True, kev_date_added=today - timedelta(days=1)))
    db_session.add(CVE(cve_id="CVE-2026-8203", is_kev=True, kev_date_added=today - timedelta(days=30)))  # hors fenêtre 14j
    db_session.add(CVE(cve_id="CVE-2026-8204", is_kev=False, kev_date_added=None))
    db_session.commit()

    body = client.get("/api/cves/stats").json()
    assert sum(body["kev_by_day"].values()) == 2


def test_stats_risk_distribution_sums_to_total(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-8301", cvss_score=9.8, is_kev=True, has_poc=True, epss_score=0.9))
    db_session.add(CVE(cve_id="CVE-2026-8302", cvss_score=2.0))
    db_session.add(CVE(cve_id="CVE-2026-8303"))
    db_session.commit()

    body = client.get("/api/cves/stats").json()
    assert sum(body["risk_distribution"].values()) == 3
    assert body["risk_distribution"].get("critical", 0) >= 1


def test_list_cves_exposes_risk_score(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-8401", cvss_score=9.8, is_kev=True))
    db_session.commit()

    body = client.get("/api/cves").json()
    cve = next(c for c in body if c["cve_id"] == "CVE-2026-8401")
    assert 0 <= cve["risk_score"] <= 100
    assert cve["risk_level"] in {"critical", "high", "medium", "low", "info"}
    assert isinstance(cve["risk_breakdown"], list)


def test_list_cves_sort_by_risk_score(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-8501", cvss_score=1.0))
    db_session.add(CVE(cve_id="CVE-2026-8502", cvss_score=9.8, is_kev=True, has_poc=True, epss_score=0.9))
    db_session.commit()

    resp = client.get("/api/cves?sort=risk_score&direction=desc")
    ids = [c["cve_id"] for c in resp.json()]
    assert ids[0] == "CVE-2026-8502"


def test_export_csv_includes_risk_score_column(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-8601", cvss_score=9.8, is_kev=True))
    db_session.commit()

    resp = client.get("/api/cves/export?format=csv")
    header = resp.text.splitlines()[0]
    assert "risk_score" in header
    assert "risk_level" in header
