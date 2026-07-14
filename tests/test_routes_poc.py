from datetime import datetime

from app.config import settings
from app.connectors.github_poc import GithubPocConnector
from app.models import CVE, CVSSHistory, PocLink
from app.rate_limit import reset_rate_limit


def test_cve_detail_exposes_epss_cwe_cpe_and_threat_context(client, db_session):
    db_session.add(CVE(
        cve_id="CVE-2026-7001",
        description="Critical RCE",
        cvss_score=9.8,
        severity="CRITICAL",
        sources=["nvd"],
        epss_score=0.91,
        epss_percentile=0.98,
        cwe_ids=["CWE-79"],
        affected_cpes=["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
        references_meta=[{"url": "https://example.com/patch", "tags": ["Patch"]}],
        threat_context={"otx": {"pulse_count": 3, "tags": ["apt"]}},
    ))
    db_session.add(CVSSHistory(cve_id="CVE-2026-7001", cvss_score=9.8, severity="CRITICAL"))
    db_session.add(PocLink(cve_id="CVE-2026-7001", url="https://github.com/a/poc", source="github_poc",
                            repo_full_name="a/poc", stars=7, discovered_at=datetime.utcnow()))
    db_session.commit()

    resp = client.get("/api/cves/CVE-2026-7001")
    assert resp.status_code == 200
    body = resp.json()
    assert body["epss_score"] == 0.91
    assert body["cwe_ids"] == ["CWE-79"]
    assert body["affected_cpes"] == ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]
    assert body["references_meta"] == [{"url": "https://example.com/patch", "tags": ["Patch"]}]
    assert body["threat_context"] == {"otx": {"pulse_count": 3, "tags": ["apt"]}}
    assert len(body["cvss_history"]) == 1
    assert body["poc_links_detailed"][0]["repo_full_name"] == "a/poc"
    assert body["unconfirmed"] is False  # source "nvd" -> confirmée


def test_cve_detail_flags_stub_cve_as_unconfirmed(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-7002", sources=["github_poc"], has_poc=True))
    db_session.commit()

    resp = client.get("/api/cves/CVE-2026-7002")
    assert resp.json()["unconfirmed"] is True


def test_recent_pocs_feed_orders_by_discovery_time_desc(client, db_session):
    db_session.add(CVE(cve_id="CVE-2026-7003", severity="CRITICAL", cvss_score=9.9, is_kev=True))
    db_session.add(CVE(cve_id="CVE-2026-7004", severity="LOW", cvss_score=2.0))
    db_session.commit()
    db_session.add(PocLink(cve_id="CVE-2026-7003", url="https://github.com/a/older", source="github_poc",
                            discovered_at=datetime(2026, 1, 1)))
    db_session.add(PocLink(cve_id="CVE-2026-7004", url="https://github.com/a/newer", source="github_poc",
                            discovered_at=datetime(2026, 6, 1)))
    db_session.commit()

    resp = client.get("/api/pocs/recent")
    assert resp.status_code == 200
    body = resp.json()
    assert [row["cve_id"] for row in body] == ["CVE-2026-7004", "CVE-2026-7003"]
    risky = next(row for row in body if row["cve_id"] == "CVE-2026-7003")
    assert risky["weaponization_risk"] is True


def test_sync_now_triggers_radar_and_is_rate_limited(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", None)
    reset_rate_limit("sync:github_poc")
    monkeypatch.setattr(GithubPocConnector, "fetch_recent", lambda self: [])

    resp = client.post("/api/pocs/sync-now")
    assert resp.status_code == 200
    assert resp.json()["source"] == "github_poc"

    assert client.post("/api/pocs/sync-now").status_code == 429


def test_sync_now_requires_auth_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "api_key", "secret")
    assert client.post("/api/pocs/sync-now").status_code == 401
