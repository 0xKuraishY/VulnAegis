from app.connectors.base import ConnectorError
from app.connectors.exploitdb import ExploitDbConnector
from app.connectors.github_poc import GithubPocConnector
from app.enrichment.epss import EpssEnricher
from app.enrichment.misp import MispEnricher
from app.enrichment.otx import OtxEnricher
from app.ingest import (
    dispatch_alerts,
    enrich_epss_scores,
    enrich_github_poc,
    enrich_has_poc_from_exploitdb,
    enrich_threat_context,
    is_unconfirmed,
    record_poc_discovery,
    upsert_cve,
)
from app.models import CVE, CVSSHistory, PocLink, SourceState
from app.schemas import NormalizedCVE


def make_normalized(**kwargs) -> NormalizedCVE:
    defaults = dict(cve_id="CVE-2026-0001", source="nvd")
    defaults.update(kwargs)
    return NormalizedCVE(**defaults)


def test_upsert_cve_first_insert_does_not_flag_score_increase(db_session):
    cve, is_new, score_increased = upsert_cve(db_session, make_normalized(cvss_score=5.0, severity="MEDIUM"))
    db_session.commit()
    assert is_new is True
    assert score_increased is False
    assert db_session.query(CVSSHistory).filter_by(cve_id=cve.cve_id).count() == 1


def test_upsert_cve_detects_score_increase(db_session):
    upsert_cve(db_session, make_normalized(cvss_score=5.0, severity="MEDIUM"))
    db_session.commit()

    cve, is_new, score_increased = upsert_cve(db_session, make_normalized(cvss_score=8.8, severity="HIGH"))
    db_session.commit()

    assert is_new is False
    assert score_increased is True
    history = db_session.query(CVSSHistory).filter_by(cve_id=cve.cve_id).order_by(CVSSHistory.id).all()
    assert [h.cvss_score for h in history] == [5.0, 8.8]


def test_upsert_cve_score_decrease_is_not_flagged_as_increase(db_session):
    upsert_cve(db_session, make_normalized(cvss_score=8.0))
    db_session.commit()
    _, _, score_increased = upsert_cve(db_session, make_normalized(cvss_score=5.0))
    assert score_increased is False


def test_upsert_cve_merges_cwe_cpe_and_references_meta_across_sources(db_session):
    upsert_cve(db_session, make_normalized(
        cwe_ids=["CWE-79"],
        affected_cpes=["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"],
        references_meta=[{"url": "https://a.example/advisory", "tags": ["Third Party Advisory"]}],
    ))
    db_session.commit()

    cve, _, _ = upsert_cve(db_session, make_normalized(
        source="github_advisories",
        cwe_ids=["CWE-89"],
        affected_cpes=["cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"],
        # Même URL que la première source mais tags mis à jour -> doit remplacer, pas dupliquer.
        references_meta=[{"url": "https://a.example/advisory", "tags": ["Patch"]}],
    ))
    db_session.commit()

    assert cve.cwe_ids == ["CWE-79", "CWE-89"]
    assert cve.affected_cpes == [
        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*",
    ]
    assert cve.references_meta == [{"url": "https://a.example/advisory", "tags": ["Patch"]}]


def test_dispatch_alerts_respects_dedupe_by_default(db_session, monkeypatch):
    monkeypatch.setattr("app.ingest.already_alerted_recently", lambda db, cve_id, channel: True)
    monkeypatch.setattr("app.ingest.send_slack_alert", lambda cve, reasons: True)
    monkeypatch.setattr("app.ingest.send_email_alert", lambda cve, reasons: True)
    monkeypatch.setattr("app.ingest.send_generic_webhook", lambda cve, reasons: True)

    cve = CVE(cve_id="CVE-2026-0002", cvss_score=9.0, severity="CRITICAL")
    db_session.add(cve)
    db_session.commit()

    sent = dispatch_alerts(db_session, cve, watchlist=[])
    assert sent == []  # déjà alerté récemment sur tous les canaux, pas de force_realert


def test_dispatch_alerts_force_realert_bypasses_dedupe(db_session, monkeypatch):
    monkeypatch.setattr("app.ingest.already_alerted_recently", lambda db, cve_id, channel: True)
    monkeypatch.setattr("app.ingest.send_slack_alert", lambda cve, reasons: True)
    monkeypatch.setattr("app.ingest.send_email_alert", lambda cve, reasons: True)
    monkeypatch.setattr("app.ingest.send_generic_webhook", lambda cve, reasons: True)

    cve = CVE(cve_id="CVE-2026-0003", cvss_score=9.0, severity="CRITICAL")
    db_session.add(cve)
    db_session.commit()

    sent = dispatch_alerts(db_session, cve, watchlist=[], force_realert=True)
    assert set(sent) == {"slack", "email", "webhook"}


def test_enrich_has_poc_from_exploitdb_updates_matching_cves(db_session, monkeypatch):
    db_session.add(CVE(cve_id="CVE-2026-0004", has_poc=False, poc_links=[]))
    db_session.add(CVE(cve_id="CVE-2026-9999", has_poc=False, poc_links=[]))  # pas dans l'index
    db_session.commit()

    monkeypatch.setattr(
        ExploitDbConnector, "fetch_index",
        lambda self: {"CVE-2026-0004": ["https://www.exploit-db.com/exploits/1"]},
    )

    summary = enrich_has_poc_from_exploitdb(db_session)
    assert summary["error"] is None
    assert summary["new"] == 1

    updated = db_session.get(CVE, "CVE-2026-0004")
    untouched = db_session.get(CVE, "CVE-2026-9999")
    assert updated.has_poc is True
    assert updated.poc_links == ["https://www.exploit-db.com/exploits/1"]
    assert untouched.has_poc is False


def test_enrich_has_poc_from_exploitdb_reports_connector_error(db_session, monkeypatch):
    def raise_error(self):
        raise ConnectorError("boom")

    monkeypatch.setattr(ExploitDbConnector, "fetch_index", raise_error)
    summary = enrich_has_poc_from_exploitdb(db_session)
    assert summary["error"] == "boom"
    assert summary["new"] == 0


def test_enrich_threat_context_merges_otx_and_misp(db_session, monkeypatch):
    db_session.add(CVE(cve_id="CVE-2026-0005"))
    db_session.commit()

    monkeypatch.setattr(OtxEnricher, "enrich", lambda self, cve_id: {"pulse_count": 3, "tags": ["ransomware"]})
    monkeypatch.setattr(MispEnricher, "enrich", lambda self, cve_id: None)  # non configuré -> no-op

    summary = enrich_threat_context(db_session, ["CVE-2026-0005"])
    assert summary["new"] == 1

    cve = db_session.get(CVE, "CVE-2026-0005")
    assert cve.threat_context == {"otx": {"pulse_count": 3, "tags": ["ransomware"]}}


def test_enrich_epss_scores_updates_matching_cves_and_tracks_source_state(db_session, monkeypatch):
    db_session.add(CVE(cve_id="CVE-2026-0006"))
    db_session.add(CVE(cve_id="CVE-2026-9998"))  # pas dans l'index EPSS
    db_session.commit()

    monkeypatch.setattr(EpssEnricher, "fetch_index", lambda self: {"CVE-2026-0006": (0.87, 0.95)})

    summary = enrich_epss_scores(db_session)
    assert summary["error"] is None
    assert summary["new"] == 1

    updated = db_session.get(CVE, "CVE-2026-0006")
    untouched = db_session.get(CVE, "CVE-2026-9998")
    assert (updated.epss_score, updated.epss_percentile) == (0.87, 0.95)
    assert untouched.epss_score is None

    state = db_session.get(SourceState, "epss")
    assert state is not None
    assert state.last_error is None


def test_enrich_epss_scores_reports_connector_error(db_session, monkeypatch):
    def raise_error(self):
        raise ConnectorError("boom")

    monkeypatch.setattr(EpssEnricher, "fetch_index", raise_error)
    summary = enrich_epss_scores(db_session)
    assert summary["error"] == "boom"
    assert summary["new"] == 0


def test_record_poc_discovery_creates_stub_cve_when_unknown(db_session):
    created, sent = record_poc_discovery(
        db_session, "CVE-2026-4242", "https://github.com/a/poc", "github_poc", watchlist=[],
        repo_full_name="a/poc", stars=10,
    )
    assert created is True
    cve = db_session.get(CVE, "CVE-2026-4242")
    assert cve is not None
    assert cve.has_poc is True
    assert cve.poc_links == ["https://github.com/a/poc"]
    assert is_unconfirmed(cve) is True  # aucune source structurée (nvd/kev/ghsa) ne l'a vue
    link = db_session.query(PocLink).filter_by(cve_id="CVE-2026-4242").one()
    assert link.repo_full_name == "a/poc"
    assert link.stars == 10


def test_record_poc_discovery_does_not_overwrite_existing_cve_data(db_session):
    upsert_cve(db_session, make_normalized(cve_id="CVE-2026-4243", description="Real NVD description"))
    db_session.commit()

    record_poc_discovery(db_session, "CVE-2026-4243", "https://github.com/a/poc2", "github_poc", watchlist=[])

    cve = db_session.get(CVE, "CVE-2026-4243")
    assert cve.description == "Real NVD description"  # jamais dégradée par une découverte de PoC
    assert is_unconfirmed(cve) is False  # vue par nvd -> pas une stub


def test_record_poc_discovery_dedupes_by_url_across_calls(db_session):
    created_1, _ = record_poc_discovery(db_session, "CVE-2026-4244", "https://github.com/a/poc3", "github_poc", watchlist=[])
    created_2, _ = record_poc_discovery(db_session, "CVE-2026-4244", "https://github.com/a/poc3", "github_poc", watchlist=[])
    assert created_1 is True
    assert created_2 is False
    assert db_session.query(PocLink).filter_by(url="https://github.com/a/poc3").count() == 1


def test_enrich_github_poc_records_discoveries_and_tracks_source_state(db_session, monkeypatch):
    monkeypatch.setattr(
        GithubPocConnector, "fetch_recent",
        lambda self: [{"cve_id": "CVE-2026-4245", "url": "https://github.com/a/poc4",
                       "repo_full_name": "a/poc4", "stars": 5, "source": "github_poc"}],
    )
    summary = enrich_github_poc(db_session)
    assert summary["error"] is None
    assert summary["new"] == 1
    assert db_session.get(CVE, "CVE-2026-4245") is not None
    state = db_session.get(SourceState, "github_poc")
    assert state is not None


def test_enrich_github_poc_reports_connector_error(db_session, monkeypatch):
    def raise_error(self):
        raise ConnectorError("boom")

    monkeypatch.setattr(GithubPocConnector, "fetch_recent", raise_error)
    summary = enrich_github_poc(db_session)
    assert summary["error"] == "boom"
    assert summary["new"] == 0


def test_enrich_threat_context_empty_list_is_noop(db_session):
    summary = enrich_threat_context(db_session, [])
    assert summary == {"source": "threat_context", "fetched": 0, "new": 0, "alerts_sent": 0, "error": None}
