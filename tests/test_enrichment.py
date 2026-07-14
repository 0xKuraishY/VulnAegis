from unittest.mock import MagicMock

from app.config import settings
from app.enrichment.misp import MispEnricher
from app.enrichment.otx import OtxEnricher

OTX_SAMPLE = {
    "pulse_info": {
        "count": 2,
        "pulses": [{"tags": ["ransomware", "apt"]}, {"tags": ["apt"]}],
    }
}


def test_otx_enricher_extracts_pulse_count_and_dedupes_tags():
    session = MagicMock()
    session.get.return_value.json.return_value = OTX_SAMPLE
    session.get.return_value.raise_for_status.return_value = None

    result = OtxEnricher(session=session).enrich("CVE-2026-0001")
    assert result["pulse_count"] == 2
    assert result["tags"] == ["apt", "ransomware"]


def test_misp_enricher_noop_when_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "misp_url", None)
    monkeypatch.setattr(settings, "misp_api_key", None)
    assert MispEnricher().enrich("CVE-2026-0001") is None


def test_misp_enricher_counts_distinct_events(monkeypatch):
    monkeypatch.setattr(settings, "misp_url", "https://misp.example.org")
    monkeypatch.setattr(settings, "misp_api_key", "key")

    session = MagicMock()
    session.post.return_value.json.return_value = {
        "response": {"Attribute": [{"event_id": "1"}, {"event_id": "1"}, {"event_id": "2"}]}
    }
    session.post.return_value.raise_for_status.return_value = None

    result = MispEnricher(session=session).enrich("CVE-2026-0001")
    assert result == {"event_count": 2, "event_ids": ["1", "2"]}
