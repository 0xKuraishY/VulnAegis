"""Enrichissement contexte menace via AlienVault OTX (pulses liés à une CVE).

Purement informatif : n'influence pas le moteur de règles d'alerte (app/alerting/rules.py),
stocké dans CVE.threat_context pour affichage dashboard/API. L'endpoint est public (fonctionne
sans clé), une clé (OTX_API_KEY, gratuite sur otx.alienvault.com) augmente juste le quota.
"""
import logging

import requests

from app.config import settings
from app.connectors.base import ConnectorError
from app.connectors.http import build_session

logger = logging.getLogger(__name__)

OTX_URL = "https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general"
_MAX_TAGS = 20


class OtxEnricher:
    name = "otx"

    def __init__(self, session: requests.Session | None = None):
        # Peu de retries/timeout court : appelé une fois par CVE nouvellement vue (jusqu'à
        # _MAX_THREAT_CONTEXT_PER_CYCLE par poll), contrairement aux connecteurs qui n'appellent
        # leur source qu'une fois par cycle - les retries larges de build_session() par défaut
        # feraient exploser la durée totale d'un poll si OTX répond lentement.
        self.session = session or build_session(total_retries=1, backoff_factor=0.5)

    def _headers(self) -> dict:
        return {"X-OTX-API-KEY": settings.otx_api_key} if settings.otx_api_key else {}

    def enrich(self, cve_id: str) -> dict | None:
        try:
            resp = self.session.get(OTX_URL.format(cve_id=cve_id), headers=self._headers(), timeout=6)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ConnectorError(f"OTX enrich failed for {cve_id}: {exc}") from exc

        pulse_info = resp.json().get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        tags = sorted({tag for pulse in pulses for tag in (pulse.get("tags") or [])})
        return {"pulse_count": pulse_info.get("count", 0), "tags": tags[:_MAX_TAGS]}
