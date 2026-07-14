"""Enrichissement contexte menace via un MISP auto-hébergé - optionnel, no-op si non configuré
(même pattern que app/alerting/webhook.py : silencieux tant que MISP_URL/MISP_API_KEY sont vides).
"""
import logging

import requests

from app.config import settings
from app.connectors.base import ConnectorError
from app.connectors.http import build_session

logger = logging.getLogger(__name__)
_MAX_EVENTS = 20


class MispEnricher:
    name = "misp"

    def __init__(self, session: requests.Session | None = None):
        # Cf. OtxEnricher : timeout court et peu de retries, appelé une fois par CVE par cycle.
        self.session = session or build_session(total_retries=1, backoff_factor=0.5)

    def enrich(self, cve_id: str) -> dict | None:
        if not (settings.misp_url and settings.misp_api_key):
            return None

        url = settings.misp_url.rstrip("/") + "/attributes/restSearch"
        headers = {
            "Authorization": settings.misp_api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        try:
            resp = self.session.post(
                url, json={"value": cve_id, "type": "vulnerability"}, headers=headers, timeout=6
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ConnectorError(f"MISP enrich failed for {cve_id}: {exc}") from exc

        attributes = (resp.json().get("response") or {}).get("Attribute") or []
        event_ids = sorted({a["event_id"] for a in attributes if a.get("event_id")})
        return {"event_count": len(event_ids), "event_ids": event_ids[:_MAX_EVENTS]}
