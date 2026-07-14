"""Connecteur CISA KEV (Known Exploited Vulnerabilities).

Flux JSON public, mis à jour par la CISA dès qu'une CVE est confirmée comme
activement exploitée. Pas de pagination, pas d'auth, tout le catalogue est
retéléchargé à chaque poll puis diffé côté pipeline (le fichier fait ~qq Mo).
Doc: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
import logging
from datetime import datetime, timezone

import requests

from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.http import build_session
from app.schemas import NormalizedCVE

logger = logging.getLogger(__name__)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevConnector(BaseConnector):
    name = "cisa_kev"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or build_session()

    def fetch_since(self, since: datetime | None) -> list[NormalizedCVE]:
        try:
            resp = self.session.get(KEV_FEED_URL, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ConnectorError(f"CISA KEV fetch failed: {exc}") from exc

        payload = resp.json()
        results = []
        for vuln in payload.get("vulnerabilities", []):
            date_added = _parse_date(vuln.get("dateAdded"))
            if since and date_added and date_added.replace(tzinfo=timezone.utc) < since:
                continue
            results.append(self._normalize(vuln))
        return results

    def _normalize(self, vuln: dict) -> NormalizedCVE:
        return NormalizedCVE(
            cve_id=vuln["cveID"],
            source=self.name,
            description=vuln.get("shortDescription", ""),
            vendor=vuln.get("vendorProject"),
            product=vuln.get("product"),
            is_kev=True,
            kev_date_added=_parse_date(vuln.get("dateAdded")),
            kev_due_date=_parse_date(vuln.get("dueDate")),
            kev_ransomware_use=vuln.get("knownRansomwareCampaignUse"),
            references=[],
            raw=vuln,
        )


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None
