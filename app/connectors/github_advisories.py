"""Connecteur GitHub Security Advisories (GHSA) - API REST.

Doc: https://docs.github.com/en/rest/security-advisories/global-advisories
Quota: 60 req/h non authentifié, 5000 req/h avec un token (GITHUB_TOKEN).
"""
import logging
from datetime import datetime, timedelta, timezone

import requests

from app.config import settings
from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.http import build_session
from app.schemas import NormalizedCVE

logger = logging.getLogger(__name__)

GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
PAGE_SIZE = 100

# GHSA utilise "moderate" là où NVD/notre modèle utilisent "MEDIUM".
_SEVERITY_MAP = {"LOW": "LOW", "MODERATE": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}


class GitHubAdvisoriesConnector(BaseConnector):
    name = "github_advisories"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or build_session()

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        return headers

    def fetch_since(self, since: datetime | None) -> list[NormalizedCVE]:
        start = since or (datetime.now(timezone.utc) - timedelta(days=1))
        params = {
            "updated": f">={start.strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "per_page": PAGE_SIZE,
            "sort": "updated",
            "direction": "asc",
        }
        results: list[NormalizedCVE] = []
        url = GITHUB_ADVISORIES_URL

        while url:
            try:
                resp = self.session.get(url, params=params, headers=self._headers(), timeout=30)
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise ConnectorError(f"GitHub Advisories fetch failed: {exc}") from exc

            for advisory in resp.json():
                cve_id = advisory.get("cve_id")
                if not cve_id:
                    continue  # advisory sans CVE assignée (ex: GHSA-only) -> hors périmètre
                results.append(self._normalize(advisory))

            # Pagination RFC5988 via l'en-tête Link.
            url = resp.links.get("next", {}).get("url")
            params = None  # déjà encodés dans l'URL "next"

        return results

    def _normalize(self, advisory: dict) -> NormalizedCVE:
        vendor = product = None
        vulnerabilities = advisory.get("vulnerabilities") or []
        if vulnerabilities:
            pkg = vulnerabilities[0].get("package") or {}
            product = pkg.get("name")
            vendor = pkg.get("ecosystem")

        cvss = advisory.get("cvss") or {}
        severity = _SEVERITY_MAP.get((advisory.get("severity") or "").upper())

        return NormalizedCVE(
            cve_id=advisory["cve_id"],
            source=self.name,
            description=advisory.get("summary", ""),
            cvss_score=cvss.get("score"),
            cvss_vector=cvss.get("vector_string"),
            severity=severity,
            vendor=vendor,
            product=product,
            published_date=advisory.get("published_at"),
            last_modified_date=advisory.get("updated_at"),
            references=[r for r in [advisory.get("html_url")] + [
                ref.get("url") for ref in advisory.get("references", []) if isinstance(ref, dict)
            ] if r],
            raw=advisory,
        )
