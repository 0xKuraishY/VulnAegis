"""Connecteur "Radar PoC" GitHub - découverte de repos de PoC pour des CVE très récentes.

Contrairement aux connecteurs classiques (métadonnées CVE), celui-ci répond à une question
différente : "un repo GitHub vient-il d'apparaître pour telle CVE ?". Il ne retourne donc pas des
NormalizedCVE mais des découvertes de PoC brutes (voir app.ingest.record_poc_discovery), sur son
propre job planifié à cadence courte (voir app.scheduler.github_poc_job), volontairement découplé
du poll principal pour rester "temps réel" même quand un gros backfill NVD est en cours.

API utilisée : GitHub REST Search (repositories), gratuite et sans clé (10 req/min ; 30 req/min
avec GITHUB_TOKEN, déjà utilisé par app.connectors.github_advisories). Le nombre de requêtes par
cycle est fixe (une par année scannée) pour rester très en dessous du quota même à cadence de
quelques minutes.
Doc: https://docs.github.com/en/rest/search/search#search-repositories
"""
import logging
import re
from datetime import datetime, timezone

import requests

from app.config import settings
from app.connectors.base import ConnectorError
from app.connectors.http import build_session
from app.schemas import normalize_cve_id

logger = logging.getLogger(__name__)

GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
PER_PAGE = 30
# Années CVE scannées en plus de l'année courante : une CVE "de l'an dernier" reçoit encore
# régulièrement de nouveaux PoC en début d'année suivante.
YEARS_BACK = 1

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,19}", re.IGNORECASE)


class GithubPocConnector:
    name = "github_poc"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or build_session()

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
        return headers

    def fetch_recent(self) -> list[dict]:
        """Retourne une liste de découvertes {cve_id, url, repo_full_name, stars, source}, une par
        (CVE, repo) trouvée. Le dédoublonnage inter-cycles (par URL) est géré par
        app.ingest.record_poc_discovery ; celui-ci ne dédoublonne qu'au sein du cycle courant."""
        current_year = datetime.now(timezone.utc).year
        discoveries: list[dict] = []
        seen = set()

        for year in range(current_year - YEARS_BACK, current_year + 1):
            for item in self._search_year(year):
                cve_id = self._extract_cve_id(item)
                url = item.get("html_url")
                if not cve_id or not url or (cve_id, url) in seen:
                    continue
                seen.add((cve_id, url))
                discoveries.append({
                    "cve_id": cve_id,
                    "url": url,
                    "repo_full_name": item.get("full_name"),
                    "stars": item.get("stargazers_count"),
                    "source": self.name,
                })
        return discoveries

    def _search_year(self, year: int) -> list[dict]:
        params = {
            "q": f"CVE-{year} in:name,description",
            "sort": "updated",
            "order": "desc",
            "per_page": PER_PAGE,
        }
        try:
            resp = self.session.get(GITHUB_SEARCH_URL, params=params, headers=self._headers(), timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ConnectorError(f"GitHub PoC search failed for {year}: {exc}") from exc
        return resp.json().get("items", [])

    @staticmethod
    def _extract_cve_id(item: dict) -> str | None:
        haystack = " ".join(filter(None, [item.get("name"), item.get("description")]))
        match = _CVE_PATTERN.search(haystack)
        return normalize_cve_id(match.group(0)) if match else None
