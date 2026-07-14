"""Connecteur NVD (NIST) - API REST 2.0.

Doc: https://nvd.nist.gov/developers/vulnerabilities
Quota public: 5 requêtes / 30s (50 avec une clé API gratuite sur demande).
"""
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import requests

from app.config import settings
from app.connectors.base import BaseConnector, ConnectorError
from app.connectors.http import build_session
from app.schemas import NormalizedCVE

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 200
# La fenêtre lastMod max autorisée par l'API NVD est de 120 jours.
MAX_WINDOW_DAYS = 120
# Plafond sur le nombre de CPE affectés stockés par CVE : certaines CVE matériel (ex: familles
# Snapdragon) listent des centaines de critères CPE, ce qui gonflerait inutilement chaque ligne.
MAX_AFFECTED_CPES = 200
_CWE_PATTERN = re.compile(r"^CWE-\d+$")


def _extract_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
            data = primary.get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString")
            severity = data.get("baseSeverity") or primary.get("baseSeverity")
            return score, vector, severity
    return None, None, None


def _iso_with_colon_offset(dt: datetime) -> str:
    # strftime("%z") produit "+0000" (sans ':'), que l'API NVD rejette (404). Elle exige
    # un offset ISO-8601 complet du type "+00:00".
    raw = dt.strftime("%Y-%m-%dT%H:%M:%S.000%z")
    return f"{raw[:-2]}:{raw[-2:]}" if raw[-5] in "+-" else raw


def _extract_cwe_ids(weaknesses: list[dict]) -> list[str]:
    ids = set()
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = (desc.get("value") or "").strip().upper()
            if _CWE_PATTERN.match(value):
                ids.add(value)
    return sorted(ids)


def _extract_affected_cpes(configurations: list[dict]) -> list[str]:
    cpes: list[str] = []
    seen = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria")
                if criteria and criteria not in seen:
                    seen.add(criteria)
                    cpes.append(criteria)
                    if len(cpes) >= MAX_AFFECTED_CPES:
                        return cpes
    return cpes


def _extract_references_meta(references: list[dict]) -> list[dict]:
    return [{"url": r["url"], "tags": r.get("tags", [])} for r in references if r.get("url")]


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


class NvdConnector(BaseConnector):
    name = "nvd"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or build_session()

    def _headers(self) -> dict:
        headers = {"Accept": "application/json"}
        if settings.nvd_api_key:
            headers["apiKey"] = settings.nvd_api_key
        return headers

    def fetch_since(self, since: datetime | None) -> list[NormalizedCVE]:
        now = datetime.now(timezone.utc)
        start = since or (now - timedelta(days=1))
        if now - start > timedelta(days=MAX_WINDOW_DAYS):
            start = now - timedelta(days=MAX_WINDOW_DAYS)

        results: list[NormalizedCVE] = []
        start_index = 0
        total_results = None
        # Sans clé API, on reste sous 5 req/30s -> on attend entre les pages.
        delay = 0.6 if settings.nvd_api_key else 6.0

        while total_results is None or start_index < total_results:
            params = {
                "lastModStartDate": _iso_with_colon_offset(start),
                "lastModEndDate": _iso_with_colon_offset(now),
                "resultsPerPage": PAGE_SIZE,
                "startIndex": start_index,
            }
            try:
                resp = self.session.get(NVD_API_URL, params=params, headers=self._headers(), timeout=30)
                resp.raise_for_status()
            except requests.RequestException as exc:
                raise ConnectorError(f"NVD fetch failed: {exc}") from exc

            payload = resp.json()
            total_results = payload.get("totalResults", 0)
            for item in payload.get("vulnerabilities", []):
                cve = item.get("cve", {})
                results.append(self._normalize(cve))

            start_index += PAGE_SIZE
            if start_index < total_results:
                time.sleep(delay)

        return results

    def _normalize(self, cve: dict) -> NormalizedCVE:
        cve_id = cve["id"]
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        score, vector, severity = _extract_cvss(cve.get("metrics", {}))
        severity = severity or _severity_from_score(score)

        references = [r.get("url") for r in cve.get("references", []) if r.get("url")]

        vendor = product = None
        configs = cve.get("configurations", [])
        for config in configs:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    if len(parts) > 4:
                        vendor, product = parts[3], parts[4]
                        break
                if vendor:
                    break
            if vendor:
                break

        return NormalizedCVE(
            cve_id=cve_id,
            source=self.name,
            description=description,
            cvss_score=score,
            cvss_vector=vector,
            severity=severity,
            vendor=vendor,
            product=product,
            published_date=cve.get("published"),
            last_modified_date=cve.get("lastModified"),
            references=references,
            cwe_ids=_extract_cwe_ids(cve.get("weaknesses", [])),
            affected_cpes=_extract_affected_cpes(configs),
            references_meta=_extract_references_meta(cve.get("references", [])),
            raw=cve,
        )
