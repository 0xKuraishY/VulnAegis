"""Enrichisseur OSV.dev.

OSV ne propose pas de "flux des CVE récentes" en REST public (les mises à jour
en masse se font via leur export GCS). Il est en revanche excellent pour
enrichir une CVE déjà connue avec les paquets/écosystèmes affectés (npm,
PyPI, Go, crates.io...) et les plages de versions vulnérables précises.

Ce connecteur est donc un *enrichisseur* appelé à la demande sur une CVE
donnée (ex: après ingestion NVD/GitHub), pas un poller autonome - il n'est
pas dans CONNECTOR_REGISTRY.
Doc: https://osv.dev/docs/
"""
import logging

import requests

from app.connectors.base import ConnectorError
from app.connectors.http import build_session

logger = logging.getLogger(__name__)

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvEnricher:
    name = "osv"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or build_session()

    def enrich(self, cve_id: str) -> dict | None:
        """Retourne la charge OSV correspondant à une CVE via recherche par alias, ou None."""
        try:
            resp = self.session.post(OSV_QUERY_URL, json={"alias": cve_id}, timeout=15)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ConnectorError(f"OSV enrich failed for {cve_id}: {exc}") from exc

        vulns = resp.json().get("vulns", [])
        return vulns[0] if vulns else None

    def affected_packages(self, osv_entry: dict) -> list[str]:
        packages = []
        for affected in osv_entry.get("affected", []):
            pkg = affected.get("package", {})
            name = pkg.get("name")
            ecosystem = pkg.get("ecosystem")
            if name:
                packages.append(f"{ecosystem}:{name}" if ecosystem else name)
        return packages
