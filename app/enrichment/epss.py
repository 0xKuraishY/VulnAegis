"""Enrichissement EPSS (Exploit Prediction Scoring System, FIRST.org) - score prédictif gratuit.

Contrairement à Exploit-DB (qui indique qu'un PoC existe), EPSS prédit la probabilité qu'une CVE
soit exploitée dans les 30 jours à venir, à partir d'un modèle entraîné sur des données réelles
d'exploitation. Publié quotidiennement en clair (CSV gzippé), sans clé ni quota - même logique de
cross-join qu'Exploit-DB (téléchargement d'un index complet, une fois par cycle, croisé avec les
CVE déjà en base) plutôt qu'un appel par CVE. Purement informatif : n'influence pas le moteur de
règles d'alerte (app/alerting/rules.py).
Doc: https://www.first.org/epss/
"""
import csv
import gzip
import logging

import requests

from app.connectors.base import ConnectorError
from app.connectors.http import build_session

logger = logging.getLogger(__name__)

EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class EpssEnricher:
    name = "epss"

    def __init__(self, session: requests.Session | None = None):
        self.session = session or build_session()

    def fetch_index(self) -> dict[str, tuple[float, float]]:
        """Retourne {cve_id: (score, percentile)} pour l'ensemble du jeu de données EPSS du jour."""
        try:
            resp = self.session.get(EPSS_CSV_URL, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise ConnectorError(f"EPSS fetch failed: {exc}") from exc

        raw = resp.content
        try:
            raw = gzip.decompress(raw)
        except OSError:
            pass  # déjà décompressé (ex: si le serveur/proxy annonce Content-Encoding: gzip)

        index: dict[str, tuple[float, float]] = {}
        text = raw.decode("utf-8")
        # La première ligne est un commentaire de métadonnées ("#model_version:...,score_date:..."),
        # pas l'en-tête CSV -> on la retire avant de passer à DictReader.
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        for row in csv.DictReader(lines):
            cve_id = (row.get("cve") or "").strip().upper()
            if not cve_id:
                continue
            try:
                index[cve_id] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, ValueError):
                continue
        return index
