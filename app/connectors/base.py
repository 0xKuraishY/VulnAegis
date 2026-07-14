"""Interface commune à tous les connecteurs de sources CVE.

Pour ajouter une nouvelle source (ex: bulletin éditeur, flux RSS...), il suffit
d'implémenter `fetch_since` et de retourner une liste de `NormalizedCVE`. Le
reste du pipeline (upsert DB, règles d'alerte, dédoublonnage, notifications)
est totalement agnostique de la source d'origine.
"""
from abc import ABC, abstractmethod
from datetime import datetime

from app.schemas import NormalizedCVE


class BaseConnector(ABC):
    name: str = "base"

    @abstractmethod
    def fetch_since(self, since: datetime | None) -> list[NormalizedCVE]:
        """Retourne les CVE publiées/modifiées depuis `since` (ou un jeu initial si None)."""
        raise NotImplementedError


class ConnectorError(Exception):
    """Erreur récupérable levée par un connecteur (réseau, quota, parsing)."""
