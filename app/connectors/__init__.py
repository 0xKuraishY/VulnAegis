from app.connectors.base import BaseConnector
from app.connectors.cisa_kev import CisaKevConnector
from app.connectors.exploitdb import ExploitDbConnector
from app.connectors.github_advisories import GitHubAdvisoriesConnector
from app.connectors.nvd import NvdConnector
from app.connectors.osv import OsvEnricher

# Registre des connecteurs "pollers" (récupèrent une liste de CVE récentes/modifiées).
# Ajouter une nouvelle source = écrire une classe BaseConnector + l'enregistrer ici.
CONNECTOR_REGISTRY: list[type[BaseConnector]] = [
    NvdConnector,
    CisaKevConnector,
    GitHubAdvisoriesConnector,
]

__all__ = [
    "BaseConnector",
    "CisaKevConnector",
    "ExploitDbConnector",
    "GitHubAdvisoriesConnector",
    "NvdConnector",
    "OsvEnricher",
    "CONNECTOR_REGISTRY",
]
