"""Attache aux objets CVE les attributs calculés à la volée (non persistés) : pourquoi une CVE
déclencherait une alerte (app.alerting.rules) et son score de risque composite (app.scoring).

Module séparé de app.api.routes_cves pour être réutilisable par app.ingest (paquets diffusés en
WebSocket) sans créer d'import circulaire (routes_cves importe déjà des symboles d'ingest)."""
from app.alerting.rules import evaluate
from app.models import CVE, WatchlistEntry
from app.scoring import compute_risk_score, is_weaponization_risk


def annotate_cve(cve: CVE, watchlist: list[WatchlistEntry]) -> CVE:
    result = evaluate(cve, watchlist)
    cve.is_flagged = result.should_alert
    cve.flag_reasons = result.reasons
    risk = compute_risk_score(cve)
    cve.risk_score = risk.score
    cve.risk_level = risk.level
    cve.risk_breakdown = risk.breakdown
    cve.is_weaponization_risk = is_weaponization_risk(cve)
    return cve
