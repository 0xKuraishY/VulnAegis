"""Moteur de règles : décide si une CVE doit générer une alerte, et pourquoi.

Le "pourquoi" (reasons) est conservé sur l'AlertLog et injecté dans les
messages Slack/email pour que l'analyste comprenne immédiatement le
déclencheur (évite le syndrome "pourquoi je reçois ça ?").
"""
from dataclasses import dataclass

from app.config import settings
from app.models import CVE, WatchlistEntry
from app.scoring import is_weaponization_risk


@dataclass
class RuleResult:
    should_alert: bool
    reasons: list[str]


def _matches_watchlist(cve: CVE, watchlist: list[WatchlistEntry]) -> str | None:
    haystack = " ".join(filter(None, [cve.vendor, cve.product, cve.description])).lower()
    for entry in watchlist:
        if entry.vendor and cve.vendor and entry.vendor.lower() in cve.vendor.lower():
            if not entry.product or (cve.product and entry.product.lower() in cve.product.lower()):
                return f"asset surveillé: {entry.vendor}" + (f"/{entry.product}" if entry.product else "")
        if entry.keyword and entry.keyword.lower() in haystack:
            return f"mot-clé surveillé: {entry.keyword}"
    return None


def evaluate(cve: CVE, watchlist: list[WatchlistEntry]) -> RuleResult:
    reasons: list[str] = []

    if cve.is_kev:
        reasons.append("exploitée activement (CISA KEV)")

    if cve.cvss_score is not None and cve.cvss_score >= settings.cvss_alert_threshold:
        reasons.append(f"CVSS {cve.cvss_score} >= seuil {settings.cvss_alert_threshold}")

    if cve.has_poc:
        if is_weaponization_risk(cve):
            reasons.append("PoC public + CVE critique/exploitée = risque d'exploitation imminente")
        else:
            reasons.append("PoC public disponible")

    watchlist_hit = _matches_watchlist(cve, watchlist)
    if watchlist_hit:
        reasons.append(watchlist_hit)

    return RuleResult(should_alert=bool(reasons), reasons=reasons)
