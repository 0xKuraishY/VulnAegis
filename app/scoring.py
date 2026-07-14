"""Score de risque composite (0-100) par CVE.

Combine CVSS, statut KEV, EPSS, disponibilité d'un PoC public et contexte
menace (OTX/MISP) en une note unique et explicable ("breakdown"), utilisée
pour le tri/affichage. Contrairement à `app.alerting.rules`, ce module ne
prend aucune décision d'alerte et n'a aucun effet de bord : c'est une
fonction pure de triage, recalculée à la volée en lecture.

Les clés `factor` du breakdown sont des identifiants machine stables (pas de
texte traduit) : le frontend les mappe vers des clés i18n via `t()`.
"""
from dataclasses import dataclass, field
from datetime import datetime

from app.config import settings
from app.models import CVE

_CVSS_MAX_POINTS = 40.0
_KEV_POINTS = 20.0
_KEV_OVERDUE_POINTS = 5.0
_EPSS_MAX_POINTS = 20.0
_POC_SEVERE_POINTS = 10.0
_POC_POINTS = 5.0
_THREAT_OTX_POINTS = 2.0
_THREAT_MISP_POINTS = 3.0
_STALENESS_MALUS = 10.0

_LEVEL_THRESHOLDS = (
    (80, "critical"),
    (60, "high"),
    (35, "medium"),
    (15, "low"),
)


@dataclass
class RiskBreakdownItem:
    factor: str
    points: float
    value: float | bool | None = None


@dataclass
class RiskScore:
    score: int
    level: str
    breakdown: list[RiskBreakdownItem] = field(default_factory=list)


def is_weaponization_risk(cve: CVE) -> bool:
    """CVE avec PoC public et déjà critique/exploitée activement -> risque d'exploitation imminente."""
    return bool(cve.has_poc and (cve.is_kev or (cve.cvss_score is not None and cve.cvss_score >= 9.0)))


def _level_for(score: int) -> str:
    for threshold, level in _LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "info"


def compute_risk_score(cve: CVE, *, now: datetime | None = None) -> RiskScore:
    now = now or datetime.utcnow()
    breakdown: list[RiskBreakdownItem] = []
    total = 0.0

    if cve.cvss_score is not None:
        points = (cve.cvss_score / 10.0) * _CVSS_MAX_POINTS
        total += points
        breakdown.append(RiskBreakdownItem(factor="cvss", points=round(points, 1), value=cve.cvss_score))

    if cve.is_kev:
        points = _KEV_POINTS
        overdue = bool(cve.kev_due_date is not None and cve.kev_due_date < now)
        if overdue:
            points += _KEV_OVERDUE_POINTS
        total += points
        breakdown.append(RiskBreakdownItem(factor="kev_overdue" if overdue else "kev", points=round(points, 1), value=True))

    if cve.epss_score is not None:
        points = cve.epss_score * _EPSS_MAX_POINTS
        total += points
        breakdown.append(RiskBreakdownItem(factor="epss", points=round(points, 1), value=cve.epss_score))

    if cve.has_poc:
        severe = is_weaponization_risk(cve)
        points = _POC_SEVERE_POINTS if severe else _POC_POINTS
        total += points
        breakdown.append(RiskBreakdownItem(factor="poc_severe" if severe else "poc", points=points, value=True))

    threat_context = cve.threat_context or {}
    otx_pulses = (threat_context.get("otx") or {}).get("pulse_count") or 0
    misp_events = (threat_context.get("misp") or {}).get("event_count") or 0
    if otx_pulses > 0:
        total += _THREAT_OTX_POINTS
        breakdown.append(RiskBreakdownItem(factor="threat_otx", points=_THREAT_OTX_POINTS, value=otx_pulses))
    if misp_events > 0:
        total += _THREAT_MISP_POINTS
        breakdown.append(RiskBreakdownItem(factor="threat_misp", points=_THREAT_MISP_POINTS, value=misp_events))

    reference_date = cve.last_modified_date or cve.published_date
    if (
        not cve.is_kev
        and not cve.has_poc
        and (cve.epss_score is None or cve.epss_score < 0.05)
        and reference_date is not None
        and (now - reference_date).days > settings.risk_score_stale_days
    ):
        total -= _STALENESS_MALUS
        breakdown.append(RiskBreakdownItem(factor="staleness", points=-_STALENESS_MALUS, value=(now - reference_date).days))

    score = max(0, min(100, round(total)))
    return RiskScore(score=score, level=_level_for(score), breakdown=breakdown)
