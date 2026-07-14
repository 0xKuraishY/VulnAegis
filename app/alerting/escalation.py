"""Escalade automatique : alerte critique non acquittée sous X heures -> notif niveau supérieur."""
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import CVE, AlertLog

logger = logging.getLogger(__name__)


def run_escalation_check(db: Session) -> int:
    cutoff = datetime.utcnow() - timedelta(hours=settings.escalation_hours)
    stmt = (
        select(AlertLog)
        .join(CVE)
        .where(
            AlertLog.acknowledged.is_(False),
            AlertLog.escalated.is_(False),
            AlertLog.sent_at <= cutoff,
        )
        .where((CVE.is_kev.is_(True)) | (CVE.severity == "CRITICAL"))
    )
    pending = db.execute(stmt).scalars().all()

    escalated = 0
    for alert in pending:
        if _notify_escalation(alert):
            alert.escalated = True
            escalated += 1
    if escalated:
        db.commit()
    return escalated


def _notify_escalation(alert: AlertLog) -> bool:
    import requests

    url = settings.escalation_slack_webhook_url or settings.slack_webhook_url
    if not url:
        logger.warning(
            "Escalade requise pour %s (alerte #%s non acquittée depuis %sh) mais aucun canal configuré",
            alert.cve_id,
            alert.id,
            settings.escalation_hours,
        )
        return False
    text = (
        f":warning: *ESCALADE* - {alert.cve_id} non acquittée depuis plus de "
        f"{settings.escalation_hours}h (alerte initiale du {alert.sent_at.isoformat()})"
    )
    try:
        resp = requests.post(url, json={"text": text}, timeout=10)
        resp.raise_for_status()
        return True
    except requests.RequestException:
        logger.exception("Échec notification d'escalade Slack pour %s", alert.cve_id)
        return False
