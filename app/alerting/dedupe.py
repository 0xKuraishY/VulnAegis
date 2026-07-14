"""Évite de renvoyer la même alerte (CVE + canal) en boucle à chaque poll."""
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models import AlertLog


def already_alerted_recently(db: Session, cve_id: str, channel: str) -> bool:
    cutoff = datetime.utcnow() - timedelta(hours=settings.alert_dedupe_hours)
    stmt = (
        select(AlertLog.id)
        .where(AlertLog.cve_id == cve_id, AlertLog.channel == channel, AlertLog.sent_at >= cutoff)
        .limit(1)
    )
    return db.execute(stmt).first() is not None
