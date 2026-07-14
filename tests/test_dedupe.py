from datetime import datetime, timedelta

from app.alerting.dedupe import already_alerted_recently
from app.config import settings
from app.models import AlertLog


def test_not_alerted_when_no_history(db_session):
    assert already_alerted_recently(db_session, "CVE-2026-0001", "slack") is False


def test_alerted_recently_within_window(db_session):
    db_session.add(AlertLog(cve_id="CVE-2026-0002", channel="slack", reasons=[], sent_at=datetime.utcnow()))
    db_session.commit()
    assert already_alerted_recently(db_session, "CVE-2026-0002", "slack") is True


def test_not_alerted_outside_window(db_session):
    old = datetime.utcnow() - timedelta(hours=settings.alert_dedupe_hours + 1)
    db_session.add(AlertLog(cve_id="CVE-2026-0003", channel="slack", reasons=[], sent_at=old))
    db_session.commit()
    assert already_alerted_recently(db_session, "CVE-2026-0003", "slack") is False


def test_channel_is_isolated(db_session):
    db_session.add(AlertLog(cve_id="CVE-2026-0004", channel="slack", reasons=[], sent_at=datetime.utcnow()))
    db_session.commit()
    assert already_alerted_recently(db_session, "CVE-2026-0004", "email") is False
