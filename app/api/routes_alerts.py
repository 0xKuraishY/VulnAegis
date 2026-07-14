import threading
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.ingest import acquire_poll_slot, poll_all_sources, release_poll_slot
from app.models import AlertLog
from app.schemas import AlertOut
from app.security import require_api_key

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

_POLL_COOLDOWN = timedelta(seconds=30)
_last_poll_completed: datetime | None = None
_cooldown_lock = threading.Lock()


@router.get("", response_model=list[AlertOut])
def list_alerts(db: Session = Depends(get_db), acknowledged: bool | None = None, limit: int = 100):
    stmt = select(AlertLog).order_by(AlertLog.sent_at.desc()).limit(limit)
    if acknowledged is not None:
        stmt = stmt.where(AlertLog.acknowledged == acknowledged)
    return db.execute(stmt).scalars().all()


@router.post("/{alert_id}/ack", response_model=AlertOut, dependencies=[Depends(require_api_key)])
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.get(AlertLog, alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alerte introuvable")
    alert.acknowledged = True
    alert.acknowledged_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/poll-now", dependencies=[Depends(require_api_key)])
def trigger_poll(db: Session = Depends(get_db)):
    """Déclenche un cycle d'ingestion immédiat (utile en dev/démo, sans attendre le scheduler).

    Protégé par un cooldown mesuré depuis la FIN du cycle précédent (pas son début) : un poll
    NVD sans clé API peut à lui seul dépasser 30s (rate-limit interne, cf. connectors/nvd.py),
    donc une fenêtre mesurée depuis le début n'aurait protégé en pratique contre rien. On bloque
    aussi tout appel concurrent pendant qu'un cycle est déjà en cours - y compris le poll planifié
    du scheduler (verrou partagé via app.ingest.acquire_poll_slot), pour éviter deux sessions
    SQLite qui écrivent en même temps ("database is locked").
    """
    global _last_poll_completed
    with _cooldown_lock:
        now = datetime.utcnow()
        if _last_poll_completed is not None and now - _last_poll_completed < _POLL_COOLDOWN:
            wait = (_POLL_COOLDOWN - (now - _last_poll_completed)).total_seconds()
            raise HTTPException(status_code=429, detail=f"Poll terminé récemment, réessayer dans {wait:.0f}s")

    if not acquire_poll_slot():
        raise HTTPException(status_code=429, detail="Un poll est déjà en cours, réessayer dans quelques secondes")

    try:
        summaries = poll_all_sources(db)
    finally:
        release_poll_slot()
        with _cooldown_lock:
            _last_poll_completed = datetime.utcnow()

    return {"summaries": summaries}
