from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors import CONNECTOR_REGISTRY
from app.database import get_db
from app.models import SourceState

router = APIRouter(prefix="/api/status", tags=["status"])

# Sources qui ne sont pas dans CONNECTOR_REGISTRY (ce ne sont pas des pollers "métadonnées CVE"
# mais des enrichisseurs/découvreurs à cadence propre - cf. app/ingest.py), mais qui tiennent
# quand même à jour leur SourceState et méritent d'apparaître dans Paramètres.
ENRICHER_NAMES = ["exploitdb", "threat_context", "epss", "github_poc"]


@router.get("")
def get_status(db: Session = Depends(get_db)):
    states = {s.source_name: s for s in db.execute(select(SourceState)).scalars().all()}
    names = [connector_cls.name for connector_cls in CONNECTOR_REGISTRY] + ENRICHER_NAMES
    return {
        "sources": [
            {
                "name": name,
                "last_polled_at": states[name].last_polled_at if name in states else None,
                "last_success_count": states[name].last_success_count if name in states else 0,
                "last_new_count": states[name].last_new_count if name in states else 0,
                "last_error": states[name].last_error if name in states else None,
            }
            for name in names
        ]
    }
