"""Radar PoC : flux des découvertes de PoC les plus récentes, toutes sources confondues."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.ingest import enrich_github_poc, is_unconfirmed
from app.rate_limit import check_rate_limit
from app.models import CVE, PocLink
from app.security import require_api_key

router = APIRouter(prefix="/api/pocs", tags=["pocs"])

# Le radar tourne déjà tout seul toutes les github_poc_interval_minutes (cf. app/scheduler.py) ;
# ce cooldown protège seulement contre un humain qui enchaîne les clics sur "Synchroniser
# maintenant" dans le dashboard, pour ne pas cogner inutilement le quota GitHub Search.
_SYNC_COOLDOWN_SECONDS = 20


@router.get("/recent")
def list_recent_pocs(db: Session = Depends(get_db), limit: int = Query(50, le=200)):
    stmt = (
        select(PocLink, CVE)
        .join(CVE, PocLink.cve_id == CVE.cve_id)
        .order_by(PocLink.discovered_at.desc())
        .limit(limit)
    )
    rows = db.execute(stmt).all()
    return [
        {
            "cve_id": cve.cve_id,
            "url": link.url,
            "source": link.source,
            "repo_full_name": link.repo_full_name,
            "stars": link.stars,
            "discovered_at": link.discovered_at,
            "severity": cve.severity,
            "cvss_score": cve.cvss_score,
            "is_kev": cve.is_kev,
            "unconfirmed": is_unconfirmed(cve),
            "weaponization_risk": cve.is_kev or (cve.cvss_score is not None and cve.cvss_score >= 9.0),
        }
        for link, cve in rows
    ]


@router.post("/sync-now", dependencies=[Depends(require_api_key)])
def sync_now(db: Session = Depends(get_db)):
    """Déclenche un cycle du radar PoC GitHub immédiatement, sans attendre la prochaine
    exécution planifiée (~toutes les github_poc_interval_minutes)."""
    if not check_rate_limit("sync:github_poc", max_attempts=1, window_seconds=_SYNC_COOLDOWN_SECONDS):
        raise HTTPException(status_code=429, detail="Synchronisation déjà lancée récemment, réessayez dans quelques secondes")
    return enrich_github_poc(db)
