import csv
import io
import json
from collections import Counter
from datetime import datetime, timedelta
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.annotate import annotate_cve
from app.config import settings
from app.database import get_db
from app.ingest import STRUCTURED_SOURCES, enrich_epss_scores, is_unconfirmed
from app.models import CVE, WatchlistEntry
from app.rate_limit import check_rate_limit
from app.schemas import CVEDetailOut, CVEOut, StatsOut
from app.scoring import compute_risk_score
from app.security import require_api_key

router = APIRouter(prefix="/api/cves", tags=["cves"])

_EPSS_BUCKETS = [
    ("0-1%", 0.0, 0.01),
    ("1-10%", 0.01, 0.10),
    ("10-50%", 0.10, 0.50),
    ("50-90%", 0.50, 0.90),
    ("90-100%", 0.90, 1.0001),
]
# Le job planifié tourne déjà une fois par jour (epss_check_interval_minutes) ; ce cooldown ne
# protège que contre un enchaînement de clics manuels sur "Synchroniser maintenant".
_SYNC_COOLDOWN_SECONDS = 20


def _watchlist_conditions(watchlist: list[WatchlistEntry]):
    """Traduit la watchlist en conditions SQL (une CVE 'matche' si vendor/product ou
    mot-clé d'au moins une entrée correspond) - réutilisé par le filtre `watchlist_only`."""
    conditions = []
    for entry in watchlist:
        if entry.vendor:
            cond = CVE.vendor.ilike(f"%{entry.vendor}%")
            if entry.product:
                cond = and_(cond, CVE.product.ilike(f"%{entry.product}%"))
            conditions.append(cond)
        if entry.keyword:
            kw = f"%{entry.keyword}%"
            conditions.append(or_(CVE.vendor.ilike(kw), CVE.product.ilike(kw), CVE.description.ilike(kw)))
    return conditions


def _annotate_flags(rows: list[CVE], watchlist: list[WatchlistEntry]) -> list[CVE]:
    """Attache is_flagged/flag_reasons/risk_score/risk_level/risk_breakdown (attributs non
    persistés) à chaque ligne : *pourquoi* une CVE compterait comme alerte (indépendant d'un
    AlertLog existant), et sa priorité de triage (score composite, cf. app/scoring.py)."""
    for row in rows:
        annotate_cve(row, watchlist)
    return rows

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _csv_safe(value):
    """Neutralise l'injection de formule CSV (un champ ouvert dans Excel/Sheets qui commence
    par =/+/-/@ peut être interprété comme une formule) en préfixant d'une apostrophe."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return f"'{value}"
    return value


def _apply_filters(
    stmt,
    cvss_min: float | None,
    severity: str | None,
    vendor: str | None,
    product: str | None,
    is_kev: bool | None,
    q: str | None,
    since_days: int | None,
    has_poc: bool | None = None,
    epss_min: float | None = None,
):
    if cvss_min is not None:
        stmt = stmt.where(CVE.cvss_score >= cvss_min)
    if severity:
        stmt = stmt.where(CVE.severity == severity.upper())
    if vendor:
        stmt = stmt.where(CVE.vendor.ilike(f"%{vendor}%"))
    if product:
        stmt = stmt.where(CVE.product.ilike(f"%{product}%"))
    if is_kev is not None:
        stmt = stmt.where(CVE.is_kev == is_kev)
    if q:
        like = f"%{q}%"
        stmt = stmt.where((CVE.cve_id.ilike(like)) | (CVE.description.ilike(like)))
    if since_days is not None:
        cutoff = datetime.utcnow() - timedelta(days=since_days)
        stmt = stmt.where(CVE.last_modified_date >= cutoff)
    if has_poc is not None:
        stmt = stmt.where(CVE.has_poc == has_poc)
    if epss_min is not None:
        stmt = stmt.where(CVE.epss_score >= epss_min)
    return stmt


@router.get("", response_model=list[CVEOut])
def list_cves(
    db: Session = Depends(get_db),
    cvss_min: float | None = None,
    severity: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    is_kev: bool | None = None,
    q: str | None = None,
    since_days: int | None = None,
    has_poc: bool | None = None,
    epss_min: float | None = None,
    watchlist_only: bool = False,
    sort: str = Query("last_seen", pattern="^(last_seen|cvss_score|published_date|cve_id|kev_due_date|risk_score)$"),
    direction: str = Query("desc", pattern="^(asc|desc)$"),
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    watchlist = db.query(WatchlistEntry).all()

    if watchlist_only and not watchlist:
        return []

    stmt = select(CVE)
    stmt = _apply_filters(stmt, cvss_min, severity, vendor, product, is_kev, q, since_days, has_poc, epss_min)
    if watchlist_only:
        stmt = stmt.where(or_(*_watchlist_conditions(watchlist)))

    if sort == "risk_score":
        # risk_score n'est pas une colonne SQL (calculé à la volée) : les filtres SQL réduisent
        # d'abord le jeu de résultats, puis le tri/pagination se fait en Python sur ce sous-ensemble.
        rows = db.execute(stmt).scalars().all()
        rows = _annotate_flags(list(rows), watchlist)
        rows.sort(key=lambda r: r.risk_score, reverse=(direction == "desc"))
        return rows[offset : offset + limit]

    column = getattr(CVE, sort)
    col_order = column.asc() if direction == "asc" else column.desc()
    if sort == "kev_due_date":
        # Les échéances nulles (CVE non-KEV) doivent rester en fin de liste, pas en tête.
        col_order = col_order.nulls_last()
    stmt = stmt.order_by(col_order).offset(offset).limit(limit)
    rows = db.execute(stmt).scalars().all()
    return _annotate_flags(rows, watchlist)


@router.get("/export")
def export_cves(
    db: Session = Depends(get_db),
    format: str = Query("json", pattern="^(json|csv)$"),
    cvss_min: float | None = None,
    severity: str | None = None,
    is_kev: bool | None = None,
    since_days: int | None = None,
):
    stmt = select(CVE)
    stmt = _apply_filters(stmt, cvss_min, severity, None, None, is_kev, None, since_days)
    rows = db.execute(stmt.order_by(CVE.last_seen.desc())).scalars().all()
    for row in rows:
        risk = compute_risk_score(row)
        row.risk_score = risk.score
        row.risk_level = risk.level

    fields = ["cve_id", "severity", "cvss_score", "vendor", "product", "is_kev", "published_date", "description", "risk_score", "risk_level"]
    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(fields)
        for r in rows:
            writer.writerow([_csv_safe(getattr(r, f)) for f in fields])
        buf.seek(0)
        return StreamingResponse(
            buf, media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=vulnaegis_export.csv"},
        )

    data = [{f: getattr(r, f) if not isinstance(getattr(r, f), datetime) else getattr(r, f).isoformat()
             for f in fields} for r in rows]
    return StreamingResponse(
        io.StringIO(json.dumps(data, default=str)), media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=vulnaegis_export.json"},
    )


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    total = db.execute(select(func.count(CVE.cve_id))).scalar_one()
    kev_count = db.execute(select(func.count(CVE.cve_id)).where(CVE.is_kev.is_(True))).scalar_one()

    by_severity_rows = db.execute(
        select(CVE.severity, func.count(CVE.cve_id)).group_by(CVE.severity)
    ).all()
    by_severity = {row[0] or "UNKNOWN": row[1] for row in by_severity_rows}

    cutoff = datetime.utcnow() - timedelta(days=14)
    by_day_rows = db.execute(
        select(func.date(CVE.first_seen), func.count(CVE.cve_id))
        .where(CVE.first_seen >= cutoff)
        .group_by(func.date(CVE.first_seen))
        .order_by(func.date(CVE.first_seen))
    ).all()
    by_day = {str(row[0]): row[1] for row in by_day_rows}

    top_vendor_rows = db.execute(
        select(CVE.vendor, func.count(CVE.cve_id))
        .where(CVE.vendor.is_not(None))
        .group_by(CVE.vendor)
        .order_by(func.count(CVE.cve_id).desc())
        .limit(10)
    ).all()
    top_vendors = {row[0]: row[1] for row in top_vendor_rows}

    # Miroir SQL de app.scoring.is_weaponization_risk() : agrégat de comptage, donc pas de recharge
    # d'objets CVE complets - garder les deux définitions synchronisées si le seuil 9.0 évolue.
    weaponization_condition = and_(CVE.has_poc.is_(True), or_(CVE.is_kev.is_(True), CVE.cvss_score >= 9.0))
    weaponization_risk_count = db.execute(
        select(func.count(CVE.cve_id)).where(weaponization_condition)
    ).scalar_one()

    epss_high_risk_count = db.execute(
        select(func.count(CVE.cve_id)).where(CVE.epss_score >= settings.epss_high_risk_threshold)
    ).scalar_one()

    kev_by_day_rows = db.execute(
        select(func.date(CVE.kev_date_added), func.count(CVE.cve_id))
        .where(CVE.kev_date_added >= cutoff)
        .group_by(func.date(CVE.kev_date_added))
        .order_by(func.date(CVE.kev_date_added))
    ).all()
    kev_by_day = {str(row[0]): row[1] for row in kev_by_day_rows}

    weaponization_by_day_rows = db.execute(
        select(func.date(CVE.first_seen), func.count(CVE.cve_id))
        .where(CVE.first_seen >= cutoff, weaponization_condition)
        .group_by(func.date(CVE.first_seen))
        .order_by(func.date(CVE.first_seen))
    ).all()
    weaponization_by_day = {str(row[0]): row[1] for row in weaponization_by_day_rows}

    # cwe_ids/sources sont des listes JSON : pas de fonction d'agrégation portable SQLite/Postgres
    # pour les "exploser" en lignes - le volume (quelques dizaines de milliers de CVE) rend un
    # comptage côté Python largement suffisant, sans dépendance au dialecte.
    cwe_counter = Counter()
    for (cwe_ids,) in db.execute(select(CVE.cwe_ids).where(CVE.cwe_ids.is_not(None))):
        cwe_counter.update(cwe_ids or [])
    top_cwe = dict(cwe_counter.most_common(10))

    unconfirmed_count = 0
    for (sources,) in db.execute(select(CVE.sources)):
        if not (set(sources or []) & STRUCTURED_SOURCES):
            unconfirmed_count += 1

    epss_distribution = {}
    for label, low, high in _EPSS_BUCKETS:
        count = db.execute(
            select(func.count(CVE.cve_id)).where(CVE.epss_score >= low, CVE.epss_score < high)
        ).scalar_one()
        if count:
            epss_distribution[label] = count

    # Distribution du score de risque composite. Ne charge que les colonnes nécessaires au calcul
    # (pas les objets CVE complets, qui embarquent le payload brut potentiellement volumineux dans
    # `raw`) pour rester praticable sur un catalogue de plusieurs dizaines de milliers de CVE.
    risk_counter = Counter()
    risk_columns = db.execute(
        select(
            CVE.cvss_score, CVE.is_kev, CVE.kev_due_date, CVE.epss_score,
            CVE.has_poc, CVE.threat_context, CVE.last_modified_date, CVE.published_date,
        )
    ).all()
    for cvss_score, is_kev, kev_due_date, epss_score, has_poc, threat_context, last_modified_date, published_date in risk_columns:
        pseudo_cve = SimpleNamespace(
            cvss_score=cvss_score, is_kev=is_kev, kev_due_date=kev_due_date, epss_score=epss_score,
            has_poc=has_poc, threat_context=threat_context,
            last_modified_date=last_modified_date, published_date=published_date,
        )
        risk_counter[compute_risk_score(pseudo_cve).level] += 1
    risk_distribution = dict(risk_counter)

    return StatsOut(
        total_cves=total,
        kev_count=kev_count,
        by_severity=by_severity,
        by_day=by_day,
        top_vendors=top_vendors,
        weaponization_risk_count=weaponization_risk_count,
        epss_high_risk_count=epss_high_risk_count,
        unconfirmed_count=unconfirmed_count,
        top_cwe=top_cwe,
        epss_distribution=epss_distribution,
        weaponization_by_day=weaponization_by_day,
        kev_by_day=kev_by_day,
        risk_distribution=risk_distribution,
    )


@router.post("/sync-epss", dependencies=[Depends(require_api_key)])
def sync_epss(db: Session = Depends(get_db)):
    """Déclenche l'enrichissement EPSS immédiatement, sans attendre la prochaine exécution
    planifiée (~1 fois/jour, cf. epss_check_interval_minutes)."""
    if not check_rate_limit("sync:epss", max_attempts=1, window_seconds=_SYNC_COOLDOWN_SECONDS):
        raise HTTPException(status_code=429, detail="Synchronisation déjà lancée récemment, réessayez dans quelques secondes")
    return enrich_epss_scores(db)


@router.get("/{cve_id}", response_model=CVEDetailOut)
def get_cve(
    cve_id: str = Path(..., pattern=r"^(?:CVE|cve)-\d{4}-\d{4,19}$"),
    db: Session = Depends(get_db),
):
    cve = db.get(CVE, cve_id.upper())
    if cve is None:
        raise HTTPException(status_code=404, detail="CVE introuvable")
    watchlist = db.query(WatchlistEntry).all()
    _annotate_flags([cve], watchlist)
    cve.unconfirmed = is_unconfirmed(cve)
    return cve
