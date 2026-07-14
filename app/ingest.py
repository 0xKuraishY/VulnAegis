"""Pipeline d'ingestion : poll une source -> upsert DB -> règles -> dédoublonnage -> alertes.

Ce module est volontairement synchrone et sans dépendance au framework web:
il est appelé aussi bien par le scheduler que par les tests ou un script CLI.
"""
import logging
import threading
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.alerting.dedupe import already_alerted_recently
from app.alerting.email import send_email_alert
from app.alerting.rules import evaluate
from app.alerting.slack import send_slack_alert
from app.alerting.webhook import send_generic_webhook
from app.annotate import annotate_cve
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import ConnectorError
from app.connectors.exploitdb import ExploitDbConnector
from app.connectors.github_poc import GithubPocConnector
from app.enrichment.epss import EpssEnricher
from app.enrichment.misp import MispEnricher
from app.enrichment.otx import OtxEnricher
from app.models import CVE, AlertLog, CVSSHistory, PocLink, SourceState, WatchlistEntry
from app.schemas import CVEOut, NormalizedCVE
from app.ws import broadcast_threadsafe

logger = logging.getLogger(__name__)

# Borne le nombre de CVE enrichies (OTX/MISP) par cycle : contrairement à Exploit-DB (un seul
# téléchargement d'index croisé en local), OTX/MISP nécessitent un appel réseau par CVE. Un
# premier sync CISA KEV peut introduire des centaines de nouvelles CVE d'un coup - les enrichir
# toutes ferait exploser la durée du poll et le quota de la source. Les CVE non enrichies dans un
# cycle le seront au prochain (ce n'est qu'un contexte informatif, pas un critère d'alerte).
_MAX_THREAT_CONTEXT_PER_CYCLE = 20

# Sources "structurées" qui alimentent une fiche CVE complète (métadonnées officielles). Une CVE
# vue uniquement par une source de découverte de PoC (radar GitHub...) avant que l'une de ces
# sources ne l'ait ingérée est une "stub" - cf. `is_unconfirmed` et le badge dashboard associé.
STRUCTURED_SOURCES = {"nvd", "cisa_kev", "github_advisories"}


def is_unconfirmed(cve: CVE) -> bool:
    return not (set(cve.sources or []) & STRUCTURED_SOURCES)

# Verrou process-wide partagé entre le job planifié (app.scheduler) et le déclenchement manuel
# (POST /api/alerts/poll-now) : SQLite ne tolère pas bien deux ingestions concurrentes qui écrivent
# en base (une session peut lever "database is locked"), donc un seul poll doit tourner à la fois
# quelle que soit son origine.
_poll_lock = threading.Lock()
_poll_in_progress = False


def acquire_poll_slot() -> bool:
    """Réserve le créneau de poll. Retourne False si un poll (manuel ou planifié) est déjà en cours."""
    global _poll_in_progress
    with _poll_lock:
        if _poll_in_progress:
            return False
        _poll_in_progress = True
        return True


def release_poll_slot() -> None:
    global _poll_in_progress
    with _poll_lock:
        _poll_in_progress = False


def _severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def upsert_cve(db: Session, normalized: NormalizedCVE) -> tuple[CVE, bool, bool]:
    """Insère ou fusionne une CVE normalisée. Ne dégrade jamais une donnée déjà connue avec du vide.

    Retourne (cve, is_new, score_increased). `score_increased` indique une réévaluation CVSS à la
    hausse par rapport à la valeur déjà connue - cf. dispatch_alerts pour le contournement du
    dédoublonnage d'alerte que ça déclenche (une CVE plus grave que prévu doit ré-alerter même
    si le canal a déjà notifié récemment sur l'ancien score)."""
    cve = db.get(CVE, normalized.cve_id)
    is_new = cve is None
    previous_score = None if cve is None else cve.cvss_score
    if cve is None:
        cve = CVE(cve_id=normalized.cve_id, sources=[])
        db.add(cve)

    if normalized.description:
        cve.description = normalized.description
    if normalized.cvss_score is not None:
        cve.cvss_score = normalized.cvss_score
        cve.cvss_vector = normalized.cvss_vector or cve.cvss_vector
    if normalized.severity:
        cve.severity = normalized.severity
    elif cve.severity is None:
        cve.severity = _severity_from_score(cve.cvss_score)
    if normalized.vendor:
        cve.vendor = normalized.vendor
    if normalized.product:
        cve.product = normalized.product
    if normalized.published_date and not cve.published_date:
        cve.published_date = _naive(normalized.published_date)
    if normalized.last_modified_date:
        cve.last_modified_date = _naive(normalized.last_modified_date)
    if normalized.references:
        cve.references = sorted(set((cve.references or []) + normalized.references))
    if normalized.is_kev:
        cve.is_kev = True
        cve.kev_date_added = _naive(normalized.kev_date_added) or cve.kev_date_added
        cve.kev_due_date = _naive(normalized.kev_due_date) or cve.kev_due_date
        cve.kev_ransomware_use = normalized.kev_ransomware_use or cve.kev_ransomware_use
    if normalized.has_poc:
        cve.has_poc = True
        cve.poc_links = sorted(set((cve.poc_links or []) + normalized.poc_links))
    if normalized.raw:
        cve.raw = normalized.raw
    if normalized.cwe_ids:
        cve.cwe_ids = sorted(set((cve.cwe_ids or []) + normalized.cwe_ids))
    if normalized.affected_cpes:
        cve.affected_cpes = sorted(set((cve.affected_cpes or []) + normalized.affected_cpes))
    if normalized.references_meta:
        merged = {r["url"]: r for r in (cve.references_meta or [])}
        merged.update({r["url"]: r for r in normalized.references_meta})
        cve.references_meta = list(merged.values())

    cve.sources = sorted(set((cve.sources or []) + [normalized.source]))
    cve.last_seen = datetime.utcnow()

    score_changed = normalized.cvss_score is not None and normalized.cvss_score != previous_score
    score_increased = score_changed and previous_score is not None and normalized.cvss_score > previous_score
    if score_changed:
        db.add(CVSSHistory(cve_id=cve.cve_id, cvss_score=cve.cvss_score, severity=cve.severity))

    return cve, is_new, score_increased


def _naive(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=None) if dt.tzinfo else dt


def _broadcast_cve_event(event_type: str, cve: CVE, watchlist: list[WatchlistEntry]) -> None:
    """Diffuse une CVE (créée ou mise à jour) aux clients WebSocket connectés, avec le même
    format (CVEOut) que l'API REST - annotée du score de risque, comme _annotate_flags côté API.

    Appelé uniquement après un `db.commit()` réussi (jamais avant), pour ne jamais pousser un
    état non validé en base."""
    annotate_cve(cve, watchlist)
    payload = CVEOut.model_validate(cve).model_dump(mode="json")
    broadcast_threadsafe(event_type, payload)


def dispatch_alerts(db: Session, cve: CVE, watchlist: list[WatchlistEntry], force_realert: bool = False) -> list[str]:
    """Évalue les règles pour une CVE et envoie les notifications non dédupliquées.

    `force_realert` contourne le dédoublonnage (utilisé quand le CVSS vient d'être réévalué à la
    hausse : une alerte déjà envoyée récemment sur l'ancien score ne doit pas faire taire la nouvelle
    gravité)."""
    result = evaluate(cve, watchlist)
    if not result.should_alert:
        return []

    sent_channels = []
    channels = {
        "slack": lambda: send_slack_alert(cve, result.reasons),
        "email": lambda: send_email_alert(cve, result.reasons),
        "webhook": lambda: send_generic_webhook(cve, result.reasons),
    }
    for channel, sender in channels.items():
        if not force_realert and already_alerted_recently(db, cve.cve_id, channel):
            continue
        if sender():
            db.add(AlertLog(cve_id=cve.cve_id, channel=channel, reasons=result.reasons))
            sent_channels.append(channel)

    if sent_channels:
        db.commit()
        broadcast_threadsafe("alert.created", {
            "cve_id": cve.cve_id, "reasons": result.reasons, "channels": sent_channels,
        })
    return sent_channels


def poll_source(db: Session, connector_cls, new_cve_ids: list[str] | None = None) -> dict:
    connector = connector_cls()
    state = db.get(SourceState, connector.name)
    since = state.last_polled_at.replace(tzinfo=timezone.utc) if state and state.last_polled_at else None

    watchlist = db.query(WatchlistEntry).all()
    poll_started_at = datetime.utcnow()
    summary = {"source": connector.name, "fetched": 0, "new": 0, "alerts_sent": 0, "error": None}

    try:
        cves = connector.fetch_since(since)
    except ConnectorError as exc:
        logger.warning("Poll échoué pour %s: %s", connector.name, exc)
        summary["error"] = str(exc)
        _update_source_state(db, connector.name, poll_started_at, 0, 0, str(exc))
        return summary

    summary["fetched"] = len(cves)
    new_cves: list[CVE] = []
    for normalized in cves:
        cve, is_new, score_increased = upsert_cve(db, normalized)
        db.flush()
        if is_new:
            summary["new"] += 1
            new_cves.append(cve)
            if new_cve_ids is not None:
                new_cve_ids.append(cve.cve_id)
        sent = dispatch_alerts(db, cve, watchlist, force_realert=score_increased)
        summary["alerts_sent"] += len(sent)

    db.commit()
    for cve in new_cves:
        _broadcast_cve_event("cve.created", cve, watchlist)
    _update_source_state(db, connector.name, poll_started_at, len(cves), summary["new"], None)
    return summary


def _update_source_state(
    db: Session, source_name: str, polled_at: datetime, fetched_count: int, new_count: int, error: str | None
) -> None:
    state = db.get(SourceState, source_name)
    if state is None:
        state = SourceState(source_name=source_name)
        db.add(state)
    # En cas d'erreur, on NE fait PAS avancer last_polled_at pour retenter la même fenêtre au prochain poll.
    if error is None:
        state.last_polled_at = polled_at
    # fetched_count peut être énorme et peu parlant (ex: taille de tout le jeu EPSS) - new_count est
    # ce qui compte vraiment pour un analyste qui regarde la page Paramètres.
    state.last_success_count = fetched_count
    state.last_new_count = new_count
    state.last_error = error
    db.commit()
    # Point de broadcast unique pour toutes les sources (poll_source, exploitdb, epss,
    # github_poc, threat_context appellent tous cette fonction) : évite de dupliquer l'appel
    # dans chacune d'elles.
    broadcast_threadsafe("source.status", {
        "name": source_name,
        "last_polled_at": state.last_polled_at.isoformat() if state.last_polled_at else None,
        "last_success_count": state.last_success_count,
        "last_new_count": state.last_new_count,
        "last_error": state.last_error,
    })


def enrich_has_poc_from_exploitdb(db: Session) -> dict:
    """Croise les CVE déjà en base avec l'index Exploit-DB pour peupler has_poc/poc_links, et
    déclenche une alerte "PoC public disponible" pour celles qui ne l'étaient pas déjà."""
    summary = {"source": "exploitdb", "fetched": 0, "new": 0, "alerts_sent": 0, "error": None}
    poll_started_at = datetime.utcnow()
    connector = ExploitDbConnector()
    try:
        index = connector.fetch_index()
    except ConnectorError as exc:
        logger.warning("Enrichissement Exploit-DB échoué: %s", exc)
        summary["error"] = str(exc)
        _update_source_state(db, "exploitdb", poll_started_at, 0, 0, str(exc))
        return summary

    summary["fetched"] = len(index)
    if not index:
        _update_source_state(db, "exploitdb", poll_started_at, 0, 0, None)
        return summary

    # On croise côté DB (bornée) plutôt qu'un `IN` avec les ~50k clés de l'index Exploit-DB.
    updated_cves: list[CVE] = []
    known_ids = {row[0] for row in db.query(CVE.cve_id).all()}
    matching_ids = known_ids & index.keys()
    if matching_ids:
        watchlist = db.query(WatchlistEntry).all()
        for cve in db.query(CVE).filter(CVE.cve_id.in_(matching_ids)).all():
            urls = index[cve.cve_id]
            new_links = sorted(set((cve.poc_links or []) + urls))
            was_flagged = cve.has_poc
            if was_flagged and new_links == (cve.poc_links or []):
                continue
            cve.has_poc = True
            cve.poc_links = new_links
            db.flush()
            summary["new"] += 1
            updated_cves.append(cve)
            if not was_flagged:
                sent = dispatch_alerts(db, cve, watchlist)
                summary["alerts_sent"] += len(sent)

    db.commit()
    for cve in updated_cves:
        _broadcast_cve_event("cve.updated", cve, watchlist)
    _update_source_state(db, "exploitdb", poll_started_at, summary["fetched"], summary["new"], None)
    return summary


def enrich_epss_scores(db: Session) -> dict:
    """Croise les CVE déjà en base avec le jeu de données EPSS (score prédictif d'exploitation,
    FIRST.org). Purement informatif : ne déclenche jamais d'alerte, affiché en fiche CVE."""
    summary = {"source": "epss", "fetched": 0, "new": 0, "alerts_sent": 0, "error": None}
    poll_started_at = datetime.utcnow()
    enricher = EpssEnricher()
    try:
        index = enricher.fetch_index()
    except ConnectorError as exc:
        logger.warning("Enrichissement EPSS échoué: %s", exc)
        summary["error"] = str(exc)
        _update_source_state(db, "epss", poll_started_at, 0, 0, str(exc))
        return summary

    summary["fetched"] = len(index)
    if index:
        known_ids = {row[0] for row in db.query(CVE.cve_id).all()}
        matching_ids = known_ids & index.keys()
        if matching_ids:
            for cve in db.query(CVE).filter(CVE.cve_id.in_(matching_ids)).all():
                score, percentile = index[cve.cve_id]
                if cve.epss_score == score and cve.epss_percentile == percentile:
                    continue
                cve.epss_score = score
                cve.epss_percentile = percentile
                summary["new"] += 1
            if summary["new"]:
                db.commit()

    _update_source_state(db, "epss", poll_started_at, summary["fetched"], summary["new"], None)
    return summary


def record_poc_discovery(
    db: Session,
    cve_id: str,
    url: str,
    source: str,
    watchlist: list[WatchlistEntry],
    repo_full_name: str | None = None,
    stars: int | None = None,
) -> tuple[bool, list[str]]:
    """Enregistre la découverte d'un PoC pour une CVE. Retourne (créé, canaux_alertés).

    Dédoublonne par URL (contrainte unique sur `PocLink.url`) : un même repo revu à un cycle
    suivant ne recrée rien. Si la CVE n'est pas encore connue (PoC publié avant que NVD/KEV/GHSA
    ne l'aient rattrapée), crée une fiche "stub" minimale - sûr car `upsert_cve` ne dégrade jamais
    une donnée existante avec du vide, une ingestion normale la complétera plus tard."""
    if db.query(PocLink).filter_by(url=url).first() is not None:
        return False, []

    cve = db.get(CVE, cve_id)
    if cve is None:
        cve = CVE(cve_id=cve_id, sources=[])
        db.add(cve)
        db.flush()

    db.add(PocLink(cve_id=cve_id, url=url, source=source, repo_full_name=repo_full_name, stars=stars))

    was_flagged = cve.has_poc
    cve.has_poc = True
    cve.poc_links = sorted(set((cve.poc_links or []) + [url]))
    db.flush()

    sent_channels: list[str] = []
    if not was_flagged:
        sent_channels = dispatch_alerts(db, cve, watchlist)
    db.commit()
    _broadcast_cve_event("cve.updated", cve, watchlist)
    return True, sent_channels


def enrich_github_poc(db: Session) -> dict:
    """Radar PoC temps réel : interroge GitHub Search pour des repos récemment mis à jour
    mentionnant une CVE récente, et enregistre chaque découverte via `record_poc_discovery`."""
    summary = {"source": "github_poc", "fetched": 0, "new": 0, "alerts_sent": 0, "error": None}
    poll_started_at = datetime.utcnow()
    connector = GithubPocConnector()
    try:
        discoveries = connector.fetch_recent()
    except ConnectorError as exc:
        logger.warning("Radar PoC GitHub échoué: %s", exc)
        summary["error"] = str(exc)
        _update_source_state(db, "github_poc", poll_started_at, 0, 0, str(exc))
        return summary

    summary["fetched"] = len(discoveries)
    watchlist = db.query(WatchlistEntry).all()
    for discovery in discoveries:
        created, sent = record_poc_discovery(
            db, discovery["cve_id"], discovery["url"], discovery["source"], watchlist,
            repo_full_name=discovery.get("repo_full_name"), stars=discovery.get("stars"),
        )
        if created:
            summary["new"] += 1
            summary["alerts_sent"] += len(sent)

    _update_source_state(db, "github_poc", poll_started_at, summary["fetched"], summary["new"], None)
    return summary


def enrich_threat_context(db: Session, cve_ids: list[str]) -> dict:
    """Enrichit une liste bornée de CVE (les nouvelles du cycle) avec le contexte menace OTX/MISP.
    Purement informatif : n'affecte jamais le moteur de règles d'alerte."""
    summary = {"source": "threat_context", "fetched": 0, "new": 0, "alerts_sent": 0, "error": None}
    if not cve_ids:
        return summary

    poll_started_at = datetime.utcnow()
    truncated = cve_ids[:_MAX_THREAT_CONTEXT_PER_CYCLE]
    otx, misp = OtxEnricher(), MispEnricher()
    errors: list[str] = []
    updated = 0
    updated_cves: list[CVE] = []

    for cve_id in truncated:
        cve = db.get(CVE, cve_id)
        if cve is None:
            continue
        context = dict(cve.threat_context or {})
        for enricher_name, enricher in (("otx", otx), ("misp", misp)):
            try:
                result = enricher.enrich(cve_id)
            except ConnectorError as exc:
                errors.append(str(exc))
                continue
            if result is not None:
                context[enricher_name] = result
        if context != (cve.threat_context or {}):
            cve.threat_context = context
            updated += 1
            updated_cves.append(cve)

    if updated:
        db.commit()
        watchlist = db.query(WatchlistEntry).all()
        for cve in updated_cves:
            _broadcast_cve_event("cve.updated", cve, watchlist)
    summary["fetched"] = len(truncated)
    summary["new"] = updated
    if errors:
        summary["error"] = "; ".join(errors[:3])
    _update_source_state(db, "threat_context", poll_started_at, summary["fetched"], summary["new"], summary["error"])
    return summary


def poll_all_sources(db: Session) -> list[dict]:
    new_cve_ids: list[str] = []
    summaries = [poll_source(db, connector_cls, new_cve_ids) for connector_cls in CONNECTOR_REGISTRY]
    summaries.append(enrich_has_poc_from_exploitdb(db))
    summaries.append(enrich_threat_context(db, new_cve_ids))
    return summaries
