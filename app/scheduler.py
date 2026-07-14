import logging
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler

from app.alerting.escalation import run_escalation_check
from app.config import settings
from app.database import SessionLocal
from app.ingest import acquire_poll_slot, enrich_epss_scores, enrich_github_poc, poll_all_sources, release_poll_slot

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler(timezone="UTC")


def poll_job() -> None:
    if not acquire_poll_slot():
        logger.info("Poll planifié ignoré : un poll (manuel ou planifié) est déjà en cours")
        return
    try:
        db = SessionLocal()
        try:
            summaries = poll_all_sources(db)
            for s in summaries:
                logger.info(
                    "poll %s: fetched=%s new=%s alerts=%s error=%s",
                    s["source"], s["fetched"], s["new"], s["alerts_sent"], s["error"],
                )
        except Exception:
            logger.exception("Erreur inattendue durant le poll planifié")
        finally:
            db.close()
    finally:
        release_poll_slot()


def escalation_job() -> None:
    db = SessionLocal()
    try:
        count = run_escalation_check(db)
        if count:
            logger.info("%s alerte(s) escaladée(s)", count)
    except Exception:
        logger.exception("Erreur inattendue durant la vérification d'escalade")
    finally:
        db.close()


def epss_job() -> None:
    db = SessionLocal()
    try:
        summary = enrich_epss_scores(db)
        logger.info("epss: fetched=%s new=%s error=%s", summary["fetched"], summary["new"], summary["error"])
    except Exception:
        logger.exception("Erreur inattendue durant l'enrichissement EPSS")
    finally:
        db.close()


def github_poc_job() -> None:
    # Volontairement indépendant de _poll_lock (poll_job) : un gros backfill NVD ne doit jamais
    # retarder le radar PoC, qui doit rester "temps réel" même pendant un cycle de poll principal
    # long (même précédent que escalation_job, qui tourne déjà sans verrou partagé).
    db = SessionLocal()
    try:
        summary = enrich_github_poc(db)
        logger.info(
            "github_poc: fetched=%s new=%s alerts=%s error=%s",
            summary["fetched"], summary["new"], summary["alerts_sent"], summary["error"],
        )
    except Exception:
        logger.exception("Erreur inattendue durant le radar PoC GitHub")
    finally:
        db.close()


def start_scheduler() -> None:
    if scheduler.running:
        return
    scheduler.add_job(
        poll_job,
        "interval",
        minutes=settings.poll_interval_minutes,
        id="poll_sources",
        next_run_time=datetime.utcnow(),  # premier run immédiat au démarrage
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        escalation_job,
        "interval",
        minutes=settings.escalation_check_interval_minutes,
        id="escalation_check",
        next_run_time=datetime.utcnow(),  # sans ça, APScheduler attend un intervalle complet avant le 1er run
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        epss_job,
        "interval",
        minutes=settings.epss_check_interval_minutes,
        id="epss_enrich",
        next_run_time=datetime.utcnow(),  # idem : sans ce paramètre, le premier sync EPSS attendrait 24h
        max_instances=1,
        coalesce=True,
    )
    scheduler.add_job(
        github_poc_job,
        "interval",
        minutes=settings.github_poc_interval_minutes,
        id="github_poc_radar",
        next_run_time=datetime.utcnow(),  # premier run immédiat : c'est la fonctionnalité "temps réel"
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler démarré: poll toutes les %s min, escalade toutes les %s min, EPSS toutes les %s min, "
        "radar PoC GitHub toutes les %s min",
        settings.poll_interval_minutes,
        settings.escalation_check_interval_minutes,
        settings.epss_check_interval_minutes,
        settings.github_poc_interval_minutes,
    )


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
