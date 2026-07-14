from datetime import datetime, timedelta

from app.config import settings
from app.scheduler import scheduler, start_scheduler


def test_start_scheduler_registers_all_expected_jobs(monkeypatch):
    # scheduler.start() lancerait le thread de fond qui exécuterait immédiatement les jobs à
    # next_run_time=now (poll réseau réel) : on vérifie seulement que les jobs sont enregistrés
    # avec la bonne cadence, sans jamais démarrer le thread.
    monkeypatch.setattr(scheduler, "start", lambda: None)
    try:
        start_scheduler()
        jobs = {job.id: job for job in scheduler.get_jobs()}
        assert set(jobs) == {"poll_sources", "escalation_check", "epss_enrich", "github_poc_radar"}
        assert jobs["poll_sources"].trigger.interval.total_seconds() == settings.poll_interval_minutes * 60
        assert jobs["github_poc_radar"].trigger.interval.total_seconds() == settings.github_poc_interval_minutes * 60
        assert jobs["epss_enrich"].trigger.interval.total_seconds() == settings.epss_check_interval_minutes * 60
    finally:
        for job_id in list(jobs):
            scheduler.remove_job(job_id)


def test_all_jobs_run_immediately_on_startup(monkeypatch):
    """Régression : epss_enrich et escalation_check n'avaient pas de next_run_time, donc
    APScheduler attendait un intervalle complet (24h / 1h) avant leur tout premier passage - un
    analyste qui vient de démarrer l'app voyait EPSS "jamais interrogée" pendant une journée entière."""
    monkeypatch.setattr(scheduler, "start", lambda: None)
    try:
        start_scheduler()
        now = datetime.utcnow()
        for job in scheduler.get_jobs():
            assert job.next_run_time is not None
            # Tolérance large : on veut juste "quasi immédiat", pas "dans un intervalle complet".
            assert abs(job.next_run_time.replace(tzinfo=None) - now) < timedelta(minutes=1), job.id
    finally:
        for job in scheduler.get_jobs():
            scheduler.remove_job(job.id)
