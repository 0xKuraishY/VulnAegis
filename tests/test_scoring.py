from datetime import datetime, timedelta

from app.config import settings
from app.models import CVE
from app.scoring import compute_risk_score, is_weaponization_risk


def make_cve(**kwargs) -> CVE:
    defaults = dict(
        cve_id="CVE-2026-0001",
        cvss_score=None,
        is_kev=False,
        kev_due_date=None,
        has_poc=False,
        epss_score=None,
        threat_context=None,
        last_modified_date=None,
        published_date=None,
    )
    defaults.update(kwargs)
    return CVE(**defaults)


def test_full_signal_cve_scores_critical():
    cve = make_cve(
        cvss_score=9.8, is_kev=True, has_poc=True, epss_score=0.97,
        threat_context={"otx": {"pulse_count": 5}, "misp": {"event_count": 2}},
        last_modified_date=datetime.utcnow(),
    )
    risk = compute_risk_score(cve)
    assert risk.level == "critical"
    assert risk.score >= 80
    factors = {item.factor for item in risk.breakdown}
    assert {"cvss", "kev", "epss", "poc_severe", "threat_otx", "threat_misp"} <= factors


def test_empty_cve_never_crashes_and_scores_low():
    cve = make_cve()
    risk = compute_risk_score(cve)
    assert risk.score == 0
    assert risk.level == "info"
    assert risk.breakdown == []


def test_kev_alone_without_cvss_still_weighs_heavily():
    cve = make_cve(is_kev=True, cvss_score=None)
    risk = compute_risk_score(cve)
    assert risk.score >= 20
    assert any(item.factor in ("kev", "kev_overdue") for item in risk.breakdown)


def test_kev_overdue_scores_higher_than_kev_on_time():
    now = datetime.utcnow()
    overdue = make_cve(is_kev=True, kev_due_date=now - timedelta(days=1))
    on_time = make_cve(is_kev=True, kev_due_date=now + timedelta(days=30))
    assert compute_risk_score(overdue, now=now).score > compute_risk_score(on_time, now=now).score


def test_poc_bonus_higher_when_severe():
    severe = make_cve(cvss_score=9.5, has_poc=True)
    routine = make_cve(cvss_score=4.0, has_poc=True)
    severe_points = next(i.points for i in compute_risk_score(severe).breakdown if i.factor == "poc_severe")
    routine_points = next(i.points for i in compute_risk_score(routine).breakdown if i.factor == "poc")
    assert severe_points > routine_points


def test_epss_scales_linearly_between_bounds():
    low = compute_risk_score(make_cve(epss_score=0.0))
    high = compute_risk_score(make_cve(epss_score=1.0))
    assert low.score == 0
    assert high.score == 20  # 1.0 * _EPSS_MAX_POINTS


def test_staleness_malus_reduces_old_inactive_cve_score():
    now = datetime.utcnow()
    old_date = now - timedelta(days=settings.risk_score_stale_days + 10)
    old_cve = make_cve(cvss_score=5.0, last_modified_date=old_date)
    fresh_cve = make_cve(cvss_score=5.0, last_modified_date=now)
    old_score = compute_risk_score(old_cve, now=now).score
    fresh_score = compute_risk_score(fresh_cve, now=now).score
    assert fresh_score - old_score == 10


def test_staleness_malus_does_not_apply_if_kev_or_poc_or_epss_active():
    now = datetime.utcnow()
    old_date = now - timedelta(days=settings.risk_score_stale_days + 10)
    kev_old = make_cve(cvss_score=5.0, is_kev=True, last_modified_date=old_date)
    risk = compute_risk_score(kev_old, now=now)
    assert not any(item.factor == "staleness" for item in risk.breakdown)


def test_score_is_always_clamped_to_100():
    cve = make_cve(
        cvss_score=10.0, is_kev=True, kev_due_date=datetime.utcnow() - timedelta(days=1),
        has_poc=True, epss_score=1.0,
        threat_context={"otx": {"pulse_count": 99}, "misp": {"event_count": 99}},
    )
    risk = compute_risk_score(cve)
    assert risk.score == 100
    assert risk.level == "critical"


def test_is_weaponization_risk_matches_legacy_inline_expression():
    for is_kev in (True, False):
        for cvss_score in (None, 5.0, 9.0, 9.9):
            for has_poc in (True, False):
                cve = make_cve(is_kev=is_kev, cvss_score=cvss_score, has_poc=has_poc)
                legacy = has_poc and (is_kev or (cvss_score is not None and cvss_score >= 9.0))
                assert is_weaponization_risk(cve) == legacy
