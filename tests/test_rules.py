from app.alerting.rules import evaluate
from app.models import CVE, WatchlistEntry


def make_cve(**kwargs) -> CVE:
    defaults = dict(
        cve_id="CVE-2026-0001",
        description="Remote code execution in Example Product",
        cvss_score=None,
        severity=None,
        vendor=None,
        product=None,
        is_kev=False,
        has_poc=False,
    )
    defaults.update(kwargs)
    return CVE(**defaults)


def test_no_alert_when_no_rule_matches():
    cve = make_cve(cvss_score=3.0)
    result = evaluate(cve, watchlist=[])
    assert result.should_alert is False
    assert result.reasons == []


def test_alert_on_high_cvss():
    cve = make_cve(cvss_score=9.8)
    result = evaluate(cve, watchlist=[])
    assert result.should_alert is True
    assert any("CVSS" in r for r in result.reasons)


def test_alert_on_kev_even_with_low_cvss():
    cve = make_cve(cvss_score=2.0, is_kev=True)
    result = evaluate(cve, watchlist=[])
    assert result.should_alert is True
    assert any("KEV" in r for r in result.reasons)


def test_alert_on_watchlist_vendor_product_match():
    cve = make_cve(cvss_score=1.0, vendor="Microsoft", product="Windows Server")
    watchlist = [WatchlistEntry(vendor="microsoft", product="windows")]
    result = evaluate(cve, watchlist)
    assert result.should_alert is True
    assert any("asset surveillé" in r for r in result.reasons)


def test_no_alert_when_vendor_matches_but_product_does_not():
    cve = make_cve(cvss_score=1.0, vendor="Microsoft", product="Excel")
    watchlist = [WatchlistEntry(vendor="microsoft", product="windows")]
    result = evaluate(cve, watchlist)
    assert result.should_alert is False


def test_alert_on_watchlist_keyword_in_description():
    cve = make_cve(cvss_score=1.0, description="Vulnerability in Log4j appender")
    watchlist = [WatchlistEntry(keyword="log4j")]
    result = evaluate(cve, watchlist)
    assert result.should_alert is True
    assert any("mot-clé" in r for r in result.reasons)


def test_multiple_reasons_are_all_reported():
    cve = make_cve(cvss_score=9.5, is_kev=True, vendor="Cisco")
    watchlist = [WatchlistEntry(vendor="cisco")]
    result = evaluate(cve, watchlist)
    assert len(result.reasons) == 3


def test_poc_on_kev_cve_uses_weaponization_reason():
    cve = make_cve(cvss_score=2.0, is_kev=True, has_poc=True)
    result = evaluate(cve, watchlist=[])
    assert any("exploitation imminente" in r for r in result.reasons)
    assert not any(r == "PoC public disponible" for r in result.reasons)


def test_poc_on_critical_cvss_without_kev_uses_weaponization_reason():
    cve = make_cve(cvss_score=9.5, has_poc=True)
    result = evaluate(cve, watchlist=[])
    assert any("exploitation imminente" in r for r in result.reasons)


def test_poc_on_low_severity_cve_uses_routine_reason():
    cve = make_cve(cvss_score=4.0, has_poc=True)
    result = evaluate(cve, watchlist=[])
    assert "PoC public disponible" in result.reasons
    assert not any("exploitation imminente" in r for r in result.reasons)
