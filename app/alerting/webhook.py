"""Webhook générique pour intégration SIEM/SOAR (TheHive, Splunk HEC, QRadar...)."""
import logging

import requests

from app.config import settings
from app.models import CVE

logger = logging.getLogger(__name__)


def send_generic_webhook(cve: CVE, reasons: list[str]) -> bool:
    if not settings.generic_webhook_url:
        return False
    payload = {
        "cve_id": cve.cve_id,
        "cvss_score": cve.cvss_score,
        "severity": cve.severity,
        "vendor": cve.vendor,
        "product": cve.product,
        "is_kev": cve.is_kev,
        "reasons": reasons,
        "description": cve.description,
        "references": cve.references,
    }
    try:
        resp = requests.post(settings.generic_webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        return True
    except requests.RequestException:
        logger.exception("Échec envoi webhook générique pour %s", cve.cve_id)
        return False
