import logging

import requests

from app.config import settings
from app.models import CVE

logger = logging.getLogger(__name__)


def build_slack_payload(cve: CVE, reasons: list[str]) -> dict:
    severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(cve.severity or "", "⚪")
    lines = [
        f"{severity_emoji} *{cve.cve_id}* - CVSS {cve.cvss_score if cve.cvss_score is not None else 'N/A'}"
        f" ({cve.severity or 'inconnue'})",
        f"*Vendeur/Produit*: {cve.vendor or '?'} / {cve.product or '?'}",
        f"*Raisons*: {', '.join(reasons)}",
        (cve.description or "")[:300],
    ]
    if cve.is_kev:
        lines.append(":rotating_light: Présente dans le catalogue CISA KEV (exploitation active)")
    if cve.references:
        lines.append(f"<{cve.references[0]}|Référence>")

    return {"text": "\n".join(lines)}


def send_slack_alert(cve: CVE, reasons: list[str], webhook_url: str | None = None) -> bool:
    url = webhook_url or settings.slack_webhook_url
    if not url:
        logger.debug("Slack webhook non configuré, alerte ignorée pour %s", cve.cve_id)
        return False
    try:
        resp = requests.post(url, json=build_slack_payload(cve, reasons), timeout=10)
        resp.raise_for_status()
        return True
    except requests.RequestException:
        logger.exception("Échec envoi alerte Slack pour %s", cve.cve_id)
        return False
