import logging
import smtplib
from email.mime.text import MIMEText

from app.config import settings
from app.models import CVE

logger = logging.getLogger(__name__)


def _header_safe(value: str) -> str:
    """Retire tout retour à la ligne d'une valeur destinée à un en-tête email (Subject...).

    Les champs CVE (vendeur/produit/sévérité) proviennent de sources externes (NVD/GHSA/KEV) ;
    sans cette normalisation, une valeur contenant un CR/LF pourrait injecter un en-tête
    supplémentaire (ex: Bcc:) dans le message envoyé (CRLF header injection)."""
    return value.replace("\r", " ").replace("\n", " ")


def build_email_body(cve: CVE, reasons: list[str]) -> str:
    return (
        f"CVE: {cve.cve_id}\n"
        f"CVSS: {cve.cvss_score} ({cve.severity})\n"
        f"Vendeur/Produit: {cve.vendor} / {cve.product}\n"
        f"KEV (exploitation active): {'oui' if cve.is_kev else 'non'}\n"
        f"Raisons de l'alerte: {', '.join(reasons)}\n\n"
        f"{cve.description}\n\n"
        f"Références:\n" + "\n".join(cve.references or [])
    )


def send_email_alert(cve: CVE, reasons: list[str]) -> bool:
    if not (settings.smtp_host and settings.smtp_from and settings.smtp_to):
        logger.debug("SMTP non configuré, alerte email ignorée pour %s", cve.cve_id)
        return False

    msg = MIMEText(build_email_body(cve, reasons), _charset="utf-8")
    subject = f"[VulnAegis] {cve.severity or '?'} {cve.cve_id} - {cve.vendor or ''} {cve.product or ''}".strip()
    msg["Subject"] = _header_safe(subject)
    msg["From"] = settings.smtp_from
    msg["To"] = ", ".join(settings.smtp_to)

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            if settings.smtp_use_tls:
                server.starttls()
            if settings.smtp_user and settings.smtp_password:
                server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.smtp_from, settings.smtp_to, msg.as_string())
        return True
    except (smtplib.SMTPException, OSError):
        logger.exception("Échec envoi alerte email pour %s", cve.cve_id)
        return False
