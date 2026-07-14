from unittest.mock import MagicMock, patch

from app.alerting.email import _header_safe, build_email_body, send_email_alert
from app.alerting.slack import build_slack_payload, send_slack_alert
from app.alerting.webhook import send_generic_webhook
from app.config import settings
from app.models import CVE


def make_cve(**kwargs) -> CVE:
    defaults = dict(
        cve_id="CVE-2026-1000", description="desc", cvss_score=9.8, severity="CRITICAL",
        vendor="Acme", product="Widget", is_kev=False, references=["https://example.com/a"],
    )
    defaults.update(kwargs)
    return CVE(**defaults)


# ---------- Slack ----------

def test_slack_payload_includes_kev_flag():
    cve = make_cve(is_kev=True)
    payload = build_slack_payload(cve, ["exploitée activement (CISA KEV)"])
    assert "CISA KEV" in payload["text"]
    assert cve.cve_id in payload["text"]


def test_send_slack_alert_noop_without_webhook(monkeypatch):
    monkeypatch.setattr(settings, "slack_webhook_url", None)
    assert send_slack_alert(make_cve(), ["x"]) is False


def test_send_slack_alert_posts_to_webhook(monkeypatch):
    monkeypatch.setattr(settings, "slack_webhook_url", "https://hooks.example/x")
    with patch("app.alerting.slack.requests.post") as post:
        post.return_value.raise_for_status.return_value = None
        assert send_slack_alert(make_cve(), ["x"]) is True
        assert post.call_args[0][0] == "https://hooks.example/x"


# ---------- Email ----------

def test_header_safe_strips_crlf():
    result = _header_safe("Acme\r\nBcc: attacker@evil.com")
    assert "\r" not in result and "\n" not in result
    assert result == "Acme  Bcc: attacker@evil.com"  # \r et \n remplacés individuellement par un espace
    assert "\r" not in _header_safe("a\r\nb\nc")
    assert "\n" not in _header_safe("a\r\nb\nc")


def test_send_email_alert_noop_without_smtp_config(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", None)
    assert send_email_alert(make_cve(), ["x"]) is False


def test_send_email_alert_sanitizes_crlf_in_subject(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_from", "vulnaegis@example.com")
    monkeypatch.setattr(settings, "smtp_to", ["analyst@example.com"])
    monkeypatch.setattr(settings, "smtp_use_tls", False)
    monkeypatch.setattr(settings, "smtp_user", None)
    monkeypatch.setattr(settings, "smtp_password", None)

    # Un vendeur malveillant tentant d'injecter un en-tête Bcc via un retour à la ligne brut.
    cve = make_cve(vendor="Acme\r\nBcc: attacker@evil.com")
    with patch("app.alerting.email.smtplib.SMTP") as smtp_cls:
        server = MagicMock()
        smtp_cls.return_value.__enter__.return_value = server
        assert send_email_alert(cve, ["x"]) is True
        sent_message = server.sendmail.call_args[0][2]

    header_block = sent_message.split("\n\n", 1)[0]
    header_lines = [line for line in header_block.splitlines() if line]
    # Sans la sanitization, l'injection créerait une ligne d'en-tête "Bcc: attacker@evil.com"
    # distincte. Avec _header_safe, le CRLF est neutralisé et tout reste sur la ligne Subject.
    assert not any(line.lower().startswith("bcc:") for line in header_lines)
    subject_line = next(line for line in header_lines if line.startswith("Subject:"))
    assert "attacker@evil.com" in subject_line


def test_build_email_body_includes_references():
    body = build_email_body(make_cve(), ["CVSS >= 7"])
    assert "https://example.com/a" in body


# ---------- Webhook générique ----------

def test_send_generic_webhook_noop_without_url(monkeypatch):
    monkeypatch.setattr(settings, "generic_webhook_url", None)
    assert send_generic_webhook(make_cve(), ["x"]) is False


def test_send_generic_webhook_posts_structured_payload(monkeypatch):
    monkeypatch.setattr(settings, "generic_webhook_url", "https://siem.example/hook")
    with patch("app.alerting.webhook.requests.post") as post:
        post.return_value.raise_for_status.return_value = None
        assert send_generic_webhook(make_cve(), ["x"]) is True
        payload = post.call_args[1]["json"]
        assert payload["cve_id"] == "CVE-2026-1000"
        assert payload["reasons"] == ["x"]
