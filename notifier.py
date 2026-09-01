from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


def email_configured() -> bool:
    required = ["IP_SENTINEL_SMTP_HOST", "IP_SENTINEL_ALERT_TO"]
    return all(os.getenv(key) for key in required)


def send_email_alert(subject: str, body: str) -> bool:
    """Send an optional SMTP alert. Returns False when SMTP is not configured."""
    if not email_configured():
        return False

    host = os.environ["IP_SENTINEL_SMTP_HOST"]
    port = int(os.getenv("IP_SENTINEL_SMTP_PORT", "587"))
    username = os.getenv("IP_SENTINEL_SMTP_USER", "")
    password = os.getenv("IP_SENTINEL_SMTP_PASSWORD", "")
    recipient = os.environ["IP_SENTINEL_ALERT_TO"]
    sender = os.getenv("IP_SENTINEL_ALERT_FROM", username or "ip-sentinel@localhost")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = recipient
    message.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=10) as smtp:
        smtp.ehlo()
        if os.getenv("IP_SENTINEL_SMTP_STARTTLS", "1") != "0":
            smtp.starttls(context=context)
            smtp.ehlo()
        if username:
            smtp.login(username, password)
        smtp.send_message(message)
    return True
