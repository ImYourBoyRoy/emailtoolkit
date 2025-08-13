# emailtoolkit/utils/smtp_probe.py

from __future__ import annotations
import smtplib, socket
from typing import Optional

def probe_rcpt(domain: str, address: str, helo: str, timeout: float) -> Optional[bool]:
    # Minimal, safe, and disabled by default. Many providers block this.
    # Returns True if 250 accepted, False if 550 rejected, None on unknown.
    mx_host = f"mail.{domain}"
    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as s:
            s.ehlo_or_helo_if_needed()
            try:
                code, _ = s.mail(f"postmaster@{helo}")
                if code >= 400: return None
                code, _ = s.rcpt(address)
                if 200 <= code < 300: return True
                if 500 <= code < 600: return False
                return None
            except smtplib.SMTPResponseException as e:
                if 500 <= e.smtp_code < 600: return False
                return None
    except (socket.timeout, ConnectionRefusedError, smtplib.SMTPConnectError, OSError):
        return None
