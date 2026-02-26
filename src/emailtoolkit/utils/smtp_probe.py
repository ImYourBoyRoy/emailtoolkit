# ./src/emailtoolkit/utils/smtp_probe.py
"""Optional SMTP RCPT probe helper retained for existing toolkit behavior.

Run path: internal utility import (currently optional/off by default in config).
Inputs: domain, recipient address, HELO hostname, and timeout.
Outputs: ``True`` (accepted), ``False`` (rejected), or ``None`` (unknown/blocked).
Side effects: opens outbound SMTP socket connection on port 25 when invoked.
Operational notes: many providers block probing; callers should treat ``None`` as non-fatal.
"""

from __future__ import annotations

import smtplib
import socket
from typing import Optional


def probe_rcpt(domain: str, address: str, helo: str, timeout: float) -> Optional[bool]:
    """Perform a best-effort RCPT probe against a guessed MX host."""
    mx_host = f"mail.{domain}"

    try:
        with smtplib.SMTP(mx_host, 25, timeout=timeout) as smtp:
            smtp.ehlo_or_helo_if_needed()
            try:
                code, _ = smtp.mail(f"postmaster@{helo}")
                if code >= 400:
                    return None

                code, _ = smtp.rcpt(address)
                if 200 <= code < 300:
                    return True
                if 500 <= code < 600:
                    return False
                return None
            except smtplib.SMTPResponseException as err:
                if 500 <= err.smtp_code < 600:
                    return False
                return None
    except (
        socket.timeout,
        ConnectionRefusedError,
        smtplib.SMTPConnectError,
        OSError,
    ):
        return None
