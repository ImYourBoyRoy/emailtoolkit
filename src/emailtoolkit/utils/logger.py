# ./src/emailtoolkit/utils/logger.py
"""Logger builder with optional email redaction for EmailToolkit.

Run path: imported by ``emailtoolkit.emails``.
Inputs: logger name/level and redaction controls.
Outputs: configured ``logging.Logger`` instance.
Side effects: attaches a stream handler when one is not already present.
Operational notes: formatter masks local-part data unless redaction style is ``none``.
"""

from __future__ import annotations

import logging
import re

_EMAIL_RX = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)


class RedactingFormatter(logging.Formatter):
    """Formatter that can mask email addresses in log messages."""

    def __init__(self, fmt: str, redact: bool, redact_style: str):
        super().__init__(fmt)
        self._redact = redact
        self._redact_style = redact_style

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        if not self._redact:
            return rendered

        def _mask(match: re.Match[str]) -> str:
            email = match.group(0)
            if self._redact_style == "none":
                return email

            try:
                local, domain = email.split("@", 1)
                if len(local) <= 2:
                    masked_local = local[:1] + "*" * max(0, len(local) - 1)
                else:
                    masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
                return f"{masked_local}@{domain}"
            except Exception:
                return "***@***"

        return _EMAIL_RX.sub(_mask, rendered)


def build_logger(
    name: str,
    level: int,
    redact_emails: bool = True,
    redact_style: str = "mask",
) -> logging.Logger:
    """Create or reuse a configured logger instance."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = RedactingFormatter(
            "%(asctime)s [%(levelname)s] %(name)s :: %(message)s",
            redact_emails,
            redact_style,
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(level)
    logger.propagate = False
    return logger
