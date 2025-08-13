import logging, re

_EMAIL_RX = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.I)

class RedactingFormatter(logging.Formatter):
    def __init__(self, fmt: str, redact: bool, redact_style: str):
        super().__init__(fmt)
        self._redact = redact
        self._redact_style = redact_style

    def format(self, record: logging.LogRecord) -> str:
        s = super().format(record)
        if not self._redact:
            return s
        def _mask(m: re.Match) -> str:
            email = m.group(0)
            if self._redact_style == "none":
                return email
            try:
                local, domain = email.split("@", 1)
                if len(local) <= 2:
                    masked = local[:1] + "*" * max(0, len(local) - 1)
                else:
                    masked = local[0] + "*" * (len(local) - 2) + local[-1]
                return masked + "@" + domain
            except Exception:
                return "***@***"
        return _EMAIL_RX.sub(_mask, s)

def build_logger(name: str, level: int, redact_emails: bool = True, redact_style: str = "mask") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        h = logging.StreamHandler()
        f = RedactingFormatter("%(asctime)s [%(levelname)s] %(name)s :: %(message)s", redact_emails, redact_style)
        h.setFormatter(f)
        logger.addHandler(h)
    logger.setLevel(level)
    logger.propagate = False
    return logger
