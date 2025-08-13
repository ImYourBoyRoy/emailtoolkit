# emailtoolkit/__init__.py
__version__ = "0.1.1"

from .emails import (
    Config,
    EmailTools,
    parse,
    is_valid,
    normalize,
    canonical,
    extract,
    compare,
    domain_health,
    build_tools,
)
from .models import Email, DomainInfo, EmailParseException

__all__ = [
    "Config",
    "EmailTools",
    "Email",
    "DomainInfo",
    "EmailParseException",
    "parse",
    "is_valid",
    "normalize",
    "canonical",
    "extract",
    "compare",
    "domain_health",
    "build_tools",
]

__all__ += ["__version__"]