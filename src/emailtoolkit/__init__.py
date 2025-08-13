# emailtoolkit/__init__.py
try:
    from ._version import __version__
except ImportError:
    __version__ = "0.0.0"

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
    "__version__",
]
