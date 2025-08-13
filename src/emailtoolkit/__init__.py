# emailtoolkit/__init__.py
from pathlib import Path

try:
    version_path = Path(__file__).parent.parent.parent / "VERSION"
    __version__ = version_path.read_text(encoding="utf-8").strip()
except FileNotFoundError:
    __version__ = "0.0.0" # Fallback version

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
