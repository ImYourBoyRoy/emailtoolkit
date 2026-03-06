# ./src/emailtoolkit/__init__.py
"""
Public package exports for EmailToolkit parsing and mailbox utilities.
Run via Python imports such as `from emailtoolkit import parse, is_valid`.
Inputs: consumer imports and email/domain strings passed to exported helpers.
Outputs: stable top-level API for parsing, normalization, validation, and mailbox checks.
Side effects: importing lazily initializes shared tool instances on first use only.
Operational notes: version import is best-effort so editable/dev installs stay resilient.
"""

from __future__ import annotations

try:
    from ._version import __version__
except Exception:  # pragma: no cover - defensive import for editable/dev installs
    __version__ = "0.0.0"

from .emails import (
    Config,
    EmailTools,
    build_tools,
    canonical,
    classify_mailbox,
    compare,
    domain_health,
    domain_matches,
    extract,
    is_valid,
    normalize,
    parse,
)
from .models import DomainInfo, Email, EmailParseException

__all__ = [
    "Config",
    "DomainInfo",
    "Email",
    "EmailParseException",
    "EmailTools",
    "__version__",
    "build_tools",
    "canonical",
    "classify_mailbox",
    "compare",
    "domain_health",
    "domain_matches",
    "extract",
    "is_valid",
    "normalize",
    "parse",
]
