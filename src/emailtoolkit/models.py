# ./src/emailtoolkit/models.py
"""
Immutable public data models used by EmailToolkit parse and health APIs.
Run via imports from `emailtoolkit` consumers and internal modules.
Inputs: normalized email/domain metadata produced during parsing and DNS checks.
Outputs: frozen dataclasses and typed exceptions for downstream application code.
Side effects: none.
Operational notes: models remain serialization-friendly and safe for caching/testing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Tuple


@dataclass(frozen=True)
class DomainInfo:
    domain: str
    ascii_domain: str
    mx_hosts: Tuple[str, ...] = field(default_factory=tuple)
    a_hosts: Tuple[str, ...] = field(default_factory=tuple)
    has_mx: bool = False
    has_a: bool = False
    disposable: bool = False


@dataclass(frozen=True)
class Email:
    original: str
    local: str
    domain: str
    ascii_email: str
    normalized: str
    canonical: str
    domain_info: DomainInfo
    valid_syntax: bool
    deliverable_dns: bool
    reason: Optional[str] = None


class EmailParseException(ValueError):
    def __init__(self, message: str, domain_info: Optional[DomainInfo] = None):
        super().__init__(message)
        self.domain_info = domain_info
