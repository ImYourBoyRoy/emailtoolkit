# ./src/emailtoolkit/emails.py
"""EmailToolkit core orchestration for parse/normalize/extract/domain functions.

Used by both the public Python API and the CLI entrypoint.
Run via imports (e.g., ``from emailtoolkit import parse``) or ``python -m emailtoolkit.main``.
Inputs: raw email/text/domain strings, config overrides via ``Config`` or ``--config`` JSON/env.
Outputs: ``Email``/``DomainInfo`` models, boolean checks, and parse exceptions with safe messages.
Side effects: optional DNS lookups and disposable-source loading at tool instance creation.
Operational notes: keeps error messages non-PII and avoids DNS work for obviously invalid domains.
"""

from __future__ import annotations

import math
import re
from typing import List, Optional, Pattern, Set

import idna
from email_validator import EmailNotValidError, caching_resolver, validate_email

from .models import DomainInfo, Email, EmailParseException
from .utils.config import Config, load_config
from .utils.dns import DNSHelper
from .utils.disposable import load_disposable
from .utils.encoding import find_and_decode_cf_emails
from .utils.logger import build_logger

_DOMAIN_LABEL_RX: Pattern[str] = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)


class EmailTools:
    """Stateful helper implementing the existing EmailToolkit behaviors."""

    def __init__(self, cfg: Optional[Config] = None, config_path: Optional[str] = None):
        self.cfg = cfg or load_config(config_path)
        self.log = build_logger(
            self.cfg.logger_name,
            self.cfg.log_level,
            redact_emails=self.cfg.pii_redact_logs,
            redact_style=self.cfg.pii_redact_style,
        )

        resolver_timeout: int = max(1, math.ceil(self.cfg.dns_timeout_seconds))
        self._resolver = caching_resolver(timeout=resolver_timeout)
        self._email_rx = re.compile(
            self.cfg.email_pattern,
            re.IGNORECASE | re.VERBOSE | re.UNICODE,
        )
        self._dns = DNSHelper(
            self.cfg.dns_timeout_seconds,
            self.cfg.dns_ttl_seconds,
            self.cfg.use_dnspython,
        )
        self._disposable = load_disposable(self.cfg.disposable_source)

    def parse(self, raw: str) -> Email:
        """Parse and enrich a single email string."""
        candidate = (raw or "").strip()
        if not candidate:
            raise EmailParseException("Empty email string")

        try:
            validated = validate_email(
                candidate,
                check_deliverability=False,
                allow_smtputf8=self.cfg.allow_smtputf8,
                dns_resolver=self._resolver,
            )
        except EmailNotValidError as err:
            guessed_domain = self._safe_domain_guess(candidate)
            guessed_info = self._domain_info_from_guess(guessed_domain)
            raise EmailParseException(
                "Invalid email syntax", domain_info=guessed_info
            ) from err

        local = validated.local_part
        domain = validated.domain
        ascii_email = validated.ascii_email or f"{local}@{domain}"

        domain_info = self._domain_info(domain)
        deliverable_dns = (
            domain_info.has_mx
            if self.cfg.require_mx
            else (domain_info.has_mx or domain_info.has_a)
        )

        if self.cfg.require_deliverability and not deliverable_dns:
            raise EmailParseException(
                "No MX or A/AAAA records found",
                domain_info=domain_info,
            )

        if self._disposable and domain_info.ascii_domain in self._disposable:
            if self.cfg.treat_disposable_as_invalid:
                raise EmailParseException(
                    "Disposable domain not allowed",
                    domain_info=domain_info,
                )

        normalized = self._normalize(local, domain_info.ascii_domain)
        canonical = self._canonical(local, domain_info.ascii_domain)

        return Email(
            original=candidate,
            local=local,
            domain=domain,
            ascii_email=ascii_email,
            normalized=normalized,
            canonical=canonical,
            domain_info=domain_info,
            valid_syntax=True,
            deliverable_dns=deliverable_dns,
        )

    def is_valid(self, raw: str) -> bool:
        """Return a boolean validity decision for a single email."""
        try:
            parsed = self.parse(raw)
        except EmailParseException:
            return False
        return parsed.valid_syntax and (
            parsed.deliverable_dns if self.cfg.require_deliverability else True
        )

    def normalize(self, raw: str) -> str:
        """Return normalized email output."""
        return self.parse(raw).normalized

    def canonical(self, raw: str) -> str:
        """Return canonical email output."""
        return self.parse(raw).canonical

    def extract(self, text: str) -> List[Email]:
        """Extract emails from text and optional Cloudflare-protected payloads."""
        results: List[Email] = []
        seen: Optional[Set[str]] = set() if self.cfg.extract_unique else None

        candidates = [
            match.group("email") for match in self._email_rx.finditer(text or "")
        ]
        decoded_cf = find_and_decode_cf_emails(text)

        for raw_candidate in [*candidates, *decoded_cf]:
            try:
                parsed = self.parse(raw_candidate)
            except EmailParseException:
                continue

            if seen is not None:
                key = parsed.canonical
                if key in seen:
                    continue
                seen.add(key)

            results.append(parsed)
            if (
                self.cfg.extract_max_results
                and len(results) >= self.cfg.extract_max_results
            ):
                break

        return results

    def compare(self, a: str, b: str) -> bool:
        """Compare two addresses by canonical form."""
        try:
            return self.canonical(a) == self.canonical(b)
        except EmailParseException:
            return False

    def domain_health(self, domain: str) -> DomainInfo:
        """Return DNS/disposable indicators for a domain."""
        return self._domain_info(domain)

    def _safe_domain_guess(self, raw: str) -> str:
        if "@" not in raw:
            return raw.strip().strip(">),.;")
        guessed = raw.split("@", 1)[1].lstrip("@")
        return guessed.strip().strip(">),.;")

    def _idna(self, domain: str) -> str:
        try:
            return idna.encode(domain).decode("ascii")
        except Exception:
            return domain.lower()

    def _domain_info_from_guess(self, guessed_domain: str) -> DomainInfo:
        """Return safe domain info for syntax-failure paths."""
        normalized = (guessed_domain or "").strip().lower()
        if self._is_dns_lookup_candidate(normalized):
            return self._domain_info(normalized)
        return DomainInfo(domain=normalized, ascii_domain=self._idna(normalized))

    def _is_dns_lookup_candidate(self, domain: str) -> bool:
        """Cheap domain validity gate to avoid wasteful DNS lookups."""
        if not domain or len(domain) > 253:
            return False
        if "@" in domain or " " in domain or ".." in domain:
            return False

        labels = domain.split(".")
        if len(labels) < 2:
            return False

        return all(_DOMAIN_LABEL_RX.match(label) is not None for label in labels)

    def _domain_info(self, domain: str) -> DomainInfo:
        normalized_domain = (domain or "").strip().lower()
        ascii_domain = self._idna(normalized_domain)

        if self.cfg.block_private_tlds and self.cfg.known_public_suffixes is not None:
            parts = ascii_domain.rsplit(".", 1)
            tld = parts[1] if len(parts) == 2 else ""
            if tld and tld not in self.cfg.known_public_suffixes:
                return DomainInfo(domain=normalized_domain, ascii_domain=ascii_domain)

        mx_hosts, a_hosts, has_mx, has_a = self._dns.query(ascii_domain)
        disposable = self._disposable is not None and ascii_domain in self._disposable
        return DomainInfo(
            domain=normalized_domain,
            ascii_domain=ascii_domain,
            mx_hosts=mx_hosts,
            a_hosts=a_hosts,
            has_mx=has_mx,
            has_a=has_a,
            disposable=disposable,
        )

    def _normalize(self, local: str, ascii_domain: str) -> str:
        normalized_local = local
        normalized_domain = (
            ascii_domain.lower() if self.cfg.normalize_case else ascii_domain
        )

        if normalized_local.startswith('"') and normalized_local.endswith('"'):
            if '\\"' not in normalized_local and "'" not in normalized_local:
                normalized_local = normalized_local[1:-1]

        return f"{normalized_local}@{normalized_domain}"

    def _canonical(self, local: str, ascii_domain: str) -> str:
        canonical_local = local
        canonical_domain = ascii_domain.lower()

        if canonical_domain == "googlemail.com":
            canonical_domain = "gmail.com"

        if canonical_domain in self.cfg.plus_normalized_domains:
            plus_index = canonical_local.find("+")
            if plus_index != -1:
                canonical_local = canonical_local[:plus_index]

        if (
            self.cfg.gmail_style_canonicalization
            and canonical_domain in self.cfg.gmail_like_domains
        ):
            canonical_local = canonical_local.replace(".", "")

        if (
            canonical_domain in self.cfg.gmail_like_domains
            or canonical_domain in self.cfg.plus_normalized_domains
        ):
            canonical_local = canonical_local.lower()

        return f"{canonical_local}@{canonical_domain}"


_default_instance: Optional[EmailTools] = None


def _get_default() -> EmailTools:
    global _default_instance
    if _default_instance is None:
        _default_instance = EmailTools()
    return _default_instance


def build_tools(overrides_path: Optional[str] = None) -> EmailTools:
    if overrides_path:
        return EmailTools(config_path=overrides_path)
    return EmailTools()


def parse(raw: str) -> Email:
    return _get_default().parse(raw)


def is_valid(raw: str) -> bool:
    return _get_default().is_valid(raw)


def normalize(raw: str) -> str:
    return _get_default().normalize(raw)


def canonical(raw: str) -> str:
    return _get_default().canonical(raw)


def extract(text: str) -> List[Email]:
    return _get_default().extract(text)


def compare(a: str, b: str) -> bool:
    return _get_default().compare(a, b)


def domain_health(domain: str) -> DomainInfo:
    return _get_default().domain_health(domain)
