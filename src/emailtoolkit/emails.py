# emailtoolkit/emails.py

from __future__ import annotations
import re, idna
import math
from typing import List, Optional, Set
from email_validator import validate_email, EmailNotValidError, caching_resolver
from .utils.config import Config, load_config
from .utils.logger import build_logger
from .utils.dns import DNSHelper
from .utils.disposable import load_disposable
from .utils.encoding import find_and_decode_cf_emails
from .models import Email, DomainInfo, EmailParseException


class EmailTools:
    def __init__(self, cfg: Optional[Config] = None, config_path: Optional[str] = None):
        self.cfg = cfg or load_config(config_path)
        self.log = build_logger(
            self.cfg.logger_name,
            self.cfg.log_level,
            redact_emails=self.cfg.pii_redact_logs,
            redact_style=self.cfg.pii_redact_style,
        )

        _ev_timeout: int = max(1, math.ceil(self.cfg.dns_timeout_seconds))
        self._resolver = caching_resolver(timeout=_ev_timeout)
        self._email_rx = re.compile(self.cfg.email_pattern, re.IGNORECASE | re.VERBOSE | re.UNICODE)
        self._dns = DNSHelper(self.cfg.dns_timeout_seconds, self.cfg.dns_ttl_seconds, self.cfg.use_dnspython)
        self._disposable = load_disposable(self.cfg.disposable_source)

    def parse(self, raw: str) -> Email:
        s = (raw or "").strip()
        if not s:
            raise EmailParseException("Empty email string")
        try:
            v = validate_email(
                s,
                check_deliverability=False,
                allow_smtputf8=self.cfg.allow_smtputf8,
                dns_resolver=self._resolver,
            )
        except EmailNotValidError as err:
            dom = self._safe_domain_guess(s)
            info = self._domain_info(dom)
            # Avoid echoing the raw address back in errors; email_validator messages often include it
            msg = "Invalid email syntax"
            raise EmailParseException(msg, domain_info=info) from err

        local = v.local_part
        domain = v.domain
        ascii_email = v.ascii_email or f"{local}@{domain}"

        info = self._domain_info(domain)
        valid_syntax = True
        deliverable_dns = info.has_mx if self.cfg.require_mx else (info.has_mx or info.has_a)

        if self.cfg.require_deliverability and not deliverable_dns:
            raise EmailParseException("No MX or A/AAAA records found", domain_info=info)

        if self._disposable and info.ascii_domain in self._disposable:
            if self.cfg.treat_disposable_as_invalid:
                raise EmailParseException("Disposable domain not allowed", domain_info=info)

        normalized = self._normalize(local, info.ascii_domain)
        canonical = self._canonical(local, info.ascii_domain)

        return Email(
            original=s,
            local=local,
            domain=domain,
            ascii_email=ascii_email,
            normalized=normalized,
            canonical=canonical,
            domain_info=info,
            valid_syntax=valid_syntax,
            deliverable_dns=deliverable_dns,
        )

    def is_valid(self, raw: str) -> bool:
        try:
            em = self.parse(raw)
        except EmailParseException:
            return False
        return em.valid_syntax and (em.deliverable_dns if self.cfg.require_deliverability else True)

    def normalize(self, raw: str) -> str:
        return self.parse(raw).normalized

    def canonical(self, raw: str) -> str:
        return self.parse(raw).canonical

    def extract(self, text: str) -> List[Email]:
        out: List[Email] = []
        seen: Set[str] = set()

        # Combine regex-found emails with Cloudflare-decoded emails
        candidates = [m.group("email") for m in self._email_rx.finditer(text or "")]
        decoded_cf = find_and_decode_cf_emails(text)
        all_candidates = candidates + decoded_cf

        for candidate in all_candidates:
            try:
                e = self.parse(candidate)
            except EmailParseException:
                continue
            
            # Use canonical form for deduplication if enabled
            key = e.canonical if self.cfg.extract_unique else e.normalized
            if self.cfg.extract_unique and key in seen:
                continue
            seen.add(key)
            
            out.append(e)
            if self.cfg.extract_max_results and len(out) >= self.cfg.extract_max_results:
                break
        return out

    def compare(self, a: str, b: str) -> bool:
        try: return self.canonical(a) == self.canonical(b)
        except EmailParseException: return False

    def domain_health(self, domain: str) -> DomainInfo:
        return self._domain_info(domain)

    # internals
    def _safe_domain_guess(self, raw: str) -> str:
        return raw.split("@",1)[1].strip().strip(">),.;") if "@" in raw else raw

    def _idna(self, domain: str) -> str:
        try: return idna.encode(domain).decode("ascii")
        except Exception: return domain.lower()

    def _domain_info(self, domain: str) -> DomainInfo:
        d = (domain or "").strip().lower()
        ascii_domain = self._idna(d)
        if self.cfg.block_private_tlds and self.cfg.known_public_suffixes is not None:
            try: tld = ascii_domain.rsplit(".",1)[1]
            except Exception: tld = ""
            if tld and tld not in self.cfg.known_public_suffixes:
                return DomainInfo(domain=d, ascii_domain=ascii_domain)
        mx, a, has_mx, has_a = self._dns.query(ascii_domain)
        disposable = (self._disposable is not None and ascii_domain in self._disposable)
        return DomainInfo(
            domain=d, ascii_domain=ascii_domain, mx_hosts=mx, a_hosts=a, has_mx=has_mx, has_a=has_a, disposable=disposable
        )

    def _normalize(self, local: str, ascii_domain: str) -> str:
        loc = local
        dom = ascii_domain.lower() if self.cfg.normalize_case else ascii_domain
        if loc.startswith('"') and loc.endswith('"'):
            if '\\"' not in loc and "'" not in loc:
                loc = loc[1:-1]
        return f"{loc}@{dom}"

    def _canonical(self, local: str, ascii_domain: str) -> str:
        loc = local
        dom = ascii_domain.lower()
        if dom == "googlemail.com":
            dom = "gmail.com"
        if dom in self.cfg.plus_normalized_domains:
            i = loc.find("+")
            if i != -1:
                loc = loc[:i]
        if self.cfg.gmail_style_canonicalization and dom in self.cfg.gmail_like_domains:
            loc = loc.replace(".", "")
        if dom in self.cfg.gmail_like_domains or dom in self.cfg.plus_normalized_domains:
            loc = loc.lower()
        return f"{loc}@{dom}"

# module-level convenience
_default = EmailTools()

def build_tools(overrides_path: Optional[str] = None) -> EmailTools:
    if overrides_path:
        return EmailTools(config_path=overrides_path)
    return EmailTools()

def parse(raw: str) -> Email: return _default.parse(raw)
def is_valid(raw: str) -> bool: return _default.is_valid(raw)
def normalize(raw: str) -> str: return _default.normalize(raw)
def canonical(raw: str) -> str: return _default.canonical(raw)
def extract(text: str) -> List[Email]: return _default.extract(text)
def compare(a: str, b: str) -> bool: return _default.compare(a, b)
def domain_health(domain: str) -> DomainInfo: return _default.domain_health(domain)
