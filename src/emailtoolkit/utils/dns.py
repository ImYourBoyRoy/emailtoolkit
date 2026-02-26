# ./src/emailtoolkit/utils/dns.py
"""DNS lookup helper used by EmailToolkit domain enrichment.

Imported by ``emailtoolkit.emails.EmailTools`` during parse/domain checks.
Run path: internal module import only (no direct CLI entrypoint).
Inputs: domain strings and runtime config (timeout, ttl, dnspython toggle).
Outputs: ``(mx_hosts, a_hosts, has_mx, has_a)`` tuples cached by TTL.
Side effects: network DNS/socket lookups and in-memory cache updates.
Operational notes: filters null-MX placeholders and keeps fallback deterministic.
"""

from __future__ import annotations

import socket
from typing import Iterable, Tuple

from .cache import TTLCache

try:
    import dns.resolver  # type: ignore

    _HAS_DNSPY = True
except Exception:
    _HAS_DNSPY = False


def _normalize_mx_hosts(records: Iterable[object]) -> Tuple[str, ...]:
    """Normalize resolver MX records and drop null/empty placeholders."""
    normalized = {
        str(record).rstrip(".").strip().lower()
        for record in records
        if str(record).strip()
    }
    normalized.discard("")
    return tuple(sorted(normalized))


class DNSHelper:
    """Resolve MX/A/AAAA records with cache and socket fallback."""

    def __init__(self, timeout: float, ttl: int, use_dnspython: bool):
        self._timeout = timeout
        self._cache = TTLCache(ttl)
        self._use_dnspython = use_dnspython and _HAS_DNSPY
        self._resolver = None

        if self._use_dnspython:
            resolver = dns.resolver.Resolver()  # type: ignore[name-defined]
            resolver.lifetime = timeout
            self._resolver = resolver

    def query(self, domain: str) -> Tuple[Tuple[str, ...], Tuple[str, ...], bool, bool]:
        """Query DNS and return cached MX/A tuple metadata."""
        key = f"dom:{domain}"
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        mx_hosts: Tuple[str, ...] = tuple()
        a_hosts: Tuple[str, ...] = tuple()
        has_mx = False
        has_a = False

        if self._use_dnspython and self._resolver is not None:
            try:
                mx_answers = self._resolver.resolve(domain, "MX")
                exchanges = (answer.exchange for answer in mx_answers)
                mx_hosts = _normalize_mx_hosts(exchanges)
                has_mx = len(mx_hosts) > 0
            except Exception:
                mx_hosts = tuple()
                has_mx = False

            try:
                a_answers = self._resolver.resolve(domain, "A")
                a_hosts = tuple(sorted(str(answer.address) for answer in a_answers))
                has_a = len(a_hosts) > 0
            except Exception:
                a_hosts = tuple()
                has_a = False

            if not has_a:
                try:
                    aaaa_answers = self._resolver.resolve(domain, "AAAA")
                    a_hosts = tuple(
                        sorted(str(answer.address) for answer in aaaa_answers)
                    )
                    has_a = len(a_hosts) > 0
                except Exception:
                    a_hosts = tuple()
                    has_a = False
        else:
            try:
                infos = socket.getaddrinfo(domain, None)
                addresses = sorted(
                    {
                        info[4][0]
                        for info in infos
                        if info[4] and isinstance(info[4][0], str)
                    }
                )
                if addresses:
                    a_hosts = tuple(addresses)
                    has_a = True
            except Exception:
                a_hosts = tuple()
                has_a = False

        result = (mx_hosts, a_hosts, has_mx, has_a)
        self._cache.set(key, result)
        return result
