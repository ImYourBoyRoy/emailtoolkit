# emailtoolkit/utils/dns.py

from __future__ import annotations
import socket
from typing import Tuple
from .cache import TTLCache

try:
    import dns.resolver  # type: ignore
    _HAS_DNSPY = True
except Exception:
    _HAS_DNSPY = False

class DNSHelper:
    def __init__(self, timeout: float, ttl: int, use_dnspython: bool):
        self._timeout = timeout
        self._cache = TTLCache(ttl)
        self._use = use_dnspython and _HAS_DNSPY
        self._resolver = None
        if self._use:
            res = dns.resolver.Resolver()  # type: ignore
            res.lifetime = timeout  # type: ignore
            self._resolver = res

    def query(self, domain: str) -> Tuple[Tuple[str, ...], Tuple[str, ...], bool, bool]:
        key = f"dom:{domain}"
        cached = self._cache.get(key)
        if cached: return cached
        mx: Tuple[str, ...] = tuple()
        a: Tuple[str, ...] = tuple()
        has_mx = False
        has_a = False
        if self._use and self._resolver:
            try:
                ans = self._resolver.resolve(domain, "MX")  # type: ignore
                mx = tuple(sorted(str(r.exchange).rstrip(".") for r in ans))  # type: ignore
                has_mx = len(mx) > 0
            except Exception:
                pass
            try:
                ans = self._resolver.resolve(domain, "A")  # type: ignore
                a = tuple(sorted(str(r.address) for r in ans))  # type: ignore
                has_a = len(a) > 0
            except Exception:
                pass
            if not has_a:
                try:
                    ans = self._resolver.resolve(domain, "AAAA")  # type: ignore
                    a = tuple(sorted(str(r.address) for r in ans))  # type: ignore
                    has_a = len(a) > 0
                except Exception:
                    pass
        else:
            try:
                socket.gethostbyname(domain)
                a = (domain,)
                has_a = True
            except Exception:
                pass
        out = (mx, a, has_mx, has_a)
        self._cache.set(key, out)
        return out
