# ./tests/test_emailtools_core.py
"""Core EmailTools behavior coverage for parse/extract/domain workflows.

This module tests current toolkit functionality without relying on live DNS by
patching resolver calls to deterministic return values per test scenario.

Run path: `pytest tests/test_emailtools_core.py`.
Inputs: EmailTools config options and synthetic email/text samples.
Outputs: assertions on parse validity, canonicalization, extraction, and policy behavior.
Operational notes: network-independent by design for CI stability.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from emailtoolkit import emails as emails_mod
from emailtoolkit.emails import EmailTools
from emailtoolkit.models import DomainInfo, EmailParseException
from emailtoolkit.utils.config import Config


def _encode_cf_email(email: str, key: int = 0x42) -> str:
    return f"{key:02x}" + "".join(f"{ord(char) ^ key:02x}" for char in email)


def test_parse_normalize_canonical_and_compare(monkeypatch: pytest.MonkeyPatch) -> None:
    tools = EmailTools(cfg=Config())
    monkeypatch.setattr(
        tools._dns,
        "query",
        lambda _domain: (("mx.example.test",), ("203.0.113.10",), True, True),
    )

    parsed = tools.parse("Test.User+Sales@Gmail.com")
    assert parsed.valid_syntax is True
    assert parsed.normalized == "Test.User+Sales@gmail.com"
    assert parsed.canonical == "testuser@gmail.com"
    assert parsed.domain_info.has_mx is True
    assert tools.compare("t.e.s.t+foo@googlemail.com", "test@gmail.com") is True


def test_parse_invalid_syntax_raises_safe_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = EmailTools(cfg=Config())
    monkeypatch.setattr(
        tools._dns,
        "query",
        lambda _domain: (tuple(), tuple(), False, False),
    )

    with pytest.raises(EmailParseException) as exc_info:
        tools.parse("invalid@@example..com")

    assert str(exc_info.value) == "Invalid email syntax"
    assert isinstance(exc_info.value.domain_info, DomainInfo)


def test_parse_invalid_guess_skips_dns_for_obvious_non_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = EmailTools(cfg=Config())

    def _unexpected_dns_call(
        _domain: str,
    ) -> tuple[tuple[str, ...], tuple[str, ...], bool, bool]:
        raise AssertionError("DNS should not run for malformed guessed domains")

    monkeypatch.setattr(tools._dns, "query", _unexpected_dns_call)

    with pytest.raises(EmailParseException) as exc_info:
        tools.parse("invalid@@example..com")

    info = exc_info.value.domain_info
    assert info is not None
    assert info.domain == "example..com"
    assert info.has_mx is False
    assert info.has_a is False


def test_require_deliverability_blocks_missing_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = Config(require_mx=False, require_deliverability=True)
    tools = EmailTools(cfg=cfg)
    monkeypatch.setattr(
        tools._dns,
        "query",
        lambda _domain: (tuple(), tuple(), False, False),
    )

    with pytest.raises(EmailParseException, match="No MX or A/AAAA records found"):
        tools.parse("user@example.com")


def test_disposable_policy_and_domain_health(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    disposable_path = tmp_path / "disposable.txt"
    disposable_path.write_text("mailinator.com\n", encoding="utf-8")

    cfg = Config(
        disposable_source=f"file://{disposable_path}",
        treat_disposable_as_invalid=True,
    )
    tools = EmailTools(cfg=cfg)
    monkeypatch.setattr(
        tools._dns,
        "query",
        lambda _domain: (("mx.mailinator.com",), ("198.51.100.4",), True, True),
    )

    with pytest.raises(EmailParseException, match="Disposable domain not allowed"):
        tools.parse("someone@mailinator.com")

    info = tools.domain_health("mailinator.com")
    assert info.disposable is True


def test_block_private_tld_short_circuits_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = Config(block_private_tlds=True, known_public_suffixes={"com", "org", "net"})
    tools = EmailTools(cfg=cfg)

    def _unexpected_dns_call(
        _domain: str,
    ) -> tuple[tuple[str, ...], tuple[str, ...], bool, bool]:
        raise AssertionError("DNS query should not run for blocked private TLD")

    monkeypatch.setattr(tools._dns, "query", _unexpected_dns_call)
    info = tools.domain_health("intranet.local")

    assert info.domain == "intranet.local"
    assert info.ascii_domain == "intranet.local"
    assert info.has_mx is False
    assert info.has_a is False


def test_extract_combines_regex_cloudflare_and_uniqueness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = Config(extract_unique=True, extract_max_results=2, require_mx=False)
    tools = EmailTools(cfg=cfg)
    monkeypatch.setattr(
        tools._dns,
        "query",
        lambda _domain: (tuple(), ("203.0.113.9",), False, True),
    )

    hidden = "hidden@example.com"
    encoded = _encode_cf_email(hidden)
    text = (
        "Reach t.e.s.t+foo@gmail.com or test@gmail.com. "
        f'<a class="__cf_email__" data-cfemail="{encoded}">hidden</a>'
    )

    extracted = tools.extract(text)
    canonicals = [item.canonical for item in extracted]

    assert len(extracted) == 2
    assert canonicals.count("test@gmail.com") == 1
    assert "hidden@example.com" in canonicals


def test_extract_limit_can_stop_early(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = Config(extract_unique=False, extract_max_results=1, require_mx=False)
    tools = EmailTools(cfg=cfg)
    monkeypatch.setattr(
        tools._dns,
        "query",
        lambda _domain: (tuple(), ("203.0.113.15",), False, True),
    )

    out = tools.extract("a@example.com b@example.com c@example.com")
    assert len(out) == 1


def test_domain_health_handles_idna(monkeypatch: pytest.MonkeyPatch) -> None:
    tools = EmailTools(cfg=Config())
    monkeypatch.setattr(
        tools._dns,
        "query",
        lambda domain: (("mx.idna.test",), tuple(), True, False)
        if domain == "xn--r8jz45g.xn--zckzah"
        else (tuple(), tuple(), False, False),
    )

    info = tools.domain_health("例え.テスト")
    assert info.ascii_domain == "xn--r8jz45g.xn--zckzah"
    assert info.has_mx is True


def test_module_default_instance_is_lazy_and_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeDefault:
        def parse(self, raw: str):
            return f"parsed:{raw}"

    created: list[_FakeDefault] = []

    def _fake_builder() -> _FakeDefault:
        instance = _FakeDefault()
        created.append(instance)
        return instance

    monkeypatch.setattr(emails_mod, "_default_instance", None)
    monkeypatch.setattr(emails_mod, "EmailTools", _fake_builder)

    assert emails_mod.parse("a@example.com") == "parsed:a@example.com"
    assert emails_mod.parse("b@example.com") == "parsed:b@example.com"
    assert len(created) == 1


def test_domain_health_cache_hits_and_misses(monkeypatch: pytest.MonkeyPatch) -> None:
    tools = EmailTools(cfg=Config(use_dnspython=False))
    call_count = [0]

    def _mock_getaddrinfo(domain: str, port):
        call_count[0] += 1
        return [(2, 1, 6, "", ("198.51.100.10", 0))]

    monkeypatch.setattr("emailtoolkit.utils.dns.socket.getaddrinfo", _mock_getaddrinfo)

    # First call (miss)
    tools.domain_health("example.com")
    assert call_count[0] == 1

    # Second call (hit, cached in _dns)
    tools.domain_health("example.com")
    assert call_count[0] == 1

    # Clear cache, call again (miss)
    tools._dns._cache.clear()
    tools.domain_health("example.com")
    assert call_count[0] == 2
