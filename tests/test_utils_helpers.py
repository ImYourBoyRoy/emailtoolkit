# ./tests/test_utils_helpers.py
"""Unit tests for EmailToolkit utility modules.

This suite validates deterministic helper behavior for config loading, TTL
cache expiry, disposable source parsing, and Cloudflare email decoding.

Run path: `pytest tests/test_utils_helpers.py`.
Inputs: temporary files, environment overrides, and synthetic encoded payloads.
Outputs: assertions proving utility correctness without external network calls.
Operational notes: environment mutations are isolated with pytest monkeypatch.
"""

from __future__ import annotations

from pathlib import Path

from emailtoolkit.utils import cache as cache_mod
from emailtoolkit.utils.cache import TTLCache
from emailtoolkit.utils.config import load_config
from emailtoolkit.utils.dns import DNSHelper
from emailtoolkit.utils.disposable import load_disposable
from emailtoolkit.utils.encoding import decode_cf_email, find_and_decode_cf_emails


def _encode_cf_email(email: str, key: int = 0x2A) -> str:
    return f"{key:02x}" + "".join(f"{ord(char) ^ key:02x}" for char in email)


def test_ttl_cache_set_get_expire_clear(monkeypatch) -> None:
    clock = [1000.0]
    monkeypatch.setattr(cache_mod.time, "time", lambda: clock[0])

    cache = TTLCache(ttl_seconds=5)
    cache.set("k", {"v": 1})
    assert cache.get("k") == {"v": 1}

    clock[0] = 1006.0
    assert cache.get("k") is None

    cache.set("x", 9)
    cache.clear()
    assert cache.get("x") is None


def test_load_disposable_from_file_source(tmp_path: Path) -> None:
    source_file = tmp_path / "disposable.txt"
    source_file.write_text(
        "# comment\nmailinator.com\n TempMail.com \n", encoding="utf-8"
    )

    values = load_disposable(f"file://{source_file}")
    assert values == {"mailinator.com", "tempmail.com"}


def test_load_disposable_none_and_invalid_source() -> None:
    assert load_disposable("none") is None
    assert load_disposable("file://definitely/missing/file.txt") is None
    assert load_disposable("unsupported://value") is None


def test_load_disposable_url_exception(monkeypatch) -> None:
    def mock_urlopen(*args, **kwargs):
        from urllib.error import URLError

        raise URLError("Timeout")

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
    assert load_disposable("url://https://timeout.example.com") is None


def test_cloudflare_decode_helpers_round_trip() -> None:
    raw = "hidden@example.com"
    encoded = _encode_cf_email(raw)
    html = f'<a class="__cf_email__" data-cfemail="{encoded}">hidden</a>'

    assert decode_cf_email(encoded) == raw
    assert find_and_decode_cf_emails(html) == [raw]
    assert decode_cf_email("zz") == ""
    assert find_and_decode_cf_emails("") == []


def test_load_config_json_then_env_override(tmp_path: Path, monkeypatch) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        ('{"require_mx": false, "normalize_case": false, "extract_max_results": 5}'),
        encoding="utf-8",
    )

    suffix_file = tmp_path / "suffixes.txt"
    suffix_file.write_text("// comment\ncom\norg\n", encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("EMAILTK_REQUIRE_MX", "true")
    monkeypatch.setenv("EMAILTK_EXTRACT_MAX_RESULTS", "0")
    monkeypatch.setenv("EMAILTK_PUBLIC_SUFFIX_FILE", str(suffix_file))

    cfg = load_config(str(config_path))
    assert cfg.require_mx is True  # env overrides JSON
    assert cfg.normalize_case is False  # from JSON
    assert cfg.extract_max_results is None  # env "0" => None sentinel
    assert cfg.known_public_suffixes == {"com", "org"}


def test_load_config_json_type_coercion_is_safe(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        (
            "{"
            '"require_mx": "false", '
            '"dns_ttl_seconds": "1200", '
            '"dns_timeout_seconds": "1.75", '
            '"extract_max_results": "3", '
            '"gmail_like_domains": ["gmail.com", "googlemail.com"], '
            '"known_public_suffixes": ["com", "org"], '
            '"pii_redact_style": "none"'
            "}"
        ),
        encoding="utf-8",
    )

    cfg = load_config(str(config_path))
    assert cfg.require_mx is False
    assert cfg.dns_ttl_seconds == 1200
    assert cfg.dns_timeout_seconds == 1.75
    assert cfg.extract_max_results == 3
    assert cfg.gmail_like_domains == ("gmail.com", "googlemail.com")
    assert cfg.known_public_suffixes == {"com", "org"}
    assert cfg.pii_redact_style == "none"


def test_dns_helper_socket_fallback_returns_ip_addresses(monkeypatch) -> None:
    helper = DNSHelper(timeout=1.0, ttl=60, use_dnspython=False)

    def _fake_getaddrinfo(_domain: str, _port):
        return [
            (2, 1, 6, "", ("198.51.100.20", 0)),
            (2, 1, 6, "", ("198.51.100.10", 0)),
            (2, 1, 6, "", ("198.51.100.20", 0)),
        ]

    monkeypatch.setattr("emailtoolkit.utils.dns.socket.getaddrinfo", _fake_getaddrinfo)

    mx, a, has_mx, has_a = helper.query("example.com")
    assert mx == tuple()
    assert has_mx is False
    assert has_a is True
    assert a == ("198.51.100.10", "198.51.100.20")


def test_dns_helper_filters_null_mx_records(monkeypatch) -> None:
    class _MXRecord:
        def __init__(self, exchange: str) -> None:
            self.exchange = exchange

    class _ARecord:
        def __init__(self, address: str) -> None:
            self.address = address

    class _FakeResolver:
        def resolve(self, _domain: str, record_type: str):
            if record_type == "MX":
                return [_MXRecord("."), _MXRecord("mail.example.com.")]
            if record_type == "A":
                return [_ARecord("203.0.113.2")]
            raise RuntimeError("unexpected record type")

    helper = DNSHelper(timeout=1.0, ttl=60, use_dnspython=False)
    monkeypatch.setattr(helper, "_use_dnspython", True)
    monkeypatch.setattr(helper, "_resolver", _FakeResolver())

    mx, a, has_mx, has_a = helper.query("example.com")
    assert mx == ("mail.example.com",)
    assert has_mx is True
    assert a == ("203.0.113.2",)
    assert has_a is True
