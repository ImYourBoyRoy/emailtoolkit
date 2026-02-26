# ./src/emailtoolkit/utils/config.py
"""Configuration loader and coercion utilities for EmailToolkit.

Used by ``EmailTools`` to merge defaults, JSON config, dotenv, and environment.
Run path: internal import via ``emailtoolkit.emails`` or direct helper import in tests.
Inputs: optional JSON config path, optional local ``.env``, and ``EMAILTK_*`` variables.
Outputs: populated ``Config`` dataclass with normalized types.
Side effects: may read local files and mutate process env when dotenv is present.
Operational notes: malformed overrides are safely ignored to preserve deterministic defaults.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Set, Tuple

try:
    from dotenv import load_dotenv as _load_dotenv

    _HAS_DOTENV = True
except Exception:
    _load_dotenv = None  # type: ignore[assignment]
    _HAS_DOTENV = False

_LOG_LEVELS = {
    "CRITICAL": 50,
    "ERROR": 40,
    "WARNING": 30,
    "INFO": 20,
    "DEBUG": 10,
    "NOTSET": 0,
}


@dataclass
class Config:
    log_level: int = 20
    logger_name: str = "emailtoolkit"

    extract_unique: bool = True
    extract_max_results: Optional[int] = None

    require_mx: bool = True
    require_deliverability: bool = False
    allow_smtputf8: bool = True

    dns_timeout_seconds: float = 2.0
    dns_ttl_seconds: int = 900
    use_dnspython: bool = True

    normalize_case: bool = True
    gmail_style_canonicalization: bool = True

    treat_disposable_as_invalid: bool = False
    block_private_tlds: bool = False
    known_public_suffixes: Optional[Set[str]] = None

    disposable_source: str = "none"

    enable_smtp_probe: bool = False
    smtp_probe_timeout: float = 3.0
    smtp_probe_concurrency: int = 5
    smtp_probe_helo: str = "example.com"

    pii_redact_logs: bool = True
    pii_redact_style: str = "mask"  # mask | none

    email_pattern: str = r"""
        (?P<email>
            [^\s"'<>()]+
            @
            [A-Za-z0-9](?:[A-Za-z0-9\-\.]*[A-Za-z0-9])?
            \.[A-Za-z]{2,}
        )
    """

    gmail_like_domains: Tuple[str, ...] = ("gmail.com", "googlemail.com")
    plus_normalized_domains: Tuple[str, ...] = (
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "yahoo.com",
        "icloud.com",
        "me.com",
        "proton.me",
        "pm.me",
    )


def _bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Optional[str], default: int) -> int:
    try:
        return int(value) if value is not None else default
    except Exception:
        return default


def _float(value: Optional[str], default: float) -> float:
    try:
        return float(value) if value is not None else default
    except Exception:
        return default


def _to_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def _to_int(value: Any, default: int) -> int:
    try:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str) and value.strip():
            return int(value.strip())
    except Exception:
        return default
    return default


def _to_float(value: Any, default: float) -> float:
    try:
        if isinstance(value, bool):
            return float(value)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str) and value.strip():
            return float(value.strip())
    except Exception:
        return default
    return default


def _to_optional_int(value: Any, default: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in {"", "0", "none", "null"}:
        return None
    if isinstance(value, (int, float, str)):
        fallback = default if default is not None else 0
        coerced = _to_int(value, fallback)
        if coerced <= 0:
            return None
        return coerced
    return default


def _to_string_tuple(value: Any, default: Tuple[str, ...]) -> Tuple[str, ...]:
    if not isinstance(value, (list, tuple, set)):
        return default
    parsed = [str(item).strip().lower() for item in value if str(item).strip()]
    return tuple(parsed) if parsed else default


def _to_optional_string_set(
    value: Any,
    default: Optional[Set[str]],
) -> Optional[Set[str]]:
    if value is None:
        return None
    if not isinstance(value, (list, tuple, set)):
        return default
    parsed = {str(item).strip().lower() for item in value if str(item).strip()}
    return parsed if parsed else None


def _apply_json_overrides(cfg: Config, data: dict[str, Any]) -> None:
    bool_fields = {
        "extract_unique",
        "require_mx",
        "require_deliverability",
        "allow_smtputf8",
        "use_dnspython",
        "normalize_case",
        "gmail_style_canonicalization",
        "treat_disposable_as_invalid",
        "block_private_tlds",
        "enable_smtp_probe",
        "pii_redact_logs",
    }
    int_fields = {"dns_ttl_seconds", "smtp_probe_concurrency"}
    float_fields = {"dns_timeout_seconds", "smtp_probe_timeout"}

    for key, value in data.items():
        if not hasattr(cfg, key):
            continue

        if key == "log_level":
            if isinstance(value, str):
                cfg.log_level = _LOG_LEVELS.get(
                    value.upper(), _to_int(value, cfg.log_level)
                )
            else:
                cfg.log_level = _to_int(value, cfg.log_level)
            continue

        if key in bool_fields:
            setattr(cfg, key, _to_bool(value, getattr(cfg, key)))
            continue

        if key in int_fields:
            setattr(cfg, key, _to_int(value, getattr(cfg, key)))
            continue

        if key in float_fields:
            setattr(cfg, key, _to_float(value, getattr(cfg, key)))
            continue

        if key == "extract_max_results":
            cfg.extract_max_results = _to_optional_int(value, cfg.extract_max_results)
            continue

        if key == "known_public_suffixes":
            cfg.known_public_suffixes = _to_optional_string_set(
                value, cfg.known_public_suffixes
            )
            continue

        if key in {"gmail_like_domains", "plus_normalized_domains"}:
            setattr(cfg, key, _to_string_tuple(value, getattr(cfg, key)))
            continue

        if key == "pii_redact_style":
            if isinstance(value, str) and value in {"mask", "none"}:
                cfg.pii_redact_style = value
            continue

        if isinstance(getattr(cfg, key), str):
            setattr(cfg, key, str(value))
            continue

        setattr(cfg, key, value)


def _load_json_config(config_path: str) -> dict[str, Any]:
    path = Path(config_path)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_dotenv_if_present() -> None:
    if not _HAS_DOTENV or _load_dotenv is None:
        return
    env_path = Path(".env")
    if not env_path.exists():
        return
    try:
        _load_dotenv(dotenv_path=env_path, override=True)
    except Exception:
        return


def _load_known_public_suffixes(path_str: str) -> Optional[Set[str]]:
    try:
        path = Path(path_str)
        if not path.is_file():
            return None
        values = {
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("//")
        }
        return values or None
    except Exception:
        return None


def load_config(config_path: Optional[str]) -> Config:
    """Load runtime config with precedence: defaults -> JSON -> dotenv -> env."""
    cfg = Config()

    if config_path:
        _apply_json_overrides(cfg, _load_json_config(config_path))

    _load_dotenv_if_present()
    env = os.environ.get

    level = env("EMAILTK_LOG_LEVEL")
    if level:
        cfg.log_level = _LOG_LEVELS.get(level.upper(), cfg.log_level)

    cfg.extract_unique = _bool(env("EMAILTK_EXTRACT_UNIQUE"), cfg.extract_unique)

    extract_limit = env("EMAILTK_EXTRACT_MAX_RESULTS")
    if extract_limit is not None:
        cfg.extract_max_results = (
            None
            if extract_limit.strip().lower() in {"", "0", "none", "null"}
            else _int(extract_limit, 0)
        )

    cfg.require_mx = _bool(env("EMAILTK_REQUIRE_MX"), cfg.require_mx)
    cfg.require_deliverability = _bool(
        env("EMAILTK_REQUIRE_DELIVERABILITY"),
        cfg.require_deliverability,
    )
    cfg.allow_smtputf8 = _bool(env("EMAILTK_ALLOW_SMTPUTF8"), cfg.allow_smtputf8)

    cfg.dns_timeout_seconds = max(
        0.1,
        _float(env("EMAILTK_DNS_TIMEOUT_SECONDS"), cfg.dns_timeout_seconds),
    )
    cfg.dns_ttl_seconds = _int(env("EMAILTK_DNS_TTL_SECONDS"), cfg.dns_ttl_seconds)
    cfg.use_dnspython = _bool(env("EMAILTK_USE_DNSPYTHON"), cfg.use_dnspython)

    cfg.normalize_case = _bool(env("EMAILTK_NORMALIZE_CASE"), cfg.normalize_case)
    cfg.gmail_style_canonicalization = _bool(
        env("EMAILTK_GMAIL_CANON"),
        cfg.gmail_style_canonicalization,
    )

    cfg.treat_disposable_as_invalid = _bool(
        env("EMAILTK_TREAT_DISPOSABLE_AS_INVALID"),
        cfg.treat_disposable_as_invalid,
    )
    cfg.block_private_tlds = _bool(
        env("EMAILTK_BLOCK_PRIVATE_TLDS"), cfg.block_private_tlds
    )

    suffix_file = env("EMAILTK_PUBLIC_SUFFIX_FILE")
    if suffix_file:
        loaded_suffixes = _load_known_public_suffixes(suffix_file)
        if loaded_suffixes is not None:
            cfg.known_public_suffixes = loaded_suffixes

    disposable_source = env("EMAILTK_DISPOSABLE_SOURCE")
    if disposable_source:
        cfg.disposable_source = disposable_source

    cfg.enable_smtp_probe = _bool(
        env("EMAILTK_ENABLE_SMTP_PROBE"), cfg.enable_smtp_probe
    )
    cfg.smtp_probe_timeout = _float(
        env("EMAILTK_SMTP_PROBE_TIMEOUT"), cfg.smtp_probe_timeout
    )
    cfg.smtp_probe_concurrency = _int(
        env("EMAILTK_SMTP_PROBE_CONCURRENCY"),
        cfg.smtp_probe_concurrency,
    )
    cfg.smtp_probe_helo = env("EMAILTK_SMTP_PROBE_HELO") or cfg.smtp_probe_helo

    cfg.pii_redact_logs = _bool(env("EMAILTK_PII_REDACT_LOGS"), cfg.pii_redact_logs)
    redaction_style = env("EMAILTK_PII_REDACT_STYLE")
    if redaction_style in {"mask", "none"}:
        cfg.pii_redact_style = redaction_style

    return cfg
