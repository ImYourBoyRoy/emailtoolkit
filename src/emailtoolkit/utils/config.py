# emailtoolkit/utils/config.py

from __future__ import annotations
import json, os
from dataclasses import dataclass
from typing import Optional, Set, Tuple, Any, Dict, Callable
from pathlib import Path

try:
    from dotenv import load_dotenv as _load_dotenv  # optional
    _HAS_DOTENV = True
except Exception:
    _load_dotenv = None  # type: ignore[assignment]
    _HAS_DOTENV = False

_LOG_LEVELS = {"CRITICAL":50,"ERROR":40,"WARNING":30,"INFO":20,"DEBUG":10,"NOTSET":0}

def _bool(s: Optional[str], default: bool) -> bool:
    if s is None: return default
    return s.strip().lower() in {"1","true","yes","on"}

def _float(s: Optional[str], default: float) -> float:
    try: return float(s) if s is not None else default
    except Exception: return default

def _int(s: Optional[str], default: int) -> int:
    try: return int(s) if s is not None else default
    except Exception: return default

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

    # PII redaction
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
        "gmail.com","googlemail.com","outlook.com","hotmail.com","live.com",
        "yahoo.com","icloud.com","me.com","proton.me","pm.me",
    )

def load_config(config_path: Optional[str]) -> Config:
    # 1) defaults
    cfg = Config()
    # 2) config.json
    if config_path:
        p = Path(config_path)
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                for k, v in data.items():
                    if hasattr(cfg, k):
                        setattr(cfg, k, v)
            except Exception:
                pass
    # 3) .env
    if _HAS_DOTENV and _load_dotenv is not None:
        env_path = Path(".env")
        if env_path.exists():
            try: 
                _load_dotenv(dotenv_path=env_path, override=True)
            except Exception: pass
    # 4) environment
    env = os.environ.get
    lvl = env("EMAILTK_LOG_LEVEL")
    if lvl: cfg.log_level = _LOG_LEVELS.get(lvl.upper(), cfg.log_level)
    cfg.extract_unique = _bool(env("EMAILTK_EXTRACT_UNIQUE"), cfg.extract_unique)
    amr = env("EMAILTK_EXTRACT_MAX_RESULTS")
    if amr is not None:
        cfg.extract_max_results = None if amr.strip() in {"", "0", "none", "null"} else _int(amr, 0)

    cfg.require_mx = _bool(env("EMAILTK_REQUIRE_MX"), cfg.require_mx)
    cfg.require_deliverability = _bool(env("EMAILTK_REQUIRE_DELIVERABILITY"), cfg.require_deliverability)
    cfg.allow_smtputf8 = _bool(env("EMAILTK_ALLOW_SMTPUTF8"), cfg.allow_smtputf8)

    cfg.dns_timeout_seconds = max(0.1, _float(env("EMAILTK_DNS_TIMEOUT_SECONDS"), cfg.dns_timeout_seconds))
    cfg.dns_ttl_seconds = _int(env("EMAILTK_DNS_TTL_SECONDS"), cfg.dns_ttl_seconds)
    cfg.use_dnspython = _bool(env("EMAILTK_USE_DNSPYTHON"), cfg.use_dnspython)

    cfg.normalize_case = _bool(env("EMAILTK_NORMALIZE_CASE"), cfg.normalize_case)
    cfg.gmail_style_canonicalization = _bool(env("EMAILTK_GMAIL_CANON"), cfg.gmail_style_canonicalization)

    cfg.treat_disposable_as_invalid = _bool(env("EMAILTK_TREAT_DISPOSABLE_AS_INVALID"), cfg.treat_disposable_as_invalid)
    cfg.block_private_tlds = _bool(env("EMAILTK_BLOCK_PRIVATE_TLDS"), cfg.block_private_tlds)

    _psf = env("EMAILTK_PUBLIC_SUFFIX_FILE")
    if _psf:
        try:
            path = Path(_psf)
            if path.is_file():
                cfg.known_public_suffixes = set(
                    s.strip() for s in path.read_text().splitlines()
                    if s.strip() and not s.startswith("//")
                )
        except Exception:
            pass

    src = env("EMAILTK_DISPOSABLE_SOURCE")
    if src: cfg.disposable_source = src

    cfg.enable_smtp_probe = _bool(env("EMAILTK_ENABLE_SMTP_PROBE"), cfg.enable_smtp_probe)
    cfg.smtp_probe_timeout = _float(env("EMAILTK_SMTP_PROBE_TIMEOUT"), cfg.smtp_probe_timeout)
    cfg.smtp_probe_concurrency = _int(env("EMAILTK_SMTP_PROBE_CONCURRENCY"), cfg.smtp_probe_concurrency)
    cfg.smtp_probe_helo = env("EMAILTK_SMTP_PROBE_HELO") or cfg.smtp_probe_helo

    # PII redaction
    cfg.pii_redact_logs = _bool(env("EMAILTK_PII_REDACT_LOGS"), cfg.pii_redact_logs)
    style = env("EMAILTK_PII_REDACT_STYLE")
    if style in {"mask","none"}:
        cfg.pii_redact_style = style

    return cfg
