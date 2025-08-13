# 📧 emailtoolkit

[![PyPI Version](https://img.shields.io/pypi/v/emailtoolkit.svg)](https://pypi.org/project/emailtoolkit/)
[![Python Versions](https://img.shields.io/pypi/pyversions/emailtoolkit.svg)](https://pypi.org/project/emailtoolkit/)
[![CI Status](https://github.com/ImYourBoyRoy/emailtoolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/ImYourBoyRoy/emailtoolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/pypi/l/emailtoolkit.svg)](https://opensource.org/licenses/MIT)
[![Typing: PEP 561](https://img.shields.io/badge/Typing-PEP%20561-informational.svg)](https://peps.python.org/pep-0561/)

> RFC‑aware email parsing, normalization, extraction, and DNS health checks with a clean, **phonenumbers‑style** API.

---

## ✨ Design goals

* **Simple API**
  Be as easy as phonenumbers. Import module‑level functions for quick tasks, or instantiate `EmailTools` for tuned, high‑performance use.

* **Practical validation**
  Separate syntax validation (via `email_validator`) from deliverability checks. Enforce your own DNS policy (require MX, or allow A/AAAA fallback).

* **Provider‑aware identity**
  Correctly determine that `test.user@gmail.com` and `testuser+sales@googlemail.com` are the same identity using canonicalization rules.

* **Operations‑ready**
  Native env, `.env`, and `config.json` support; PII‑safe logging; TTL‑cached DNS; robust CLI.

---

## 🚀 Installation

```bash
pip install emailtoolkit
# extras for DNS and .env support
pip install "emailtoolkit[dns,dotenv]"
```

---

## 🧪 Quick start

```python
import emailtoolkit as et

# Validate
et.is_valid("Test.User+sales@Gmail.com")  # True

# Canonical form (provider‑specific rules)
et.canonical("t.e.s.t+sales@googlemail.com")  # "test@gmail.com"

# Compare by canonical identity
et.compare("t.e.s.t+sales@googlemail.com", "test@gmail.com")  # True

# Extract from free text (returns Email objects)
found = et.extract("Contact a@example.com, A@EXAMPLE.com, and junk@@bad.")
print([e.normalized for e in found])  # ["a@example.com", "A@example.com"]
```

---

## 🛠️ Command‑line interface (CLI)

```bash
# Canonical form
emailtoolkit canonical "t.e.s.t+bar@googlemail.com"
# → test@gmail.com

# Domain DNS health (JSON)
emailtoolkit domain example.com
# {
#   "domain": "example.com",
#   "ascii_domain": "example.com",
#   "mx_hosts": [],
#   "a_hosts": ["93.184.216.34"],
#   "has_mx": false,
#   "has_a": true,
#   "disposable": false
# }

# Extract from stdin
echo "Contact me at a@example.com" | emailtoolkit extract
```

---

## ⚙️ Configuration

Load precedence:

1. Environment variables (e.g., `EMAILTK_LOG_LEVEL`)
2. `.env` in the working directory (requires `dotenv` extra)
3. `config.json` (when passed to CLI `--config` or `build_tools("/path/to/config.json")`)
4. Internal defaults

### Environment variables (full)

| Variable                              | Type                                  | Default       | Description                                                           |
| ------------------------------------- | ------------------------------------- | ------------- | --------------------------------------------------------------------- |
| `EMAILTK_LOG_LEVEL`                   | str                                   | `INFO`        | Logging level: `DEBUG` `INFO` `WARNING` `ERROR`                       |
| `EMAILTK_REQUIRE_MX`                  | bool                                  | `true`        | If true, deliverability requires MX. If false, MX or A/AAAA is enough |
| `EMAILTK_REQUIRE_DELIVERABILITY`      | bool                                  | `false`       | If true, `parse` raises if deliverability fails                       |
| `EMAILTK_ALLOW_SMTPUTF8`              | bool                                  | `true`        | Allow UTF‑8 local parts per RFC 6531                                  |
| `EMAILTK_DNS_TIMEOUT_SECONDS`         | float                                 | `2.0`         | DNS timeout seconds                                                   |
| `EMAILTK_DNS_TTL_SECONDS`             | int                                   | `900`         | TTL for cached DNS answers                                            |
| `EMAILTK_USE_DNSPYTHON`               | bool                                  | `true`        | Use dnspython when available                                          |
| `EMAILTK_EXTRACT_UNIQUE`              | bool                                  | `true`        | Deduplicate by canonical form during extraction                       |
| `EMAILTK_EXTRACT_MAX_RESULTS`         | int or empty                          | empty         | Hard cap on extractor results. Empty or 0 means no cap                |
| `EMAILTK_NORMALIZE_CASE`              | bool                                  | `true`        | Lowercase domain on normalize                                         |
| `EMAILTK_GMAIL_CANON`                 | bool                                  | `true`        | Apply Gmail dot and plus canonicalization rules                       |
| `EMAILTK_TREAT_DISPOSABLE_AS_INVALID` | bool                                  | `false`       | If true, disposable domains cause `parse` to raise                    |
| `EMAILTK_BLOCK_PRIVATE_TLDS`          | bool                                  | `false`       | Enforce known public suffixes if provided                             |
| `EMAILTK_PUBLIC_SUFFIX_FILE`          | path                                  | empty         | File with known public suffixes, one per line                         |
| `EMAILTK_DISPOSABLE_SOURCE`           | `file://...` or `url://...` or `none` | `none`        | Source for disposable domains                                         |
| `EMAILTK_ENABLE_SMTP_PROBE`           | bool                                  | `false`       | Reserved for optional SMTP probing module                             |
| `EMAILTK_SMTP_PROBE_TIMEOUT`          | float                                 | `3.0`         | Probe timeout                                                         |
| `EMAILTK_SMTP_PROBE_CONCURRENCY`      | int                                   | `5`           | Probe concurrency                                                     |
| `EMAILTK_SMTP_PROBE_HELO`             | str                                   | `example.com` | HELO/EHLO identity                                                    |
| `EMAILTK_PII_REDACT_LOGS`             | bool                                  | `true`        | Mask emails in logs and exceptions                                    |
| `EMAILTK_PII_REDACT_STYLE`            | `mask` or `none`                      | `mask`        | Redaction style                                                       |

See `.env.example` for a ready‑to‑copy template.

---

## 🧱 Disposable domain filtering

Create a text file and point to it:

```text
# disposable.txt
# Lines beginning with # are comments
# Domains are matched case‑insensitively on ASCII form
mailinator.com
10minutemail.com
sharklasers.com
```

Enable via `.env`:

```env
EMAILTK_DISPOSABLE_SOURCE=file://./disposable.txt
```

Optionally set:

```env
EMAILTK_TREAT_DISPOSABLE_AS_INVALID=true
```

This will raise `EmailParseException` when parsing addresses on those domains.

---

## 🤖 Agents, MCP servers, and tool‑calling

```python
from pydantic import BaseModel, Field
import emailtoolkit as et

class EmailInput(BaseModel):
    email: str = Field(..., description="Email address to parse")

class DomainInput(BaseModel):
    domain: str = Field(..., description="Domain to inspect")

def tool_parse(args: EmailInput):
    e = et.parse(args.email)
    return {
        "normalized": e.normalized,
        "canonical": e.canonical,
        "deliverable": e.deliverable_dns,
        "domain": e.domain_info.ascii_domain,
    }

def tool_domain(args: DomainInput):
    d = et.domain_health(args.domain)
    return {
        "domain": d.ascii_domain,
        "has_mx": d.has_mx,
        "has_a": d.has_a,
        "disposable": d.disposable,
    }
```

---

## 📚 API surface

```python
import emailtoolkit as et
from emailtoolkit import EmailTools, Email, DomainInfo, EmailParseException

# module functions
et.parse(raw: str) -> Email
et.is_valid(raw: str) -> bool
et.normalize(raw: str) -> str
et.canonical(raw: str) -> str
et.extract(text: str) -> list[Email]
et.compare(a: str, b: str) -> bool
et.domain_health(domain: str) -> DomainInfo
et.build_tools(overrides_path: str | None = None) -> EmailTools

# dataclasses
Email(
  original, local, domain, ascii_email, normalized, canonical,
  domain_info: DomainInfo, valid_syntax: bool, deliverable_dns: bool, reason: str|None
)
DomainInfo(domain, ascii_domain, mx_hosts, a_hosts, has_mx, has_a, disposable)
```

---

## 🔒 Security & privacy

* PII redaction in logs is on by default (`EMAILTK_PII_REDACT_LOGS`).
* Avoid logging raw addresses in your application.
* If SMTP probing is enabled in the future, keep it opt‑in, rate‑limited, and legally reviewed.

---

## 🧰 Development

```bash
pip install -e ".[dns,dotenv]" pytest ruff mypy
ruff check src
mypy src/emailtoolkit
pytest -q
```

---

## 🙏 Acknowledgments

Built on:

* **email\_validator** by Joshua Tauberer (Unlicense)
* **dnspython** (ISC) \[optional]
* **idna** (BSD‑3‑Clause)

See `THIRD_PARTY_NOTICES.md` for license texts.

---

## 📦 License

MIT. See [LICENSE](LICENSE). Third‑party licenses in [THIRD\_PARTY\_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## ⭐ Support

If this toolkit helps you, star the repo and share it. Issues and PRs welcome.
