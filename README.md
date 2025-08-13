# 📧 emailtoolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
[![Type hints: PEP 561](https://img.shields.io/badge/Typing-PEP%20561-informational.svg)](https://peps.python.org/pep-0561/)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)](#roadmap)

> RFC-aware email parsing, normalization, extraction, and DNS health checks with a clean, phonenumbers-style API. Env-configurable. Privacy-safe logging. Optional CLI.

---

## ✨ Why emailtoolkit

* **Practical and strict where it matters**
  Syntax validated with `email_validator`, IDN via `idna`, DNS health via `dnspython` (optional).
* **Real-world canonicalization**
  Provider-aware normalization and canonical comparison. Gmail dot and plus rules, googlemail aliasing, optional plus-stripping for common providers.
* **Production ergonomics**
  `.env` and `config.json` support, structured data classes, robust logging with PII redaction, TTL-cached DNS.
* **Simple API**
  Import functions or use the `EmailTools` class. Also ships a CLI for quick checks and pipelines.

---

## 🧩 Features

* Parse, validate, normalize, canonicalize, compare
* Extract addresses from free text with Unicode-aware regex
* DNS health checks with MX and A/AAAA lookups, TTL caching
* IDN handling with punycode conversion
* Disposable domain filtering from file or URL source
* Config precedence: environment > `.env` > `config.json` > defaults
* Privacy by default: email redaction in logs and exceptions
* CLI entry point for scripting and ops

---

## 🚀 Install

### From source (editable)

```bash
# from repo root
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -U pip

# optional extras:
#   dns -> dnspython
#   dotenv -> python-dotenv
pip install -e ".[dns,dotenv]"
```

### From PyPI (when published)

```bash
pip install emailtoolkit
# with optional extras
pip install "emailtoolkit[dns,dotenv]"
```

---

## ⚙️ Configuration

emailtoolkit loads configuration in this order:

1. Environment variables
2. `.env` file in the working directory (if `python-dotenv` is installed)
3. `config.json` if you pass `--config` or `build_tools("/path/to/config.json")`
4. Internal defaults

### Environment variables

| Variable                              | Type                                  | Default       | Description                                                           |
| ------------------------------------- | ------------------------------------- | ------------- | --------------------------------------------------------------------- |
| `EMAILTK_LOG_LEVEL`                   | str                                   | `INFO`        | Logging level: `DEBUG` `INFO` `WARNING` `ERROR`                       |
| `EMAILTK_REQUIRE_MX`                  | bool                                  | `true`        | If true, deliverability requires MX. If false, MX or A/AAAA is enough |
| `EMAILTK_REQUIRE_DELIVERABILITY`      | bool                                  | `false`       | If true, `parse` raises if deliverability fails                       |
| `EMAILTK_ALLOW_SMTPUTF8`              | bool                                  | `true`        | Allow UTF-8 local parts per RFC 6531                                  |
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

### Example `.env`

```env
EMAILTK_LOG_LEVEL=INFO
EMAILTK_REQUIRE_MX=true
EMAILTK_REQUIRE_DELIVERABILITY=false
EMAILTK_DNS_TIMEOUT_SECONDS=1.5
EMAILTK_DNS_TTL_SECONDS=60
EMAILTK_USE_DNSPYTHON=true
EMAILTK_PII_REDACT_LOGS=true
EMAILTK_PII_REDACT_STYLE=mask
EMAILTK_DISPOSABLE_SOURCE=file://./disposable.txt
```

### Example `config.json`

```json
{
  "log_level": "INFO",
  "extract_unique": true,
  "extract_max_results": null,
  "require_mx": true,
  "require_deliverability": false,
  "allow_smtputf8": true,
  "dns_timeout_seconds": 2.0,
  "dns_ttl_seconds": 900,
  "use_dnspython": true,
  "normalize_case": true,
  "gmail_style_canonicalization": true,
  "treat_disposable_as_invalid": false,
  "block_private_tlds": false,
  "known_public_suffixes": null,
  "disposable_source": "none"
}
```

---

## 🧪 Quick start

```python
import emailtoolkit as et

et.is_valid("Test.User+sales@Gmail.com")            # True
et.normalize("Test.User+sales@Gmail.com")           # "Test.User+sales@gmail.com"
et.canonical("t.e.s.t+sales@googlemail.com")        # "test@gmail.com"
et.compare("t.e.s.t+sales@googlemail.com", "test@gmail.com")  # True

e = et.parse("Alice@example.com")
print(e.normalized)          # "Alice@example.com"
print(e.domain_info.has_mx)  # may be True/False depending on resolver

found = et.extract("Contact a@example.com, A@EXAMPLE.com, junk@@bad")
print([x.normalized for x in found])  # ["a@example.com"]
```

Prefer a configured instance:

```python
from emailtoolkit import EmailTools
from emailtoolkit.utils.config import load_config

tools = EmailTools(load_config("./config.json"))
tools.is_valid("user@例え.テスト")
```

---

## 🛠️ CLI

```bash
# from anywhere once installed
emailtoolkit parse "Test.User+foo@Gmail.com"
emailtoolkit validate "user@example.com"
emailtoolkit normalize "Test.User+foo@Gmail.com"
emailtoolkit canonical "t.e.s.t+bar@googlemail.com"
emailtoolkit domain example.com
echo "a@example.com, t.e.s.t+z@gmail.com" | emailtoolkit extract --limit 5

# use a config
emailtoolkit --config ./emailtoolkit/configs/config.example.json parse "user@domain.com"
```

---

## 📚 API reference

### Data models

```python
from emailtoolkit import Email, DomainInfo, EmailParseException
```

* `Email`

  * `original` str
  * `local` str
  * `domain` str
  * `ascii_email` str
  * `normalized` str
  * `canonical` str
  * `domain_info` DomainInfo
  * `valid_syntax` bool
  * `deliverable_dns` bool
  * `reason` Optional\[str]

* `DomainInfo`

  * `domain` str
  * `ascii_domain` str
  * `mx_hosts` tuple\[str, ...]
  * `a_hosts` tuple\[str, ...]
  * `has_mx` bool
  * `has_a` bool
  * `disposable` bool

* `EmailParseException(ValueError)`
  Includes `domain_info` for context.

### Module functions

```python
import emailtoolkit as et

et.parse(raw: str) -> Email
et.is_valid(raw: str) -> bool
et.normalize(raw: str) -> str
et.canonical(raw: str) -> str
et.extract(text: str) -> list[Email]
et.compare(a: str, b: str) -> bool
et.domain_health(domain: str) -> DomainInfo
et.build_tools(overrides_path: str | None = None) -> EmailTools
```

### Class

```python
from emailtoolkit import EmailTools
from emailtoolkit.utils.config import Config, load_config

tools = EmailTools(cfg=Config())              # or EmailTools(config_path="config.json") via loader
tools.parse(...)
```

Behavior notes:

* `parse` uses `email_validator` for syntax and normalization only.
  Deliverability is decided by our DNS layer:

  * If `require_mx` is true, deliverable means MX exists.
  * If `require_mx` is false, deliverable means MX or A/AAAA exists.
* Gmail canonicalization:

  * `googlemail.com` is treated as `gmail.com` for identity comparison.
  * Dots are stripped and plus-tags are removed for Gmail if enabled.

---

## 🔒 Security and privacy

* PII redaction in logs is enabled by default. Control with:

  * `EMAILTK_PII_REDACT_LOGS=true|false`
  * `EMAILTK_PII_REDACT_STYLE=mask|none`
* Do not log raw emails in your app. The logger masks the local part by default.
* If you enable SMTP probing in the future, keep it opt-in, rate limited, and legally vetted.

---

## 🧰 Development

```bash
# lint and type checks (examples; use your preferred tools)
pip install -e ".[dns,dotenv]" pytest ruff mypy
ruff check src
mypy src/emailtoolkit
pytest -q
```

Optional sanity test script example is in the repo root:

```
python test_emailtoolkit.py
```

---

## 🧭 Roadmap

* Async resolver and extractor for high concurrency
* Provider rules registry loaded from data files
* Optional SMTP RCPT probe with strict rate limits
* Public suffix enforcement with a bundled list
* Disposable domain updater command

---

## 🙏 Acknowledgments

This project stands on the shoulders of these excellent libraries:

* **email\_validator** by Joshua Tauberer — Unlicense (public domain)
* **dnspython** — ISC license (optional dependency)
* **idna** — BSD 3-Clause

Full texts in `THIRD_PARTY_NOTICES.md`. Thank you to the maintainers and contributors of these projects.

---

## 📦 License

MIT. See [LICENSE](LICENSE).

Third-party licenses are included in [THIRD\_PARTY\_NOTICES.md](THIRD_PARTY_NOTICES.md).

---

## 💡 Contributing

* Open an issue with clear reproduction steps or a focused proposal.
* Small PRs preferred. Include tests and update docs where relevant.
* Keep performance and privacy top of mind.

---

## ⭐ Support

If this toolkit helps you, star the repo and share it. Issues and PRs welcome.
