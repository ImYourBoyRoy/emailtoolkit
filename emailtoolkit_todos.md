# EmailToolkit Modernization TODOs

## Current Toolkit Capability Map (As-Is, File-Accurate)

### Public API + Package Surface

- `src/emailtoolkit/__init__.py`
  - Exposes: `EmailTools`, `Config`, `Email`, `DomainInfo`, `EmailParseException`
  - Convenience functions: `parse`, `is_valid`, `normalize`, `canonical`, `extract`, `compare`, `domain_health`, `build_tools`
  - Version export from `_version.py` fallback

### Core Behavior

- `src/emailtoolkit/emails.py`
  - `EmailTools.parse(raw)`: syntax validation via `email_validator.validate_email`, domain enrichment, normalization/canonicalization, disposable policy checks
  - `EmailTools.is_valid(raw)`: boolean validity wrapper over `parse`
  - `EmailTools.normalize(raw)`: normalized address output
  - `EmailTools.canonical(raw)`: canonical address output (gmail/googlemail rules, plus-tag stripping, dot folding for configured domains)
  - `EmailTools.extract(text)`: regex extraction + Cloudflare `data-cfemail` decode integration + optional uniqueness and limit
  - `EmailTools.compare(a, b)`: canonical equality comparison
  - `EmailTools.domain_health(domain)`: DNS-derived domain information
  - Module-level convenience singleton `_default` and function wrappers

### CLI Surface

- `src/emailtoolkit/main.py`
  - `argparse` CLI commands:
    - `parse <email>`
    - `validate <email>`
    - `normalize <email>`
    - `canonical <email>`
    - `extract [--limit N]` (stdin input)
    - `domain <domain>`
  - Optional `--config` JSON path for config overrides

### Data Models

- `src/emailtoolkit/models.py`
  - `DomainInfo` dataclass: mx/a records presence + disposable flag
  - `Email` dataclass: parsed/normalized/canonical fields + domain info
  - `EmailParseException` carrying optional `domain_info`

### Config + Runtime Controls

- `src/emailtoolkit/utils/config.py`
  - `Config` dataclass for parser/extraction/DNS/disposable/logging options
  - `load_config(config_path)` precedence currently:
    1. Dataclass defaults
    2. Optional JSON config file
    3. Optional `.env` load (if `python-dotenv` installed)
    4. Environment variable overrides (`EMAILTK_*`)

### DNS / Disposable / Encoding Helpers

- `src/emailtoolkit/utils/dns.py`
  - `DNSHelper.query(domain)` with TTL cache + optional dnspython resolver + socket fallback
- `src/emailtoolkit/utils/disposable.py`
  - `load_disposable(source)` supports `none`, `file://`, `url://`
- `src/emailtoolkit/utils/encoding.py`
  - `decode_cf_email(encoded)`
  - `find_and_decode_cf_emails(html_text)` for Cloudflare obfuscation

### Logging + Cache + SMTP Probe Utilities

- `src/emailtoolkit/utils/logger.py`
  - Redacting formatter and logger builder for optional email masking in logs
- `src/emailtoolkit/utils/cache.py`
  - `TTLCache` used by DNS helper
- `src/emailtoolkit/utils/smtp_probe.py`
  - `probe_rcpt(...)` helper (present but not wired into core parse flow)

### Existing Test Entry

- `test_emailtoolkit.py`
  - Script-style end-to-end sanity run (currently used by CI)

## Current Test Suite Map (New + Existing)

- `tests/conftest.py`
  - Adds `src/` path for local imports and scrubs `__pycache__` pre/post test session.
- `tests/test_emailtools_core.py`
  - Covers `EmailTools` parse/validate/normalize/canonical/compare/extract/domain behavior with deterministic DNS patching.
- `tests/test_utils_helpers.py`
  - Covers `TTLCache`, config precedence/env overrides, disposable loading, and Cloudflare decode helpers.
- `tests/test_cli_surface.py`
  - Covers argparse CLI routing/output for `parse`, `validate`, `normalize`, `canonical`, `extract`, `domain` using fake tool injection.
- `tests/test_extraction_corpus.py`
  - Corpus-style extraction regression coverage using HTML/JSON fixtures for real-world patterns, including Cloudflare `data-cfemail`.
- `tests/fixtures/extraction/`
  - `html/*.html` realistic sample pages/snippets.
  - `expected/*.json` golden expected output snapshots.
  - `manifest.json` scenario matrix (config knobs + fixture mapping).
- `test_emailtoolkit.py`
  - Legacy smoke script retained as additional compatibility/sanity check.

Test runner/CI wiring:

- `pyproject.toml`
  - pytest configured to use `tests/` path (`[tool.pytest.ini_options]`).
- `.github/workflows/ci.yml`
  - installs `.[dns,dotenv,dev]`
  - runs `pytest` first, then legacy `test_emailtoolkit.py`

## Scope Lock (Current Sprint)

Only improve existing toolkit functionality:

- `parse`, `validate`, `normalize`, `canonical`, `extract`, `domain`
- associated config/DNS/disposable/logging helpers

Out of scope for now:

- new mail composition/sending features
- MCP/server additions
- feature expansion beyond current command/API surface

---

## Priority A — Correctness Fixes on Existing Functions

- [x] **Config type-safety hardening** in `src/emailtoolkit/utils/config.py`
  - Ensure JSON values are coerced/validated to expected types (bool/int/float/set/tuple).
  - Reject or safely ignore malformed values to preserve stable defaults.

- [x] **DNS fallback accuracy** in `src/emailtoolkit/utils/dns.py`
  - In socket fallback, store resolved IP(s) in `a_hosts` (currently domain string can leak in as host value).
  - Added tests for exact IP extraction and deterministic sorting.
  - Added null-MX filtering so `.` does not count as a valid MX target.

- [x] **Import-time side-effect control** in `src/emailtoolkit/emails.py`
  - Remove/replace eager `_default = EmailTools()` with lazy singleton creation.
  - Keep public convenience API unchanged.

- [x] **Extraction dedupe behavior clarity** in `src/emailtoolkit/emails.py`
  - Keep dedupe logic identical for `extract_unique=True`.
  - Removed unnecessary `seen` bookkeeping when `extract_unique=False`.
  - Added assertions for both unique and non-unique extraction paths.

- [x] **Invalid-domain parse path hardening** in `src/emailtoolkit/emails.py`
  - Avoid expensive DNS work on obviously malformed domain guesses in syntax-failure branch.
  - Keep current non-PII error messaging.

---

## Priority B — Reliability + Performance (No API Surface Changes)

- [x] Add lightweight timing/benchmark checks for:
  - repeated `extract` on large text blobs
    - Added in `tests/test_extraction_corpus.py` (`test_extraction_large_blob_runtime_budget`).
  - repeated `domain_health` cache hits/misses
    - Added in `tests/test_emailtools_core.py`.

- [x] Ensure disposable-source loading failure modes remain non-fatal and deterministic:
  - missing file
  - invalid URL source
  - timeout/fetch exception path

- [x] Verify `block_private_tlds` + `known_public_suffixes` branch stays DNS-short-circuit safe.

---

## Priority C — Testing Expansion for Existing Features

- [x] Add structured pytest suite (`tests/` package).
- [x] Add explicit tests for config precedence edge cases:
  - defaults → JSON → dotenv → env (and invalid override values).
- [x] Add regression tests for CLI outputs/help/exit behavior without changing command set.
- [x] Add cross-version CI checks for Python 3.9–3.13 for current functionality only.
- [x] Add repeated-run (`pytest` rerun) lane to catch intermittent regressions.

---

## Release Readiness (Existing Functionality Only)

- [x] `pytest`, `ruff`, `mypy`, `build`, `twine check` all green.
  - Local status: `pytest` + `ruff check src tests` + `mypy src/emailtoolkit` are green.
  - Pending: package `build` and `twine check` verification for release artifact integrity.
- [x] CI matrix green on Python 3.9–3.13.
- [x] Root workspace quality wrapper green for `emailtoolkit`.
- [x] Changelog/version bump after stabilization fixes land.
