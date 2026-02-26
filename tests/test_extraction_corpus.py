# ./tests/test_extraction_corpus.py
"""Corpus-based extraction regression coverage for real-world HTML patterns.

This module validates EmailToolkit extraction against fixture HTML snapshots and
expected outputs, including Cloudflare-protected email decode scenarios.

Run path: ``pytest tests/test_extraction_corpus.py``.
Inputs: fixture HTML/JSON files under ``tests/fixtures/extraction``.
Outputs: assertions for normalized/canonical/domain lists and runtime budget.
Operational notes: DNS is monkeypatched for deterministic, network-free tests.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pytest

from emailtoolkit.emails import EmailTools
from emailtoolkit.utils.config import Config

_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "extraction"
_MANIFEST_PATH = _FIXTURE_ROOT / "manifest.json"


@dataclass(frozen=True)
class ExtractionScenario:
    case_id: str
    html_path: Path
    expected_path: Path
    extract_unique: bool
    extract_max_results: Optional[int]


def _load_scenarios() -> tuple[ExtractionScenario, ...]:
    payload = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    scenarios: list[ExtractionScenario] = []

    for item in payload:
        scenarios.append(
            ExtractionScenario(
                case_id=str(item["case_id"]),
                html_path=_FIXTURE_ROOT / str(item["html"]),
                expected_path=_FIXTURE_ROOT / str(item["expected"]),
                extract_unique=bool(item["extract_unique"]),
                extract_max_results=item["extract_max_results"],
            )
        )

    return tuple(scenarios)


def _read_expected(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _fake_dns_query(
    _domain: str,
) -> tuple[tuple[str, ...], tuple[str, ...], bool, bool]:
    return (tuple(), ("203.0.113.50",), False, True)


_SCENARIOS = _load_scenarios()


@pytest.mark.parametrize("scenario", _SCENARIOS, ids=lambda item: item.case_id)
def test_extraction_corpus_regression(
    scenario: ExtractionScenario,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = Config(
        require_mx=False,
        require_deliverability=False,
        extract_unique=scenario.extract_unique,
        extract_max_results=scenario.extract_max_results,
        disposable_source="none",
    )
    tools = EmailTools(cfg=cfg)
    monkeypatch.setattr(tools._dns, "query", _fake_dns_query)

    html = scenario.html_path.read_text(encoding="utf-8")
    expected = _read_expected(scenario.expected_path)

    extracted = tools.extract(html)

    assert len(extracted) == expected["count"]
    assert [item.normalized for item in extracted] == expected["normalized"]
    assert [item.canonical for item in extracted] == expected["canonical"]
    assert [item.domain_info.ascii_domain for item in extracted] == expected[
        "ascii_domains"
    ]


def test_extraction_large_blob_runtime_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cfg = Config(
        require_mx=False,
        require_deliverability=False,
        extract_unique=True,
        extract_max_results=None,
    )
    tools = EmailTools(cfg=cfg)
    monkeypatch.setattr(tools._dns, "query", _fake_dns_query)

    source = (_FIXTURE_ROOT / "html" / "landing_unique.html").read_text(
        encoding="utf-8"
    )
    blob = "\n".join(source for _ in range(200))

    start = time.perf_counter()
    extracted = tools.extract(blob)
    elapsed = time.perf_counter() - start

    assert [item.canonical for item in extracted] == [
        "hello@example.com",
        "team@gmail.com",
        "info@example.org",
    ]
    assert elapsed < 12.0
