# ./tests/test_cli_surface.py
"""CLI command behavior tests for the current argparse entrypoint.

Tests patch `build_tools` with a deterministic fake service so command output
and argument handling can be validated without network or DNS dependencies.

Run path: `pytest tests/test_cli_surface.py`.
Inputs: synthetic argv/stdin payloads and a fake tools object.
Outputs: assertions on JSON/plain-text output and command routing.
Operational notes: preserves existing CLI contract while enabling safe refactors.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from types import SimpleNamespace

import pytest

from emailtoolkit import main as cli_mod
from emailtoolkit.models import DomainInfo, Email


class _FakeTools:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(extract_max_results=None)

    def parse(self, email: str) -> Email:
        return Email(
            original=email,
            local="user",
            domain="example.com",
            ascii_email="user@example.com",
            normalized="user@example.com",
            canonical="user@example.com",
            domain_info=DomainInfo(
                domain="example.com",
                ascii_domain="example.com",
                mx_hosts=("mx.example.com",),
                a_hosts=("203.0.113.2",),
                has_mx=True,
                has_a=True,
                disposable=False,
            ),
            valid_syntax=True,
            deliverable_dns=True,
        )

    def is_valid(self, _email: str) -> bool:
        return True

    def normalize(self, _email: str) -> str:
        return "normalized@example.com"

    def canonical(self, _email: str) -> str:
        return "canonical@example.com"

    def extract(self, _text: str) -> list[Email]:
        return [self.parse("first@example.com"), self.parse("second@example.com")]

    def domain_health(self, domain: str) -> DomainInfo:
        return DomainInfo(
            domain=domain,
            ascii_domain=domain,
            mx_hosts=("mx.example.com",),
            a_hosts=("203.0.113.3",),
            has_mx=True,
            has_a=True,
            disposable=False,
        )


def _run_cli(
    monkeypatch: pytest.MonkeyPatch,
    argv: list[str],
    stdin_text: str = "",
) -> str:
    fake = _FakeTools()
    monkeypatch.setattr(cli_mod, "build_tools", lambda _config=None: fake)
    monkeypatch.setattr(sys, "argv", ["emailtoolkit", *argv])
    if stdin_text:
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_text))
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        cli_mod._cli()
    return stream.getvalue()


def test_cli_parse_outputs_json(monkeypatch: pytest.MonkeyPatch) -> None:
    output = _run_cli(monkeypatch, ["parse", "hello@example.com"])
    payload = json.loads(output)
    assert payload["canonical"] == "user@example.com"
    assert payload["domain_info"]["has_mx"] is True


def test_cli_validate_normalize_canonical_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validate_out = _run_cli(monkeypatch, ["validate", "hello@example.com"])
    assert validate_out.strip() == "true"

    normalize_out = _run_cli(monkeypatch, ["normalize", "hello@example.com"])
    assert normalize_out.strip() == "normalized@example.com"

    canonical_out = _run_cli(monkeypatch, ["canonical", "hello@example.com"])
    assert canonical_out.strip() == "canonical@example.com"


def test_cli_extract_respects_limit_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _FakeTools()
    monkeypatch.setattr(cli_mod, "build_tools", lambda _config=None: fake)
    monkeypatch.setattr(sys, "argv", ["emailtoolkit", "extract", "--limit", "1"])
    monkeypatch.setattr(
        sys, "stdin", io.StringIO("contact first@example.com second@example.com")
    )

    stream = io.StringIO()
    with contextlib.redirect_stdout(stream):
        cli_mod._cli()
    output = stream.getvalue()
    payload = json.loads(output)

    assert fake.cfg.extract_max_results == 1
    assert isinstance(payload, list)
    assert len(payload) == 2  # fake extract returns deterministic list


def test_cli_domain_outputs_domain_info_json(monkeypatch: pytest.MonkeyPatch) -> None:
    output = _run_cli(monkeypatch, ["domain", "example.com"])
    payload = json.loads(output)
    assert payload["domain"] == "example.com"
    assert payload["has_a"] is True
