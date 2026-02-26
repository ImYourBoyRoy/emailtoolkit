# ./tests/conftest.py
"""Pytest session fixtures for EmailToolkit test stability.

This module ensures local `src/` imports resolve without editable installation
and scrubs stale `__pycache__` folders before/after test execution.

Run path: auto-loaded by `pytest` in this repository.
Inputs: repository filesystem state.
Outputs: deterministic import path setup and cache cleanup side effects.
Operational notes: safe to run repeatedly; cleanup is best-effort.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
_CACHE_SCRUB_EXCLUDES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
}


def _scrub_pycache(root: Path) -> None:
    for dirpath, dirnames, _filenames in os.walk(root, topdown=True):
        dirnames[:] = [
            name
            for name in dirnames
            if name not in _CACHE_SCRUB_EXCLUDES and name != "__pycache__"
        ]
        pycache = Path(dirpath) / "__pycache__"
        if pycache.exists():
            shutil.rmtree(pycache, ignore_errors=True)


if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _cache_scrub_session() -> None:
    _scrub_pycache(PROJECT_ROOT)
    yield
    _scrub_pycache(PROJECT_ROOT)
