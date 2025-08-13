# emailtoolkit/utils/disposable.py

from __future__ import annotations
from pathlib import Path
from typing import Optional, Set
import urllib.request

def load_disposable(source: str) -> Optional[Set[str]]:
    # source: "none", "file://path", "url://https://…"
    if not source or source == "none":
        return None
    try:
        if source.startswith("file://"):
            p = Path(source[7:])
            if p.is_file():
                return set(s.strip().lower() for s in p.read_text(encoding="utf-8").splitlines() if s.strip() and not s.startswith("#"))
        if source.startswith("url://"):
            url = source[6:]
            with urllib.request.urlopen(url, timeout=5) as r:
                text = r.read().decode("utf-8", errors="ignore")
                return set(s.strip().lower() for s in text.splitlines() if s.strip() and not s.startswith("#"))
    except Exception:
        return None
    return None
