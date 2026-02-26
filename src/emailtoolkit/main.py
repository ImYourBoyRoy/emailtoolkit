#!/usr/bin/env python3
# ./src/emailtoolkit/main.py
"""Command-line interface for EmailToolkit's existing command surface.

Run via ``emailtoolkit`` (console script) or ``python -m emailtoolkit.main``.
Inputs: CLI command + positional email/domain values + optional ``--config`` JSON path.
Outputs: JSON/text printed to stdout; process exits non-zero on unhandled exceptions.
Side effects: may perform DNS lookups through EmailTools depending on command/config.
Operational notes: intentionally mirrors existing API commands without adding new features.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .emails import build_tools


def _to_json(data: Any) -> str:
    return json.dumps(data, default=lambda value: value.__dict__, indent=2)


def _cli() -> int:
    parser = argparse.ArgumentParser(
        prog="emailtoolkit",
        description="Email parsing and DNS checks",
    )
    parser.add_argument("--config", help="Path to config.json", default=None)
    subcommands = parser.add_subparsers(dest="cmd", required=True)

    parse_parser = subcommands.add_parser("parse", help="Parse a single email")
    parse_parser.add_argument("email")

    validate_parser = subcommands.add_parser("validate", help="Validate a single email")
    validate_parser.add_argument("email")

    normalize_parser = subcommands.add_parser(
        "normalize", help="Normalize a single email"
    )
    normalize_parser.add_argument("email")

    canonical_parser = subcommands.add_parser(
        "canonical", help="Canonical form of a single email"
    )
    canonical_parser.add_argument("email")

    extract_parser = subcommands.add_parser(
        "extract", help="Extract from text on stdin"
    )
    extract_parser.add_argument("--limit", type=int, default=0)

    domain_parser = subcommands.add_parser("domain", help="Domain health")
    domain_parser.add_argument("domain")

    args = parser.parse_args()
    tools = build_tools(args.config)

    if args.cmd == "parse":
        print(_to_json(tools.parse(args.email).__dict__))
    elif args.cmd == "validate":
        print("true" if tools.is_valid(args.email) else "false")
    elif args.cmd == "normalize":
        print(tools.normalize(args.email))
    elif args.cmd == "canonical":
        print(tools.canonical(args.email))
    elif args.cmd == "extract":
        text = sys.stdin.read()
        if args.limit:
            tools.cfg.extract_max_results = args.limit
        print(_to_json([email.__dict__ for email in tools.extract(text)]))
    elif args.cmd == "domain":
        print(_to_json(tools.domain_health(args.domain).__dict__))

    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
