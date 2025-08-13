# emailtoolkit/main.py

#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from .emails import build_tools

def _cli():
    p = argparse.ArgumentParser(prog="emailtoolkit", description="Email parsing and DNS checks")
    p.add_argument("--config", help="Path to config.json", default=None)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("parse", help="Parse a single email")
    sp.add_argument("email")

    sv = sub.add_parser("validate", help="Validate a single email")
    sv.add_argument("email")

    sn = sub.add_parser("normalize", help="Normalize a single email")
    sn.add_argument("email")

    sc = sub.add_parser("canonical", help="Canonical form of a single email")
    sc.add_argument("email")

    se = sub.add_parser("extract", help="Extract from text on stdin")
    se.add_argument("--limit", type=int, default=0)

    sd = sub.add_parser("domain", help="Domain health")
    sd.add_argument("domain")

    args = p.parse_args()
    tools = build_tools(args.config)

    if args.cmd == "parse":
        e = tools.parse(args.email)
        print(json.dumps(e.__dict__, default=lambda o: o.__dict__, indent=2))
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
        out = [e.__dict__ for e in tools.extract(text)]
        print(json.dumps(out, default=lambda o: o.__dict__, indent=2))
    elif args.cmd == "domain":
        info = tools.domain_health(args.domain)
        print(json.dumps(info.__dict__, indent=2))

if __name__ == "__main__":
    _cli()
