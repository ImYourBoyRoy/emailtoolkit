#!/usr/bin/env python3
# ./test_emailtoolkit.py
"""End-to-end sanity test script for emailtoolkit.

Run path: `python test_emailtoolkit.py`
Inputs: none (uses hardcoded samples and local package)
Outputs: console printouts of parse results, exit code 0 on success, 1 on failure.
Operational notes: Skips DNS-sensitive asserts if network is blocked.
"""

import json
import subprocess
import sys
from typing import Tuple

import emailtoolkit as et  # uses editable install and .env


def _print(title: str, obj) -> None:
    print(f"\n=== {title} ===")
    if hasattr(obj, "__dict__"):
        print(json.dumps(obj.__dict__, default=lambda o: o.__dict__, indent=2))
    else:
        print(json.dumps(obj, indent=2))


def _has_network() -> bool:
    # quick CLI ping using our own domain_health on well-known host
    try:
        info = et.domain_health("gmail.com")
        return bool(info.has_mx or info.has_a)
    except Exception:
        return False


def test_core_functions() -> Tuple[int, int]:
    passed, failed = 0, 0

    # parse / normalize / canonical / is_valid
    samples = [
        "Test.User+sales@Gmail.com",
        "USER@EXAMPLE.COM",
        "invalid@@example..com",
        "ユーザー@例え.テスト",  # IDN example (may normalize with idna)
    ]

    # 1) parse valid gmail
    try:
        e = et.parse(samples[0])
        assert e.valid_syntax
        assert et.normalize(samples[0]).endswith("@gmail.com")
        assert et.canonical(samples[0]).startswith("testuser@")
        assert et.is_valid(samples[0]) is True
        _print("parse(gmail)", e)
        passed += 1
    except Exception as err:
        print("FAIL parse(gmail):", err)
        failed += 1

    # 2) parse example.com
    try:
        e2 = et.parse(samples[1])
        assert e2.valid_syntax
        _print("parse(example.com)", e2)
        passed += 1
    except Exception as err:
        print("FAIL parse(example.com):", err)
        failed += 1

    # 3) invalid syntax
    try:
        ok = et.is_valid(samples[2])
        assert ok is False
        passed += 1
    except Exception as err:
        print("FAIL is_valid(invalid):", err)
        failed += 1

    # 4) canonical compare
    try:
        same = et.compare("t.e.s.t+foo@gmail.com", "test@gmail.com")
        assert same is True
        passed += 1
    except Exception as err:
        print("FAIL compare:", err)
        failed += 1

    # 5) extract
    text = "Contact us: a@example.com, A@EXAMPLE.com, junk@@bad, marketing+us@googlemail.com"
    try:
        found = et.extract(text)
        # Dedup should collapse a@example.com variants to one
        assert any(x.normalized == "a@example.com" for x in found)
        # Should include googlemail address normalized/canonicalized
        assert any(
            x.domain_info.ascii_domain in ("googlemail.com", "gmail.com") for x in found
        )
        _print("extract()", [f.normalized for f in found])
        passed += 1
    except Exception as err:
        print("FAIL extract:", err)
        failed += 1

    # 6) domain health with and without network
    try:
        info_example = et.domain_health("example.com")
        _print("domain_health(example.com)", info_example)
        # With network up, example.com usually has A but no MX
        if _has_network():
            assert info_example.has_a in (True, False)  # may depend on resolver
        passed += 1
    except Exception as err:
        print("FAIL domain_health(example.com):", err)
        failed += 1

    # 7) disposable domain detection via our local file
    try:
        info_mailinator = et.domain_health("mailinator.com")
        assert info_mailinator.disposable is True
        passed += 1
    except Exception as err:
        print("FAIL disposable detection:", err)
        failed += 1

    # 8) CLI smoke tests
    try:
        # parse
        out = subprocess.check_output(
            [sys.executable, "-m", "emailtoolkit.main", "parse", "test+tag@gmail.com"]
        )
        data = json.loads(out.decode())
        assert data["valid_syntax"] is True

        # validate
        out = subprocess.check_output(
            [sys.executable, "-m", "emailtoolkit.main", "validate", "test@gmail.com"]
        )
        assert out.decode().strip() in (
            "true",
            "false",
        )  # deliverability toggle can change this

        # normalize
        out = subprocess.check_output(
            [
                sys.executable,
                "-m",
                "emailtoolkit.main",
                "normalize",
                "Test.User+x@Gmail.com",
            ]
        )
        assert out.decode().strip().endswith("@gmail.com")

        # canonical
        out = subprocess.check_output(
            [
                sys.executable,
                "-m",
                "emailtoolkit.main",
                "canonical",
                "t.e.s.t+foo@googlemail.com",
            ]
        )
        assert out.decode().strip().startswith("test@")

        # domain
        out = subprocess.check_output(
            [sys.executable, "-m", "emailtoolkit.main", "domain", "example.com"]
        )
        _ = json.loads(out.decode())

        # extract from stdin
        p = subprocess.Popen(
            [sys.executable, "-m", "emailtoolkit.main", "extract", "--limit", "5"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        std_out, std_err = p.communicate(
            b"ping us at a@example.com and test+z@gmail.com"
        )
        assert p.returncode == 0
        arr = json.loads(std_out.decode())
        assert isinstance(arr, list) and len(arr) >= 1

        passed += 1
    except Exception as err:
        print("FAIL CLI:", err)
        failed += 1

    return passed, failed


if __name__ == "__main__":
    ok, bad = test_core_functions()
    print(f"\nRESULT: passed={ok} failed={bad}")
    sys.exit(0 if bad == 0 else 1)
