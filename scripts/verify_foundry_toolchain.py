#!/usr/bin/env python3
"""Verify that all required Foundry executables match the pinned release."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys


TOOLS = ("forge", "cast", "anvil")
VERSION_LINE = re.compile(r"\bVersion:\s*([^\s]+)")


def reported_version(output: str) -> str | None:
    match = VERSION_LINE.search(output)
    return match.group(1) if match else None


def version_matches(output: str, expected: str) -> bool:
    return reported_version(output) == expected


def verify(expected: str) -> int:
    if not re.fullmatch(r"\d+\.\d+\.\d+", expected):
        print(f"Invalid expected Foundry version: {expected!r}", file=sys.stderr)
        return 2

    failed = False
    for name in TOOLS:
        executable = shutil.which(name)
        if not executable:
            print(f"FAIL: {name} is missing from PATH", file=sys.stderr)
            failed = True
            continue
        result = subprocess.run(
            [executable, "--version"],
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
        output = result.stdout + result.stderr
        actual = reported_version(output)
        print(output.strip() or f"{name}: no version output")
        if result.returncode != 0 or actual != expected:
            print(
                f"FAIL: {name} expected Foundry {expected}, got {actual!r} "
                f"(exit {result.returncode})",
                file=sys.stderr,
            )
            failed = True
        else:
            print(f"PASS: {name} is Foundry {expected}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(verify(sys.argv[1] if len(sys.argv) > 1 else "1.9.0"))
