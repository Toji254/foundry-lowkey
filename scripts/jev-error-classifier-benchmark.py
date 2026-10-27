#!/usr/bin/env python3
"""Standalone wrapper for Lowkey's native Jev benchmark handler."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lowkey.jev_error_benchmark import run  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(
        run(
            ["benchmark", *sys.argv[1:]],
            prog="python3 scripts/jev-error-classifier-benchmark.py",
        )
    )
