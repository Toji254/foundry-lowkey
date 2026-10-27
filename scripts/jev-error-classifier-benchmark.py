#!/usr/bin/env python3
"""Run the offline rules baseline, optionally comparing it with TypeSafe Jev."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from lowkey.jev_error_benchmark import CASES, build_report  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark a small set of labeled Foundry/Solidity diagnostics."
    )
    parser.add_argument(
        "--with-jev",
        action="store_true",
        help="Call TypeSafe Direct Jev once per case (requires TYPESAFE_API_KEY).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Run only the first N cases; useful for a low-cost live smoke test.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-request timeout seconds for Jev, from 1 to 60 (default: 30).",
    )
    parser.add_argument(
        "--output",
        default=".audit/jev-error-classifier-benchmark.json",
        help="JSON report path (default: .audit/jev-error-classifier-benchmark.json).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.limit < 0:
        print("ERROR: --limit must be zero (all cases) or a positive integer.", file=sys.stderr)
        return 2
    if args.with_jev and not os.environ.get("TYPESAFE_API_KEY", "").strip():
        print(
            "ERROR: --with-jev requires TYPESAFE_API_KEY. The offline rules benchmark needs no key.",
            file=sys.stderr,
        )
        return 2
    if not 1 <= args.timeout <= 60:
        print("ERROR: --timeout must be between 1 and 60 seconds.", file=sys.stderr)
        return 2

    cases = CASES[:args.limit] if args.limit else CASES
    report = build_report(cases=cases, with_jev=args.with_jev, timeout_seconds=args.timeout)
    output = Path(args.output).expanduser()
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: Could not write benchmark report to {output}: {exc}", file=sys.stderr)
        return 2

    print("LOWKEY JEV ERROR-CLASSIFIER EXPERIMENT")
    print("=====================================")
    print(f"Cases evaluated: {report['summary']['case_count']}")
    rules = report["summary"]["rules"]
    print(
        "Rules baseline: "
        f"stage {rules['stage']['correct']}/{rules['stage']['total']} "
        f"({rules['stage']['accuracy']}); "
        f"root cause {rules['root_cause']['correct']}/{rules['root_cause']['total']} "
        f"({rules['root_cause']['accuracy']})"
    )
    if args.with_jev:
        jev = report["summary"]["jev"]
        print(
            "Jev: "
            f"stage {jev['stage']['correct']}/{jev['stage']['total']} "
            f"({jev['stage']['accuracy']}); "
            f"root cause {jev['root_cause']['correct']}/{jev['root_cause']['total']} "
            f"({jev['root_cause']['accuracy']}); "
            f"request errors {jev['request_errors']}; "
            f"average latency {jev['average_latency_ms']} ms"
        )
        print(f"Jev token usage: input {jev['input_tokens']}, output {jev['output_tokens']}")
    else:
        print("Mode: offline rules only (no network request, no API key required).")
    print(f"Report: {output.resolve()}")
    print("Caution: this curated smoke corpus is not a production-accuracy estimate.")

    if args.with_jev and report["summary"]["jev"]["request_errors"] == len(cases):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
