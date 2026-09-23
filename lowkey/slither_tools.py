#!/usr/bin/env python3
"""LowkeySlither: auditor-focused orchestration around Slither."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Sequence


def slither_path() -> str | None:
    return shutil.which("slither")


def foundry_project_root(start: Path | None = None) -> Path:
    path = (start or Path.cwd()).expanduser().resolve()
    if path.is_file():
        path = path.parent
    for parent in (path, *path.parents):
        if (parent / "foundry.toml").is_file():
            return parent
    return path


def _default_paths(root: Path) -> tuple[Path, Path]:
    evidence = root / ".audit" / "slither"
    evidence.mkdir(parents=True, exist_ok=True)
    return evidence / "latest.json", evidence / "latest.sarif"


def _summary(payload: dict) -> None:
    detectors = payload.get("results", {}).get("detectors", [])
    if not isinstance(detectors, list):
        detectors = []

    counts = {}
    for finding in detectors:
        impact = str(finding.get("impact") or "Unknown")
        counts[impact] = counts.get(impact, 0) + 1

    print("\n=== LOWKEY SLITHER SUMMARY ===")
    print(f"Findings: {len(detectors)}")
    for level in ("High", "Medium", "Low", "Informational", "Optimization"):
        if counts.get(level):
            print(f"  {level:<15} {counts[level]}")
    for level, count in counts.items():
        if level not in {"High", "Medium", "Low", "Informational", "Optimization"}:
            print(f"  {level:<15} {count}")

    if detectors:
        print("\nTop findings:")
        for finding in detectors[:10]:
            check = finding.get("check") or "unknown-detector"
            impact = finding.get("impact") or "Unknown"
            confidence = finding.get("confidence") or "Unknown"
            description = str(finding.get("description") or "").splitlines()[0]
            print(f"  [{impact}/{confidence}] {check}")
            if description:
                print(f"    {description}")


def run_default(root: Path, extra: Sequence[str] = ()) -> int:
    binary = slither_path()
    if not binary:
        print("LowkeySlither: slither was not found on PATH. Install Slither first.", file=sys.stderr)
        return 1

    json_path, sarif_path = _default_paths(root)
    command = [
        binary,
        str(root),
        "--exclude-dependencies",
        "--disable-color",
        "--fail-none",
        "--json",
        str(json_path),
        "--sarif",
        str(sarif_path),
        *extra,
    ]

    print("=== LOWKEY SLITHER ===")
    print(f"Project : {root}")
    print("Mode    : all detectors, dependencies excluded")
    print("Failure : analysis findings do not abort the workflow; use --fail-high/medium/low for CI gates")
    print(f"JSON    : {json_path}")
    print(f"SARIF   : {sarif_path}")

    try:
        result = subprocess.run(command, cwd=root, text=True, capture_output=True)
    except OSError as exc:
        print(f"LowkeySlither: could not execute slither: {exc}", file=sys.stderr)
        return 1

    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)

    if json_path.exists():
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                _summary(payload)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"LowkeySlither: could not parse JSON evidence: {exc}", file=sys.stderr)

    print(f"\nSlither exit code: {result.returncode}")
    print("Use the detector output as evidence to investigate; a detector finding is not by itself a proven vulnerability.")
    return result.returncode


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    binary = slither_path()
    if not binary:
        print("LowkeySlither: slither was not found on PATH. Install Slither first.", file=sys.stderr)
        return 1

    if not args:
        return run_default(foundry_project_root())

    # Explicit Slither arguments remain a transparent escape hatch. When
    # the user starts with an option, automatically target the current Foundry
    # project so option-first commands work naturally.
    if args and args[0].startswith("-"):
        args = [str(foundry_project_root()), *args]
    command = [binary, *args]
    try:
        return subprocess.run(command).returncode
    except OSError as exc:
        print(f"LowkeySlither: could not execute slither: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
