#!/usr/bin/env python3
"""LowkeySlither: auditor-focused orchestration around Slither."""
from __future__ import annotations

import json
import re
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


DETECTOR_GUIDANCE = {
    "solc-version": {
        "title": "Compiler version",
        "meaning": "The project allows a Solidity compiler version that Slither associates with known compiler bugs.",
        "why": "A compiler bug can change how otherwise-correct Solidity behaves after compilation. This is a build-safety issue, not proof that the contract is exploitable.",
        "next": "Check the exact compiler version used by Foundry, compare it with the Solidity bug list, and pin a patched version that is compatible with the project.",
    },
    "low-level-calls": {
        "title": "Low-level external call",
        "meaning": "The contract sends a call directly to another address instead of using a higher-level typed call.",
        "why": "The callee can control how that call behaves. Review reentrancy, return-value handling, recipient control, and whether state is updated safely around the call.",
        "next": "Inspect the full calling function and trace the state changes before and after the call. Then reproduce the path with a hostile recipient in a Foundry test.",
    },
    "naming-convention": {
        "title": "Naming convention",
        "meaning": "A Solidity identifier does not follow the naming convention configured or expected by Slither.",
        "why": "This is primarily a readability and maintainability issue. It normally has no direct security impact.",
        "next": "Rename it only if the project's style guide requires it. Do not treat this finding as a vulnerability.",
    },
    "reentrancy-eth": {
        "title": "ETH reentrancy",
        "meaning": "An external call that transfers ETH occurs in a code path where state may be affected in a way that deserves reentrancy review.",
        "why": "A malicious recipient can execute code during an external call and potentially re-enter the contract before its assumptions are restored.",
        "next": "Check checks-effects-interactions ordering, reentrancy guards, and whether the same value can be claimed twice. Reproduce with a malicious receiver contract.",
    },
    "reentrancy-no-eth": {
        "title": "Reentrancy risk",
        "meaning": "An external call occurs in a path where state changes may be exposed to reentrant execution.",
        "why": "A callback can re-enter before the function finishes and may observe or change state that the original call assumed was protected.",
        "next": "Trace the state writes and external calls in order, then build a malicious callback test to see whether the security property can actually be violated.",
    },
    "tx-origin": {
        "title": "tx.origin used for authorization",
        "meaning": "The contract relies on the original transaction signer rather than the immediate caller for some logic.",
        "why": "Another contract can call the target while preserving the user's tx.origin, which can break authorization assumptions.",
        "next": "Inspect the affected authorization path and check whether msg.sender should be used instead. Build a proxy-contract reproduction.",
    },
}

IMPACT_ORDER = ("High", "Medium", "Low", "Informational")
CONFIDENCE_ORDER = ("High", "Medium", "Low")


def _clean_description(value: object) -> str:
    text = " ".join(str(value or "").split())
    # Keep the evidence, but remove distracting repeated reference URLs from the
    # main human-readable explanation.
    text = re.sub(r"\s*https?://\S+", "", text).strip()
    return text.rstrip()


def _source_location(finding: dict) -> str | None:
    elements = finding.get("elements")
    if not isinstance(elements, list):
        return None

    for element in elements:
        if not isinstance(element, dict):
            continue
        mapping = element.get("source_mapping")
        if not isinstance(mapping, dict):
            continue
        filename = (
            mapping.get("filename_short")
            or mapping.get("filename_relative")
            or mapping.get("filename_used")
        )
        lines = mapping.get("lines")
        if filename and isinstance(lines, list) and lines:
            first = lines[0]
            last = lines[-1]
            if first == last:
                return f"{filename}:{first}"
            return f"{filename}:{first}-{last}"
        if filename:
            return str(filename)
    return None


def _element_context(finding: dict) -> str | None:
    elements = finding.get("elements")
    if not isinstance(elements, list):
        return None

    labels = []
    for element in elements:
        if not isinstance(element, dict):
            continue
        kind = str(element.get("type") or "").strip().lower()
        name = str(element.get("name") or "").strip()
        if not name or kind == "node":
            continue
        labels.append(f"{kind} {name}" if kind else name)
        if len(labels) == 2:
            break

    return ", ".join(labels) if labels else None


def _human_observation(finding: dict, check: str) -> str:
    elements = finding.get("elements")
    first_function = None
    first_enum = None
    first_pragma = None

    if isinstance(elements, list):
        for element in elements:
            if not isinstance(element, dict):
                continue
            kind = str(element.get("type") or "").lower()
            name = str(element.get("name") or "").strip()
            if kind == "function" and name and first_function is None:
                first_function = name
            elif kind == "enum" and name and first_enum is None:
                first_enum = name
            elif kind == "pragma" and name and first_pragma is None:
                first_pragma = name

    if check == "low-level-calls":
        return (
            f"The function {first_function}() makes a raw external call that can execute code "
            "in the receiving address."
            if first_function
            else "The contract makes a raw external call that can execute code in the receiving address."
        )
    if check == "naming-convention":
        return (
            f"The enum '{first_enum}' uses a naming style that does not match the project's "
            "expected Solidity convention."
            if first_enum
            else "A Solidity identifier does not follow the expected naming convention."
        )
    if check == "solc-version":
        return (
            f"The project accepts Solidity compiler versions allowed by '{first_pragma}', "
            "including releases that Slither flags for known compiler issues."
            if first_pragma
            else "The project accepts Solidity compiler versions that Slither flags for known compiler issues."
        )
    if check == "reentrancy-eth":
        return (
            f"The function {first_function}() contains an ETH transfer path that needs a reentrancy review."
            if first_function
            else "An ETH transfer path needs a reentrancy review."
        )
    if check == "reentrancy-no-eth":
        return (
            f"The function {first_function}() contains an external call in a path that may be re-entered."
            if first_function
            else "An external call occurs in a path that may be re-entered."
        )
    if check == "tx-origin":
        return "The contract uses the original transaction signer for logic where caller-based authorization should be reviewed."
    return "Static analysis found a code pattern that deserves manual security review."


def _human_finding(finding: dict, number: int, total: int) -> None:
    check = str(finding.get("check") or "unknown-detector")
    impact = str(finding.get("impact") or "Unknown")
    confidence = str(finding.get("confidence") or "Unknown")
    guidance = DETECTOR_GUIDANCE.get(check, {
        "title": check.replace("-", " ").replace("_", " ").title(),
        "meaning": "Static analysis found a code pattern that deserves manual security review.",
        "why": "The pattern may be intentional or may not violate a security property in this contract.",
        "next": "Read the affected code in context, identify the relevant security property, and reproduce the behavior with Foundry before recording a finding.",
    })

    print(f"\nFINDING {number}/{total}")
    print("-" * 56)
    print(f"Issue       : {guidance['title']}")
    print(f"Impact      : {impact}")
    print(f"Confidence  : {confidence}")

    location = _source_location(finding)
    if location:
        print(f"Where       : {location}")

    context = _element_context(finding)
    if context:
        print(f"Code area   : {context}")

    print(f"\nObserved:\n  {_human_observation(finding, check)}")
    print(f"\nWhat it means:\n  {guidance['meaning']}")
    print(f"\nWhy it matters:\n  {guidance['why']}")
    print(f"\nNext audit move:\n  {guidance['next']}")


def _summary(payload: dict) -> None:
    results = payload.get("results")
    if not isinstance(results, dict):
        results = {}
    detectors = results.get("detectors", [])
    if not isinstance(detectors, list):
        detectors = []

    counts = {}
    for finding in detectors:
        impact = str(finding.get("impact") or "Unknown")
        counts[impact] = counts.get(impact, 0) + 1

    print("\n" + "=" * 56)
    print("LOWKEY STATIC ANALYSIS REPORT — SLITHER")
    print("=" * 56)
    print(f"Findings discovered: {len(detectors)}")

    if not detectors:
        print("\nNo static-analysis findings were reported.")
        print("That means Slither found no matching detector result in this run.")
        print("It does not prove the contract is secure.")

    if detectors:
        print("\nFinding summary:")
        for level in IMPACT_ORDER:
            if counts.get(level):
                print(f"  {level:<15}: {counts[level]}")
        for level, count in sorted(counts.items()):
            if level not in IMPACT_ORDER:
                print(f"  {level:<15}: {count}")

        # Highest-impact findings first, then confidence.
        ranked = sorted(
            enumerate(detectors),
            key=lambda item: (
                IMPACT_ORDER.index(str(item[1].get("impact") or "Unknown"))
                if str(item[1].get("impact") or "Unknown") in IMPACT_ORDER else 99,
                CONFIDENCE_ORDER.index(str(item[1].get("confidence") or "Unknown"))
                if str(item[1].get("confidence") or "Unknown") in CONFIDENCE_ORDER else 99,
                str(item[1].get("check") or ""),
            ),
        )
        for display_number, (_, finding) in enumerate(ranked, 1):
            _human_finding(finding, display_number, len(detectors))

    print("\n" + "=" * 56)
    print("AUDITOR'S NOTE")
    print("=" * 56)
    print("Slither reports patterns and evidence. A detector result is not")
    print("automatically a confirmed vulnerability. Validate impact with")
    print("source review, traces, state changes, and Foundry tests.")


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

    if result.stderr and result.returncode != 0:
        print("Slither error details:", file=sys.stderr)
        print(result.stderr.rstrip(), file=sys.stderr)

    if json_path.exists():
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                _summary(payload)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"LowkeySlither: could not parse JSON evidence: {exc}", file=sys.stderr)

    # Specialized commands such as --list-detectors or printers may not produce
    # detector JSON. Surface their stdout under a clear heading instead of
    # silently discarding it.
    show_specialized_output = any(option in extra for option in ("--print", "--list-detectors", "--list-printers", "--checklist"))
    if result.stdout.strip() and (show_specialized_output or not json_path.exists()):
        print("\n=== SLITHER TOOL OUTPUT ===")
        print(result.stdout.rstrip())

    print(f"\nSlither status: {'completed successfully' if result.returncode == 0 else 'failed'}")
    print("Auditor's note: static-analysis results are evidence to investigate, not automatic proof of a vulnerability.")
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
