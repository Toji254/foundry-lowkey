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

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import audit_context


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
        "actions": ["doctor", "build"],
    },
    "low-level-calls": {
        "title": "Low-level external call",
        "meaning": "The contract sends a call directly to another address instead of using a higher-level typed call.",
        "why": "The callee can control how that call behaves. Review reentrancy, return-value handling, recipient control, and whether state is updated safely around the call.",
        "next": "Inspect the full calling function and trace the state changes before and after the call. Then reproduce the path with a hostile recipient in a Foundry test.",
        "actions": ["functions", "ask", "state-diff", "trace", "generate test"],
    },
    "naming-convention": {
        "title": "Naming convention",
        "meaning": "A Solidity identifier does not follow the naming convention configured or expected by Slither.",
        "why": "This is primarily a readability and maintainability issue. It normally has no direct security impact.",
        "next": "Rename it only if the project's style guide requires it. Do not treat this finding as a vulnerability.",
        "actions": ["fmt"],
    },
    "reentrancy-eth": {
        "title": "ETH reentrancy",
        "meaning": "An external call that transfers ETH occurs in a code path where state may be affected in a way that deserves reentrancy review.",
        "why": "A malicious recipient can execute code during an external call and potentially re-enter the contract before its assumptions are restored.",
        "next": "Check checks-effects-interactions ordering, reentrancy guards, and whether the same value can be claimed twice. Reproduce with a malicious receiver contract.",
        "actions": ["state-diff", "trace", "fuzz", "invariant", "generate test"],
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
        "actions": ["functions", "ask", "probe", "matrix", "generate test"],
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


def _terminal_link(label: str, absolute: Path, line: int, column: int = 1) -> str:
    """Compatibility wrapper around the shared audit-context source linker."""
    return audit_context.source_link(
        absolute,
        line,
        column,
        absolute.parent.parent,
        display=label,
    )



def _source_location(finding: dict, project_root: Path) -> tuple[str, str] | None:
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
            mapping.get("filename_relative")
            or mapping.get("filename_short")
            or mapping.get("filename_used")
        )
        lines = mapping.get("lines")
        if not filename or not isinstance(lines, list) or not lines:
            continue

        try:
            first = int(lines[0])
            last = int(lines[-1])
        except (TypeError, ValueError):
            continue

        try:
            column = int(mapping.get("starting_column", 1))
        except (TypeError, ValueError):
            column = 1

        label = str(filename)
        if first == last:
            label = f"{label}:{first}"
        else:
            label = f"{label}:{first}-{last}"

        linked = audit_context.source_link(
            str(filename),
            first,
            column,
            project_root,
            display=label,
        )
        return label, linked

    return None




def _signal_function(finding: dict) -> str | None:
    elements = finding.get("elements")
    if not isinstance(elements, list):
        return None
    for element in elements:
        if not isinstance(element, dict):
            continue
        if str(element.get("type") or "").lower() == "function":
            signature = (
                element.get("type_specific_fields", {}).get("signature")
                if isinstance(element.get("type_specific_fields"), dict)
                else None
            )
            return str(signature or element.get("name") or "") or None
    return None


def _signal_from_finding(finding: dict) -> dict:
    check = str(finding.get("check") or "static-analysis")
    guidance = DETECTOR_GUIDANCE.get(check, {})
    file_name = ""
    line = None
    column = None

    elements = finding.get("elements", [])
    if isinstance(elements, list):
        for element in elements:
            if not isinstance(element, dict):
                continue
            mapping = element.get("source_mapping")
            if not isinstance(mapping, dict):
                continue
            file_name = str(
                mapping.get("filename_relative")
                or mapping.get("filename_short")
                or mapping.get("filename_used")
                or ""
            )
            lines = mapping.get("lines")
            if isinstance(lines, list) and lines:
                try:
                    line = int(lines[0])
                except (TypeError, ValueError):
                    line = None
            try:
                column = int(mapping.get("starting_column", 1))
            except (TypeError, ValueError):
                column = 1
            if file_name:
                break

    return {
        "tool": "slither",
        "check": check,
        "title": guidance.get("title") or check.replace("-", " ").title(),
        "impact": str(finding.get("impact") or "Unknown"),
        "confidence": str(finding.get("confidence") or "Unknown"),
        "file": file_name,
        "line": line,
        "column": column,
        "description": _human_observation(finding, check),
        "function": _signal_function(finding),
        "meaning": guidance.get("meaning", ""),
        "why": guidance.get("why", ""),
        "next": guidance.get("next", ""),
        "actions": list(guidance.get("actions", [])),
    }


def _human_finding(finding: dict, number: int, total: int, project_root: Path) -> None:
    check = str(finding.get("check") or "unknown-detector")
    impact = str(finding.get("impact") or "Unknown")
    confidence = str(finding.get("confidence") or "Unknown")
    guidance = DETECTOR_GUIDANCE.get(check, {
        "title": check.replace("-", " ").replace("_", " ").title(),
        "meaning": "Static analysis found a code pattern that deserves manual security review.",
        "why": "The pattern may be intentional or may not violate a security property in this contract.",
        "next": "Read the affected code in context, identify the relevant security property, and reproduce the behavior with Foundry before recording a finding.",
        "actions": ["functions", "ask", "state-diff", "trace", "generate test"],
    })

    print(f"\nFINDING {number}/{total}")
    print("-" * 56)
    print(f"Issue       : {guidance['title']}")
    print(f"Impact      : {impact}")
    print(f"Confidence  : {confidence}")

    location = _source_location(finding, project_root)
    if location:
        _, linked_location = location
        print(f"Where       : {linked_location}")

    context = _element_context(finding)
    if context:
        print(f"Code area   : {context}")

    print(f"\nObserved:\n  {_human_observation(finding, check)}")
    print(f"\nWhat it means:\n  {guidance['meaning']}")
    print(f"\nWhy it matters:\n  {guidance['why']}")
    print(f"\nNext audit move:\n  {guidance['next']}")


def _summary(payload: dict, project_root: Path | None = None) -> None:
    project_root = (project_root or Path.cwd()).resolve()
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
            _human_finding(finding, display_number, len(detectors), project_root)

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
    ]
    fail_flags = {"--fail-pedantic", "--fail-low", "--fail-medium", "--fail-high", "--fail-none", "--no-fail-pedantic"}
    if not any(flag in extra for flag in fail_flags):
        command.append("--fail-none")
    command.extend(["--json", str(json_path), "--sarif", str(sarif_path)])
    command.extend(extra)


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
                _summary(payload, root)

                detectors = payload.get("results", {}).get("detectors", [])
                if not isinstance(detectors, list):
                    detectors = []

                for finding in detectors:
                    if isinstance(finding, dict):
                        audit_context.add_signal(_signal_from_finding(finding), root)

                audit_context.record_tool(
                    "slither",
                    root,
                    status="completed" if result.returncode == 0 else "failed",
                    summary=f"{len(detectors)} static-analysis finding(s) reported",
                    data={
                        "json": str(json_path),
                        "sarif": str(sarif_path),
                        "finding_count": len(detectors),
                    },
                )
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

    # Explicit Slither options still flow through Lowkey's human-readable
    # reporter and shared audit context. The project is supplied automatically.
    return run_default(foundry_project_root(), args)



if __name__ == "__main__":
    raise SystemExit(main())
