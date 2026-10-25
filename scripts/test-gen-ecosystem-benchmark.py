#!/usr/bin/env python3
"""Run Lowkey's test generator against a representative public EVM corpus.

This benchmark is deliberately separate from generator logic: repository and target
names live in a manifest, and never select implementation behavior inside lk.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "tests" / "fixtures" / "test-generation-ecosystem.json"
SOLIDITY_TYPES = "unit,fuzz,invariant,integration,exploit,fork,poc,regression"
ALL_TYPES = SOLIDITY_TYPES + ",formal"
DECLARATION = re.compile(
    r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)\b"
)


def run(command: list[str], cwd: Path | None = None, timeout: int = 1800) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command, cwd=cwd, capture_output=True, text=True,
            timeout=timeout, check=False,
        )
        return {
            "command": command,
            "exit_code": completed.returncode,
            "stdout_tail": completed.stdout[-5000:],
            "stderr_tail": completed.stderr[-5000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "exit_code": None,
            "error": f"timed out after {timeout} seconds",
            "stdout_tail": str(exc.stdout or "")[-5000:],
            "stderr_tail": str(exc.stderr or "")[-5000:],
        }
    except OSError as exc:
        return {"command": command, "exit_code": None, "error": str(exc)}


def resolve_revision(root: Path, requested: Any) -> dict[str, Any]:
    """Ensure a benchmark checkout uses the immutable commit named in its manifest."""
    if requested is not None and (
        not isinstance(requested, str)
        or not re.fullmatch(r"[0-9a-fA-F]{40}", requested.strip())
    ):
        return {
            "ok": False,
            "status": "invalid-revision-pin",
            "requested_revision": requested,
            "error": "revision must be a full 40-character Git commit SHA",
        }

    current = run(["git", "rev-parse", "HEAD"], cwd=root, timeout=30)
    if current.get("exit_code") != 0:
        return {
            "ok": False,
            "status": "revision-read-failed",
            "requested_revision": requested,
            "current_revision_command": current,
        }
    actual = str(current.get("stdout_tail") or "").strip()
    evidence: dict[str, Any] = {"initial_revision_command": current}
    if requested is not None and actual.lower() != requested.lower():
        fetched = run(
            ["git", "fetch", "--depth", "1", "origin", requested],
            cwd=root, timeout=1800,
        )
        evidence["fetch_requested_revision"] = fetched
        if fetched.get("exit_code") != 0:
            return {
                "ok": False, "status": "revision-fetch-failed",
                "requested_revision": requested, "actual_revision": actual,
                "evidence": evidence,
            }
        checkout = run(["git", "checkout", "--detach", requested], cwd=root, timeout=60)
        evidence["checkout_requested_revision"] = checkout
        if checkout.get("exit_code") != 0:
            return {
                "ok": False, "status": "revision-checkout-failed",
                "requested_revision": requested, "actual_revision": actual,
                "evidence": evidence,
            }
        submodules = run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=root, timeout=1800,
        )
        evidence["submodules_after_checkout"] = submodules
        if submodules.get("exit_code") != 0:
            return {
                "ok": False, "status": "pinned-submodule-update-failed",
                "requested_revision": requested, "actual_revision": actual,
                "evidence": evidence,
            }
        verified = run(["git", "rev-parse", "HEAD"], cwd=root, timeout=30)
        evidence["verified_revision_command"] = verified
        if verified.get("exit_code") != 0:
            return {
                "ok": False, "status": "revision-verification-failed",
                "requested_revision": requested, "evidence": evidence,
            }
        actual = str(verified.get("stdout_tail") or "").strip()

    if requested is not None and actual.lower() != requested.lower():
        return {
            "ok": False, "status": "revision-mismatch",
            "requested_revision": requested, "actual_revision": actual,
            "evidence": evidence,
        }
    return {
        "ok": True,
        "status": "pinned" if requested is not None else "unpinned",
        "requested_revision": requested,
        "actual_revision": actual,
        "evidence": evidence,
    }


def mask_solidity(source: str) -> str:
    """Mask comments and quoted literals so source cues are not mistaken for code."""
    chars = list(source)
    state = "code"
    quote = ""
    index = 0
    while index < len(chars):
        char = chars[index]
        nxt = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "line"
                continue
            if char == "/" and nxt == "*":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "block"
                continue
            if char in ("'", '"'):
                quote = char
                chars[index] = " "
                state = "string"
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block":
            if char == "*" and nxt == "/":
                chars[index] = chars[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                chars[index] = " "
        elif state == "string":
            if char == "\\":
                chars[index] = " "
                if index + 1 < len(chars):
                    if chars[index + 1] != "\n":
                        chars[index + 1] = " "
                    index += 2
                    continue
            elif char == quote:
                chars[index] = " "
                state = "code"
            elif char != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)

def find_contracts(root: Path) -> dict[str, str]:
    """Discover contract declarations without assuming project-specific paths."""
    declarations: dict[str, str] = {}
    excluded = {".git", "out", "cache", "node_modules", ".audit", "broadcast"}
    for path in root.rglob("*.sol"):
        if any(part in excluded for part in path.parts):
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in DECLARATION.finditer(mask_solidity(source)):
            declarations.setdefault(match.group(1), path.relative_to(root).as_posix())
    return declarations


def load_report(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def evaluate_target(project_root: Path, contract: str, output_root: Path) -> dict[str, Any]:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", contract)
    all_dir = output_root / (slug + "-all")
    solidity_dir = output_root / (slug + "-solidity")
    common = ["lk", "test-gen", contract, "--force"]
    generation = run(
        common + ["--types", "all", "--output-dir", str(all_dir)],
        cwd=project_root,
    )
    generation_report = load_report(all_dir / slug / "report.json")

    validation = run(
        common + ["--types", SOLIDITY_TYPES, "--output-dir", str(solidity_dir), "--validate"],
        cwd=project_root,
    )
    validation_report = load_report(solidity_dir / slug / "report.json")
    assessments = (generation_report or {}).get("generation_assessment", {})
    validation_status = (validation_report or {}).get("validation", {}).get("status", "report-missing")
    generation_succeeded = generation.get("exit_code") == 0 and generation_report is not None
    validation_succeeded = (
        validation.get("exit_code") == 0
        and validation_report is not None
        and validation_status == "passed"
    )
    return {
        "contract": contract,
        "generation_command": generation,
        "generation_report_found": generation_report is not None,
        "generation_succeeded": generation_succeeded,
        "generation_assessment": assessments,
        "validation_command": validation,
        "validation_status": validation_status,
        "validation_report_found": validation_report is not None,
        "validation_succeeded": validation_succeeded,
        "formal_artifact_exists": any(all_dir.rglob("*Formal*")),
        "honest_result": (
            "generation-and-validation-passed"
            if generation_succeeded and validation_succeeded
            else "tool-or-report-failure"
            if generation_report is None or validation_report is None
            else "generation-or-validation-failed"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=Path(".audit/test-gen-ecosystem-benchmark.json"))
    parser.add_argument("--work-dir", type=Path, help="Keep cloned projects in this directory.")
    parser.add_argument("--keep-workspaces", action="store_true")
    parser.add_argument("--limit-projects", type=int, default=0, help="Limit project count for smoke runs.")
    parser.add_argument("--targets-per-project", type=int, default=2)
    args = parser.parse_args()

    for executable in ("git", "lk", "forge"):
        if shutil.which(executable) is None:
            print(f"Required executable unavailable: {executable}", file=sys.stderr)
            return 2
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot read benchmark manifest: {exc}", file=sys.stderr)
        return 2

    projects = manifest.get("projects", [])
    if args.limit_projects > 0:
        projects = projects[:args.limit_projects]

    owned_temp = None
    if args.work_dir:
        workspace_root = args.work_dir.resolve()
        workspace_root.mkdir(parents=True, exist_ok=True)
    else:
        owned_temp = tempfile.TemporaryDirectory(prefix="lowkey-test-gen-benchmark-")
        workspace_root = Path(owned_temp.name)

    output_path = args.output.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    try:
        for project in projects:
            project_id = project["id"]
            clone_dir = workspace_root / project_id
            item: dict[str, Any] = {
                "id": project_id,
                "repository": project["repository"],
                "target_candidates": project.get("target_candidates", []),
                "status": "pending",
            }
            clone = run(
                ["git", "clone", "--depth", "1", "--recurse-submodules", project["repository"], str(clone_dir)],
                timeout=1800,
            )
            item["clone"] = clone
            if clone.get("exit_code") != 0:
                item["status"] = "clone-failed"
                results.append(item)
                continue

            revision_pin = resolve_revision(clone_dir, project.get("revision"))
            item["revision_pin"] = revision_pin
            if not revision_pin.get("ok"):
                item["status"] = revision_pin.get("status", "revision-pin-failed")
                results.append(item)
                continue
            revision = revision_pin.get("actual_revision")
            item["revision"] = revision

            declarations = find_contracts(clone_dir)
            item["discovered_contract_count"] = len(declarations)
            candidates = [
                name for name in project.get("target_candidates", [])
                if name in declarations
            ][:max(1, args.targets_per_project)]
            item["candidate_sources"] = {name: declarations[name] for name in candidates}
            if not candidates:
                item["status"] = "no-listed-contract-candidate-found"
                results.append(item)
                continue

            build = run(["forge", "build"], cwd=clone_dir, timeout=1800)
            item["baseline_build"] = build
            item["targets"] = [
                evaluate_target(clone_dir, name, clone_dir / ".audit" / "ecosystem-benchmark")
                for name in candidates
            ]
            if build.get("exit_code") != 0:
                item["status"] = "baseline-build-failed"
            elif item["targets"] and all(
                target.get("honest_result") == "generation-and-validation-passed"
                for target in item["targets"]
            ):
                item["status"] = "evaluated"
            else:
                item["status"] = "generation-validation-failed"
            results.append(item)

        summary = {
            "schema_version": 1,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "manifest": str(args.manifest),
            "project_count": len(projects),
            "evaluated_count": sum(item["status"] == "evaluated" for item in results),
            "baseline_build_failed_count": sum(item["status"] == "baseline-build-failed" for item in results),
            "generation_validation_failed_count": sum(item["status"] == "generation-validation-failed" for item in results),
            "revision_pin_failed_count": sum(
                "revision" in item.get("status", "") or "submodule" in item.get("status", "")
                for item in results
            ),
            "results": results,
            "limitations": [
                "A completed benchmark run is not a security certification.",
                "Generation, compilation, execution, mutation testing, fork validation, and formal proof are distinct outcomes.",
                "This runner currently records generator validation and artifacts; it does not yet implement isolated mutation campaigns.",
                "Projects requiring private credentials, unsupported build systems, or unavailable dependencies remain blocked and must not be counted as passes.",
            ],
        }
        output_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"Benchmark report: {output_path}")
        print(f"Projects: {len(results)}; baseline builds successful: {summary['evaluated_count']}")
        for item in results:
            print(f"  {item['id']}: {item['status']}")
        return 0 if results and all(item["status"] == "evaluated" for item in results) else 1
    finally:
        if owned_temp is not None and not args.keep_workspaces:
            owned_temp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
