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


def run(
    command: list[str],
    cwd: Path | None = None,
    timeout: int = 1800,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    try:
        completed = subprocess.run(
            command, cwd=cwd, env=process_env, capture_output=True, text=True,
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


def expected_unsupported_outcome(project: dict[str, Any]) -> dict[str, str] | None:
    """Return an explicit negative-control outcome declared by the corpus manifest."""
    value = project.get("expected_outcome")
    if not isinstance(value, str) or not value.strip():
        return None
    return {
        "status": "expected-unsupported",
        "reason": value.strip(),
    }


def _nearest_foundry_root(project_root: Path, source_path: str | Path) -> Path | None:
    """Find the closest Foundry package containing the selected source."""
    root = project_root.resolve()
    source = Path(source_path)
    source = source if source.is_absolute() else root / source
    current = source.resolve().parent
    while current == root or current.is_relative_to(root):
        if (current / "foundry.toml").is_file():
            return current
        if current == root:
            break
        current = current.parent
    return None


def _infer_source_directory(project_root: Path, source_paths: list[str]) -> str:
    """Infer a source root from conventional Solidity folders in selected paths."""
    root = project_root.resolve()
    candidates: list[Path] = []
    for raw in source_paths:
        parts = Path(raw).parts
        conventional = [i for i, part in enumerate(parts) if part in {"src", "contracts"}]
        if conventional:
            candidates.append(Path(*parts[:conventional[-1] + 1]))
        elif parts:
            candidates.append(Path(*parts[:-1]))
    if not candidates:
        return "src" if (root / "src").is_dir() else "contracts"
    common = Path(os.path.commonpath([str(root / item) for item in candidates]))
    try:
        relative = common.relative_to(root)
    except ValueError:
        return "src" if (root / "src").is_dir() else "contracts"
    return relative.as_posix() or ("src" if (root / "src").is_dir() else "contracts")


def _synthetic_foundry_config(project_root: Path, source_paths: list[str]) -> tuple[Path, bool]:
    """Create an isolated Foundry config under .audit for non-Foundry Solidity projects."""
    root = project_root.resolve()
    existing = root / "foundry.toml"
    if existing.is_file():
        return existing, False
    config_path = root / ".audit" / "lowkey-ecosystem-foundry.toml"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    source_dir = _infer_source_directory(root, source_paths)
    config_text = (
        "[profile.default]\n"
        f'src = "{source_dir}"\n'
        'test = "test"\n'
        'out = ".lowkey-ecosystem-out"\n'
        'cache_path = ".lowkey-ecosystem-cache"\n'
        'libs = ["lib", "node_modules"]\n'
        "auto_detect_solc = true\n"
        "optimizer = true\n"
        "optimizer_runs = 200\n"
        'allow_paths = ["node_modules"]\n'
    )
    config_path.write_text(config_text, encoding="utf-8")
    return config_path, True

def _is_abstract_contract(project_root: Path, relative_source: str, contract: str) -> bool:
    path = project_root / relative_source
    try:
        source = mask_solidity(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return True
    return bool(re.search(
        r"\babstract\s+contract\s+" + re.escape(contract) + r"\b",
        source,
    ))


def _report_accounts_for_every_type(report: dict[str, Any] | None) -> bool:
    """A complete report may explain evidence gaps, but cannot omit categories."""
    if not isinstance(report, dict):
        return False
    requested = report.get("requested_types")
    assessments = report.get("generation_assessment")
    if not isinstance(requested, list) or not requested or not isinstance(assessments, dict):
        return False
    for kind in requested:
        item = assessments.get(kind)
        if not isinstance(item, dict):
            return False
        if not isinstance(item.get("level"), str) or not item["level"].strip():
            return False
        if not isinstance(item.get("note"), str) or not item["note"].strip():
            return False
    return isinstance(report.get("generated", []), list)


def evaluate_target(
    project_root: Path,
    contract: str,
    output_root: Path,
    *,
    constructor_args: list[str] | None = None,
    env: dict[str, str] | None = None,
    source_path: str | None = None,
    abstract_contract: bool = False,
) -> dict[str, Any]:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "_", contract)
    all_dir = output_root / (slug + "-all")
    solidity_dir = output_root / (slug + "-solidity")
    common = ["lk", "test-gen", contract, "--force"]
    if constructor_args is not None:
        common.extend(["--constructor-args", json.dumps(constructor_args)])
    generation = run(
        common + ["--types", "all", "--output-dir", str(all_dir)],
        cwd=project_root,
        env=env,
    )
    generation_report = load_report(all_dir / slug / "report.json")
    validation = run(
        common + ["--types", SOLIDITY_TYPES, "--output-dir", str(solidity_dir), "--validate"],
        cwd=project_root,
        env=env,
    )
    validation_report = load_report(solidity_dir / slug / "report.json")
    assessments = (generation_report or {}).get("generation_assessment", {})
    validation_data = (validation_report or {}).get("validation", {})
    validation_status = validation_data.get("status", "report-missing")
    generation_assessed = _report_accounts_for_every_type(generation_report)
    generation_succeeded = (
        generation.get("exit_code") == 0
        and generation_assessed
        and not (generation_report or {}).get("skipped")
    )
    executions = validation_data.get("test_executions", [])
    executable_kinds = {"unit", "fuzz", "invariant"}
    executable_expected = any(
        isinstance(assessments.get(kind), dict)
        and assessments[kind].get("level") == "executable-candidate"
        for kind in executable_kinds
    )
    validation_succeeded = (
        validation.get("exit_code") == 0
        and validation_report is not None
        and validation_status == "passed"
        and isinstance(executions, list)
        and bool(executions)
        and all(isinstance(item, dict) and item.get("exit_code") == 0 for item in executions)
    )
    no_executable_candidate = (
        not executable_expected
        and validation_report is not None
        and validation_status in {"not-applicable", "compiled-only"}
        and isinstance(executions, list)
        and not executions
    )
    if generation_report is None or validation_report is None or not generation_assessed:
        honest_result = "tool-or-report-failure"
    elif executable_expected and not validation_succeeded:
        honest_result = "execution-failed"
    elif not executable_expected and not no_executable_candidate and not validation_succeeded:
        honest_result = "validation-incomplete"
    elif generation_succeeded and validation_succeeded:
        honest_result = "generation-and-validation-passed"
    else:
        honest_result = "assessed-with-evidence-gaps"
    return {
        "contract": contract,
        "source_path": source_path,
        "abstract_contract": abstract_contract,
        "constructor_args_supplied": constructor_args is not None,
        "generation_command": generation,
        "generation_report_found": generation_report is not None,
        "generation_assessment_complete": generation_assessed,
        "generation_succeeded": generation_succeeded,
        "generation_assessment": assessments,
        "generation_skipped": (generation_report or {}).get("skipped", []),
        "validation_command": validation,
        "validation_status": validation_status,
        "validation_report_found": validation_report is not None,
        "validation_test_executions": executions,
        "validation_succeeded": validation_succeeded,
        "formal_artifact_exists": any((all_dir / slug).glob("*Formal*")),
        "honest_result": honest_result,
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

            expected_outcome = expected_unsupported_outcome(project)
            if expected_outcome is not None:
                item["status"] = expected_outcome["status"]
                item["expected_outcome"] = expected_outcome["reason"]
                item["classification_evidence"] = {
                    "manifest_declaration": "expected_outcome",
                    "discovered_contract_candidates": item["candidate_sources"],
                    "generation_executed": False,
                }
                results.append(item)
                continue

            # Resolve the closest Foundry package for each target. Legacy Solidity
            # repositories get a disposable config with source roots inferred from
            # the selected source paths; existing project configs are never rewritten.
            grouped: dict[Path, list[tuple[str, str]]] = {}
            configs: dict[Path, tuple[Path, bool]] = {}
            for name in candidates:
                relative_source = item["candidate_sources"][name]
                package_root = _nearest_foundry_root(clone_dir, relative_source)
                if package_root is None:
                    package_root = clone_dir.resolve()
                    config = _synthetic_foundry_config(clone_dir, list(item["candidate_sources"].values()))
                else:
                    config = (package_root / "foundry.toml", False)
                configs[package_root] = config
                local_source = (clone_dir / relative_source).resolve().relative_to(package_root).as_posix()
                grouped.setdefault(package_root, []).append((name, local_source))

            item["targets"] = []
            item["baseline_builds"] = []
            for package_root, target_group in grouped.items():
                config_path, synthetic_config = configs[package_root]
                forge_env = {"FOUNDRY_CONFIG": str(config_path.resolve())}
                baseline_key = str(package_root)
                if baseline_key not in {entry["root"] for entry in item["baseline_builds"]}:
                    build = run(["forge", "build"], cwd=package_root, timeout=1800, env=forge_env)
                    item["baseline_builds"].append({
                        "root": baseline_key,
                        "config": str(config_path),
                        "synthetic_config": synthetic_config,
                        "result": build,
                    })
                else:
                    build = next(entry["result"] for entry in item["baseline_builds"] if entry["root"] == baseline_key)
                if build.get("exit_code") != 0:
                    for name, source_local in target_group:
                        item["targets"].append({
                            "contract": name,
                            "source_path": source_local,
                            "abstract_contract": _is_abstract_contract(package_root, source_local, name),
                            "honest_result": "baseline-build-failed",
                            "baseline_build": build,
                        })
                    continue

                for name, source_local in target_group:
                    setup = (project.get("target_setup") or {}).get(name, {})
                    constructor_args = setup.get("constructor_args") if isinstance(setup, dict) else None
                    abstract_contract = _is_abstract_contract(package_root, source_local, name)
                    target_result = evaluate_target(
                        package_root,
                        name,
                        package_root / ".audit" / "ecosystem-benchmark",
                        constructor_args=constructor_args,
                        env=forge_env,
                        source_path=source_local,
                        abstract_contract=abstract_contract,
                    )
                    item["targets"].append(target_result)

            baseline_failed = any(
                entry["result"].get("exit_code") != 0 for entry in item["baseline_builds"]
            )
            target_outcomes = {target.get("honest_result") for target in item["targets"]}
            fully_passed = bool(item["targets"]) and target_outcomes == {"generation-and-validation-passed"}
            assessed = bool(item["targets"]) and target_outcomes.issubset({
                "generation-and-validation-passed", "assessed-with-evidence-gaps"
            })
            if baseline_failed:
                item["status"] = "baseline-build-failed"
            elif fully_passed:
                item["status"] = "evaluated"
            elif assessed:
                item["status"] = "assessed-with-evidence-gaps"
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
            "expected_unsupported_count": sum(item["status"] == "expected-unsupported" for item in results),
            "assessed_with_evidence_gaps_count": sum(item["status"] == "assessed-with-evidence-gaps" for item in results),
            "unresolved_project_count": sum(
                item["status"] not in {"evaluated", "assessed-with-evidence-gaps", "expected-unsupported"}
                for item in results
            ),
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
        print(f"Projects fully generated and validated: {summary['evaluated_count']}")
        print(f"Projects assessed with explicit evidence gaps: {summary['assessed_with_evidence_gaps_count']}")
        for item in results:
            print(f"  {item['id']}: {item['status']}")
        accepted = {"evaluated", "assessed-with-evidence-gaps", "expected-unsupported"}
        return 0 if results and all(item["status"] in accepted for item in results) else 1
    finally:
        if owned_temp is not None and not args.keep_workspaces:
            owned_temp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
