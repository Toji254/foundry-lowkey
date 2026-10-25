"""Reproducible mutation validation for generated/project test suites.

Only explicit, unique source replacements are applied. The baseline must pass.
Compiler/setup failures and timeouts are reported separately rather than counted
as evidence that a test killed a behavioral mutant.
"""
from __future__ import annotations

import hashlib
import os
import signal
import json
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


IGNORED_COPY_DIRS = {
    ".git", ".audit", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", "node_modules",
    "out", "cache", "artifacts", "build", "dist", "target",
}
DEFAULT_INVALID_MARKERS = (
    "compiler run failed", "could not compile", "compilation failed",
    "syntaxerror:", "modulenotfounderror:", "no module named",
    "cannot find module", "command not found",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(root: Path, argv: list[str], timeout: int) -> dict[str, Any]:
    try:
        process = subprocess.Popen(
            argv, cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=(os.name == "posix"),
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            return {
                "status": "passed" if process.returncode == 0 else "failed",
                "exit_code": process.returncode,
                "stdout": stdout or "",
                "stderr": stderr or "",
            }
        except subprocess.TimeoutExpired:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                else:
                    process.kill()
            except OSError:
                pass
            try:
                stdout, stderr = process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except OSError:
                    pass
                stdout, stderr = process.communicate()
            return {
                "status": "timeout", "exit_code": 124,
                "stdout": stdout or "", "stderr": (stderr or "") + f"\nLOWKEY_TIMEOUT_SECONDS={timeout}",
            }
    except OSError as exc:
        return {"status": "error", "exit_code": 127, "stdout": "", "stderr": str(exc)}


def _copy_project(source: Path, destination: Path) -> None:
    def ignore(_directory: str, names: list[str]) -> set[str]:
        return {name for name in names if name in IGNORED_COPY_DIRS}
    shutil.copytree(source, destination, ignore=ignore, symlinks=True)


def validate_mutations(
    project_root: str | Path,
    argv: list[str],
    mutants: list[dict[str, str]],
    *,
    timeout_seconds: int = 300,
    invalid_markers: tuple[str, ...] = DEFAULT_INVALID_MARKERS,
) -> dict[str, Any]:
    """Run a passing baseline then each mutant in an isolated project copy.

    Each mutant requires id, file, before, and after. File must be a relative
    path inside the project; before must occur exactly once.
    """
    source = Path(project_root).expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"project root is not a directory: {source}")
    if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
        raise ValueError("argv must be a non-empty list of native command arguments")
    if not isinstance(mutants, list):
        raise ValueError("mutants must be a list")
    timeout = max(1, min(int(timeout_seconds), 7200))
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="lowkey-mutation-") as temporary:
        temp_root = Path(temporary)
        baseline_root = temp_root / "baseline"
        _copy_project(source, baseline_root)
        baseline = _run(baseline_root, argv, timeout)
        if baseline["status"] != "passed":
            return {
                "schema_version": 1,
                "run_id": run_id,
                "status": "baseline_failed",
                "project": str(source),
                "command": argv,
                "baseline": baseline,
                "mutants": [],
                "summary": {"killed": 0, "survived": 0, "invalid": 0, "timeout": 0, "error": 0},
                "mutation_score": None,
                "interpretation": "No mutation conclusion: the unmodified project test command did not pass.",
            }

        for index, mutant in enumerate(mutants):
            if not isinstance(mutant, dict):
                results.append({"id": f"mutant-{index + 1}", "status": "invalid", "reason": "each mutant must be an object"})
                continue
            mutant_id = str(mutant.get("id") or f"mutant-{index + 1}")
            relative = Path(str(mutant.get("file") or ""))
            if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                results.append({"id": mutant_id, "status": "invalid", "reason": "mutant file must be a safe relative path"})
                continue
            before, after = mutant.get("before"), mutant.get("after")
            if not isinstance(before, str) or not before or not isinstance(after, str):
                results.append({"id": mutant_id, "status": "invalid", "reason": "before/after must be non-empty/valid strings"})
                continue
            mutant_root = temp_root / f"mutant-{index + 1}"
            try:
                _copy_project(source, mutant_root)
                target = (mutant_root / relative).resolve()
                if not target.is_relative_to(mutant_root) or not target.is_file():
                    results.append({"id": mutant_id, "status": "invalid", "reason": "mutant target is missing or escapes project root"})
                    continue
                original = target.read_text(encoding="utf-8")
                occurrences = original.count(before)
                if occurrences != 1:
                    results.append({
                        "id": mutant_id, "status": "invalid",
                        "reason": f"expected source fragment exactly once; found {occurrences}",
                        "file": str(relative),
                    })
                    continue
                target.write_text(original.replace(before, after, 1), encoding="utf-8")
                mutant_hash = _sha256(target)
                execution = _run(mutant_root, argv, timeout)
                combined = (execution.get("stdout", "") + "\n" + execution.get("stderr", "")).lower()
                if execution["status"] == "timeout":
                    status = "timeout"
                elif execution["status"] == "error":
                    status = "error"
                elif execution["status"] == "passed":
                    status = "survived"
                elif any(marker.lower() in combined for marker in invalid_markers):
                    status = "invalid"
                else:
                    status = "killed"
                results.append({
                    "id": mutant_id, "status": status, "file": str(relative),
                    "mutated_file_sha256": mutant_hash, "before_sha256": hashlib.sha256(before.encode()).hexdigest(),
                    "after_sha256": hashlib.sha256(after.encode()).hexdigest(),
                    "exit_code": execution["exit_code"], "stdout": execution["stdout"],
                    "stderr": execution["stderr"],
                })
            except (OSError, UnicodeError, shutil.Error) as exc:
                results.append({"id": mutant_id, "status": "error", "reason": str(exc)})

    summary = {
        status: sum(item.get("status") == status for item in results)
        for status in ("killed", "survived", "invalid", "timeout", "error")
    }
    scored = summary["killed"] + summary["survived"]
    return {
        "schema_version": 1,
        "run_id": run_id,
        "status": "completed",
        "project": str(source),
        "command": argv,
        "baseline": baseline,
        "mutants": results,
        "summary": summary,
        "mutation_score": (summary["killed"] / scored) if scored else None,
        "interpretation": "Mutation score counts only killed and survived behavioral mutants; invalid mutations, setup/compiler failures, and timeouts are reported separately.",
    }


def write_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path



def run_cli(args: list[str]) -> int:
    """CLI for reproducible mutation campaigns described by a JSON manifest."""
    import sys

    if not args or any(str(arg).lower() in {"-h", "--help", "help"} for arg in args):
        print("""Lowkey mutation validation

Usage:
  lk mutation-check <manifest.json> [--output .audit/verification/mutation-report.json] [--timeout 300]

Manifest format:
  {
    "command": ["forge", "test"],
    "mutants": [
      {"id": "disable-withdraw-check", "file": "src/Vault.sol",
       "before": "require(amount <= balance);", "after": "require(amount < 0);"}
    ]
  }

The baseline suite must pass before mutants are evaluated. Mutations must match
exactly once. Commands execute without a shell in isolated temporary copies.
""")
        return 0 if args and any(str(arg).lower() in {"-h", "--help", "help"} for arg in args) else 2

    manifest_path: Path | None = None
    output_path = Path(".audit/verification/mutation-report.json")
    timeout = 300
    index = 0
    while index < len(args):
        value = str(args[index])
        if value == "--output":
            index += 1
            if index >= len(args):
                print("Error: --output needs a path", file=sys.stderr)
                return 2
            output_path = Path(args[index]).expanduser()
        elif value.startswith("--output="):
            output_path = Path(value.split("=", 1)[1]).expanduser()
        elif value == "--timeout":
            index += 1
            if index >= len(args):
                print("Error: --timeout needs seconds", file=sys.stderr)
                return 2
            try:
                timeout = int(args[index])
            except ValueError:
                print("Error: --timeout must be an integer", file=sys.stderr)
                return 2
        elif value.startswith("--timeout="):
            try:
                timeout = int(value.split("=", 1)[1])
            except ValueError:
                print("Error: --timeout must be an integer", file=sys.stderr)
                return 2
        elif value.startswith("-"):
            print(f"Error: unknown option: {value}", file=sys.stderr)
            return 2
        elif manifest_path is None:
            manifest_path = Path(value).expanduser()
        else:
            print(f"Error: unexpected argument: {value}", file=sys.stderr)
            return 2
        index += 1
    if manifest_path is None:
        print("Error: provide a mutation manifest JSON file", file=sys.stderr)
        return 2
    if not manifest_path.is_absolute():
        manifest_path = Path.cwd() / manifest_path
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error: cannot read mutation manifest: {exc}", file=sys.stderr)
        return 2
    if not isinstance(manifest, dict):
        print("Error: mutation manifest must be a JSON object", file=sys.stderr)
        return 2
    argv = manifest.get("command")
    mutants = manifest.get("mutants")
    if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
        print("Error: manifest.command must be a non-empty array of CLI arguments", file=sys.stderr)
        return 2
    if not isinstance(mutants, list):
        print("Error: manifest.mutants must be an array", file=sys.stderr)
        return 2
    try:
        import audit_context
        root_value = audit_context.foundry_project_root()
    except (ImportError, OSError):
        root_value = None
    root = Path(str(root_value)).resolve() if root_value else Path.cwd().resolve()
    report = validate_mutations(root, argv, mutants, timeout_seconds=timeout)
    destination = output_path if output_path.is_absolute() else root / output_path
    try:
        written = write_report(report, destination)
    except OSError as exc:
        print(f"Error: could not write mutation report: {exc}", file=sys.stderr)
        return 2
    summary = report.get("summary") or {}
    print(f"Mutation validation: {report.get('status')}")
    print(f"  Baseline: {report.get('baseline', {}).get('status', 'not run')}")
    if report.get("status") == "baseline_failed":
        baseline = report.get("baseline") or {}
        for label in ("stdout", "stderr"):
            detail = str(baseline.get(label) or "").strip()
            if detail:
                print(f"  Baseline {label} (last 40 lines):")
                print("\\n".join(detail.splitlines()[-40:]))
    print(f"  Killed: {summary.get('killed', 0)}  Survived: {summary.get('survived', 0)}  Invalid: {summary.get('invalid', 0)}  Timeout: {summary.get('timeout', 0)}")
    score = report.get("mutation_score")
    print(f"  Mutation score: {score:.1%}" if isinstance(score, (float, int)) else "  Mutation score: not available")
    print(f"  Report: {written}")
    return 0 if report.get("status") == "completed" else 1
