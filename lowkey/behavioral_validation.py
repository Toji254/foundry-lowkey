"""Reproducible mutation validation for generated/project test suites.

Only explicit, unique source replacements are applied. The baseline must pass.
Compiler/setup failures and timeouts are reported separately rather than counted
as evidence that a test killed a behavioral mutant.
"""
from __future__ import annotations

import hashlib
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
            process.kill()
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
    shutil.copytree(source, destination, ignore=ignore, symlinks=False)


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
