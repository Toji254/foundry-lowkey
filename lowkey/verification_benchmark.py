"""Reproducible, manifest-driven verification benchmark runner."""
from __future__ import annotations

import hashlib
import json
import math
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from behavioral_validation import validate_mutations
except ImportError:
    from lowkey.behavioral_validation import validate_mutations


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _git_revision(root: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root,
            capture_output=True, text=True, timeout=3,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def run_benchmark(
    manifest_path: str | Path,
    *,
    workspace_root: str | Path | None = None,
    min_mutation_score: float | None = None,
) -> dict[str, Any]:
    manifest_file = Path(manifest_path).expanduser().resolve()
    raw_manifest = manifest_file.read_bytes()
    manifest = json.loads(raw_manifest.decode("utf-8"))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("cases"), list):
        raise ValueError("benchmark manifest must be an object with a cases array")
    workspace = Path(workspace_root).expanduser().resolve() if workspace_root else Path.cwd().resolve()
    if min_mutation_score is not None and (
        not math.isfinite(min_mutation_score) or min_mutation_score < 0 or min_mutation_score > 1
    ):
        raise ValueError("min_mutation_score must be between 0 and 1")
    if not workspace.is_dir():
        raise ValueError(f"workspace root is not a directory: {workspace}")
    cases = []
    for index, case in enumerate(manifest["cases"]):
        if not isinstance(case, dict):
            cases.append({"id": f"case-{index + 1}", "status": "invalid", "reason": "case must be an object"})
            continue
        case_id = str(case.get("id") or f"case-{index + 1}")
        project_value = Path(str(case.get("project") or "."))
        if project_value.is_absolute() or ".." in project_value.parts:
            cases.append({"id": case_id, "status": "invalid", "reason": "project must be a safe relative path"})
            continue
        project = (workspace / project_value).resolve()
        if not project.is_relative_to(workspace) or not project.is_dir():
            cases.append({"id": case_id, "status": "invalid", "reason": "project directory is missing or escapes workspace"})
            continue
        command = case.get("command")
        mutants = case.get("mutants", [])
        if not isinstance(command, list) or not command or not all(isinstance(arg, str) for arg in command):
            cases.append({"id": case_id, "status": "invalid", "reason": "command must be a non-empty argv array"})
            continue
        try:
            result = validate_mutations(
                project, command, mutants,
                timeout_seconds=int(case.get("timeout_seconds", 300)),
            )
        except (ValueError, OSError, TypeError) as exc:
            cases.append({"id": case_id, "status": "error", "reason": str(exc)})
            continue
        labels = case.get("labels") if isinstance(case.get("labels"), dict) else {}
        cases.append({
            "id": case_id,
            "status": result.get("status"),
            "labels": labels,
            "project": str(project),
            "command": command,
            "result": result,
        })

    completed = [case for case in cases if case.get("status") == "completed"]
    killed = sum((case.get("result", {}).get("summary") or {}).get("killed", 0) for case in completed)
    survived = sum((case.get("result", {}).get("summary") or {}).get("survived", 0) for case in completed)
    invalid = sum((case.get("result", {}).get("summary") or {}).get("invalid", 0) for case in completed)
    timeout_count = sum((case.get("result", {}).get("summary") or {}).get("timeout", 0) for case in completed)
    scored = killed + survived
    score = killed / scored if scored else None
    failures = [case for case in cases if case.get("status") != "completed"]
    gate_passed = not failures and score is not None and (
        min_mutation_score is None or score >= min_mutation_score
    )
    return {
        "schema_version": 1,
        "benchmark": str(manifest.get("name") or manifest_file.stem),
        "started_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "manifest_path": str(manifest_file),
        "manifest_sha256": _sha256_bytes(raw_manifest),
        "workspace_root": str(workspace),
        "git_revision": _git_revision(workspace),
        "runtime": {"python": sys.version.split()[0], "platform": platform.platform()},
        "case_count": len(cases),
        "completed_cases": len(completed),
        "failed_cases": len(failures),
        "summary": {
            "killed": killed, "survived": survived, "invalid": invalid,
            "timeout": timeout_count, "scored_mutants": scored,
        },
        "mutation_score": score,
        "min_mutation_score": min_mutation_score,
        "gate": "passed" if gate_passed else "failed",
        "cases": cases,
        "interpretation": "The aggregate score counts only killed and survived mutants. Failed baselines, invalid mutations, and timeouts remain visible and do not inflate the score.",
    }


def write_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def run_cli(args: list[str]) -> int:
    import sys as _sys

    if not args or any(str(arg).lower() in {"-h", "--help", "help"} for arg in args):
        print("""Lowkey verification benchmark

Usage:
  lk verification-benchmark <manifest.json> [--workspace <dir>]
      [--output .audit/verification/benchmark-report.json]
      [--min-mutation-score 0.80]

Manifest:
  {
    "name": "vault-regression",
    "cases": [{
      "id": "foundry-vault",
      "project": ".",
      "command": ["forge", "test"],
      "timeout_seconds": 300,
      "labels": {"language": "solidity", "build_system": "foundry", "protocol": "vault"},
      "mutants": [{"id": "accounting-off-by-one", "file": "src/Vault.sol",
                   "before": "shares = assets;", "after": "shares = assets + 1;"}]
    }]
  }

Commands run without a shell. Baseline tests must pass before mutation results count.
""")
        return 0 if args else 2

    manifest_path: Path | None = None
    workspace: Path | None = None
    output_path = Path(".audit/verification/benchmark-report.json")
    minimum: float | None = None
    index = 0
    while index < len(args):
        value = str(args[index])
        if value in {"--workspace", "--output", "--min-mutation-score"}:
            index += 1
            if index >= len(args):
                print(f"Error: {value} requires a value", file=_sys.stderr)
                return 2
            raw = str(args[index])
            if value == "--workspace":
                workspace = Path(raw).expanduser()
            elif value == "--output":
                output_path = Path(raw).expanduser()
            else:
                try:
                    minimum = float(raw)
                except ValueError:
                    print("Error: --min-mutation-score must be numeric", file=_sys.stderr)
                    return 2
        elif value.startswith("--workspace="):
            workspace = Path(value.split("=", 1)[1]).expanduser()
        elif value.startswith("--output="):
            output_path = Path(value.split("=", 1)[1]).expanduser()
        elif value.startswith("--min-mutation-score="):
            try:
                minimum = float(value.split("=", 1)[1])
            except ValueError:
                print("Error: --min-mutation-score must be numeric", file=_sys.stderr)
                return 2
        elif value.startswith("-"):
            print(f"Error: unknown option: {value}", file=_sys.stderr)
            return 2
        elif manifest_path is None:
            manifest_path = Path(value).expanduser()
        else:
            print(f"Error: unexpected argument: {value}", file=_sys.stderr)
            return 2
        index += 1
    if manifest_path is None:
        print("Error: provide a benchmark manifest JSON file", file=_sys.stderr)
        return 2
    try:
        report = run_benchmark(
            manifest_path, workspace_root=workspace,
            min_mutation_score=minimum,
        )
        written = write_report(report, output_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Error: benchmark failed: {exc}", file=_sys.stderr)
        return 2
    score = report.get("mutation_score")
    print(f"Verification benchmark: {report['benchmark']}")
    print(f"  Cases: {report['completed_cases']}/{report['case_count']} completed")
    print(f"  Mutation score: {score:.1%}" if isinstance(score, (int, float)) else "  Mutation score: not available")
    print(f"  Gate: {report['gate']}")
    print(f"  Report: {written}")
    return 0 if report["gate"] == "passed" else 1
