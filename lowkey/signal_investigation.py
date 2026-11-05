"""Signal-scoped, evidence-backed test generation for eligible Solidity findings."""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any


def _slug(signal_id: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_-]+", "-", signal_id).strip("-_")[:48] or "signal"
    return readable + "-" + hashlib.sha256(signal_id.encode("utf-8")).hexdigest()[:10]


def _is_access_control_finding(signal: dict[str, Any]) -> bool:
    value = " ".join(str(signal.get(key) or "") for key in (
        "category", "check", "pattern_id", "title", "description", "meaning", "why"
    )).lower()
    return bool(re.search(
        r"access[\s_-]*control|onlyowner|authori[sz]ation|unauthori[sz]ed|"
        r"owner(?:ship)?|privileged|permission(?:less)?|tx[\s._-]*origin|"
        r"unprotected|role[\s_-]*based",
        value,
    ))


def _is_reentrancy_finding(signal: dict[str, Any]) -> bool:
    value = " ".join(str(signal.get(key) or "") for key in (
        "category", "check", "pattern_id", "title", "description", "meaning", "why"
    )).lower()
    return bool(re.search(r"re[\s_-]*entr(?:ancy|ant)|reentrant", value))


def _native_signal(root: Path, signal_id: str, audit_context: Any) -> dict[str, Any]:
    wanted = str(signal_id or "").strip()
    if not wanted:
        raise ValueError("provide an existing Lowkey signal ID")
    signal = next((
        item for item in audit_context.signals(root)
        if isinstance(item, dict) and str(item.get("id") or "") == wanted
    ), None)
    if signal is None:
        raise ValueError(f"signal '{wanted}' was not found in the current project")
    return dict(signal)


def plan_signal_investigation(
    signal_id: str,
    *,
    project_root: str | Path,
    audit_context: Any,
) -> dict[str, Any]:
    """Create a read-only plan for one native signal; never writes or executes tests."""
    root = Path(project_root).expanduser().resolve()
    signal = _native_signal(root, signal_id, audit_context)
    raw_file = str(signal.get("file") or "").strip()
    source_path = Path(raw_file).expanduser()
    if not raw_file:
        source_path = None
    elif not source_path.is_absolute():
        source_path = root / source_path
    if source_path is not None:
        try:
            source_path = source_path.resolve()
        except (OSError, RuntimeError):
            source_path = None
    if source_path is not None and not source_path.is_relative_to(root):
        return {
            "signal_id": str(signal_id),
            "status": "blocked",
            "reason": "The native signal source path resolves outside the selected project; Lowkey will not guess or read it.",
            "effects": {"writes": False, "provider_call": False, "forge": False, "tests_run": False},
        }
    if source_path is None or not source_path.is_file():
        return {
            "signal_id": str(signal_id),
            "status": "blocked",
            "reason": "The native signal has no readable source file inside the selected project; Lowkey will not guess one.",
            "effects": {"writes": False, "provider_call": False, "forge": False, "tests_run": False},
        }

    function_value = str(signal.get("function") or "").strip()
    function_name_match = re.search(r"\b([A-Za-z_]\w*)\s*\(", function_value)
    function_name = function_name_match.group(1) if function_name_match else function_value
    try:
        source = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {
            "signal_id": str(signal_id),
            "status": "blocked",
            "reason": f"Could not read the signal source: {exc}",
            "effects": {"writes": False, "provider_call": False, "forge": False, "tests_run": False},
        }
    if function_name and not re.search(
        r"\bfunction\s+" + re.escape(function_name) + r"\s*\(",
        re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.S),
    ):
        return {
            "signal_id": str(signal_id),
            "status": "needs-investigation",
            "reason": "The signal's function name could not be mapped to a declaration in its source file.",
            "source_file": source_path.relative_to(root).as_posix(),
            "effects": {"writes": False, "provider_call": False, "forge": False, "tests_run": False},
        }

    access_control = _is_access_control_finding(signal)
    reentrancy = _is_reentrancy_finding(signal)
    if access_control:
        proposed_name = f"test_nonPrivilegedCallerCannot_{function_name or 'Target'}"
        property_text = "A caller outside the declared authorization policy should not complete the privileged state transition."
    elif reentrancy:
        proposed_name = f"test_reentryDoesNotDuplicate_{function_name or 'Target'}"
        property_text = "A callback must not consume the same entitlement or payout more than once."
    else:
        proposed_name = None
        property_text = "The detector signal needs protocol-specific caller, state and impact analysis before a test can be selected."

    # Keep this recommendation advisory and read-only.  The command does not
    # generate tests or execute a provider-backed workflow.
    suggested = f"lk ai test-plan --finding {signal_id}"
    return {
        "signal_id": str(signal_id),
        "status": "plan-only",
        "signal": {
            "detector": signal.get("tool"),
            "rule": signal.get("check") or signal.get("pattern_id"),
            "title": signal.get("title"),
            "source_file": source_path.relative_to(root).as_posix(),
            "source_line": signal.get("line"),
            "function": function_name or None,
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        },
        "property_hypothesis": property_text,
        "suggested_test_name": proposed_name,
        "recommended_next_command": suggested,
        "execution_command": (
            f"lk verification run-test {signal_id} <TEST_PATH> <TEST_NAME>"
        ),
        "execution_prerequisite": (
            "Write or locate a complete test, inspect its setup and assertions, then supply its exact path and function name."
        ),
        "effects": {
            "writes": False,
            "provider_call": False,
            "forge": False,
            "tests_run": False,
            "deployments": False,
            "transactions": False,
            "network": False,
        },
        "human_disposition_changed": False,
    }


def execute_inspected_test(
    signal_id: str,
    test_path: str | Path,
    test_name: str,
    *,
    project_root: str | Path,
    audit_context: Any,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    """Run one inspected Foundry test by exact file and function; never changes disposition."""
    root = Path(project_root).expanduser().resolve()
    signal = _native_signal(root, signal_id, audit_context)
    requested = Path(str(test_path)).expanduser()
    candidate = requested if requested.is_absolute() else root / requested
    try:
        selected = candidate.resolve(strict=True)
        selected.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError("test path must resolve to an existing file inside the selected project") from exc
    if selected.suffix.lower() != ".sol" or not selected.name.endswith(".t.sol"):
        raise ValueError("select one existing Foundry test file ending in .t.sol")

    config_path = root / "foundry.toml"
    if not config_path.is_file():
        raise ValueError("selected project has no foundry.toml; a Foundry test cannot be run")
    try:
        import tomllib
        config = tomllib.loads(config_path.read_text(encoding="utf-8", errors="replace"))
        profile_name = os.environ.get("FOUNDRY_PROFILE", "default")
        profile = config.get("profile", {}).get(profile_name, {})
        test_directory = str(profile.get("test") or config.get("test") or "test")
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"could not resolve the active Foundry test directory: {exc}") from exc
    configured_tests = (root / test_directory).resolve()
    try:
        selected.relative_to(configured_tests)
    except ValueError as exc:
        raise ValueError(
            f"selected file is outside the active Foundry test directory ({test_directory}); "
            "place reviewed tests under that directory before execution"
        ) from exc

    name = str(test_name or "").strip()
    if not re.fullmatch(r"(?:test|invariant)[A-Za-z0-9_]*", name):
        raise ValueError("test name must be one exact Foundry test/invariant function name")
    source = selected.read_text(encoding="utf-8", errors="replace")
    clean = re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.S)
    declarations = re.findall(
        r"\bfunction\s+" + re.escape(name) + r"\s*\(",
        clean,
    )
    if len(declarations) != 1:
        raise ValueError(
            f"expected exactly one declaration named {name} in {selected.relative_to(root)}; found {len(declarations)}"
        )
    forge = shutil.which("forge")
    if not forge:
        raise ValueError("forge is not installed or not on PATH; no test was executed")

    relative = selected.relative_to(root).as_posix()
    argv = [
        forge, "test",
        "--match-path", "^" + re.escape(relative) + "$",
        "--match-test", "^" + re.escape(name) + "$",
    ]
    timeout = max(1, min(int(timeout_seconds), 900))
    try:
        completed = subprocess.run(
            argv, cwd=root, capture_output=True, text=True,
            timeout=timeout, stdin=subprocess.DEVNULL, check=False,
        )
        exit_code = int(completed.returncode)
        stdout = str(completed.stdout or "")[-8000:]
        stderr = str(completed.stderr or "")[-8000:]
        # Forge can exit zero when a filter matches no tests.  A process exit
        # code alone is therefore insufficient evidence that this exact test ran.
        combined_output = re.sub(r"\x1b\[[0-9;]*m", "", stdout + "\n" + stderr)
        executed = re.search(
            r"(?m)^\s*\[(PASS|FAIL|SKIP)\]\s+"
            + re.escape(name) + r"\s*\(",
            combined_output,
            re.I,
        )
        if not executed or executed.group(1).upper() == "SKIP":
            status = "not_run"
        elif executed.group(1).upper() == "PASS" and exit_code == 0:
            status = "passed"
        else:
            status = "failed"
    except subprocess.TimeoutExpired as exc:
        exit_code = None
        status = "timeout"
        stdout = str(exc.stdout or "")[-8000:]
        stderr = str(exc.stderr or "")[-8000:]
    except OSError as exc:
        exit_code = None
        status = "error"
        stdout = ""
        stderr = str(exc)

    source_path = Path(str(signal.get("file") or "")).expanduser()
    if not source_path.is_absolute():
        source_path = root / source_path
    source_digest = None
    try:
        resolved_source = source_path.resolve(strict=True)
        resolved_source.relative_to(root)
        source_digest = hashlib.sha256(resolved_source.read_bytes()).hexdigest()
    except (OSError, RuntimeError, ValueError):
        pass
    test_digest = hashlib.sha256(selected.read_bytes()).hexdigest()
    stable = "|".join((str(signal_id), relative, name, test_digest))
    evidence_id = "INSPECTED-TEST-" + hashlib.sha256(stable.encode("utf-8")).hexdigest()[:12].upper()
    evidence = {
        "id": evidence_id,
        "kind": "inspected-native-test-execution",
        "status": status,
        "signal_id": str(signal_id),
        "source_file": signal.get("file"),
        "source_sha256": source_digest,
        "test_file": relative,
        "test_name": name,
        "test_sha256": test_digest,
        "forge_argv": argv,
        "exit_code": exit_code,
        "stdout_tail": stdout,
        "stderr_tail": stderr,
        "security_finding_confirmed": False,
        "human_disposition_changed": False,
        "interpretation": (
            "A passing test only supports its encoded assertion; a failing test needs assertion/impact review. "
            "Neither result automatically confirms or rejects the source finding."
        ),
    }
    attached = audit_context.attach_signal_evidence(str(signal_id), evidence, root)
    return {
        "signal_id": str(signal_id),
        "status": status,
        "test_file": relative,
        "test_name": name,
        "command": argv,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "evidence_id": evidence_id,
        "evidence_attached": attached is not None,
        "security_finding_confirmed": False,
        "human_disposition_changed": False,
    }


def investigate_signal(
    signal_id: str,
    *,
    project_root: str | Path,
    audit_context: Any,
    constructor_args: list[str] | None = None,
) -> dict[str, Any]:
    """Deprecated safe alias for a read-only signal plan.

    This compatibility entrypoint intentionally does not write reports, generate
    Solidity, invoke Forge, or attach disposition-changing evidence. Execution
    is available only through execute_inspected_test with one exact test file
    and function name after the auditor has inspected that test.
    """
    report = plan_signal_investigation(
        signal_id, project_root=project_root, audit_context=audit_context,
    )
    report["compatibility_note"] = (
        "investigate_signal is plan-only. "
        "constructor_args are not execution authorization and are not consumed. "
        "No Solidity test was generated or run."
    )
    report["effects"] = {
        "writes": False,
        "provider_call": False,
        "forge": False,
        "tests_run": False,
        "deployments": False,
        "transactions": False,
        "network": False,
    }
    report["human_disposition_changed"] = False
    return report
