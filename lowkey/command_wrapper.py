#!/usr/bin/env python3
"""Run a dedicated Lowkey CLI route and publish a sanitized completion event.

The primary lk.py dispatcher records its own completions. This wrapper covers
specialized modules launched directly by bin/lk, preserving child output and
exit status while sharing the project's append-only audit event journal.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable

try:
    import audit_context
    import shared_context
    import capability_registry
    import error_context
    import error_advisor
except ImportError:
    from lowkey import (
        audit_context, shared_context, capability_registry,
        error_context, error_advisor,
    )


HELP_FLAGS = {"-h", "--h", "--help", "help"}
RPC_CONTEXT_COMMANDS = capability_registry.RPC_CONTEXT_COMMANDS


def _load_global_config() -> dict:
    path = Path.home() / ".lowkey" / "config.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _has_explicit_rpc(command: list[str]) -> bool:
    for index, raw in enumerate(command):
        token = str(raw)
        if token == "--rpc-url" and index + 1 < len(command):
            return True
        if token.startswith("--rpc-url="):
            return True
    return False


def _explicit_root(command: list[str]) -> str | None:
    for index, raw in enumerate(command):
        token = str(raw)
        if token == "--root" and index + 1 < len(command):
            return str(command[index + 1])
        if token.startswith("--root="):
            return token.split("=", 1)[1]
    return None


def _project_rpc_environment(command_name: str, command: list[str]) -> dict[str, str] | None:
    """Apply project-owned RPC defaults to RPC-aware child routes only.

    An explicit --rpc-url remains authoritative. The inherited process
    environment is not mutated; project RPC values exist only in the child.
    """
    if command_name not in RPC_CONTEXT_COMMANDS or _has_explicit_rpc(command):
        return None
    try:
        explicit_root = _explicit_root(command)
        root = audit_context.foundry_project_root(explicit_root) if explicit_root else audit_context.foundry_project_root()
        state = audit_context.load(root)
        resolved = shared_context.resolve_runtime_context(
            root,
            state,
            _load_global_config(),
            allow_legacy_target=True,
            environ={},
        )
        selected_rpc = resolved.get("rpc")
        if not isinstance(selected_rpc, str) or not selected_rpc.strip():
            return None
        child_env = os.environ.copy()
        selected_rpc = selected_rpc.strip()
        child_env["FOUNDRY_ETH_RPC_URL"] = selected_rpc
        child_env["ETH_RPC_URL"] = selected_rpc
        child_env["LOWKEY_RPC_URL"] = selected_rpc
        return child_env
    except Exception:
        # A context lookup must never make an otherwise valid specialized
        # command unusable. Native parsing and explicit options still apply.
        return None


def _record_completion(command_name: str, exit_code: int, root=None) -> None:
    try:
        project_root = root if root is not None else audit_context.foundry_project_root()
        status = "completed" if exit_code == 0 else "failed"
        audit_context.emit(
            "command-completed",
            project_root,
            tool="cli",
            status=status,
            summary=f"{command_name} {status}",
            data={"command": command_name, "exit_code": exit_code},
        )
    except Exception:
        return


def _project_root_for_command(command: list[str], *, fallback_to_cwd: bool = False):
    """Resolve an explicit/project root without making native commands depend on it."""
    try:
        root_hint = _explicit_root(command)
        return audit_context.foundry_project_root(root_hint) if root_hint else audit_context.foundry_project_root()
    except Exception:
        return Path.cwd() if fallback_to_cwd else None


def _automatic_error_explanations_enabled() -> bool:
    try:
        return bool(error_context.auto_error_explain_enabled())
    except Exception:
        return False


def _is_manual_error_explainer(command_name: str, command: list[str]) -> bool:
    return command_name == "ai" and "explain-error" in [str(value) for value in command[1:4]]


def _record_and_explain_failure(
    command_name: str,
    command: list[str],
    output: str,
    exit_code: int,
    *,
    explain: bool = True,
) -> None:
    """Save a redacted failure and optionally explain it; never affect native status."""
    diagnostic = error_context.redact(
        output or f"The command exited with status {exit_code} and produced no captured output.",
        limit=6000,
    )
    root = _project_root_for_command(command, fallback_to_cwd=True)
    safe_command = ["lk", command_name]
    try:
        record = error_context.record_last_error(
            command=safe_command,
            error=diagnostic,
            exit_code=exit_code,
            project_root=str(root) if root else None,
            source="command-wrapper",
        )
    except Exception:
        # Still make a best-effort diagnosis from the in-memory redacted record.
        record = {
            "command": " ".join(safe_command),
            "error": diagnostic,
            "exit_code": exit_code,
            "project_label": Path(root).name if root else None,
            "project_root": str(root) if root else None,
        }
    try:
        error_context.record_command_event(
            project_root=root,
            command=safe_command,
            exit_code=exit_code,
            output=diagnostic,
            source="command-wrapper",
        )
    except Exception:
        pass
    if not explain:
        return
    try:
        suggestion = error_advisor.maybe_auto_explain(record)
    except Exception as exc:
        suggestion = (
            "Optional AI error explanation unavailable ("
            + type(exc).__name__
            + "). Run 'lk ai explain-error --last' after fixing the provider."
        )
    if suggestion:
        sys.stderr.write("\n" + str(suggestion).rstrip() + "\n")
        sys.stderr.flush()


def run_command(
    command_name: str,
    command: list[str],
    *,
    skip_exit_codes: Iterable[int] = (),
) -> int:
    name = str(command_name or "unknown").strip().lower()[:64] or "unknown"
    if not command:
        return 127
    skip_codes = set(skip_exit_codes)
    help_only = any(str(value).strip().lower() in HELP_FLAGS for value in command[1:])
    child_env = _project_rpc_environment(name, command)

    repair_capture = False
    try:
        import test_repair
        repair_capture = (not help_only and test_repair.should_capture(name, command[1:]))
    except Exception:
        repair_capture = False

    # The error-explanation setting is independent of the guide/lazy repair
    # setting. Capture every dedicated route when it is enabled, not only the
    # small set of commands supported by test_repair.
    auto_error_capture = (
        not help_only
        and not _is_manual_error_explainer(name, command)
        and _automatic_error_explanations_enabled()
    )
    capture_output = repair_capture or auto_error_capture
    captured_out = ""
    captured_err = ""
    failure_output = ""
    repair_handled = False
    status = 1

    try:
        kwargs = {"check": False}
        if child_env is not None:
            kwargs["env"] = child_env
        if capture_output:
            kwargs.update({"capture_output": True, "text": True})
        result = subprocess.run(command, **kwargs)
        status = result.returncode if isinstance(result.returncode, int) else 1
        if status < 0:
            status = 128 + abs(status)

        if capture_output:
            captured_out = str(getattr(result, "stdout", "") or "")
            captured_err = str(getattr(result, "stderr", "") or "")
            if captured_out:
                sys.stdout.write(captured_out)
                sys.stdout.flush()
            if captured_err:
                sys.stderr.write(captured_err)
                sys.stderr.flush()
            failure_output = captured_out + "\n" + captured_err

        if repair_capture and status != 0 and status not in skip_codes:
            try:
                root = _project_root_for_command(command, fallback_to_cwd=True)
                status, repair_handled = test_repair.handle_failure(
                    name, command[1:], failure_output, status, root,
                )
            except Exception:
                repair_handled = False
    except KeyboardInterrupt:
        status = 130
    except FileNotFoundError as exc:
        failure_output = f"Lowkey: executable not found: {exc.filename or command[0]}"
        print(failure_output, file=sys.stderr)
        status = 127
    except OSError as exc:
        failure_output = f"Lowkey: could not execute {command[0]}: {exc}"
        print(failure_output, file=sys.stderr)
        status = 126

    # A routed native command can fail after its own parser or domain-specific
    # checks (for example, lk control). Explain the actual output after it has
    # been shown, while keeping its original exit code and side effects unchanged.
    if auto_error_capture and status != 0 and status not in skip_codes:
        _record_and_explain_failure(
            name,
            command,
            failure_output or captured_out + "\n" + captured_err,
            status,
            explain=not repair_handled,
        )

    if not help_only and status not in skip_codes:
        event_root = _project_root_for_command(command)
        _record_completion(name, status, root=event_root)
    return status

def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if not values:
        print("Usage: command_wrapper.py COMMAND [--skip-status CODE] -- EXECUTABLE [ARGS...]", file=sys.stderr)
        return 2
    command_name = values.pop(0)
    skip_codes: set[int] = set()
    while values and values[0] != "--":
        option = values.pop(0)
        if option != "--skip-status" or not values:
            print(f"Lowkey: unknown command-wrapper option: {option}", file=sys.stderr)
            return 2
        try:
            skip_codes.add(int(values.pop(0)))
        except ValueError:
            print("Lowkey: --skip-status requires an integer.", file=sys.stderr)
            return 2
    if not values or values.pop(0) != "--" or not values:
        print("Usage: command_wrapper.py COMMAND [--skip-status CODE] -- EXECUTABLE [ARGS...]", file=sys.stderr)
        return 2
    return run_command(command_name, values, skip_exit_codes=skip_codes)


if __name__ == "__main__":
    raise SystemExit(main())
