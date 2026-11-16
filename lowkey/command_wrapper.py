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
except ImportError:
    from lowkey import audit_context, shared_context, capability_registry


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


def run_command(
    command_name: str,
    command: list[str],
    *,
    skip_exit_codes: Iterable[int] = (),
) -> int:
    name = str(command_name or "unknown").strip().lower()[:64] or "unknown"
    if not command:
        return 127
    help_only = any(str(value).strip().lower() in HELP_FLAGS for value in command[1:])
    child_env = _project_rpc_environment(name, command)
    repair_capture = False
    try:
        import test_repair
        repair_capture = (not help_only and test_repair.should_capture(name, command[1:]))
    except Exception:
        repair_capture = False
    try:
        kwargs = {"check": False}
        if child_env is not None:
            kwargs["env"] = child_env
        if repair_capture:
            kwargs.update({"capture_output": True, "text": True})
        result = subprocess.run(command, **kwargs)
        status = result.returncode if isinstance(result.returncode, int) else 1
        if status < 0:
            status = 128 + abs(status)
        if repair_capture:
            captured_out = str(getattr(result, "stdout", "") or "")
            captured_err = str(getattr(result, "stderr", "") or "")
            if captured_out:
                sys.stdout.write(captured_out)
                sys.stdout.flush()
            if captured_err:
                sys.stderr.write(captured_err)
                sys.stderr.flush()
            if status != 0 and status not in set(skip_exit_codes):
                try:
                    root_hint = _explicit_root(command)
                    project_root = audit_context.foundry_project_root(root_hint) if root_hint else audit_context.foundry_project_root()
                    status, _ = test_repair.handle_failure(
                        name, command[1:], captured_out + "\n" + captured_err,
                        status, project_root,
                    )
                except Exception:
                    pass
    except KeyboardInterrupt:
        status = 130
    except FileNotFoundError as exc:
        print(f"Lowkey: executable not found: {exc.filename or command[0]}", file=sys.stderr)
        status = 127
    except OSError as exc:
        print(f"Lowkey: could not execute {command[0]}: {exc}", file=sys.stderr)
        status = 126
    if not help_only and status not in set(skip_exit_codes):
        explicit_root = _explicit_root(command)
        event_root = (
            audit_context.foundry_project_root(explicit_root)
            if explicit_root
            else None
        )
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
