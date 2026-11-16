#!/usr/bin/env python3
"""Run a dedicated Lowkey CLI route and publish a sanitized completion event.

The primary lk.py dispatcher records its own completions. This wrapper covers
specialized modules launched directly by bin/lk, preserving child output and
exit status while sharing the project's append-only audit event journal.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Iterable

try:
    import audit_context
except ImportError:
    from lowkey import audit_context


HELP_FLAGS = {"-h", "--h", "--help", "help"}


def _record_completion(command_name: str, exit_code: int) -> None:
    try:
        root = audit_context.foundry_project_root()
        status = "completed" if exit_code == 0 else "failed"
        audit_context.emit(
            "command-completed",
            root,
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
    try:
        result = subprocess.run(command, check=False)
        status = result.returncode if isinstance(result.returncode, int) else 1
        if status < 0:
            status = 128 + abs(status)
    except KeyboardInterrupt:
        status = 130
    except FileNotFoundError as exc:
        print(f"Lowkey: executable not found: {exc.filename or command[0]}", file=sys.stderr)
        status = 127
    except OSError as exc:
        print(f"Lowkey: could not execute {command[0]}: {exc}", file=sys.stderr)
        status = 126
    if not help_only and status not in set(skip_exit_codes):
        _record_completion(name, status)
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
