#!/usr/bin/env python3
"""Exercise Lowkey's complete registered command-help surface safely.

The command list is derived from COMMAND_HELP and HELP_ALIASES in the checked-out
Lowkey source, not from a hard-coded command inventory. Only --help requests
are invoked. Each invocation runs under an isolated HOME supplied by CI.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
HELP_FLAGS = {"-h", "--h", "--help", "help"}


def _string_keys(node: ast.Dict) -> list[str]:
    result = []
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            result.append(key.value)
    return result


def registered_commands(source_path: pathlib.Path) -> tuple[list[str], dict[str, str]]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    canonical: set[str] = set()
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if "COMMAND_HELP" in targets and isinstance(node.value, ast.Dict):
                canonical.update(_string_keys(node.value))
            if "HELP_ALIASES" in targets and isinstance(node.value, ast.Dict):
                for key, value in zip(node.value.keys, node.value.values):
                    if (
                        isinstance(key, ast.Constant) and isinstance(key.value, str)
                        and isinstance(value, ast.Constant) and isinstance(value.value, str)
                    ):
                        aliases[key.value] = value.value
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if (
                isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "COMMAND_HELP"
                and call.func.attr == "update"
                and call.args and isinstance(call.args[0], ast.Dict)
            ):
                canonical.update(_string_keys(call.args[0]))

    if not canonical:
        raise RuntimeError("Could not derive COMMAND_HELP entries from lowkey/lk.py.")
    if not aliases:
        raise RuntimeError("Could not derive HELP_ALIASES entries from lowkey/lk.py.")
    return sorted(canonical), aliases


def run_help(executable: str, command: str, env: dict[str, str], timeout: float) -> dict:
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]*", command):
        return {"command": command, "status": "INVALID_REGISTRY_KEY"}
    process = subprocess.Popen(
        [executable, command, "--help"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    started = time.monotonic()
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        duration = time.monotonic() - started
        return {
            "command": command,
            "status": "PASS" if process.returncode == 0 and (stdout.strip() or stderr.strip()) else "FAILED",
            "exit_code": process.returncode,
            "duration_seconds": round(duration, 3),
            "output_bytes": len(stdout.encode("utf-8")) + len(stderr.encode("utf-8")),
            "stdout_tail": stdout[-600:],
            "stderr_tail": stderr[-600:],
        }
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
        return {
            "command": command,
            "status": "TIMEOUT",
            "duration_seconds": round(time.monotonic() - started, 3),
            "stdout_tail": stdout[-600:],
            "stderr_tail": stderr[-600:],
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lk", default=os.environ.get("LOWKEY_BIN") or shutil.which("lk"))
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()
    if not args.lk:
        parser.error("Provide --lk or place the installed lk executable on PATH.")
    executable = str(pathlib.Path(args.lk).expanduser().resolve())
    if not pathlib.Path(executable).is_file():
        parser.error(f"Lowkey executable does not exist: {executable}")
    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be between 0 and 30 seconds.")

    canonical, aliases = registered_commands(ROOT / "lowkey" / "lk.py")
    commands = sorted(set(canonical) | set(aliases))
    env = os.environ.copy()
    env["BROWSER"] = "true"
    env["LOWKEY_DISABLE_AUTO_GUIDANCE"] = "1"
    results = [run_help(executable, command, env, args.timeout) for command in commands]
    failures = [item for item in results if item["status"] != "PASS"]
    report = {
        "canonical_help_keys": len(canonical),
        "aliases": len(aliases),
        "unique_invocations": len(commands),
        "passed": len(results) - len(failures),
        "failed": len(failures),
        "results": results,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        destination = args.output.expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered + "\n", encoding="utf-8")
    print(
        "LOWKEY COMMAND HELP MATRIX: "
        f"{report['passed']}/{report['unique_invocations']} passed "
        f"({report['canonical_help_keys']} registered commands, "
        f"{report['aliases']} aliases)"
    )
    for item in failures:
        print(
            f"  {item['status']}: lk {item['command']} --help "
            f"(exit={item.get('exit_code', 'n/a')}, "
            f"{item.get('duration_seconds', 0):.2f}s)"
        )
        detail = item.get("stderr_tail") or item.get("stdout_tail") or ""
        if detail:
            print("    " + detail.strip().replace("\n", "\n    "))
    if args.output:
        print(f"DETAILS  {args.output}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
