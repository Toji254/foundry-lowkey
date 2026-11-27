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


def launcher_commands(launcher_path: pathlib.Path) -> list[str]:
    """Extract first-argument routes from the installed shell launcher."""
    text = launcher_path.read_text(encoding="utf-8")
    commands: set[str] = set()
    commands.update(re.findall(
        r'\[\[\s*"\$\{1:-\}"\s*==\s*"([A-Za-z0-9][A-Za-z0-9_-]*)"',
        text,
    ))
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.fullmatch(r'\s*case\s*"\$\{1:-\}"\s+in\s*', line):
            continue
        depth = 1
        for nested_line in lines[index + 1:]:
            candidate = nested_line.split("#", 1)[0].strip()
            if re.match(r"^case\b.*\bin\s*$", candidate):
                depth += 1
                continue
            if re.fullmatch(r"esac", candidate):
                depth -= 1
                if depth == 0:
                    break
                continue
            if depth != 1:
                continue
            labels = re.fullmatch(r"([A-Za-z0-9_-]+(?:\|[A-Za-z0-9_-]+)*)\)", candidate)
            if labels:
                commands.update(labels.group(1).split("|"))
    return sorted(
        command for command in commands
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", command)
    )


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
    launcher = launcher_commands(ROOT / "bin" / "lk")
    commands = sorted(set(canonical) | set(aliases) | set(launcher))
    env = os.environ.copy()
    root_help = subprocess.run(
        [executable, "--help"], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        timeout=args.timeout, check=False,
    )
    if root_help.returncode != 0 or not root_help.stdout.strip():
        raise AssertionError(
            "Installed lk --help failed: "
            + root_help.stderr[-2000:] + root_help.stdout[-2000:]
        )
    env["BROWSER"] = "true"
    env["LOWKEY_DISABLE_AUTO_GUIDANCE"] = "1"
    results = [run_help(executable, command, env, args.timeout) for command in commands]
    failures = [item for item in results if item["status"] != "PASS"]
    report = {
        "canonical_help_keys": len(canonical),
        "aliases": len(aliases),
        "launcher_routes": len(launcher),
        "root_help_exit_code": root_help.returncode,
        "root_help_output_bytes": len(root_help.stdout.encode("utf-8")),
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
        f"{report['aliases']} aliases, {report['launcher_routes']} launcher routes)"
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
