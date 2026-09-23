#!/usr/bin/env python3
"""LowkeyForge: a thin, audit-focused interface over the native Forge CLI."""
from __future__ import annotations
import re
import shutil
import subprocess
import sys
from typing import Iterable, Sequence

NATIVE_COMMANDS = {
    "build", "test", "script", "create", "inspect", "snapshot", "coverage",
    "fmt", "lint", "geiger", "flatten", "verify-contract",
    "verify-check", "verify-bytecode", "tree", "install", "remove", "update",
    "init", "clean", "cache", "config", "remappings", "bind",
    "bind-json", "doc", "compiler", "eip712", "soldeer",
    "completions", "clone", "fuzz", "lsp",
}

def die(message: str, code: int = 2) -> int:
    print(f"LowkeyForge: {message}", file=sys.stderr)
    return code

def forge_path() -> str | None:
    return shutil.which("forge")

def run_forge(args: Sequence[str]) -> int:
    binary = forge_path()
    if not binary:
        return die("forge was not found on PATH. Install Foundry first.")
    try:
        return subprocess.run([binary, *args]).returncode
    except OSError as exc:
        return die(f"could not execute forge: {exc}", 1)

def command_available(command: str) -> bool:
    binary = forge_path()
    if not binary:
        return False
    try:
        return subprocess.run(
            [binary, command, "--help"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
    except OSError:
        return False

def supported_native_commands() -> set[str]:
    return {command for command in NATIVE_COMMANDS if command_available(command)}

def has_verbosity(args: Sequence[str]) -> bool:
    return any(
        arg == "--verbosity"
        or bool(re.fullmatch(r"-v+", arg))
        for arg in args
    )

def run_audit(args: Sequence[str]) -> int:
    checks = "--checks" in args
    forwarded = [a for a in args if a != "--checks"]
    test_cmd = ["test", *forwarded]
    if not has_verbosity(forwarded):
        test_cmd.insert(1, "-vvv")
    steps = [("build", ["build"]), ("tests", test_cmd), ("coverage", ["coverage"])]
    if checks:
        for optional in ("lint", "geiger"):
            if command_available(optional):
                steps.append((optional, [optional]))
            else:
                print(f"LowkeyForge: skipping unavailable command: forge {optional}")
    for label, command in steps:
        print(f"\n=== LOWKEY FORGE: {label.upper()} ===")
        code = run_forge(command)
        if code != 0:
            print(f"\nLowkeyForge: stopped after failed step: forge {' '.join(command)}", file=sys.stderr)
            return code
    print("\nLowkeyForge: audit preflight completed. Review coverage and findings manually.")
    return 0

def run_test_audit(args: Sequence[str]) -> int:
    forwarded = list(args)
    if not has_verbosity(forwarded):
        forwarded.insert(0, "-vvvv")
    return run_forge(["test", *forwarded])

def run_inspect_audit(args: Sequence[str]) -> int:
    if not args:
        return die("usage: lk forge inspect-audit <ContractName> [forge options]")
    contract, extra = args[0], list(args[1:])
    code = run_forge(["build", *extra])
    if code != 0:
        return code
    failures = 0
    for title, field in [
        ("ABI", "abi"), ("METHODS", "methods"), ("ERRORS", "errors"),
        ("EVENTS", "events"), ("STORAGE", "storage-layout")
    ]:
        print(f"\n=== {title} ===")
        code = run_forge(["inspect", contract, field, *extra])
        if code != 0:
            print(f"LowkeyForge: inspect field '{field}' failed; continuing.", file=sys.stderr)
            if failures == 0:
                failures = code
    return failures

def print_help() -> None:
    print("""LowkeyForge - audit-focused interface over native Forge

Usage:
  lk forge <forge-command> [args...]
  lk forge audit [--checks]
  lk forge test-audit [forge test args...]
  lk forge inspect-audit <ContractName> [forge options]

Examples:
  lk forge test -vvvv
  lk forge test-audit --match-test testWithdraw
  lk forge inspect-audit BountyArena
  lk forge audit
  lk forge audit --checks

Native commands are passed through to Forge unchanged.
Audit helpers are workflow shortcuts, not vulnerability scanners.
""")

def main(argv: Iterable[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        print_help()
        return 0
    command, rest = args[0], args[1:]
    if command == "audit":
        return run_audit(rest)
    if command in {"test-audit", "audit-test"}:
        return run_test_audit(rest)
    if command in {"inspect-audit", "recon"}:
        return run_inspect_audit(rest)
    if command in NATIVE_COMMANDS:
        if not command_available(command):
            return die(f"Forge command '{command}' is not supported by the installed Forge.")
        return run_forge(args)
    return die(f"unknown Forge command '{command}'. Use 'lk forge --help'.")

if __name__ == "__main__":
    raise SystemExit(main())
