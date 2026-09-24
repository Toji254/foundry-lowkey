#!/usr/bin/env python3
"""LowkeyForge: a thin, audit-focused interface over the native Forge CLI."""
from __future__ import annotations
import shutil
import subprocess
import sys
from typing import Iterable, Sequence

try:
    from audit_engine import run_slither
except ImportError:
    run_slither = None

try:
    from clone_tools import run_clone
except ImportError:
    run_clone = None

try:
    import system_model
except ImportError:
    system_model = None

NATIVE_COMMANDS = {
    "build", "test", "script", "create", "inspect", "snapshot", "coverage",
    "fmt", "lint", "geiger", "flatten", "verify-contract",
    "verify-check", "verify-bytecode", "tree", "install", "remove", "update",
    "init", "clean", "cache", "config", "remappings", "bind",
    "bind-json", "doc", "compiler", "eip712", "soldeer",
    "completions", "fuzz", "lsp",
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

def _refresh_system_manifest(reason: str) -> None:
    if system_model is None:
        return
    try:
        config = {}
        if isinstance(getattr(system_model, "_config", None), type(lambda: None)):
            config = system_model._config()
        system_model.refresh_manifest(
            ".",
            rpc=config.get("rpc"),
            config=config,
            reason=reason,
        )
    except Exception:
        # Deployment evidence enrichment must never mask the real Forge result.
        pass

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

def run_audit(args: Sequence[str]) -> int:
    checks = "--checks" in args
    forwarded = [a for a in args if a != "--checks"]
    test_cmd = ["test", *forwarded]
    if not any(a.startswith("-v") for a in forwarded):
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
    print("\n=== LOWKEY FORGE: SLITHER ===")
    if run_slither is None:
        print("LowkeyForge: Slither integration module is not installed.")
    else:
        slither_code = run_slither(".")
        if slither_code == 127:
            print("LowkeyForge: Slither unavailable; continuing without static analysis.")
        elif slither_code != 0:
            print("LowkeyForge: Slither returned a non-zero status; inspect .audit/evidence/slither.json.", file=sys.stderr)
    print("\nLowkeyForge: audit preflight completed. Review evidence and findings manually.")
    return 0

def run_test_audit(args: Sequence[str]) -> int:
    forwarded = list(args)
    if not any(a.startswith("-v") for a in forwarded):
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
  lk clone <repo-url> [directory] [options]

Native Forge commands are passed through unchanged. `lk clone` uses Lowkey's
fast, shallow, parallel, cache-aware project onboarding.
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
    if command == "clone":
        if run_clone is None:
            return die("Lowkey clone integration is not installed. Reinstall Lowkey.")
        return run_clone(rest)
    if command in {"test-audit", "audit-test"}:
        return run_test_audit(rest)
    if command in {"inspect-audit", "recon"}:
        return run_inspect_audit(rest)
    if command in NATIVE_COMMANDS:
        if not command_available(command):
            return die(f"Forge command '{command}' is not supported by the installed Forge.")
        code = run_forge(args)
        if code == 0 and command in {"script", "create"}:
            _refresh_system_manifest(f"forge:{command}")
        return code
    return die(f"unknown Forge command '{command}'. Use 'lk forge --help'.")

if __name__ == "__main__":
    raise SystemExit(main())
