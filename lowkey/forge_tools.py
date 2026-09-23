#!/usr/bin/env python3
"""LowkeyForge: a thin, audit-focused interface over the native Forge CLI."""
from __future__ import annotations
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))
import audit_context

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
    root = audit_context.foundry_project_root()
    try:
        code = subprocess.run([binary, *args]).returncode
    except OSError as exc:
        audit_context.emit(
            "forge-command",
            root,
            tool="forge",
            status="failed",
            summary=args[0] if args else "forge",
        )
        return die(f"could not execute forge: {exc}", 1)

    audit_context.emit(
        "forge-command",
        root,
        tool="forge",
        status="completed" if code == 0 else "failed",
        summary=f"forge {args[0] if args else ''}".strip(),
        data={"command": args[0] if args else None, "exit_code": code},
    )
    audit_context.record_tool(
        "forge",
        root,
        status="completed" if code == 0 else "failed",
        summary=f"forge {args[0] if args else ''}".strip(),
        data={"last_command": args[0] if args else None, "last_exit_code": code},
    )
    return code

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


LOWKEY_GENERATED_PATH_MARKERS = (
    "test/Lowkey_",
    "script/Lowkey_",
)


def _filter_generated_diagnostics(output: str) -> tuple[str, int]:
    """Hide lint diagnostics emitted only by Lowkey-generated helper artifacts."""
    text = str(output or "")
    if not text.strip():
        return "", 0
    blocks = re.split(r"\n\s*\n", text)
    kept = []
    filtered = 0
    for block in blocks:
        if any(marker in block for marker in LOWKEY_GENERATED_PATH_MARKERS):
            filtered += len(re.findall(r"(?m)^\s*note\[", block)) or 1
            continue
        kept.append(block)
    return "\n\n".join(kept).strip(), filtered


def run_forge_diagnostics(args: Sequence[str], label: str) -> int:
    """Run Forge diagnostics and keep Lowkey-generated helper noise out of lk audit."""
    binary = forge_path()
    root = audit_context.foundry_project_root()
    if not binary:
        return die("forge was not found on PATH. Install Foundry first.")
    try:
        result = subprocess.run([binary, *args], cwd=root, capture_output=True, text=True)
    except OSError as exc:
        return die(f"could not execute forge: {exc}", 1)
    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
    visible, filtered = _filter_generated_diagnostics(combined)
    if visible:
        print(visible)
    if filtered:
        print(f"LowkeyForge: filtered {filtered} diagnostic(s) from Lowkey-generated helper files; use 'lk forge {label}' to see them.")
    status = "completed" if result.returncode == 0 else "failed"
    audit_context.emit("forge-command", root, tool="forge", status=status,
                       summary=f"forge {label}",
                       data={"command": label, "exit_code": result.returncode, "filtered": filtered})
    audit_context.record_tool(f"forge-{label}", root, status=status,
                              summary=f"forge {label}",
                              data={"exit_code": result.returncode, "filtered": filtered})
    return result.returncode


def run_slither_preflight(root: Path) -> int:
    helper = Path(__file__).with_name("slither_tools.py")
    binary = shutil.which("slither")

    if not binary:
        print("LowkeyForge: skipping Slither (not found on PATH).")
        audit_context.record_tool(
            "slither",
            root,
            status="skipped",
            summary="Slither is not installed",
            data={"available": False},
        )
        return 0

    if helper.is_file():
        try:
            code = subprocess.run(
                [sys.executable, str(helper)],
                cwd=root,
            ).returncode
            return code
        except OSError as exc:
            print(f"LowkeyForge: could not execute Lowkey Slither reporter: {exc}", file=sys.stderr)
            return 1

    # Fallback for unusual installations where the companion reporter is absent.
    print("\n=== LOWKEY STATIC: SLITHER ===")
    command = [binary, str(root), "--exclude-dependencies", "--disable-color", "--fail-none"]
    try:
        return subprocess.run(command, cwd=root).returncode
    except OSError as exc:
        print(f"LowkeyForge: could not execute Slither: {exc}", file=sys.stderr)
        return 1


def _has_path_filter(args: Sequence[str]) -> bool:
    return any(arg in {"--match-path", "--no-match-path"} for arg in args)


def _supports_option(command: str, option: str) -> bool:
    binary = forge_path()
    if not binary:
        return False
    try:
        result = subprocess.run([binary, command, "--help"], capture_output=True, text=True)
    except OSError:
        return False
    return option in ((result.stdout or "") + (result.stderr or ""))



def _profile_from_args(args: Sequence[str]) -> str | None:
    """Return an explicitly selected Foundry profile, when present."""
    for index, arg in enumerate(args):
        if arg == "--profile" and index + 1 < len(args):
            return str(args[index + 1])
        if arg.startswith("--profile="):
            return arg.split("=", 1)[1]
    return None


def _resolved_forge_config(root: Path, args: Sequence[str] = ()) -> dict:
    """Read Forge's effective configuration instead of guessing from foundry.toml."""
    binary = forge_path()
    if not binary:
        return {}

    command = [binary, "config", "--json"]
    profile = _profile_from_args(args)
    if profile:
        command.extend(["--profile", profile])

    try:
        result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    except OSError:
        return {}
    if result.returncode != 0:
        return {}

    try:
        payload = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _has_flag(args: Sequence[str], *names: str) -> bool:
    return any(
        arg in names or any(arg.startswith(name + "=") for name in names)
        for arg in args
    )


def _coverage_needs_ir(root: Path, args: Sequence[str]) -> bool:
    """Detect whether the effective project config relies on via-IR."""
    config = _resolved_forge_config(root, args)
    return bool(config.get("via_ir"))


def _coverage_compatibility_flags(root: Path, args: Sequence[str]) -> list[str]:
    """Add coverage-only compiler compatibility flags without editing project config."""
    if _has_flag(args, "--ir-minimum", "--via-ir"):
        return []
    if not _coverage_needs_ir(root, args):
        return []
    if not _supports_option("coverage", "--ir-minimum"):
        print(
            "LowkeyForge: project uses via-IR, but this Forge does not expose "
            "coverage --ir-minimum; coverage may use an incompatible compiler mode.",
            file=sys.stderr,
        )
        return []

    print(
        "LowkeyForge: detected via_ir=true in the effective Foundry config; "
        "using forge coverage --ir-minimum to match the project's compiler constraints."
    )
    return ["--ir-minimum"]


def _is_stack_too_deep(output: str) -> bool:
    text = str(output or "").lower()
    return "stack too deep" in text or "stack-too-deep" in text


def run_coverage_audit(command: Sequence[str], root: Path) -> int:
    """Run coverage and retry once with IR minimum when coverage hits stack-too-deep."""
    binary = forge_path()
    if not binary:
        return die("forge was not found on PATH. Install Foundry first.")

    def execute(current: Sequence[str]):
        try:
            result = subprocess.run(
                [binary, *current],
                cwd=root,
                text=True,
                capture_output=True,
            )
        except OSError as exc:
            return None, str(exc)

        combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
        if result.stdout:
            print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
        if result.stderr:
            print(
                result.stderr,
                file=sys.stderr,
                end="" if result.stderr.endswith("\n") else "\n",
            )
        return result, combined

    result, output = execute(command)
    if result is None:
        return die(f"could not execute forge coverage: {output}", 1)

    attempts = 1
    if (
        result.returncode != 0
        and _is_stack_too_deep(output)
        and not _has_flag(command, "--ir-minimum", "--via-ir")
    ):
        if _supports_option("coverage", "--ir-minimum"):
            retry = [*command, "--ir-minimum"]
            attempts = 2
            print(
                "LowkeyForge: coverage compilation hit stack too deep; retrying once "
                "with --ir-minimum without modifying the project's foundry.toml."
            )
            result, retry_output = execute(retry)
            if result is None:
                return die(f"could not execute forge coverage retry: {retry_output}", 1)
        else:
            print(
                "LowkeyForge: coverage hit stack too deep, but this Forge does not "
                "support --ir-minimum; leaving coverage failed.",
                file=sys.stderr,
            )

    status = "completed" if result.returncode == 0 else "failed"
    audit_context.emit(
        "forge-command",
        root,
        tool="forge",
        status=status,
        summary="forge coverage",
        data={
            "command": "coverage",
            "exit_code": result.returncode,
            "attempts": attempts,
        },
    )
    audit_context.record_tool(
        "forge-coverage",
        root,
        status=status,
        summary=f"forge coverage ({attempts} attempt{'s' if attempts != 1 else ''})",
        data={"exit_code": result.returncode, "attempts": attempts},
    )
    return result.returncode


def _project_owned_tests(root: Path) -> list[Path]:
    test_root = root / "test"
    if not test_root.is_dir():
        return []
    return [path for path in test_root.rglob("*.t.sol") if not path.name.startswith("Lowkey_")]


def run_audit(args: Sequence[str]) -> int:
    root = Path.cwd().resolve()
    checks = "--checks" in args
    forwarded = [a for a in args if a != "--checks"]
    test_cmd = ["test", *forwarded]
    if not has_verbosity(forwarded):
        test_cmd.insert(1, "-vvv")
    if not _has_path_filter(forwarded):
        test_cmd.extend(["--no-match-path", "test/Lowkey_*"])

    coverage_cmd = ["coverage", *forwarded]
    coverage_cmd.extend(_coverage_compatibility_flags(root, forwarded))
    if not _has_path_filter(forwarded) and _supports_option("coverage", "--no-match-path"):
        coverage_cmd.extend([
            "--no-match-path", "test/Lowkey_*",
            "--no-match-path", "script/Lowkey_*",
        ])

    steps = [("build", ["build", "--skip", "test", "--skip", "script"])]
    if checks:
        steps.append(("slither", None))
        for optional in ("lint", "geiger"):
            if command_available(optional):
                steps.append((optional, None))
            else:
                print(f"LowkeyForge: skipping unavailable command: forge {optional}")
    steps.extend([("tests", test_cmd), ("coverage", coverage_cmd)])

    if not _project_owned_tests(root):
        print("LowkeyForge: no project-owned Forge tests found; Lowkey-generated experiments are excluded from the audit suite.")

    for label, command in steps:
        print(f"\n=== LOWKEY {'STATIC' if label == 'slither' else 'FORGE'}: {label.upper()} ===")
        if label == "slither":
            code = run_slither_preflight(root)
        elif label in {"lint", "geiger"}:
            code = run_forge_diagnostics([label], label)
        elif label == "coverage":
            code = run_coverage_audit(command, root)
        else:
            code = run_forge(command)
        if code != 0:
            print(f"\nLowkeyForge: stopped after failed step: forge {label}", file=sys.stderr)
            return code
    print("\nLowkeyForge: audit preflight completed. Generated Lowkey experiments stay available through lk probe/lk changes/lk generate.")
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
