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

def run_forge(args: Sequence[str], quiet: bool = False) -> int:
    """Run Forge, optionally hiding successful command output for compound audits."""
    binary = forge_path()
    if not binary:
        return die("forge was not found on PATH. Install Foundry first.")
    root = audit_context.foundry_project_root()
    try:
        if quiet:
            result = subprocess.run([binary, *args], cwd=root, capture_output=True, text=True)
            code = result.returncode
            if code != 0:
                combined = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
                if combined:
                    print(
                        f"\nForge {args[0] if args else 'command'} failed:\n"
                        + "\n".join(combined.splitlines()[-24:]),
                        file=sys.stderr,
                    )
        else:
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


def run_forge_diagnostics(args: Sequence[str], label: str, quiet: bool = False) -> int:
    """Run Forge diagnostics and optionally hide successful raw output."""
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
    if visible and (not quiet or result.returncode != 0):
        print(visible, file=sys.stderr if result.returncode != 0 else sys.stdout)
    if filtered and not quiet:
        print(f"LowkeyForge: filtered {filtered} diagnostic(s) from Lowkey-generated helper files; use 'lk forge {label}' to see them.")
    status = "completed" if result.returncode == 0 else "failed"
    audit_context.emit("forge-command", root, tool="forge", status=status, summary=f"forge {label}", data={"command":label,"exit_code":result.returncode,"filtered":filtered})
    audit_context.record_tool(f"forge-{label}", root, status=status, summary=f"forge {label}", data={"exit_code":result.returncode,"filtered":filtered})
    return result.returncode
def run_slither_preflight(root: Path, quiet: bool = False) -> int:
    helper = Path(__file__).with_name("slither_tools.py")
    binary = shutil.which("slither")

    if not binary:
        if not quiet:
            print("LowkeyForge: skipping Slither (not found on PATH).")
        audit_context.record_tool(
            "slither", root, status="skipped",
            summary="Slither is not installed", data={"available": False},
        )
        return 0

    if helper.is_file():
        try:
            command = [sys.executable, str(helper)]
            if quiet:
                command.append("--quiet")
            return subprocess.run(command, cwd=root).returncode
        except OSError as exc:
            print(f"LowkeyForge: could not execute Lowkey Slither reporter: {exc}", file=sys.stderr)
            return 1

    # Fallback for unusual installations where the companion reporter is absent.
    command = [binary, str(root), "--exclude-dependencies", "--disable-color", "--fail-none"]
    try:
        if quiet:
            result = subprocess.run(command, cwd=root, capture_output=True, text=True)
            if result.returncode != 0 and result.stderr:
                print(result.stderr.rstrip(), file=sys.stderr)
            return result.returncode
        print("\n=== LOWKEY STATIC: SLITHER ===")
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


def _coverage_compatibility_flags(root: Path, args: Sequence[str], quiet: bool = False) -> list[str]:
    """Add coverage-only compiler compatibility flags without editing project config."""
    if _has_flag(args, "--ir-minimum", "--via-ir", "--no-via-ir"):
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

    if not quiet:
        print(
            "LowkeyForge: detected via_ir=true in the effective Foundry config; "
            "using forge coverage --ir-minimum to match the project's compiler constraints."
        )
    return ["--ir-minimum"]


def _is_stack_too_deep(output: str) -> bool:
    text = str(output or "").lower()
    return "stack too deep" in text or "stack-too-deep" in text



def _parse_coverage_metric(cell: str) -> tuple[str, int, int] | None:
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)%\s*\(\s*(\d+)\s*/\s*(\d+)\s*\)\s*", cell)
    if not match:
        return None
    return match.group(1), int(match.group(2)), int(match.group(3))


def _parse_coverage_table(output: str) -> list[dict[str, object]]:
    """Extract Foundry coverage rows so Lowkey can render a clearer audit summary."""
    rows: list[dict[str, object]] = []
    in_table = False
    for line in str(output or "").splitlines():
        stripped = line.strip()
        if stripped.startswith("| File") and "% Lines" in stripped and "% Statements" in stripped:
            in_table = True
            continue
        if not in_table:
            continue
        if stripped.startswith(("+", "╭", "╰", "├", "-")):
            continue
        if not stripped.startswith("|"):
            if stripped:
                break
            continue

        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 5:
            continue
        name = cells[0]
        metrics = {}
        for key, cell in zip(("lines", "statements", "branches", "functions"), cells[1:5]):
            metrics[key] = _parse_coverage_metric(cell)
        if name and any(value is not None for value in metrics.values()):
            rows.append({"file": name, **metrics})
    return rows


def _coverage_gap(metric: tuple[str, int, int] | None) -> str:
    if metric is None:
        return "N/A"
    _, covered, total = metric
    return str(max(total - covered, 0))


def _coverage_cell(metric: tuple[str, int, int] | None) -> str:
    if metric is None:
        return "—"
    percent, covered, total = metric
    return f"{covered}/{total} ({percent}%)"


def _coverage_uncovered(metric: tuple[str, int, int] | None) -> str:
    if metric is None:
        return "—"
    _, covered, total = metric
    return str(max(total - covered, 0))


def _format_coverage_report(output: str) -> str:
    """Render Foundry coverage as a readable table without hiding coverage data."""
    rows = _parse_coverage_table(output)
    if not rows:
        return ""

    lines = [
        "\nCOVERAGE TABLE",
        "==============",
        "What this means:",
        "  Lines      = source-code lines executed by tests",
        "  Statements = executable statements executed by tests",
        "  Branches   = decision paths exercised by tests",
        "  Functions  = functions reached by tests",
        "  Each cell is: tested / total (percentage). 'Not exercised' shows the gap.",
        "",
    ]

    widths = {
        "file": 44,
        "lines": 18,
        "statements": 22,
        "branches": 19,
        "functions": 19,
        "gap": 26,
    }
    header = (
        f"{'File':<{widths['file']}} "
        f"{'Lines':>{widths['lines']}} "
        f"{'Statements':>{widths['statements']}} "
        f"{'Branches':>{widths['branches']}} "
        f"{'Functions':>{widths['functions']}} "
        f"{'Not exercised (L/S/B/F)':>{widths['gap']}}"
    )
    separator = "-" * (
        widths["file"] + widths["lines"] + widths["statements"] +
        widths["branches"] + widths["functions"] + widths["gap"] + 5
    )
    lines.extend([header, separator])

    for row in rows:
        cells = {
            "lines": _coverage_cell(row["lines"]),
            "statements": _coverage_cell(row["statements"]),
            "branches": _coverage_cell(row["branches"]),
            "functions": _coverage_cell(row["functions"]),
        }
        gaps = " / ".join(
            _coverage_uncovered(row[key])
            for key in ("lines", "statements", "branches", "functions")
        )
        lines.append(
            f"{str(row['file']):<{widths['file']}} "
            f"{cells['lines']:>{widths['lines']}} "
            f"{cells['statements']:>{widths['statements']}} "
            f"{cells['branches']:>{widths['branches']}} "
            f"{cells['functions']:>{widths['functions']}} "
            f"{gaps:>{widths['gap']}}"
        )

    total = next((row for row in rows if str(row["file"]).strip() == "Total"), None)
    if total:
        lines.append(separator)
        total_cells = [
            _coverage_cell(total[key])
            for key in ("lines", "statements", "branches", "functions")
        ]
        lines.append(
            f"{'All reported files':<{widths['file']}} "
            f"{total_cells[0]:>{widths['lines']}} "
            f"{total_cells[1]:>{widths['statements']}} "
            f"{total_cells[2]:>{widths['branches']}} "
            f"{total_cells[3]:>{widths['functions']}}"
        )

    lines.extend([
        "",
        "Read it like this: 312/322 (96.89%) means 312 lines were exercised and 10 were not.",
        "High coverage improves test confidence, but it does not prove the behavior is secure.",
    ])
    return "\n".join(lines)


def _strip_coverage_table(output: str) -> str:
    """Remove only Foundry's raw coverage box; Lowkey prints the readable table instead."""
    lines = str(output or "").splitlines()
    kept: list[str] = []
    in_table = False
    saw_header = False

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("╭") and "──" not in stripped:
            # Foundry's coverage box starts immediately before the File header.
            in_table = True
            continue

        if stripped.startswith("| File") and "% Lines" in stripped and "% Statements" in stripped:
            in_table = True
            saw_header = True
            continue

        if in_table:
            if (
                stripped.startswith("|")
                or stripped.startswith("+")
                or stripped.startswith("╭")
                or stripped.startswith("╰")
                or stripped.startswith("├")
            ):
                continue
            if saw_header:
                in_table = False
                saw_header = False
            else:
                # Keep non-table text from before the coverage header.
                in_table = False

        kept.append(line)

    return "\n".join(kept).strip()


def run_coverage_audit(command: Sequence[str], root: Path, quiet: bool = False) -> int:
    """Run coverage and retry once with IR minimum when coverage hits stack-too-deep."""
    binary = forge_path()
    if not binary:
        return die("forge was not found on PATH. Install Foundry first.")

    def execute(current: Sequence[str]):
        try:
            result = subprocess.run([binary, *current], cwd=root, text=True, capture_output=True)
        except OSError as exc:
            return None, str(exc)
        combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
        visible_stdout = _strip_coverage_table(result.stdout) if result.stdout else ""
        visible_stderr = _strip_coverage_table(result.stderr) if result.stderr else ""
        coverage_report = _format_coverage_report(combined)
        if not quiet:
            if visible_stdout:
                print(visible_stdout, end="" if visible_stdout.endswith("\n") else "\n")
            if visible_stderr:
                print(visible_stderr, file=sys.stderr, end="" if visible_stderr.endswith("\n") else "\n")
        if coverage_report:
            print(coverage_report)
        if quiet and result.returncode != 0 and combined.strip():
            print("\nForge coverage failed:\n" + "\n".join(combined.splitlines()[-24:]), file=sys.stderr)
        return result, combined

    result, output = execute(command)
    if result is None:
        return die(f"could not execute forge coverage: {output}", 1)
    attempts = 1
    if result.returncode != 0 and _is_stack_too_deep(output) and not _has_flag(command, "--ir-minimum", "--via-ir", "--no-via-ir"):
        if _supports_option("coverage", "--ir-minimum"):
            retry = [*command, "--ir-minimum"]
            attempts = 2
            if not quiet:
                print("LowkeyForge: coverage compilation hit stack too deep; retrying once with --ir-minimum without modifying the project's foundry.toml.")
            result, retry_output = execute(retry)
            if result is None:
                return die(f"could not execute forge coverage retry: {retry_output}", 1)
        else:
            print("LowkeyForge: coverage hit stack too deep, but this Forge does not support --ir-minimum; leaving coverage failed.", file=sys.stderr)
    status = "completed" if result.returncode == 0 else "failed"
    audit_context.emit("forge-command", root, tool="forge", status=status, summary="forge coverage", data={"command":"coverage","exit_code":result.returncode,"attempts":attempts})
    audit_context.record_tool("forge-coverage", root, status=status, summary=f"forge coverage ({attempts} attempt{'s' if attempts != 1 else ''})", data={"exit_code":result.returncode,"attempts":attempts})
    return result.returncode
def _project_owned_tests(root: Path) -> list[Path]:
    test_root = root / "test"
    if not test_root.is_dir():
        return []
    return [path for path in test_root.rglob("*.t.sol") if not path.name.startswith("Lowkey_")]


def _dashboard_status(state: dict | None) -> tuple[str, str]:
    if not isinstance(state, dict):
        return "NOT RUN", "no evidence recorded"
    status = str(state.get("status") or "").lower()
    if status in {"completed", "pass", "passed"}:
        return "PASS", str(state.get("summary") or "completed")
    if status in {"skipped", "skip"}:
        return "SKIPPED", str(state.get("summary") or "skipped")
    if status in {"failed", "fail"}:
        return "FAIL", str(state.get("summary") or "failed")
    if status == "running":
        return "RUNNING", str(state.get("summary") or "running")
    return status.upper() or "UNKNOWN", str(state.get("summary") or "recorded")


def render_audit_dashboard(root: Path, pipeline_code: int = 0) -> int:
    """Render the compact evidence dashboard at the end of every connected audit."""
    context = audit_context.load(root)
    tools = context.get("tools", {}) if isinstance(context.get("tools"), dict) else {}
    rows = []

    for key, label in (
        ("forge-build", "Forge build"),
        ("slither", "Slither"),
        ("forge-lint", "Forge lint"),
        ("forge-geiger", "Forge geiger"),
        ("forge-tests", "Forge tests"),
        ("forge-coverage", "Coverage"),
        ("generator", "PoC scaffold"),
    ):
        status, detail = _dashboard_status(tools.get(key))
        if key == "slither" and isinstance(tools.get(key), dict):
            count = tools[key].get("finding_count")
            if count is not None:
                detail = f"{count} finding(s)"
        rows.append((label, status, detail))

    signals = context.get("signals", [])
    open_signals = sum(1 for item in signals if isinstance(item, dict) and item.get("status") == "open")
    focused = context.get("focus") if isinstance(context.get("focus"), dict) else None

    mandatory = [
        tools.get("forge-build", {}).get("status") if isinstance(tools.get("forge-build"), dict) else None,
        tools.get("forge-tests", {}).get("status") if isinstance(tools.get("forge-tests"), dict) else None,
        tools.get("forge-coverage", {}).get("status") if isinstance(tools.get("forge-coverage"), dict) else None,
    ]
    overall = "PASS" if pipeline_code == 0 and all(x == "completed" for x in mandatory) else "REVIEW NEEDED"

    print("\n=== LOWKEY AUDIT DASHBOARD ===")
    print("=" * 88)
    print(f"Target : {(context.get('target') or {}).get('contract') or (context.get('target') or {}).get('address') or 'not configured'}")
    print(f"Actor  : {context.get('actor') or 'none'}")
    print(f"Signals: {open_signals} open")
    if focused:
        print(f"Focus  : {focused.get('signal_id') or focused.get('title') or 'active'}")
    print(f"Overall: {overall}")
    print("\n+------------------+------------+------------------------------------------------+")
    print("| Step             | Status     | Details                                        |")
    print("+------------------+------------+------------------------------------------------+")
    for label, status, detail in rows:
        label = str(label)[:16]
        status = str(status)[:10]
        detail = str(detail).replace("\n", " ")
        if len(detail) > 46:
            detail = detail[:43] + "..."
        print(f"| {label:<16} | {status:<10} | {detail:<46} |")
    print("+------------------+------------+------------------------------------------------+")
    print("Evidence: .audit/context.json + .audit/events.jsonl")
    print("Heuristic/static results are investigation leads, not vulnerability verdicts.")
    return 0 if overall == "PASS" else 1


def run_audit(args: Sequence[str]) -> int:
    """Run the complete audit pipeline with concise output by default."""
    root = Path.cwd().resolve()
    checks = "--checks" in args
    verbose = "--verbose" in args
    quiet = not verbose
    forwarded = [a for a in args if a not in {"--checks", "--verbose", "--quiet"}]
    test_cmd = ["test", *forwarded]
    if not has_verbosity(forwarded):
        test_cmd.insert(1, "-vvv")
    if not _has_path_filter(forwarded):
        test_cmd.extend(["--no-match-path", "test/Lowkey_*"])
    coverage_cmd = ["coverage", *forwarded]
    coverage_cmd.extend(_coverage_compatibility_flags(root, forwarded, quiet=quiet))
    if not _has_path_filter(forwarded) and _supports_option("coverage", "--no-match-path"):
        coverage_cmd.extend(["--no-match-path", "**/Lowkey_*"])
    steps = [("build", ["build", "--skip", "test", "--skip", "script"])]
    if checks:
        steps.append(("slither", None))
        for optional in ("lint", "geiger"):
            if command_available(optional):
                steps.append((optional, None))
    steps.extend([("tests", test_cmd), ("coverage", coverage_cmd)])
    print("LOWKEY CONNECTED AUDIT")
    print("======================")
    print(f"Project : {root}")
    print(f"Mode    : {'verbose' if verbose else 'quiet'}")
    print("Pipeline: build" + (" -> Slither -> lint/geiger" if checks else "") + " -> tests -> coverage")
    print()
    if not _project_owned_tests(root):
        print("Tests   : no project-owned Forge tests (Lowkey experiments excluded)")
    for label, command in steps:
        if label == "slither":
            code = run_slither_preflight(root, quiet=quiet)
        elif label in {"lint", "geiger"}:
            code = run_forge_diagnostics([label], label, quiet=quiet)
        elif label == "coverage":
            code = run_coverage_audit(command, root, quiet=quiet)
        else:
            code = run_forge(command, quiet=quiet)
        context = audit_context.load(root)
        detail = ""
        if label == "slither":
            state = context.get("tools", {}).get("slither", {})
            if isinstance(state, dict) and state.get("finding_count") is not None:
                detail = f" — {state['finding_count']} finding(s)"
        print(f"{'PASS' if code == 0 else 'FAIL':<5} {label:<9}{detail}")
        stable_key = {
            "build": "forge-build",
            "tests": "forge-tests",
            "coverage": "forge-coverage",
            "lint": "forge-lint",
            "geiger": "forge-geiger",
        }.get(label)
        if stable_key:
            audit_context.record_tool(
                stable_key,
                root,
                status="completed" if code == 0 else "failed",
                summary=f"{label} audit step",
                data={"exit_code": code},
            )
        if code != 0:
            print(f"\nLowkeyForge: audit stopped at {label}.", file=sys.stderr)
            render_audit_dashboard(root, pipeline_code=code)
            return code
    render_audit_dashboard(root, pipeline_code=0)
    print("\nAUDIT SUMMARY")
    print("=============")
    print("Result  : PASS")
    print("Artifacts: .audit/context.json + tool evidence")
    print("Next    : lk findings  |  lk context")
    if checks:
        print("Static  : lk findings -> lk focus <ID> -> lk changes ...")
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
  lk forge audit [--checks] [--verbose]
  lk forge test-audit [forge test args...]
  lk forge inspect-audit <ContractName> [forge options]

Examples:
  lk forge test -vvvv
  lk forge test-audit --match-test testWithdraw
  lk forge inspect-audit BountyArena
  lk forge audit
  lk forge audit --checks
  lk forge audit --checks --verbose

Audit is quiet by default; use --verbose for native Forge/Slither output.

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
