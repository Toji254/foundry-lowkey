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
try:
    import project_tools
except ImportError:
    project_tools = None

NATIVE_COMMANDS = {
    "build", "test", "script", "create", "inspect", "snapshot", "coverage",
    "fmt", "lint", "flatten", "verify-contract",
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

def _project_root() -> Path:
    return Path(audit_context.foundry_project_root() or Path.cwd()).resolve()


def _project_vyper_sources(root: Path) -> list[Path]:
    ignored = {
        ".git", ".audit", ".venv", ".tox", ".nox", "__pycache__",
        ".pytest_cache", "node_modules", "cache", "out", "artifacts",
        "build", "dist", "lib", "tests", "test", "fixtures", "mocks", "mock",
    }
    return sorted(
        path for path in root.rglob("*.vy")
        if path.is_file() and not any(part in ignored for part in path.parts)
    )


def _vyper_output(root: Path, source: Path, fmt: str) -> tuple[int, str, str]:
    binary = shutil.which("vyper")
    if not binary:
        return 127, "", "vyper was not found on PATH"
    returncode = subprocess.run(
        [binary, "-f", fmt, str(source)],
        cwd=root,
        capture_output=True,
        text=True,
    )
    return returncode.returncode, returncode.stdout.strip(), returncode.stderr.strip()


def run_vyper_build(quiet: bool = False) -> int:
    """Compile Vyper sources into Lowkey-owned normalized ABI artifacts."""
    root = _project_root()
    sources = _project_vyper_sources(root)
    if not sources:
        return die("no Vyper sources found in the current project.")

    binary = shutil.which("vyper")
    if not binary:
        return die("vyper was not found on PATH. Install the project compiler first.", 1)

    output_dir = root / ".audit" / "build" / "vyper"
    output_dir.mkdir(parents=True, exist_ok=True)
    failures = 0
    built = 0

    for source in sources:
        outputs = {}
        source_failed = False
        for fmt in ("abi", "bytecode", "bytecode_runtime", "layout"):
            code, stdout, stderr = _vyper_output(root, source, fmt)
            if code != 0:
                failures += 1
                source_failed = True
                if not quiet:
                    print(
                        f"Vyper build failed: {source.relative_to(root)} ({fmt})",
                        file=sys.stderr,
                    )
                    print(stderr or stdout or "compiler returned non-zero status", file=sys.stderr)
                break
            outputs[fmt] = stdout

        if source_failed or not outputs:
            continue

        try:
            abi = json.loads(outputs["abi"])
        except json.JSONDecodeError:
            failures += 1
            print(f"Vyper returned invalid ABI JSON: {source}", file=sys.stderr)
            continue

        bytecode = outputs["bytecode"].strip()
        runtime_bytecode = outputs["bytecode_runtime"].strip()
        try:
            layout = json.loads(outputs["layout"])
        except json.JSONDecodeError:
            layout = {}

        artifact = {
            "contractName": source.stem,
            "sourceName": source.relative_to(root).as_posix(),
            "abi": abi,
            "bytecode": {"object": bytecode},
            "deployedBytecode": {"object": runtime_bytecode},
            "storageLayout": layout,
            "language": "Vyper",
            "compiler": {"name": "vyper", "version": subprocess.run(
                [binary, "--version"], cwd=root, capture_output=True, text=True
            ).stdout.strip()},
        }
        destination = output_dir / f"{source.stem}.json"
        destination.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
        built += 1

    audit_context.record_tool(
        "vyper-build",
        root,
        status="completed" if failures == 0 else "failed",
        summary=f"compiled {built} Vyper contract(s)",
        data={"contracts": built, "failures": failures},
    )
    if not quiet:
        print(f"Vyper build: {built} contract(s) compiled.")
        print(f"Artifacts: {output_dir}")
    return 1 if failures else 0

def _project_kind(root: Path) -> str:
    if project_tools is not None:
        try:
            return str(project_tools.detect_project(root).get("kind") or "generic")
        except Exception:
            pass
    if (root / "foundry.toml").is_file():
        return "foundry"
    if any(root.glob("hardhat.config.*")):
        return "hardhat"
    if (root / "brownie-config.yaml").is_file():
        return "brownie"
    if _project_vyper_sources(root):
        return "vyper"
    return "generic"


def _run_native_project(command: list[str], root: Path, label: str) -> int:
    try:
        result = subprocess.run(command, cwd=root)
    except OSError as exc:
        return die(f"could not execute {label}: {exc}", 1)
    audit_context.record_tool(
        label,
        root,
        status="completed" if result.returncode == 0 else "failed",
        summary=" ".join(command),
        data={"command": command, "exit_code": result.returncode},
    )
    return result.returncode


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
    """Hide diagnostics emitted only by Lowkey-generated helper artifacts."""
    text = str(output or "")
    if not text.strip():
        return "", 0
    blocks = re.split(r"\n\s*\n", text)
    kept = []
    filtered = 0
    for block in blocks:
        if any(marker in block for marker in LOWKEY_GENERATED_PATH_MARKERS):
            filtered += len(re.findall(r"(?m)^\s*(?:warning|note|error)\[", block)) or 1
            continue
        kept.append(block)
    return "\n\n".join(kept).strip(), filtered


def _strip_generated_lint_abort(blocks: Sequence[str]) -> list[str]:
    """Remove Forge's generic lint-abort footer when only generated files warned."""
    cleaned = []
    for block in blocks:
        if re.fullmatch(r"\s*Error: aborting due to \d+ linter warning\(s\)\.?\s*", block):
            continue
        cleaned.append(block)
    return cleaned


def run_forge_diagnostics(args: Sequence[str], label: str, quiet: bool = False) -> int:
    """Run Forge diagnostics, persist evidence, and isolate Lowkey-generated diagnostics."""
    binary = forge_path()
    root = audit_context.foundry_project_root()
    if not binary:
        return die("forge was not found on PATH. Install Foundry first.")

    try:
        result = subprocess.run(
            [binary, *args],
            cwd=root,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return die(f"could not execute forge: {exc}", 1)

    combined = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()

    evidence_dir = root / ".audit" / "forge"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = evidence_dir / f"{label}.latest.txt"
    evidence_path.write_text(
        combined + ("\n" if combined else ""),
        encoding="utf-8",
    )

    blocks = re.split(r"\n\s*\n", combined) if combined else []
    non_generated_blocks = [
        block
        for block in blocks
        if block.strip()
        and not any(marker in block for marker in LOWKEY_GENERATED_PATH_MARKERS)
    ]
    project_blocks = _strip_generated_lint_abort(non_generated_blocks)

    visible, filtered = _filter_generated_diagnostics(combined)
    effective_code = result.returncode

    # A generated Lowkey helper is outside the user's audit scope. If Forge
    # rejected only that generated file's lint warning, do not turn the helper
    # into a project-audit failure.
    if result.returncode != 0 and filtered and not project_blocks:
        effective_code = 0

    if visible and (not quiet or effective_code != 0):
        print(
            visible,
            file=sys.stderr if effective_code != 0 else sys.stdout,
        )
    if filtered and not quiet:
        print(
            f"LowkeyForge: filtered {filtered} diagnostic(s) from Lowkey-generated helper files; "
            f"evidence: {evidence_path}"
        )

    status = "completed" if effective_code == 0 else "failed"
    command_text = " ".join(str(item) for item in args)
    evidence_data = {
        "command": list(args),
        "command_text": command_text,
        "exit_code": effective_code,
        "raw_exit_code": result.returncode,
        "filtered": filtered,
        "evidence": str(evidence_path),
    }
    audit_context.emit(
        "forge-command",
        root,
        tool="forge",
        status=status,
        summary=f"forge {label}",
        data=evidence_data,
    )
    audit_context.record_tool(
        f"forge-{label}",
        root,
        status=status,
        summary=f"forge {label}",
        data=evidence_data,
    )
    return effective_code


def run_slither_preflight(root: Path, quiet: bool = False) -> int:
    """Run Lowkey's normalized Slither reporter when available."""
    helper = Path(__file__).with_name("slither_tools.py")
    binary = shutil.which("slither")

    if not binary:
        if not quiet:
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
            command = [sys.executable, str(helper)]
            if quiet:
                command.append("--quiet")
            result = subprocess.run(command, cwd=root)
            return result.returncode
        except OSError as exc:
            print(
                f"LowkeyForge: could not execute Lowkey Slither reporter: {exc}",
                file=sys.stderr,
            )
            return 1

    command = [
        binary,
        str(root),
        "--exclude-dependencies",
        "--disable-color",
        "--fail-none",
    ]
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



def _geiger_command(extra: Sequence[str] = ()) -> list[str] | None:
    """Return the current unsafe-cheatcode lint command, with legacy fallback."""
    extra = list(extra)
    if command_available("lint") and _supports_option("lint", "--only-lint"):
        return ["lint", "--only-lint", "unsafe-cheatcode", *extra]
    if command_available("geiger"):
        return ["geiger", *extra]
    return None


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


def _coverage_project_paths(root: Path) -> list[str]:
    """Return configured first-party source prefixes without invoking Forge."""
    prefixes: list[str] = []
    for name in ("foundry.toml",):
        path = root / name
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r'(?m)^\s*src\s*=\s*["\']([^"\']+)["\']', content)
        if match:
            value = match.group(1).strip().strip("/\\").replace("\\", "/")
            if value:
                prefixes.append(value)
    return prefixes or ["src", "contracts"]



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


def _format_coverage_report(output: str, root: Path | None = None) -> str:
    """Render application coverage without counting Lowkey helper scripts."""
    rows = _parse_coverage_table(output)
    if root is not None:
        prefixes = _coverage_project_paths(root)
        filtered_rows = [
            row for row in rows
            if any(
                str(row.get("file") or "").replace("\\", "/").lstrip("./").startswith(prefix + "/")
                for prefix in prefixes
            )
        ]
        if filtered_rows:
            rows = filtered_rows
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
        coverage_report = _format_coverage_report(combined, root)
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
    """Render an evidence dashboard using the project's detected toolchain."""
    context = audit_context.load(root)
    tools = context.get("tools", {}) if isinstance(context.get("tools"), dict) else {}

    kind = "foundry"
    languages = []
    if project_tools is not None:
        try:
            profile = project_tools.detect_project(root)
            kind = str(profile.get("kind") or "generic")
            languages = list(profile.get("languages") or [])
        except Exception:
            pass
    foundry_kind = kind in {"foundry", "mixed-foundry-vyper"}

    rows = []
    if foundry_kind:
        row_specs = [
            ("forge-build", "Forge build"),
            ("slither", "Slither"),
            ("forge-lint", "Forge lint"),
            ("forge-geiger", "Forge geiger"),
            ("forge-tests", "Forge tests"),
            ("forge-coverage", "Coverage"),
            ("generator", "PoC scaffold"),
        ]
        mandatory_keys = ("forge-build", "forge-tests", "forge-coverage")
    else:
        row_specs = [
            ("project-build", "Project build"),
            ("slither", "Slither"),
            ("project-tests", "Project tests"),
            ("project-coverage", "Coverage"),
            ("generator", "PoC scaffold"),
        ]
        mandatory_keys = ("project-build", "project-tests", "project-coverage")

    for key, label in row_specs:
        state = tools.get(key)
        status, detail = _dashboard_status(state)
        if key == "slither" and isinstance(state, dict):
            count = state.get("finding_count")
            if count is not None:
                detail = f"{count} finding(s)"
        elif key == "generator" and isinstance(state, dict) and status == "PASS":
            detail = "scaffold generated"
            if state.get("placeholder"):
                detail += " (placeholder)"
            if state.get("candidate_signal"):
                detail += f" | {state['candidate_signal']}"
        rows.append((label, status, detail))

    signals = context.get("signals", [])
    security_patterns = [
        item for item in signals
        if isinstance(item, dict) and item.get("category") == "security-pattern"
    ]
    security_reviews = sum(
        1 for item in security_patterns
        if str(item.get("verification_status") or "CANDIDATE").upper() == "REVIEW"
    )
    security_confirmed = sum(
        1 for item in security_patterns
        if str(item.get("verification_status") or "CANDIDATE").upper() == "CONFIRMED"
    )
    security_candidates = sum(
        1 for item in security_patterns
        if str(item.get("verification_status") or "CANDIDATE").upper() == "CANDIDATE"
    )
    open_signals = sum(
        1 for item in signals
        if isinstance(item, dict) and item.get("status") == "open"
    )
    focused = context.get("focus") if isinstance(context.get("focus"), dict) else None

    mandatory_states = []
    for key in mandatory_keys:
        state = tools.get(key)
        mandatory_states.append(
            str(state.get("status") or "").lower()
            if isinstance(state, dict) else ""
        )

    mandatory_pass = all(state in {"completed", "skipped", "pass", "passed"} for state in mandatory_states)
    pipeline_failed = pipeline_code not in (None, 0) or any(
        state in {"failed", "fail"} for state in mandatory_states
    )
    static_failures = any(
        isinstance(tools.get(key), dict)
        and str(tools.get(key, {}).get("status") or "").lower() in {"failed", "fail"}
        for key in ("slither", "forge-lint", "forge-geiger")
    )

    target_data = context.get("target") if isinstance(context.get("target"), dict) else {}
    has_target = bool(target_data.get("address"))
    if pipeline_failed:
        overall = "PIPELINE FAILED"
    elif not has_target or open_signals or static_failures:
        overall = "REVIEW NEEDED"
    else:
        overall = "BASELINE PASS"

    print("\n=== LOWKEY AUDIT DASHBOARD ===")
    print("=" * 88)
    target_label = target_data.get("contract") or target_data.get("address") or "not configured"
    print(f"Project kind: {kind}")
    print(f"Target : {target_label}")
    if not has_target:
        print("         No live project target is connected; run 'lk lab' or 'lk audit auto' for local reproduction.")
    print(f"Actor  : {context.get('actor') or 'none'}")
    print(f"Signals: {open_signals} open")
    print(
        "Security patterns: "
        f"{len(security_patterns)} total | "
        f"{security_reviews} review | {security_confirmed} confirmed | {security_candidates} candidate"
    )
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
    if open_signals:
        print(f"Review state: {open_signals} open signal(s) require human investigation.")
    if static_failures:
        print("Review state: one or more static checks failed; inspect tool evidence.")
    if not has_target:
        print("Live audit state: INCOMPLETE")
        print("  Passing project checks only proves the available static/native baseline ran.")
        print("  Run 'lk lab' or 'lk walkthrough --auto' for a disposable local target.")
    return 1 if pipeline_failed else 0




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
        ("EVENTS", "events"), ("STORAGE", "storage-layout"),
    ]:
        print(f"\n=== {title} ===")
        code = run_forge(["inspect", contract, field, *extra])
        if code != 0:
            print(
                f"LowkeyForge: inspect field '{field}' failed; continuing.",
                file=sys.stderr,
            )
            if failures == 0:
                failures = code
    return failures


def run_audit(args: Sequence[str]) -> int:
    """Run the complete Foundry audit baseline, including static checks by default."""
    root = _project_root()
    profile = project_tools.detect_project(root) if project_tools is not None else {}
    kind = str(profile.get("kind") or "foundry")
    stacks = set(profile.get("stacks") or [])
    foundry_kind = "foundry" in stacks or kind in {"foundry", "mixed-foundry-vyper"}

    if not foundry_kind:
        return die(f"no Foundry project is available at {root} (detected {kind}).", 1)

    checks = "--no-checks" not in args
    verbose = "--verbose" in args
    quiet = not verbose
    forwarded = [
        a for a in args
        if a not in {"--checks", "--no-checks", "--verbose", "--quiet"}
    ]

    test_cmd = ["test", *forwarded]
    if not has_verbosity(forwarded):
        test_cmd.insert(1, "-vvv")
    if not _has_path_filter(forwarded):
        test_cmd.extend(["--no-match-path", "test/Lowkey_*"])

    coverage_cmd = ["coverage", *forwarded]
    coverage_cmd.extend(_coverage_compatibility_flags(root, forwarded, quiet=quiet))

    steps = [("build", ["build", "--skip", "test", "--skip", "script"])]
    if checks:
        steps.append(("slither", None))
        steps.append(("lint", ["lint"]) if command_available("lint") else ("lint", None))
        geiger = _geiger_command()
        steps.append(("geiger", geiger) if geiger else ("geiger", None))
    else:
        for key, summary in (
            ("slither", "static Slither check disabled"),
            ("forge-lint", "static Forge lint disabled"),
            ("forge-geiger", "unsafe-cheatcode check disabled"),
        ):
            audit_context.record_tool(
                key,
                root,
                status="skipped",
                summary=summary,
                data={"enabled": False},
            )
    steps.extend([("tests", test_cmd), ("coverage", coverage_cmd)])

    print("LOWKEY CONNECTED AUDIT")
    print("======================")
    print(f"Project : {root}")
    print(f"Mode    : {'verbose' if verbose else 'quiet'}")
    pipeline_labels = ["build"]
    if checks:
        pipeline_labels.extend(["Slither", "lint", "unsafe-cheatcodes"])
    pipeline_labels.extend(["tests", "coverage"])
    print("Pipeline: " + " -> ".join(pipeline_labels))
    print()

    if not _project_owned_tests(root):
        print("Tests   : no project-owned Forge tests (Lowkey experiments excluded)")

    for label, command in steps:
        if label == "slither":
            code = run_slither_preflight(root, quiet=quiet)
        elif label == "lint":
            if command is None:
                audit_context.record_tool(
                    "forge-lint",
                    root,
                    status="skipped",
                    summary="Forge lint is unavailable in this Forge version",
                    data={"available": False},
                )
                code = 0
            else:
                code = run_forge_diagnostics(command, label, quiet=quiet)
        elif label == "geiger":
            if command is None:
                audit_context.record_tool(
                    "forge-geiger",
                    root,
                    status="skipped",
                    summary="unsafe-cheatcode lint is unavailable in this Forge version",
                    data={"available": False},
                )
                code = 0
            else:
                code = run_forge_diagnostics(command, label, quiet=quiet)
        elif label == "coverage":
            code = run_coverage_audit(command, root, quiet=quiet)
        else:
            code = run_forge(command, quiet=quiet)

        context = audit_context.load(root)
        detail = ""
        if label == "slither":
            state = context.get("tools", {}).get("slither", {})
            if isinstance(state, dict):
                count = state.get("finding_count")
                if count is not None:
                    detail = f" — {count} finding(s)"
        elif label in {"lint", "geiger"}:
            key = "forge-lint" if label == "lint" else "forge-geiger"
            state = context.get("tools", {}).get(key, {})
            if isinstance(state, dict):
                filtered = state.get("filtered")
                if filtered:
                    detail = f" — {filtered} Lowkey diagnostic(s) filtered"

        print(f"{'PASS' if code == 0 else 'FAIL':<5} {label:<9}{detail}")

        if code != 0:
            print(f"\nLowkeyForge: audit stopped at {label}.", file=sys.stderr)
            render_audit_dashboard(root, pipeline_code=code)
            return code

    try:
        from generator import run_generate
        poc_code = run_generate({}, ["poc"])
        if poc_code != 0:
            print(
                "LowkeyForge: initial PoC scaffold was not generated.",
                file=sys.stderr,
            )
    except Exception as exc:
        print(
            f"LowkeyForge: initial PoC scaffold skipped: {exc}",
            file=sys.stderr,
        )

    render_audit_dashboard(root, pipeline_code=0)
    print("\nAUDIT SUMMARY")
    print("=============")
    context = audit_context.load(root)
    target_data = context.get("target") if isinstance(context.get("target"), dict) else {}
    has_target = bool(target_data.get("address"))
    tool_states = context.get("tools", {}) if isinstance(context.get("tools"), dict) else {}
    open_signals = sum(
        1
        for item in (context.get("signals") or [])
        if isinstance(item, dict) and item.get("status") == "open"
    )
    pipeline_ok = all(
        isinstance(tool_states.get(key), dict)
        and tool_states.get(key, {}).get("status") == "completed"
        for key in ("forge-build", "forge-tests", "forge-coverage")
    )

    if not pipeline_ok:
        result_label = "PIPELINE FAILED"
    elif not has_target:
        result_label = "STATIC BASELINE — NO LIVE TARGET"
    elif open_signals:
        result_label = "REVIEW NEEDED"
    else:
        result_label = "BASELINE PASS"

    print(f"Result  : {result_label}")
    if not has_target:
        print("Live    : NOT CONNECTED")
        print("Fix     : run 'lk lab' for a disposable local target.")
    elif open_signals:
        print(f"Review  : {open_signals} open signal(s) still require investigation.")
    else:
        print("Review  : no open evidence signals recorded by Lowkey.")
    print("Artifacts: .audit/context.json + tool evidence")
    print("Next    : lk findings | lk context")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help", "help"}:
        print("LowkeyForge - native Forge bridge")
        print("  lk forge <forge-command> [args...]")
        print("  lk lint [args...]")
        print("  lk geiger [args...]  (unsafe-cheatcode lint compatibility alias)")
        print("  lk forge audit [--no-checks] [--verbose]")
        return 0

    command, rest = args[0], args[1:]
    if command == "audit":
        return run_audit(rest)
    if command in {"test-audit", "audit-test"}:
        return run_test_audit(rest)
    if command in {"inspect-audit", "recon"}:
        return run_inspect_audit(rest)
    if command == "lint":
        return run_forge_diagnostics(["lint", *rest], "lint")
    if command == "geiger":
        command_args = _geiger_command(rest)
        if command_args is None:
            return die("unsafe-cheatcode lint is unavailable in the installed Forge.")
        return run_forge_diagnostics(command_args, "geiger")
    if command in NATIVE_COMMANDS:
        if not command_available(command):
            return die(f"Forge command '{command}' is not supported by the installed Forge.")
        return run_forge(args)
    return die(f"unknown Forge command '{command}'. Use 'lk forge --help'.")


if __name__ == "__main__":
    raise SystemExit(main())
