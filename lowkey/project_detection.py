#!/usr/bin/env python3
"""Evidence-driven project and audit-backend detection for Lowkey.

The detector separates:
  1. project identity (manifests/configuration),
  2. source-language inventory,
  3. runnable toolchains,
  4. audit backend selection.

Vendored/build/dependency directories are pruned so a nested .sol file cannot
turn a Cairo/Vyper project into a Foundry project.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Sequence


IGNORED_DIRS = {
    ".git", ".audit", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", "node_modules",
    "vendor", "vendors", "lib", "libs", "out", "cache", "broadcast",
    "artifacts", "target", "build", "dist", ".idea", ".vscode",
}

LANGUAGE_BY_SUFFIX = {
    ".sol": "solidity",
    ".vy": "vyper",
    ".vyi": "vyper-interface",
    ".cairo": "cairo",
    ".rs": "rust",
    ".move": "move",
    ".go": "go",
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".huff": "huff",
    ".yul": "yul",
}

def project_root(start: str | os.PathLike[str] = ".") -> Path:
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent

    markers = (
        "foundry.toml", "Scarb.toml", "Anchor.toml", "Move.toml",
        "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs",
        "hardhat.config.ts", "ape-config.yaml", "ape-config.yml",
        "brownie-config.yaml", "brownie-config.yml", "pyproject.toml",
        "package.json", "Cargo.toml", "go.mod",
    )
    for parent in (path, *path.parents):
        if any((parent / marker).is_file() for marker in markers):
            return parent
    return path

def _walk_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        for filename in sorted(files):
            yield Path(current) / filename

def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""

def _has(root: Path, *names: str) -> bool:
    return any((root / name).is_file() for name in names)

def _mentions_vyper(root: Path) -> bool:
    names = ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "setup.cfg")
    return any("vyper" in _read(root / name).lower() for name in names if (root / name).is_file())

def _source_counts(root: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in _walk_files(root):
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))

def detect_project(start: str | os.PathLike[str] = ".") -> dict[str, Any]:
    root = project_root(start)
    sources = _source_counts(root)

    foundry = (root / "foundry.toml").is_file()
    scarb = (root / "Scarb.toml").is_file() or bool(sources.get("cairo"))
    hardhat = _has(
        root,
        "hardhat.config.js", "hardhat.config.cjs",
        "hardhat.config.mjs", "hardhat.config.ts",
    )
    anchor = (root / "Anchor.toml").is_file()
    move = (root / "Move.toml").is_file()
    ape = _has(root, "ape-config.yaml", "ape-config.yml")
    brownie = _has(root, "brownie-config.yaml", "brownie-config.yml")
    vyper = bool(sources.get("vyper") or sources.get("vyper-interface")) and (
        _mentions_vyper(root) or ape or brownie or not (
            foundry or scarb or hardhat or anchor or move
        )
    )

    stacks: list[str] = []
    if foundry:
        stacks.append("foundry")
    if scarb:
        stacks.append("cairo-starknet")
    if vyper:
        stacks.append("vyper")
    if hardhat:
        stacks.append("hardhat")
    if anchor:
        stacks.append("solana-anchor")
    if move:
        stacks.append("move")
    if ape:
        stacks.append("ape")
    if brownie:
        stacks.append("brownie")

    supporting: list[str] = []
    if (root / "package.json").is_file():
        supporting.append("node")
    if (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file():
        supporting.append("python")
    if (root / "Cargo.toml").is_file():
        supporting.append("cargo")
    if (root / "go.mod").is_file():
        supporting.append("go")

    if len(stacks) == 1:
        kind = stacks[0]
    elif len(stacks) > 1:
        kind = "multi-stack"
    elif sources.get("solidity"):
        kind = "solidity-source"
    elif sources.get("vyper") or sources.get("vyper-interface"):
        kind = "vyper"
    elif sources.get("cairo"):
        kind = "cairo"
    elif sources.get("rust"):
        kind = "rust"
    elif sources.get("move"):
        kind = "move-source"
    elif sources:
        kind = "source-project"
    else:
        kind = "unknown"

    if "foundry" in stacks and len(stacks) == 1:
        backend = "foundry"
    elif "cairo-starknet" in stacks and not {"foundry", "hardhat", "vyper"} & set(stacks):
        backend = "cairo-starknet"
    elif "vyper" in stacks and not {"foundry", "hardhat", "cairo-starknet"} & set(stacks):
        backend = "vyper"
    elif "hardhat" in stacks and len(stacks) == 1:
        backend = "hardhat"
    elif "solana-anchor" in stacks and len(stacks) == 1:
        backend = "solana-anchor"
    elif "move" in stacks and len(stacks) == 1:
        backend = "move"
    elif len(stacks) > 1:
        backend = "multi"
    else:
        backend = "generic"

    native = {
        "forge": bool(shutil.which("forge")),
        "scarb": bool(shutil.which("scarb")),
        "snforge": bool(shutil.which("snforge")),
        "vyper": bool(shutil.which("vyper")),
        "pytest": bool(shutil.which("pytest")),
        "ape": bool(shutil.which("ape")),
        "brownie": bool(shutil.which("brownie")),
        "hardhat": (root / "node_modules" / ".bin" / "hardhat").is_file(),
        "anchor": bool(shutil.which("anchor")),
        "aptos": bool(shutil.which("aptos")),
        "sui": bool(shutil.which("sui")),
    }

    return {
        "root": str(root),
        "kind": kind,
        "backend": backend,
        "stacks": stacks,
        "languages": sources,
        "supporting_tools": supporting,
        "native": native,
        "manifests": {
            "foundry": foundry,
            "scarb": (root / "Scarb.toml").is_file(),
            "hardhat": hardhat,
            "anchor": anchor,
            "move": move,
            "ape": ape,
            "brownie": brownie,
            "package_json": (root / "package.json").is_file(),
            "pyproject": (root / "pyproject.toml").is_file(),
        },
    }

def format_detection(info: dict[str, Any]) -> str:
    languages = info.get("languages", {})
    stacks = info.get("stacks", [])
    supporting = info.get("supporting_tools", [])
    native = [name for name, ok in (info.get("native") or {}).items() if ok]
    return "\n".join([
        "=== LOWKEY PROJECT DETECTION ===",
        f"Root       : {info.get('root')}",
        f"Type       : {info.get('kind', 'unknown')}",
        f"Backend    : {info.get('backend', 'generic')}",
        f"Languages  : {', '.join(f'{name} ({count})' for name, count in languages.items()) or 'none'}",
        f"Toolchains : {', '.join(stacks) or 'none detected'}",
        f"Supporting : {', '.join(supporting) or 'none detected'}",
        f"Native     : {', '.join(native) or 'none detected'}",
    ])

def _has_test_files(root: Path) -> bool:
    for path in _walk_files(root):
        if path.name.startswith("test_") or path.name.endswith("_test.py") or path.suffix in {".t.sol", ".t.cairo"}:
            return True
    return False

def _run(command: Sequence[str], root: Path) -> tuple[int, str]:
    try:
        result = subprocess.run(
            list(command),
            cwd=root,
            capture_output=True,
            text=True,
            timeout=900,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    output = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
    return result.returncode, output.strip()

def _report_step(label: str, command: Sequence[str], code: int, output: str) -> None:
    status = "PASS" if code == 0 else "FAIL"
    print(f"{status:<5} {label:<22} {' '.join(command)}")
    if output:
        print("\n".join(output.splitlines()[-12:]))

def run_native_audit(info: dict[str, Any], args: Sequence[str] = ()) -> int:
    """Run safe native verification for non-Foundry stacks.

    This intentionally reports build/test evidence, not vulnerability verdicts.
    """
    root = Path(info["root"])
    backend = info.get("backend", "generic")
    native = info.get("native", {})
    failures = 0

    print("\nLOWKEY NATIVE AUDIT")
    print("===================")

    def step(label: str, command: Sequence[str]) -> None:
        nonlocal failures
        code, output = _run(command, root)
        _report_step(label, command, code, output)
        if code != 0:
            failures = failures or code

    if backend == "cairo-starknet":
        if native.get("scarb"):
            step("cairo build", ["scarb", "build"])
            if native.get("snforge"):
                step("cairo tests", ["snforge", "test"])
            else:
                step("cairo tests", ["scarb", "test"])
        else:
            print("DEFER  cairo checks — Scarb is not installed.")
        return failures

    if backend == "vyper":
        if native.get("ape") and _has(root, "ape-config.yaml", "ape-config.yml"):
            step("vyper tests", ["ape", "test"])
        elif native.get("brownie") and _has(root, "brownie-config.yaml", "brownie-config.yml"):
            step("vyper tests", ["brownie", "test"])
        elif native.get("pytest") and _has_test_files(root):
            step("python tests", ["pytest", "-q"])
        elif native.get("vyper"):
            vyper_files = [
                path for path in _walk_files(root)
                if path.suffix.lower() == ".vy"
            ]
            if not vyper_files:
                print("DEFER  vyper checks — no .vy sources found.")
            else:
                for path in vyper_files:
                    rel = str(path.relative_to(root))
                    step("vyper compile " + rel, ["vyper", "-f", "abi", rel])
        else:
            print("DEFER  vyper checks — no Vyper/Ape/Brownie/Pytest runner found.")
        return failures

    if backend == "hardhat":
        binary = root / "node_modules" / ".bin" / "hardhat"
        if binary.is_file():
            step("hardhat compile", [str(binary), "compile"])
            step("hardhat tests", [str(binary), "test"])
        else:
            print("DEFER  hardhat checks — local node_modules hardhat binary not found.")
        return failures

    if backend == "solana-anchor":
        if native.get("anchor"):
            step("anchor build", ["anchor", "build"])
        else:
            print("DEFER  anchor checks — Anchor is not installed.")
        return failures

    if backend == "move":
        if native.get("aptos"):
            step("aptos move tests", ["aptos", "move", "test"])
        elif native.get("sui"):
            step("sui move tests", ["sui", "move", "test"])
        else:
            print("DEFER  Move checks — no supported Move CLI found.")
        return failures

    if backend == "multi":
        print("MIXED STACK: no single security backend selected.")
        for stack in info.get("stacks", []):
            if stack == "foundry":
                print("  Foundry: handled by the existing Forge audit layer.")
            elif stack == "cairo-starknet":
                print("  Cairo/Starknet: use native Scarb checks.")
            elif stack == "vyper":
                print("  Vyper: use native Vyper/Ape/Brownie/Pytest checks.")
            else:
                print(f"  {stack}: native checks are not yet specialized.")
        return 0

    print("STATIC-ONLY: no specialized project audit backend is installed.")
    print("Source inventory and manual review remain available.")
    return 0

if __name__ == "__main__":
    print(format_detection(detect_project()))
