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
import re
import shutil
import subprocess
import sys
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

def _python_module_available(name: str) -> bool:
    try:
        import importlib.util
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def _local_executable(root: Path, name: str) -> bool:
    candidates = [
        root / ".venv" / "bin" / name,
        root / "venv" / "bin" / name,
    ]
    virtual_env = os.environ.get("VIRTUAL_ENV")
    if virtual_env:
        candidates.append(Path(virtual_env) / "bin" / name)
    return any(path.is_file() and os.access(path, os.X_OK) for path in candidates)


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

    supporting: list[str] = []
    for submodule in _nested_python_projects(root):
        if shutil.which("uv"):
            code = _bootstrap_step(
                f"python subproject ({submodule.relative_to(root)})",
                ["uv", "sync", "--all-extras", "--dev"],
                submodule,
            )
        elif (submodule / "poetry.lock").is_file() and shutil.which("poetry"):
            code = _bootstrap_step(
                f"python subproject ({submodule.relative_to(root)})",
                ["poetry", "install"],
                submodule,
            )
        else:
            continue
        if code != 0:
            failures = failures or code

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
        "git": bool(shutil.which("git")),
        "uv": bool(shutil.which("uv")),
        "poetry": bool(shutil.which("poetry")),
        "pipenv": bool(shutil.which("pipenv")),
        "npm": bool(shutil.which("npm")),
        "pnpm": bool(shutil.which("pnpm")),
        "yarn": bool(shutil.which("yarn")),
        "bun": bool(shutil.which("bun")),
        "forge": bool(shutil.which("forge")),
        "scarb": bool(shutil.which("scarb")),
        "snforge": bool(shutil.which("snforge")),
        "vyper": bool(shutil.which("vyper") or _local_executable(root, "vyper") or _python_module_available("vyper")),
        "pytest": bool(shutil.which("pytest") or _local_executable(root, "pytest") or _python_module_available("pytest")),
        "boa": _python_module_available("boa"),
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

def _git_submodule_paths(root: Path) -> list[Path]:
    """Return submodule paths declared by the repository's .gitmodules file."""
    text = _read(root / ".gitmodules")
    paths: list[Path] = []
    for line in text.splitlines():
        match = re.match(r"\\s*path\\s*=\\s*(.+?)\\s*$", line)
        if not match:
            continue
        path = Path(match.group(1).strip())
        if path.is_absolute() or ".." in path.parts:
            continue
        paths.append(path)
    return paths


def _nested_python_projects(root: Path) -> list[Path]:
    """Find Python projects rooted inside declared git submodules."""
    projects: list[Path] = []
    for relative in _git_submodule_paths(root):
        project = root / relative
        if (project / "pyproject.toml").is_file():
            projects.append(project)
    return projects


def _has_test_files(root: Path, ignored_roots: Sequence[Path] = ()) -> bool:
    ignored = [path.resolve() for path in ignored_roots]
    for path in _walk_files(root):
        resolved = path.resolve()
        if any(ignored_path == resolved or ignored_path in resolved.parents for ignored_path in ignored):
            continue
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

def _project_python_runner(root: Path, command: str, *args: str) -> list[str]:
    """Prefer the project's package-managed Python environment over global executables."""
    if (root / "pyproject.toml").is_file() and shutil.which("uv"):
        return ["uv", "run", command, *args]
    if (root / "poetry.lock").is_file() and shutil.which("poetry"):
        return ["poetry", "run", command, *args]
    for candidate in (
        root / ".venv" / "bin" / command,
        root / "venv" / "bin" / command,
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return [str(candidate), *args]
    return [command, *args]


def _bootstrap_step(label: str, command: Sequence[str], root: Path) -> int:
    print(f"BOOT  {label:<24} {' '.join(command)}")
    code, output = _run(command, root)
    if code == 0:
        print(f"PASS  {label}")
    else:
        print(f"FAIL  {label}")
        if output:
            print("\n".join(output.splitlines()[-16:]))
    return code


def bootstrap_project(info: dict[str, Any], args: Sequence[str] = ()) -> int:
    """Prepare an audit workspace using project-declared tooling.

    This is intentionally project-local: Lowkey does not install protocol
    dependencies system-wide. It prefers lockfiles and the package manager
    declared/available for the repository.
    """
    root = Path(info["root"])
    failures = 0
    print("\nLOWKEY PROJECT BOOTSTRAP")
    print("========================")

    if (root / ".gitmodules").is_file() and shutil.which("git"):
        code = _bootstrap_step(
            "git submodules",
            ["git", "submodule", "update", "--init", "--recursive", "--depth", "1"],
            root,
        )
        if code != 0:
            failures = failures or code
    elif (root / ".gitmodules").is_file():
        print("DEFER  git submodules — git is not installed.")

    if (root / "pyproject.toml").is_file():
        if shutil.which("uv"):
            code = _bootstrap_step(
                "python dependencies",
                ["uv", "sync", "--all-extras", "--dev"],
                root,
            )
            if code != 0:
                failures = failures or code
        elif (root / "poetry.lock").is_file() and shutil.which("poetry"):
            code = _bootstrap_step("python dependencies", ["poetry", "install"], root)
            if code != 0:
                failures = failures or code
        elif (root / "Pipfile").is_file() and shutil.which("pipenv"):
            code = _bootstrap_step("python dependencies", ["pipenv", "sync", "--dev"], root)
            if code != 0:
                failures = failures or code
        elif not (root / ".venv" / "bin" / "python").is_file() and not (root / "venv" / "bin" / "python").is_file():
            print("DEFER  python dependencies — no supported project manager found.")
    elif (root / "requirements.txt").is_file() or (root / "requirements-dev.txt").is_file():
        venv = root / ".venv"
        python = venv / "bin" / "python"
        pip = venv / "bin" / "pip"
        if not python.is_file():
            code = _bootstrap_step("python virtualenv", ["python3", "-m", "venv", str(venv)], root)
            if code != 0:
                failures = failures or code
        if pip.is_file():
            requirements = []
            if (root / "requirements.txt").is_file():
                requirements.append("requirements.txt")
            if (root / "requirements-dev.txt").is_file():
                requirements.append("requirements-dev.txt")
            for requirement in requirements:
                code = _bootstrap_step(
                    f"python {requirement}",
                    [str(pip), "install", "-r", requirement],
                    root,
                )
                if code != 0:
                    failures = failures or code

    if (root / "package.json").is_file():
        node_modules = root / "node_modules"
        if not node_modules.is_dir():
            if (root / "pnpm-lock.yaml").is_file() and shutil.which("pnpm"):
                code = _bootstrap_step("node dependencies", ["pnpm", "install", "--frozen-lockfile"], root)
            elif (root / "yarn.lock").is_file() and shutil.which("yarn"):
                code = _bootstrap_step("node dependencies", ["yarn", "install", "--immutable"], root)
            elif (root / "bun.lockb").is_file() and shutil.which("bun"):
                code = _bootstrap_step("node dependencies", ["bun", "install", "--frozen-lockfile"], root)
            elif (root / "package-lock.json").is_file() and shutil.which("npm"):
                code = _bootstrap_step("node dependencies", ["npm", "ci"], root)
            elif shutil.which("npm"):
                code = _bootstrap_step("node dependencies", ["npm", "install"], root)
            else:
                code = 0
                print("DEFER  node dependencies — no supported package manager found.")
            if code != 0:
                failures = failures or code

    if (root / "go.mod").is_file() and shutil.which("go"):
        code = _bootstrap_step("go dependencies", ["go", "mod", "download"], root)
        if code != 0:
            failures = failures or code

    return failures


def run_native_audit(info: dict[str, Any], args: Sequence[str] = ()) -> int:
    """Run safe native verification for non-Foundry stacks.

    This intentionally reports build/test evidence, not vulnerability verdicts.
    """
    root = Path(info["root"])
    bootstrap_code = bootstrap_project(info, args)
    if bootstrap_code != 0:
        return bootstrap_code
    info = detect_project(root)
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
        elif native.get("pytest") and (_has_test_files(root) or _nested_python_projects(root)):
            nested_projects = _nested_python_projects(root)
            ignored_test_roots = [project / "tests" for project in nested_projects if (project / "tests").is_dir()]
            if _has_test_files(root, ignored_test_roots):
                command = _project_python_runner(root, "pytest", "-q")
                for test_root in ignored_test_roots:
                    command.extend(["--ignore", str(test_root.relative_to(root))])
                step("python tests", command)
            elif not nested_projects:
                step("python tests", _project_python_runner(root, "pytest", "-q"))
            for project in nested_projects:
                if _has_test_files(project):
                    step(
                        f"python tests ({project.relative_to(root)})",
                        _project_python_runner(project, "pytest", "-q"),
                    )
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
                    step("vyper compile " + rel, _project_python_runner(root, "vyper", "-f", "abi", rel))
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
        print("MIXED STACK: running each detected native backend independently.")
        for stack in info.get("stacks", []):
            if stack == "foundry":
                print("  Foundry: handled by the existing Forge audit layer.")
                continue
            child = dict(info)
            child["backend"] = stack
            child_code = run_native_audit(child, args)
            if child_code != 0:
                failures = failures or child_code
        return failures

    print("STATIC-ONLY: no specialized project audit backend is installed.")
    print("Source inventory and manual review remain available.")
    return 0

if __name__ == "__main__":
    print(format_detection(detect_project()))
