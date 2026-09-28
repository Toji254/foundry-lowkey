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

import json
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

PROJECT_MARKERS = (
    "foundry.toml", "Scarb.toml", "Anchor.toml", "Move.toml",
    "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs",
    "hardhat.config.ts", "ape-config.yaml", "ape-config.yml",
    "brownie-config.yaml", "brownie-config.yml", "pyproject.toml",
    "requirements.txt", "requirements-dev.txt", "Pipfile",
    "package.json", "pnpm-workspace.yaml",
    "Cargo.toml", "go.mod", "go.work",
    "mix.exs", "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts",
    "Package.swift", "CMakeLists.txt", "Makefile",
)

PRIMARY_PROJECT_MARKERS = (
    "foundry.toml", "Scarb.toml", "Anchor.toml", "Move.toml",
    "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs",
    "hardhat.config.ts", "ape-config.yaml", "ape-config.yml",
    "brownie-config.yaml", "brownie-config.yml", "pyproject.toml",
    "requirements.txt", "requirements-dev.txt", "Pipfile",
    "Cargo.toml", "go.mod", "mix.exs",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts",
    "Package.swift", "CMakeLists.txt",
)

WORKSPACE_MARKERS = (
    "pnpm-workspace.yaml", "go.work",
)

def _marker_names(root: Path, markers: Sequence[str] = PROJECT_MARKERS) -> list[str]:
    return [marker for marker in markers if (root / marker).is_file()]

def _package_json_data(root: Path) -> dict[str, Any]:
    path = root / "package.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(_read(path))
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}

def _is_workspace_package(root: Path) -> bool:
    if any((root / marker).is_file() for marker in WORKSPACE_MARKERS):
        return True
    package = _package_json_data(root)
    return bool(package.get("workspaces")) if isinstance(package, dict) else False

def _source_tree_present(root: Path) -> bool:
    return bool(_source_counts(root))

def _is_project_candidate(root: Path) -> bool:
    if any((root / marker).is_file() for marker in PRIMARY_PROJECT_MARKERS):
        return True
    if (root / "package.json").is_file():
        package = _package_json_data(root)
        if _is_workspace_package(root):
            return False
        scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
        return bool(_source_tree_present(root) or (isinstance(scripts, dict) and scripts))
    return _source_tree_present(root) and any(
        (root / marker).is_file()
        for marker in ("Makefile", "CMakeLists.txt", "package.json", "pyproject.toml")
    )

def _candidate_score(root: Path) -> int:
    score = 0
    for marker in _marker_names(root, PRIMARY_PROJECT_MARKERS):
        if marker in {"foundry.toml", "Scarb.toml", "Cargo.toml", "go.mod", "Move.toml", "Anchor.toml"}:
            score += 100
        elif marker.startswith("hardhat.config") or marker.startswith("ape-") or marker.startswith("brownie-"):
            score += 90
        else:
            score += 70
    if (root / "package.json").is_file() and not _is_workspace_package(root):
        score += 40
    if _source_tree_present(root):
        score += min(30, sum(_source_counts(root).values()))
    if (root / "tests").is_dir():
        score += 10
    if (root / "src").is_dir() or (root / "contracts").is_dir():
        score += 10
    return score

def _workspace_project_metadata(projects):
    """Enrich workspace projects with audit-scope evidence and relationships."""
    package_projects = {}
    for project in projects:
        root = Path(project["root"])
        package = _package_json_data(root)
        package_name = str(package.get("name")).strip() if package.get("name") else None
        project["package_name"] = package_name
        if package_name:
            package_projects[package_name.lower()] = project

    for project in projects:
        root = Path(project["root"])
        package = _package_json_data(root)

        description = package.get("description")
        if not description:
            readme = root / "README.md"
            if readme.is_file():
                try:
                    for line in readme.read_text(encoding="utf-8", errors="ignore").splitlines():
                        text = line.strip().lstrip("#").strip()
                        if text and not text.startswith(("!", "[")):
                            description = text
                            break
                except OSError:
                    pass
        project["description"] = str(description or root.name).strip()

        test_files = 0
        setup_files = 0
        protocol_source_files = 0
        contract_count = 0
        entry_contracts = []

        source_suffixes = {
            ".sol", ".vy", ".cairo", ".move", ".rs", ".go", ".huff", ".yul",
        }
        setup_dirs = {"script", "scripts", "deploy", "deployment", "migrations", "cmd", "programs"}
        for path in _walk_files(root):
            lower_name = path.name.lower()
            suffix = path.suffix.lower()
            if (
                lower_name.startswith("test_")
                or lower_name.endswith("_test.py")
                or ".test." in lower_name
                or ".spec." in lower_name
                or suffix in {".t.sol", ".t.cairo"}
            ):
                test_files += 1
            if any(part.lower() in setup_dirs for part in path.relative_to(root).parts):
                setup_files += 1
            if suffix in source_suffixes:
                protocol_source_files += 1
            if suffix == ".sol":
                source = _read(path)
                names = re.findall(r"(?m)\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)", source)
                contract_count += len(names)
                for name in names:
                    if len(entry_contracts) < 8:
                        entry_contracts.append(name)

        project["test_files"] = test_files
        project["setup_files"] = setup_files
        project["protocol_source_files"] = protocol_source_files
        project["contract_count"] = contract_count
        project["entry_contracts"] = entry_contracts
        project["has_tests"] = test_files > 0
        project["has_setup"] = setup_files > 0
        project["audit_capable"] = project.get("backend") not in {"generic", "unknown"} and protocol_source_files > 0

        # Package-manager relationships are the strongest workspace-level signal.
        dependencies = set()
        for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            values = package.get(key, {}) if isinstance(package, dict) else {}
            if isinstance(values, dict):
                for name in values:
                    sibling = package_projects.get(str(name).lower())
                    if sibling is not None and sibling is not project:
                        dependencies.add(Path(sibling["root"]).as_posix())

        # Foundry remappings commonly point at sibling workspace packages.
        remappings = root / "remappings.txt"
        if remappings.is_file():
            for line in _read(remappings).splitlines():
                value = line.strip()
                if not value or value.startswith("#") or "=" not in value:
                    continue
                _, destination = (part.strip() for part in value.split("=", 1))
                if not destination:
                    continue
                candidate_path = (root / destination).resolve()
                for sibling in projects:
                    sibling_root = Path(sibling["root"]).resolve()
                    if sibling is project:
                        continue
                    try:
                        candidate_path.relative_to(sibling_root)
                    except ValueError:
                        continue
                    dependencies.add(sibling_root.as_posix())
                    break

        # Direct relative imports can also cross package boundaries.
        import_pattern = re.compile(r"""\bimport\s+(?:[^"']+\s+from\s+)?["']([^"']+)["']""")
        for path in _walk_files(root):
            if path.suffix.lower() not in {".sol", ".vy", ".vyi", ".cairo", ".move", ".rs"}:
                continue
            for raw in import_pattern.findall(_read(path)):
                if not raw.startswith("."):
                    continue
                resolved = (path.parent / raw).resolve()
                for sibling in projects:
                    sibling_root = Path(sibling["root"]).resolve()
                    if sibling is project:
                        continue
                    try:
                        resolved.relative_to(sibling_root)
                    except ValueError:
                        continue
                    dependencies.add(sibling_root.as_posix())
                    break

        project["depends_on_roots"] = sorted(dependencies)

    project_by_root = {Path(item["root"]).resolve(): item for item in projects}
    for project in projects:
        dependency_items = []
        for dep_root in project.get("depends_on_roots", []):
            dep = project_by_root.get(Path(dep_root).resolve())
            if dep is not None:
                dependency_items.append(dep)
        project["depends_on"] = sorted(
            [str(item.get("relative") or item.get("name") or Path(item["root"]).name) for item in dependency_items],
            key=str.lower,
        )

    for project in projects:
        dependents = []
        current_root = Path(project["root"]).resolve()
        for other in projects:
            if other is project:
                continue
            if current_root.as_posix() in {Path(item).resolve().as_posix() for item in other.get("depends_on_roots", [])}:
                dependents.append(str(other.get("relative") or other.get("name") or Path(other["root"]).name))
        project["depended_on_by"] = sorted(dependents, key=str.lower)
        project["used_by_siblings"] = len(dependents)

        lower_identity = " ".join(
            str(value or "").lower()
            for value in (
                project.get("name"),
                project.get("package_name"),
                project.get("description"),
                project.get("relative"),
            )
        )
        support_words = re.compile(r"(^|[/._-])(helper|helpers|common|toolbox|tools|benchmark|benchmarks|fixture|fixtures|mock|mocks)([/._-]|$)")
        explicit_support = bool(support_words.search(lower_identity))

        primary_score = (
            int(project.get("setup_files", 0)) * 12
            + int(project.get("contract_count", 0)) * 2
            + min(int(project.get("test_files", 0)), 25)
            - int(project.get("used_by_siblings", 0)) * 10
        )
        if explicit_support:
            primary_score -= 100
        if int(project.get("protocol_source_files", 0)) == 0:
            primary_score -= 100
        project["audit_entry_score"] = primary_score

    eligible = [
        item for item in projects
        if int(item.get("protocol_source_files", 0)) > 0
        and bool(item.get("audit_capable"))
        and int(item.get("audit_entry_score", 0)) > 0
        and not re.search(
            r"(^|[/._-])(helper|helpers|common|toolbox|tools|benchmark|benchmarks|fixture|fixtures|mock|mocks)([/._-]|$)",
            " ".join(str(item.get(x) or "").lower() for x in ("name", "package_name", "relative")),
        )
    ]
    max_score = max((int(item.get("audit_entry_score", 0)) for item in eligible), default=0)
    primary_roots = {
        Path(item["root"]).resolve()
        for item in eligible
        if int(item.get("audit_entry_score", 0)) == max_score and max_score > 0
    }

    for project in projects:
        root = Path(project["root"]).resolve()
        if root in primary_roots:
            project["scope_role"] = "primary audit candidate"
            project["scope_reason"] = (
                "Strongest project-level evidence of being an audit entry: application code, "
                "tests, and/or deployment setup, with no stronger sibling entry signal."
            )
        elif project.get("depended_on_by"):
            project["scope_role"] = "important dependency"
            project["scope_reason"] = (
                "Other workspace projects depend on this package, so its behavior can affect the audit target."
            )
        elif explicit_support:
            project["scope_role"] = "support / tooling"
            project["scope_reason"] = "Project metadata identifies this as supporting infrastructure rather than an audit entry."
        elif int(project.get("protocol_source_files", 0)) > 0:
            project["scope_role"] = "component / library"
            project["scope_reason"] = "Contains protocol/source code but is not identified as the main audit entry."
        else:
            project["scope_role"] = "support / tooling"
            project["scope_reason"] = "No protocol source units were detected; treated as supporting workspace code."

        project["entrypoint"] = project.get("entry_contracts", [None])[0] if project.get("entry_contracts") else None

    # Replace internal absolute dependency roots with stable data for callers.
    for project in projects:
        project.pop("depends_on_roots", None)

    return projects

def discover_nested_projects(
    start: str | os.PathLike[str] = ".",
    *,
    max_depth: int = 5,
) -> list[dict[str, Any]]:
    """Discover nested projects without assuming a language or directory name."""
    root = Path(start).expanduser().resolve()
    if root.is_file():
        root = root.parent

    found: dict[str, dict[str, Any]] = {}
    for current, dirs, _files in os.walk(root):
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            continue
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        if depth == 0:
            continue
        if depth > max_depth:
            dirs[:] = []
            continue
        if not _is_project_candidate(current_path):
            continue

        info = detect_project(current_path)
        found[str(current_path)] = {
            "root": str(current_path),
            "relative": current_path.relative_to(root).as_posix(),
            "name": current_path.name,
            "kind": info.get("kind", "unknown"),
            "backend": info.get("backend", "generic"),
            "languages": info.get("languages", {}),
            "score": _candidate_score(current_path),
        }

    projects = sorted(
        found.values(),
        key=lambda item: (-int(item.get("score", 0)), str(item.get("relative", ""))),
    )
    return _workspace_project_metadata(projects)

def workspace_root(start: str | os.PathLike[str] = ".") -> Path:
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent
    for parent in (path, *path.parents):
        if any((parent / marker).is_file() for marker in WORKSPACE_MARKERS):
            return parent
        if (parent / "package.json").is_file() and _is_workspace_package(parent):
            return parent
        cargo = parent / "Cargo.toml"
        if cargo.is_file() and re.search(r"(?m)^\\s*\\[workspace(?:\\.[^]]+)?\\]", _read(cargo)):
            return parent
    return path

def workspace_selection(start: str | os.PathLike[str] = ".") -> Path | None:
    root = workspace_root(start)
    try:
        data = json.loads((root / ".audit" / "workspace.json").read_text(encoding="utf-8"))
        selected = Path(str(data.get("active_project", ""))).expanduser().resolve()
        selected.relative_to(root)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return selected if selected.is_dir() and selected != root else None

def set_workspace_selection(workspace: str | os.PathLike[str], project: str | os.PathLike[str]) -> bool:
    root = Path(workspace).expanduser().resolve()
    selected = Path(project).expanduser().resolve()
    try:
        selected.relative_to(root)
    except ValueError:
        return False
    if selected == root or not selected.is_dir():
        return False
    state_path = root / ".audit" / "workspace.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps({"active_project": str(selected)}, indent=2) + "\n", encoding="utf-8")
    return True

def clear_workspace_selection(workspace: str | os.PathLike[str]) -> None:
    try:
        (Path(workspace).expanduser().resolve() / ".audit" / "workspace.json").unlink()
    except OSError:
        pass
def is_workspace_root(start: str | os.PathLike[str] = ".") -> bool:
    root = Path(start).expanduser().resolve()
    if root.is_file():
        root = root.parent
    if any((root / marker).is_file() for marker in WORKSPACE_MARKERS):
        return True
    if (root / "package.json").is_file() and _is_workspace_package(root):
        return True
    if (root / "Cargo.toml").is_file():
        text = _read(root / "Cargo.toml")
        if re.search(r"(?m)^\\s*\\[workspace(?:\\.[^]]+)?\\]", text):
            return True
    nested = discover_nested_projects(root, max_depth=3)
    return not any((root / marker).is_file() for marker in PRIMARY_PROJECT_MARKERS) and len(nested) > 1

def workspace_context(start: str | os.PathLike[str] = ".") -> dict[str, Any]:
    """Return one consistent workspace view for commands that need package scope."""
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent

    root = workspace_root(path)
    workspace_mode = is_workspace_root(root)
    candidates = discover_nested_projects(root) if workspace_mode else []

    current = None
    for candidate in candidates:
        candidate_root = Path(candidate["root"]).resolve()
        try:
            path.relative_to(candidate_root)
        except ValueError:
            continue
        if current is None or len(candidate_root.parts) > len(current.parts):
            current = candidate_root

    active = workspace_selection(root)
    if active is not None and not any(
        Path(item["root"]).resolve() == active.resolve() for item in candidates
    ):
        active = None

    return {
        "workspace": root,
        "projects": candidates,
        "current": current,
        "active": active,
    }


def project_root(start: str | os.PathLike[str] = ".") -> Path:
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent

    nearest = path
    found_marker = False
    for parent in (path, *path.parents):
        if any((parent / marker).is_file() for marker in PROJECT_MARKERS):
            nearest = parent
            found_marker = True
            break

    if not found_marker:
        nested = discover_nested_projects(path)
        if len(nested) == 1:
            return Path(nested[0]["root"])
        return path

    # A workspace marker may be above the directory where Lowkey was invoked.
    # Honor an explicitly selected nested project anywhere inside that workspace.
    if is_workspace_root(nearest):
        selected = workspace_selection(nearest)
        if selected is not None:
            return selected
        if nearest == path:
            nested = discover_nested_projects(nearest)
            if len(nested) == 1:
                return Path(nested[0]["root"])

    return nearest


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
        match = re.match(r"\s*path\s*=\s*(.+?)\s*$", line)
        if not match:
            continue
        path = Path(match.group(1).strip())
        if path.is_absolute() or ".." in path.parts:
            continue
        paths.append(path)
    return paths


def _nested_python_projects(root: Path) -> list[Path]:
    """Find declared submodules that contain Python/Vyper test suites."""
    projects: list[Path] = []
    for relative in _git_submodule_paths(root):
        project = root / relative
        if not project.is_dir():
            continue
        if (project / "pyproject.toml").is_file() or (
            (project / "tests").is_dir()
            and any(
                path.suffix.lower() in {".py", ".vy", ".vyi"}
                for path in _walk_files(project / "tests")
            )
        ):
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

def _project_python_runner(
    root: Path,
    command: str,
    *args: str,
    dependency_root: Path | None = None,
) -> list[str]:
    """Prefer a project-managed Python environment over global executables.

    When the project has a namespace-style tests/ directory, launch pytest
    through a tiny in-process shim so an unrelated site-packages ``tests``
    package cannot shadow the repository's own tests package.
    """
    env_root = dependency_root or root
    if command == "pytest" and (root / "tests").is_dir() and not (root / "tests" / "__init__.py").is_file():
        shim = (
            "import pathlib,sys,types;"
            "p=pathlib.Path('tests').resolve();"
            "m=types.ModuleType('tests');m.__path__=[str(p)];"
            "sys.modules['tests']=m;"
            "import pytest;"
            "raise SystemExit(pytest.main(sys.argv[1:]))"
        )
        if (env_root / "pyproject.toml").is_file() and shutil.which("uv"):
            return ["uv", "run", "python", "-c", shim, *args]
        for candidate in (
            env_root / ".venv" / "bin" / "python",
            env_root / "venv" / "bin" / "python",
        ):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return [str(candidate), "-c", shim, *args]
    if (env_root / "pyproject.toml").is_file() and shutil.which("uv"):
        if dependency_root is not None:
            return ["uv", "run", "--project", str(env_root), command, *args]
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
    if not info.get("_bootstrap_done"):
        bootstrap_code = bootstrap_project(info, args)
        if bootstrap_code != 0:
            return bootstrap_code
    info = detect_project(root)
    info["_bootstrap_done"] = True
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
        elif (native.get("pytest") or _nested_python_projects(root)) and (_has_test_files(root) or _nested_python_projects(root)):
            test_submodules = [
                path for path in _git_submodule_paths(root)
                if path.parts and path.parts[0] == "tests"
            ]
            command = _project_python_runner(root, "pytest", "-q")
            for submodule in test_submodules:
                command.extend(["--ignore", str(submodule)])
                print(
                    f"INFO  ignoring test submodule {submodule} in parent pytest "
                    "(project fixture/vendor tree)"
                )
            step("python tests", command)
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
