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
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

def _load_analysis_adapters():
    import importlib.util

    module_path = MODULE_DIR / "analysis_adapters.py"
    spec = importlib.util.spec_from_file_location("_lowkey_analysis_adapters", module_path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def _bind_analysis_symbols():
    """Bind the canonical analysis control plane without all-or-nothing imports."""
    module = None
    try:
        import analysis_adapters as module  # type: ignore
    except ImportError:
        try:
            module = _load_analysis_adapters()
        except (ImportError, OSError):
            module = None
    if module is None:
        return None, None, None
    return (
        getattr(module, "canonical_project_root", None),
        getattr(module, "inspect_repository", None),
        getattr(module, "is_dependency_path", None)
        or getattr(module, "_is_dependency_path", None),
    )

canonical_project_root, inspect_repository_canonical, universal_is_dependency_path = _bind_analysis_symbols()

try:
    from bootstrap import (
        bootstrap_status as shared_bootstrap_status,
        classify_build_failure as shared_classify_build_failure,
        project_build_command as shared_project_build_command,
        project_test_command as shared_project_test_command,
        dependency_boundary as shared_dependency_boundary,
        run_bootstrap as run_shared_bootstrap,
        runtime_environment,
    )
except ImportError:
    shared_bootstrap_status = shared_classify_build_failure = run_shared_bootstrap = None
    shared_project_build_command = shared_project_test_command = shared_dependency_boundary = None

    def runtime_environment(root: str | os.PathLike[str] = ".") -> tuple[dict[str, str], str | None]:
        return dict(os.environ), None


IGNORED_DIRS = {
    ".git", ".audit", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", "node_modules",
    "vendor", "vendors", "out", "cache", "broadcast",
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

def _is_lowkey_source_checkout(root: Path) -> bool:
    """Recognize Lowkey's own source checkout without confusing ~/.lowkey with it."""
    try:
        resolved = root.resolve()
        source_root = Path(__file__).resolve().parents[1]
        if resolved == source_root and (source_root / "lowkey" / "lk.py").is_file():
            return True
    except OSError:
        pass
    return (
        (root / "lowkey" / "lk.py").is_file()
        and (root / "lowkey" / "project_detection.py").is_file()
        and (root / "install.sh").is_file()
    )

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
        project["audit_capable"] = project.get("backend") not in {"generic", "unknown"}

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
        if int(project.get("protocol_source_files", 0)) == 0 and project.get("backend") in {"generic", "unknown"}:
            primary_score -= 100
        if project.get("audit_capable"):
            primary_score += 1
        project["audit_entry_score"] = primary_score

    eligible = [
        item for item in projects
        if bool(item.get("audit_capable"))
        and int(item.get("audit_entry_score", 0)) > 0
        and not re.search(
            r"(^|[/._-])(helper|helpers|common|toolbox|tools|benchmark|benchmarks|fixture|fixtures|mock|mocks)([/._-]|$)",
            " ".join(str(item.get(x) or "").lower() for x in ("name", "package_name", "relative")),
        )
    ]
    max_score = max((int(item.get("audit_entry_score", 0)) for item in eligible), default=0)
    ranked_eligible = sorted(
        eligible,
        key=lambda item: (
            -int(item.get("audit_entry_score", 0)),
            str(item.get("relative") or "").lower(),
        ),
    )
    primary_roots = (
        {Path(ranked_eligible[0]["root"]).resolve()}
        if ranked_eligible and max_score > 0
        else set()
    )

    for project in projects:
        root = Path(project["root"]).resolve()
        lower_identity = " ".join(
            str(value or "").lower()
            for value in (
                project.get("name"),
                project.get("package_name"),
                project.get("description"),
                project.get("relative"),
            )
        )
        explicit_support = bool(
            re.search(
                r"(^|[/._-])(helper|helpers|common|toolbox|tools|benchmark|benchmarks|fixture|fixtures|mock|mocks)([/._-]|$)",
                lower_identity,
            )
        )
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
        project["scope_hint"] = {
            "primary audit candidate": "primary audit candidate",
            "important dependency": "shared dependency",
            "component / library": "component / library",
            "support / tooling": "shared dependency" if project.get("depended_on_by") else "support / tooling",
        }.get(str(project.get("scope_role") or ""), str(project.get("scope_role") or ""))

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
        dirs[:] = sorted(
            d for d in dirs
            if d not in IGNORED_DIRS
            and not (
                universal_is_dependency_path is not None
                and universal_is_dependency_path(current_path / d, root)
            )
        )
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
        if cargo.is_file() and re.search(r"(?m)^\s*\[workspace(?:\.[^]]+)?\]", _read(cargo)):
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
def _has_multiple_nested_projects(root: Path, *, max_depth: int = 3) -> bool:
    count = 0
    for current, dirs, _files in os.walk(root):
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            continue
        dirs[:] = sorted(
            directory for directory in dirs
            if directory not in IGNORED_DIRS
            and not (
                universal_is_dependency_path is not None
                and universal_is_dependency_path(current_path / directory, root)
            )
        )
        if depth == 0:
            continue
        if depth > max_depth:
            dirs[:] = []
            continue
        if _is_project_candidate(current_path):
            count += 1
            if count > 1:
                return True
    return False

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
        if re.search(r"(?m)^\s*\[workspace(?:\.[^]]+)?\]", text):
            return True
    return not any((root / marker).is_file() for marker in PRIMARY_PROJECT_MARKERS) and _has_multiple_nested_projects(root)

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

    # Lowkey's own source checkout is a development/tooling tree, not an audit
    # workspace. Resolve this before canonical detection so an example project
    # inside the checkout cannot become the active audit root.
    if _is_lowkey_source_checkout(path):
        return path

    if canonical_project_root is not None:
        try:
            selected = Path(canonical_project_root(path)).resolve()
            if selected != path:
                return selected
            if path.is_dir() and _is_workspace_package(path):
                try:
                    from analysis_adapters import _workspace_manifest_member
                    member = _workspace_manifest_member(path)
                    if member is not None:
                        return Path(member).resolve()
                except (ImportError, OSError, ValueError):
                    pass
                candidates = discover_nested_projects(path)
                if len(candidates) == 1:
                    return Path(candidates[0]["root"]).resolve()
            return selected
        except Exception:
            pass

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
    """Compatibility source inventory backed by the canonical dependency-safe walker."""
    if universal_is_dependency_path is not None:
        try:
            from analysis_adapters import project_source_files as canonical_source_files
            paths = canonical_source_files(root, set(LANGUAGE_BY_SUFFIX) if LANGUAGE_BY_SUFFIX else None, include_support=True)
            counts: dict[str, int] = {}
            for path in paths:
                language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
                if language:
                    counts[language] = counts.get(language, 0) + 1
            return dict(sorted(counts.items()))
        except (ImportError, OSError, ValueError):
            pass

    counts: dict[str, int] = {}
    for path in _walk_files(root):
        language = LANGUAGE_BY_SUFFIX.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))

def detect_project(start: str | os.PathLike[str] = ".") -> dict[str, Any]:
    """Return the legacy project schema backed by the canonical analysis model."""
    if inspect_repository_canonical is not None:
        canonical = inspect_repository_canonical(start)
    else:
        canonical = {}

    requested_root = Path(start).expanduser().resolve()
    root = Path(canonical.get("root") or start).expanduser().resolve()

    # A workspace may contain one unambiguous real project. The canonical
    # aggregate detector can still report the workspace root, so resolve the
    # sole nested member before returning the legacy project schema.
    if root == requested_root and requested_root.is_dir() and _is_workspace_package(requested_root):
        selected = workspace_selection(requested_root)
        if selected is not None and selected.is_dir():
            root = selected.resolve()
        else:
            candidates = discover_nested_projects(requested_root)
            if len(candidates) == 1:
                root = Path(candidates[0]["root"]).resolve()

    if _is_lowkey_source_checkout(root):
        return {
            "root": str(root),
            "kind": "lowkey-source",
            "backend": "none",
            "build_backend": "none",
            "stacks": [],
            "languages": {},
            "supporting_tools": [],
            "native": {},
            "manifests": {},
            "analysis": canonical,
            "security_analyzers": canonical.get("security_analyzers", []),
        }

    source_counts = _source_counts(root)
    canonical_counts = dict(canonical.get("languages") or {})
    for language, count in canonical_counts.items():
        source_counts.setdefault(language, count)
    stacks = list(canonical.get("stacks") or [])
    backend = str(canonical.get("backend") or "unknown")

    # Compatibility fallback: the canonical control plane is authoritative,
    # but older embedding/test environments may import this module without the
    # sibling adapter being available. Recover only the minimum identity facts.
    if not stacks and backend in {"unknown", ""}:
        if (root / "foundry.toml").is_file():
            stacks = ["foundry"]
            backend = "foundry"
        elif any((root / name).is_file() for name in ("hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts")):
            stacks = ["hardhat"]
            backend = "hardhat"
        elif (root / "Anchor.toml").is_file():
            stacks = ["solana-anchor"]
            backend = "solana-anchor"
        elif (root / "Scarb.toml").is_file():
            stacks = ["cairo-starknet"]
            backend = "cairo-starknet"
        elif (root / "Move.toml").is_file():
            stacks = ["move"]
            backend = "move"
        elif (root / "Cargo.toml").is_file():
            stacks = ["cargo"]
            backend = "cargo"
        elif any((root / name).is_file() for name in ("ape-config.yaml", "ape-config.yml", "brownie-config.yaml", "brownie-config.yml")):
            stacks = ["vyper"]
            backend = "vyper"

    package_path = root / "package.json"
    pyproject_path = root / "pyproject.toml"
    package = {}
    package_text = _read(package_path)
    if package_path.is_file():
        try:
            loaded = json.loads(package_text)
            package = loaded if isinstance(loaded, dict) else {}
        except (TypeError, json.JSONDecodeError):
            package = {}

    manifests = {str(item) for item in (canonical.get("evidence") or {}).get("manifests", [])}
    has_foundry = "foundry.toml" in manifests or "foundry" in stacks
    has_scarb = "Scarb.toml" in manifests or "cairo-starknet" in stacks
    has_hardhat = "hardhat" in stacks
    has_anchor = "Anchor.toml" in manifests or "solana-anchor" in stacks
    has_move = "Move.toml" in manifests or "move" in stacks
    has_ape = any(name in manifests for name in ("ape-config.yaml", "ape-config.yml")) or "ape" in stacks
    has_brownie = any(name in manifests for name in ("brownie-config.yaml", "brownie-config.yml")) or "brownie" in stacks
    has_vyper = "vyper" in stacks or bool(source_counts.get("vyper") or source_counts.get("vyper-interface"))

    source_kind_map = {
        "solidity": "solidity-source",
        "vyper": "vyper",
        "cairo": "cairo",
        "rust": "rust",
        "move": "move-source",
    }
    if len(stacks) == 1:
        kind = stacks[0]
    elif len(stacks) > 1:
        kind = "multi-stack"
    else:
        kind = next(
            (value for language, value in source_kind_map.items() if source_counts.get(language)),
            "source-project" if source_counts else "unknown",
        )

    if backend == "evm-source":
        legacy_backend = "vyper" if has_vyper else "generic"
    elif backend in {"generic-source", "rust", "move-source", "unknown"}:
        legacy_backend = "generic"
    elif backend == "cairo":
        legacy_backend = "cairo-starknet"
    elif backend == "move":
        legacy_backend = "move"
    elif backend == "cairo":
        legacy_backend = "cairo-starknet"
    else:
        legacy_backend = backend

    # Brownie/Ape are Vyper execution environments; keep their legacy kind when
    # their explicit manifest exists, while the canonical model remains authoritative.
    if has_vyper and not has_foundry and not has_hardhat and not has_scarb and not has_anchor and not has_move:
        kind = "vyper"
        legacy_backend = "vyper"
    if has_foundry and has_vyper and len(stacks) >= 2:
        kind = "mixed-foundry-vyper"
        legacy_backend = "foundry"
    elif has_brownie and len(stacks) == 1:
        kind = "brownie"
        legacy_backend = "vyper"
    elif has_ape and len(stacks) == 1:
        kind = "vyper"
        legacy_backend = "vyper"
    elif has_scarb and len(stacks) == 1:
        kind = "cairo-starknet"
        legacy_backend = "cairo-starknet"
    elif has_anchor and len(stacks) == 1:
        kind = "solana-anchor"
        legacy_backend = "solana-anchor"
    elif has_move and len(stacks) == 1:
        kind = "move"
        legacy_backend = "move"
    elif has_hardhat and len(stacks) == 1:
        kind = "hardhat"
        legacy_backend = "hardhat"

    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    if isinstance(scripts, dict) and (scripts.get("build") or scripts.get("test")) and not has_hardhat:
        build_backend = "node-script"
    elif backend in {"cargo", "cosmwasm", "solana-anchor"} or "cargo" in stacks:
        build_backend = "cargo"
    elif "go" in stacks:
        build_backend = "go"
    elif "mix" in stacks:
        build_backend = "mix"
    elif "maven" in stacks:
        build_backend = "maven"
    elif "gradle" in stacks:
        build_backend = "gradle"
    elif "swift" in stacks:
        build_backend = "swift"
    elif "cmake" in stacks:
        build_backend = "cmake"
    elif backend:
        build_backend = legacy_backend
    else:
        build_backend = "generic"

    languages: list[str] = []
    for language in sorted(source_counts):
        if language in {"javascript", "typescript"}:
            if "javascript/typescript" not in languages:
                languages.append("javascript/typescript")
        else:
            languages.append(language)
    if package_path.is_file() and "javascript/typescript" not in languages:
        languages.append("javascript/typescript")
    if pyproject_path.is_file() and "python" not in languages:
        languages.append("python")

    supporting = []
    if package_path.is_file():
        supporting.append("node")
    if pyproject_path.is_file():
        supporting.append("python")
    if "cargo" in stacks or root.joinpath("Cargo.toml").is_file():
        supporting.append("cargo")
    if "go" in stacks or root.joinpath("go.mod").is_file():
        supporting.append("go")

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
        "cargo-audit": bool(shutil.which("cargo-audit")),
        "cargo-geiger": bool(shutil.which("cargo-geiger")),
    }

    return {
        "root": str(root),
        "kind": kind,
        "backend": legacy_backend,
        "build_backend": build_backend,
        "stacks": stacks,
        "languages": source_counts,
        "supporting_tools": supporting,
        "native": native,
        "manifests": {
            "foundry": has_foundry,
            "scarb": has_scarb,
            "hardhat": has_hardhat,
            "anchor": has_anchor,
            "move": has_move,
            "ape": has_ape,
            "brownie": has_brownie,
            "package_json": package_path.is_file(),
            "pyproject": pyproject_path.is_file(),
        },
        "analysis": canonical,
        "security_analyzers": list(canonical.get("security_analyzers") or []),
    }

def project_test_command(
    info: dict[str, Any] | None = None,
    root: str | os.PathLike[str] = ".",
) -> tuple[Path, list[str], str] | None:
    """Expose the shared native test planner to the detection/routing layer."""
    if shared_project_test_command is not None:
        return shared_project_test_command(info or detect_project(root), root)
    return None


def format_detection(info: dict[str, Any]) -> str:
    languages = info.get("languages", {})
    if isinstance(languages, dict):
        language_items = languages.items()
    elif isinstance(languages, (list, tuple, set)):
        language_items = ((str(name), 1) for name in languages)
    else:
        language_items = ()
    stacks = info.get("stacks", [])
    supporting = info.get("supporting_tools", [])
    native = [name for name, ok in (info.get("native") or {}).items() if ok]
    return "\n".join([
        "=== LOWKEY PROJECT DETECTION ===",
        f"Root       : {info.get('root')}",
        f"Type       : {info.get('kind', 'unknown')}",
        f"Backend    : {info.get('backend', 'generic')}",
        f"Build      : {info.get('build_backend', info.get('backend', 'generic'))}",
        f"Languages  : {', '.join(f'{name} ({count})' for name, count in language_items) or 'none'}",
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

def _native_timeout(default: int = 120) -> int:
    """Return a bounded timeout for native project commands.
    
    Unfamiliar-repository audits must not hang indefinitely on a broken or
    incompatible toolchain. Users can raise/lower this per environment.
    """
    try:
        value = int(os.environ.get("LOWKEY_NATIVE_TIMEOUT", str(default)))
    except ValueError:
        value = default
    return max(30, min(value, 1800))


def _python_test_paths(root: Path) -> list[Path]:
    paths = []
    for path in _walk_files(root):
        if path.suffix.lower() != ".py":
            continue
        relative = path.resolve().relative_to(root.resolve())
        if any(part in {"node_modules", ".git", ".audit", ".venv", "venv", "target", "build", "dist"} for part in relative.parts):
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py") or "tests" in {part.lower() for part in relative.parts[:-1]}:
            paths.append(path)
    return sorted(paths)


def _supplemental_native_tests(info: dict[str, Any]) -> int:
    """Run first-party Python/shell test suites that the protocol adapter cannot own."""
    root = Path(info["root"]).resolve()
    failures = 0

    python_tests = _python_test_paths(root)
    if python_tests:
        if shutil.which("pytest") or (root / "pyproject.toml").is_file() and shutil.which("uv") or _local_executable(root, "pytest"):
            command = _project_python_runner(root, "pytest", "-q")
            code, output = _run(command, root)
            _report_step("python tests", command, code, output)
            if code != 0:
                failures = failures or code
        else:
            print("DEFER  python tests — pytest/uv is not available.")
    
    for relative in ("tests.sh", "test.sh", "scripts/tests.sh", "scripts/test.sh"):
        script = root / relative
        if not script.is_file():
            continue
        command = ["bash", relative]
        code, output = _run(command, root)
        _report_step("script tests", command, code, output)
        if code != 0:
            failures = failures or code
        break

    return failures


def _run(command: Sequence[str], root: Path) -> tuple[int, str]:
    try:
        runtime_env, _node_pin = runtime_environment(root)
        result = subprocess.run(
            list(command),
            cwd=root,
            capture_output=True,
            text=True,
            timeout=_native_timeout(),
            env=runtime_env,
        )
    except subprocess.TimeoutExpired as exc:
        return 124, f"command timed out after {_native_timeout()}s"
    except OSError as exc:
        return 1, str(exc)
    output = (result.stdout or "") + (("\n" + result.stderr) if result.stderr else "")
    return result.returncode, output.strip()

def _report_step(label: str, command: Sequence[str], code: int, output: str) -> None:
    status = "PASS" if code == 0 else "TIMEOUT" if code == 124 else "FAIL"
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
        if (env_root / "pyproject.toml").is_file():
            return ["uv", "run", "python", "-c", shim, *args]
        for candidate in (
            env_root / ".venv" / "bin" / "python",
            env_root / "venv" / "bin" / "python",
        ):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return [str(candidate), "-c", shim, *args]
        # The namespace shim is still required when uv/venv is unavailable.
        # Fall back to the interpreter running Lowkey rather than plain pytest.
        return [sys.executable, "-c", shim, *args]
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


def bootstrap_project(
    info: dict[str, Any],
    args: Sequence[str] = (),
    *,
    force: bool = False,
    reason: str = "prepare",
) -> int:
    """Prepare the selected project through Lowkey's shared bootstrap engine."""
    if run_shared_bootstrap is None:
        print("DEFER  shared bootstrap engine is unavailable.")
        return 0
    # The shared bootstrap engine derives its plan from info and
    # intentionally does not consume audit CLI arguments. Keep native audit
    # preparation bounded so an unfamiliar repository cannot hang the console.
    try:
        timeout = _native_timeout()
    except NameError:
        timeout = 180
    return run_shared_bootstrap(info, force=force, reason=reason, timeout=timeout)


def bootstrap_status(info: dict[str, Any]) -> dict[str, Any]:
    """Expose diagnostics-only bootstrap state to CLI surfaces such as doctor."""
    if shared_bootstrap_status is None:
        return {
            "project_root": str(info.get("root") or ""),
            "workspace_root": str(info.get("root") or ""),
            "dependency_root": str(info.get("root") or ""),
            "actions": [],
            "runtime_requirements": {},
            "ready": True,
            "repairable": False,
        }
    return shared_bootstrap_status(info)


def classify_build_failure(output: str | None, command: Sequence[str] = ()) -> dict[str, Any]:
    if shared_classify_build_failure is None:
        return {
            "category": "source_or_build_error",
            "repairable": False,
            "reason": "Shared failure classifier is unavailable.",
        }
    return shared_classify_build_failure(output, command)


def project_build_command(info: dict[str, Any]) -> tuple[Path, list[str], str] | None:
    if shared_project_build_command is None:
        return None
    return shared_project_build_command(info)


def dependency_boundary(info: dict[str, Any] | str | os.PathLike[str]) -> Path:
    value = info.get("root") if isinstance(info, dict) else info
    if shared_dependency_boundary is None:
        return Path(value or ".").expanduser().resolve()
    return shared_dependency_boundary(value or ".")

def _hardhat_fork_spec(root: Path) -> tuple[str, int] | None:
    """Read the repository's pinned Hardhat fork endpoint and block."""
    config_candidates = (
        root / "hardhat.config.ts",
        root / "hardhat.config.js",
        root / "hardhat.config.cjs",
        root / "hardhat.config.mjs",
    )
    config_path = next((path for path in config_candidates if path.is_file()), None)
    if config_path is None:
        return None

    hardhat_text = _read(config_path)
    network_match = re.search(
        r'(?m)^\s*(?:export\s+const|const)\s+NETWORK\s*=\s*["\']([^"\']+)["\']',
        hardhat_text,
    )
    network = network_match.group(1) if network_match else None
    if not network:
        network_match = re.search(
            r'(?m)^\s*const\s+network\s*=\s*["\']([^"\']+)["\']',
            hardhat_text,
        )
        network = network_match.group(1) if network_match else None

    fork_path = root / "utils" / "forkConfig.ts"
    if not fork_path.is_file() or not network:
        return None
    fork_text = _read(fork_path)
    # Match both multiline object formatting and compact inline fork configs.
    network_match = re.search(
        rf"(?s){re.escape(network)}\s*:\s*\{{(.*?)\}}",
        fork_text,
    )
    if not network_match:
        return None
    block = network_match.group(1)

    url_match = re.search(
        r"""url\s*:\s*vars\.get\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*\)""",
        block,
    )
    if url_match:
        env_name, default_url = url_match.groups()
        url = os.environ.get(env_name, default_url)
    else:
        direct_url = re.search(r"""url\s*:\s*["']([^"']+)["']""", block)
        url = direct_url.group(1) if direct_url else None

    block_match = re.search(r"\bblockNumber\s*:\s*(\d+)", block)
    if not url or not block_match:
        return None
    return str(url), int(block_match.group(1))


def _historical_state_unavailable(output: str | None) -> bool:
    return bool(
        output
        and re.search(
            r"missing trie node|historical state .* is not available|historical state .* unavailable|state 0x[0-9a-f]+ is not available",
            output,
            re.IGNORECASE,
        )
    )


def _find_free_local_port(start: int = 9545) -> int:
    for port in range(start, start + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    return 0


def _run_hardhat_fork_fallback(
    root: Path,
    hardhat_binary: Path,
    command: Sequence[str],
) -> tuple[int, str, str] | None:
    """Retry fork-backed Hardhat tests through a temporary Hardhat JSON-RPC node."""
    spec = _hardhat_fork_spec(root)
    if spec is None:
        return None

    # A pinned fork needs historical state. Do not silently substitute a
    # latest-state RPC because that changes the semantics of the repository's
    # tests. An explicit Lowkey archive endpoint is the safe fallback.
    archive_url = os.environ.get("LOWKEY_ARCHIVE_RPC", "").strip()
    if not archive_url:
        return (
            1,
            "No LOWKEY_ARCHIVE_RPC is configured for the pinned Hardhat fork; "
            "the repository's current fork endpoint cannot serve the requested historical state.",
            "defer",
        )

    _fork_url, block_number = spec
    port = _find_free_local_port()
    if not port:
        return None

    env, _node_pin = runtime_environment(root)
    hardhat_node = subprocess.Popen(
        [
            str(hardhat_binary),
            "node",
            "--hostname",
            "127.0.0.1",
            "--port",
            str(port),
            "--fork",
            archive_url,
            "--fork-block-number",
            str(block_number),
        ],
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    try:
        ready = False
        for _ in range(60):
            if hardhat_node.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                    ready = True
                    break
            except OSError:
                time.sleep(0.25)

        if not ready:
            if hardhat_node.poll() is None:
                hardhat_node.terminate()
            output = ""
            try:
                output, _ = hardhat_node.communicate(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                output = ""
            message = f"Lowkey Hardhat fork failed to start. {output}".strip()
            if _historical_state_unavailable(output):
                return 1, message, "defer"
            return 1, message, "fail"

        fallback_command = [str(hardhat_binary), "--network", "localhost", "test"]
        print(
            f"RETRY  hardhat tests via local Hardhat fork at 127.0.0.1:{port} "
            f"(pinned block {block_number})"
        )
        fallback_code, fallback_output = _run(fallback_command, root)
        if fallback_code != 0 and _historical_state_unavailable(fallback_output):
            return fallback_code, fallback_output, "defer"
        return (
            fallback_code,
            fallback_output,
            "pass" if fallback_code == 0 else "fail",
        )
    finally:
        if hardhat_node.poll() is None:
            hardhat_node.terminate()
            try:
                hardhat_node.wait(timeout=5)
            except subprocess.TimeoutExpired:
                hardhat_node.kill()



def _run_native_security_analysis(info: dict[str, Any]) -> int:
    """Run installed non-EVM security tooling without inventing an audit verdict."""
    try:
        from analysis_adapters import run_security_analysis
    except ImportError:
        return 0

    analysis = info.get("analysis") if isinstance(info.get("analysis"), dict) else {}
    backend = str(info.get("_native_backend") or info.get("backend") or "").lower()
    if backend in {"foundry", "hardhat", "vyper"}:
        return 0

    if analysis:
        security_info = dict(analysis)
    else:
        security_info = {
            "root": str(info.get("root") or "."),
            "backend": backend,
            "stacks": list(info.get("stacks") or []),
            "languages": list(info.get("languages") or []),
        }

    try:
        result = run_security_analysis(security_info)
    except Exception as exc:
        print(f"FAIL  security analyzer dispatch: {exc}", file=sys.stderr)
        return 1

    results = result.get("results") or []
    if not results:
        print("DEFER  security analysis — no installed non-EVM security analyzer is available.")
        return 0

    failures = 0
    print("\nLOWKEY SECURITY ANALYSIS")
    print("========================")
    for item in results:
        status = str(item.get("status") or "unknown")
        print(f"  {item.get('name', 'analyzer')}: {status} (exit {item.get('exit_code', 1)})")
        if status != "passed":
            failures = failures or int(item.get("exit_code") or 1)
    return failures

def _run_native_child(parent_info: dict[str, Any], stack: str, args: Sequence[str]) -> int:
    """Dispatch one child backend while preserving the parent's detected scope."""
    child = dict(parent_info)
    child["backend"] = stack
    child["_native_backend"] = stack
    child["_bootstrap_done"] = True
    return run_native_audit(child, args)


def run_native_audit(info: dict[str, Any], args: Sequence[str] = ()) -> int:
    """Run safe native verification for non-Foundry stacks.

    This intentionally reports build/test evidence, not vulnerability verdicts.
    """
    root = Path(info["root"])
    if not info.get("_bootstrap_done"):
        bootstrap_code = bootstrap_project(info, args)
        if bootstrap_code != 0:
            return bootstrap_code

    # Parent multi-stack audits may dispatch a child backend explicitly.
    # Do not rediscover the project in that case: rediscovery collapses the
    # child back into "multi" and causes infinite multi -> child -> multi recursion.
    forced_backend = info.get("_native_backend")
    if forced_backend:
        backend = str(forced_backend)
        native = info.get("native", {})
    elif str(info.get("backend") or "").lower() not in {"", "generic", "unknown", "multi"}:
        backend = str(info.get("backend"))
        native = info.get("native", {})
    else:
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

    if backend == "evm-source":
        print("SOURCE-ONLY EVM: static Solidity analysis is available, but no EVM build/test harness was detected.")
        if shutil.which("slither"):
            try:
                from audit_engine import run_slither_project
                code = run_slither_project(str(root), info)
            except Exception as exc:
                print(f"FAIL  source Slither dispatch: {exc}", file=sys.stderr)
                code = 1
        else:
            print("DEFER  source Solidity checks — Slither is not installed.")
            code = 0
        failures = failures or code
        failures = failures or _supplemental_native_tests(info)
        return failures

    if backend == "cairo-starknet":
        if native.get("scarb"):
            step("cairo build", ["scarb", "build"])
            if native.get("snforge"):
                step("cairo tests", ["snforge", "test"])
            else:
                step("cairo tests", ["scarb", "test"])
        else:
            print("DEFER  cairo checks — Scarb is not installed.")
        security_code = _run_native_security_analysis(info)
        failures = failures or _supplemental_native_tests(info)
        return failures or security_code

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
            if command[:1] == ["uv"] and not shutil.which("uv"):
                command = [sys.executable, "-c", command[4], *command[5:]]
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
        security_code = _run_native_security_analysis(info)
        return failures or security_code

    if backend == "hardhat":
        boundary = dependency_boundary(info)
        binary = boundary / "node_modules" / ".bin" / "hardhat"
        if os.name == "nt":
            binary = binary.with_suffix(".cmd")
        if binary.is_file():
            step("hardhat compile", [str(binary), "compile"])

            test_command = [str(binary), "test"]
            test_code, test_output = _run(test_command, root)
            historical_state_issue = test_code != 0 and _historical_state_unavailable(test_output)
            if historical_state_issue:
                print(f"DEFER  hardhat tests        {' '.join(test_command)}")
                if test_output:
                    print("\n".join(test_output.splitlines()[-12:]))
            else:
                _report_step("hardhat tests", test_command, test_code, test_output)

            if historical_state_issue:
                fallback_result = _run_hardhat_fork_fallback(root, binary, test_command)
                if fallback_result is not None:
                    fallback_code, fallback_output, fallback_status = fallback_result
                    if fallback_output:
                        print("\n".join(fallback_output.splitlines()[-40:]))
                    if fallback_status == "defer":
                        test_code = 0
                        print(
                            "DEFER hardhat tests (fork fallback) — historical state is unavailable "
                            "or no archive RPC is configured."
                        )
                    elif fallback_code == 0:
                        test_code = 0
                        print("PASS  hardhat tests (local fork fallback)")
                    else:
                        print("FAIL  hardhat tests (local fork fallback)")
            if test_code != 0:
                failures = failures or test_code
        else:
            print(
                "DEFER  hardhat checks — local Hardhat binary not found at "
                f"{binary}. Lowkey did not use npx because that could download a different version."
            )
        security_code = _run_native_security_analysis(info)
        return failures or security_code

    if backend == "solana-anchor":
        if native.get("anchor"):
            step("anchor build", ["anchor", "build"])
        else:
            print("DEFER  anchor checks — Anchor is not installed.")
        security_code = _run_native_security_analysis(info)
        failures = failures or _supplemental_native_tests(info)
        return failures or security_code

    if backend == "move":
        if native.get("aptos"):
            step("aptos move tests", ["aptos", "move", "test"])
        elif native.get("sui"):
            step("sui move tests", ["sui", "move", "test"])
        else:
            print("DEFER  Move checks — no supported Move CLI found.")
        security_code = _run_native_security_analysis(info)
        failures = failures or _supplemental_native_tests(info)
        return failures or security_code

    if backend == "multi":
        print("MIXED STACK: running each detected native backend independently.")
        for stack in info.get("stacks", []):
            if stack == "foundry":
                print("  Foundry: handled by the existing Forge audit layer.")
                continue
            child_code = _run_native_child(info, stack, args)
            if child_code != 0:
                failures = failures or child_code
        failures = failures or _supplemental_native_tests(info)
        return failures

    build_backend = str(info.get("build_backend") or "").lower()
    if build_backend in {"node-script", "cargo", "go", "mix", "maven", "gradle", "swift"}:
        command_info = project_build_command(info)
        if command_info:
            _cwd, command, evidence = command_info
            step("project build", command)
            print(f"      evidence: {evidence}")
        else:
            print(f"DEFER  {build_backend} build — no executable project build command is available.")

        test_info = project_test_command(info)
        if test_info:
            _cwd, test_command, test_evidence = test_info
            step("project tests", test_command)
            print(f"      evidence: {test_evidence}")
        else:
            print(f"DEFER  {build_backend} tests — no executable project test command is available.")
        security_code = _run_native_security_analysis(info)
        failures = failures or _supplemental_native_tests(info)
        return failures or security_code

    print("STATIC-ONLY: no specialized project audit backend is installed.")
    print("Source inventory and manual review remain available.")
    security_code = _run_native_security_analysis(info)
    return failures or security_code

if __name__ == "__main__":
    print(format_detection(detect_project()))
