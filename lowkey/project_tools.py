#!/usr/bin/env python3
"""Project detection and source-graph helpers for Lowkey.

The module is deliberately dependency-light. It discovers the project's own
toolchain/configuration instead of assuming Foundry or a src/ directory.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Sequence

EXCLUDED_DIRS = {
    ".git",
    ".audit",
    ".venv",
    ".tox",
    ".nox",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "node_modules",
    "out",
    "cache",
    "lib",
    "broadcast",
    "artifacts",
    "build",
    "dist",
}


def project_root(root: str | Path = ".") -> Path:
    path = Path(root).resolve()
    if not path.is_dir():
        return path.parent
    if (path / "pyproject.toml").exists() or (path / "foundry.toml").exists() or (path / "package.json").exists():
        return path
    current = path
    for parent in [current, *current.parents]:
        if (
            (parent / "pyproject.toml").exists()
            or (parent / "foundry.toml").exists()
            or (parent / "package.json").exists()
        ):
            return parent
    return path


def _walk_files(root: Path, suffixes: set[str]) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        files.append(path)
    return sorted(files)


def project_source_files(root: str | Path = ".", languages: Iterable[str] | None = None) -> list[Path]:
    root_path = project_root(root)
    wanted = {str(item).lower().lstrip(".") for item in (languages or {"sol", "vy", "vyi"})}
    suffixes = {"." + item for item in wanted}
    return _walk_files(root_path, suffixes)


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _pyproject_vyper(content: str) -> bool:
    return bool(re.search(r"(?im)(?:^|\\s)(?:[\"'])?vyper(?:[\"']?)(?:[<>=!~\\s]|$)", content))


def _pyproject_dependencies(content: str) -> list[str]:
    values: list[str] = []
    in_dependencies = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_dependencies = stripped in {
                "[project]",
                "[project.optional-dependencies]",
                "[dependency-groups]",
            }
        if in_dependencies:
            match = re.search(r"""["']([A-Za-z0-9_.-]+)(?:\[[^]]+\])?(?:[<>=!~].*)?["']""", line)
            if match:
                values.append(match.group(1))
    return values


def _python_requirement(content: str) -> str | None:
    match = re.search(r"(?im)^\s*requires-python\s*=\s*[\"']([^\"']+)[\"']", content)
    return match.group(1) if match else None


def _git_submodules(root: Path) -> list[dict[str, Any]]:
    content = _read(root / ".gitmodules")
    if not content:
        return []

    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[submodule "):
            if current:
                records.append(current)
            current = {}
            continue
        if current is None or "=" not in stripped:
            continue
        key, value = (item.strip() for item in stripped.split("=", 1))
        if key == "path":
            current["path"] = value
        elif key == "url":
            current["url"] = value
    if current:
        records.append(current)

    for item in records:
        sub_path = root / str(item.get("path") or "")
        item["path"] = str(item.get("path") or "")
        item["present"] = sub_path.is_dir()
        item["initialized"] = item["present"] and any(sub_path.iterdir())
    return records


def detect_project(root: str | Path = ".") -> dict[str, Any]:
    root_path = project_root(root)
    pyproject = root_path / "pyproject.toml"
    package_json = root_path / "package.json"
    foundry_toml = root_path / "foundry.toml"
    hardhat_configs = [
        root_path / "hardhat.config.js",
        root_path / "hardhat.config.cjs",
        root_path / "hardhat.config.mjs",
        root_path / "hardhat.config.ts",
    ]
    brownie_config = root_path / "brownie-config.yaml"

    sol_files = project_source_files(root_path, {"sol"})
    vy_files = project_source_files(root_path, {"vy", "vyi"})

    pyproject_text = _read(pyproject)
    package_text = _read(package_json)
    has_uv = pyproject.exists() and shutil.which("uv") is not None
    has_vyper = bool(vy_files) or (pyproject.exists() and _pyproject_vyper(pyproject_text))
    has_foundry = foundry_toml.exists()
    has_hardhat = any(path.exists() for path in hardhat_configs) or (
        package_json.exists() and bool(re.search(r'["\']hardhat["\']', package_text))
    )
    has_brownie = brownie_config.exists()

    languages: list[str] = []
    if sol_files:
        languages.append("solidity")
    if vy_files or has_vyper:
        languages.append("vyper")
    if package_json.exists():
        languages.append("javascript/typescript")
    if pyproject.exists():
        languages.append("python")

    systems: list[str] = []
    if has_foundry:
        systems.append("foundry")
    if has_vyper:
        systems.append("vyper")
    if has_uv:
        systems.append("uv")
    if has_hardhat:
        systems.append("hardhat")
    if has_brownie:
        systems.append("brownie")

    if has_foundry and has_vyper:
        kind = "mixed-foundry-vyper"
    elif has_foundry:
        kind = "foundry"
    elif has_vyper and has_uv:
        kind = "vyper-uv"
    elif has_vyper:
        kind = "vyper"
    elif has_hardhat:
        kind = "hardhat"
    elif has_brownie:
        kind = "brownie"
    elif pyproject.exists():
        kind = "python"
    elif package_json.exists():
        kind = "node"
    else:
        kind = "generic"

    candidate_roots: list[str] = []
    for name in ("src", "contracts", "interfaces", "script", "scripts", "vyper"):
        path = root_path / name
        if path.is_dir() and name not in candidate_roots:
            candidate_roots.append(name)
    if not candidate_roots:
        observed = []
        for path in [*sol_files, *vy_files]:
            rel = Path(_relative(path.parent, root_path))
            first = rel.parts[0] if rel.parts else "."
            if first not in observed:
                observed.append(first)
        candidate_roots = observed or ["."]

    return {
        "root": str(root_path),
        "kind": kind,
        "languages": languages,
        "build_systems": systems,
        "configs": {
            "foundry": _relative(foundry_toml, root_path) if foundry_toml.exists() else None,
            "pyproject": _relative(pyproject, root_path) if pyproject.exists() else None,
            "uv_lock": _relative(root_path / "uv.lock", root_path) if (root_path / "uv.lock").exists() else None,
            "package_json": _relative(package_json, root_path) if package_json.exists() else None,
            "hardhat": next((_relative(path, root_path) for path in hardhat_configs if path.exists()), None),
            "brownie": _relative(brownie_config, root_path) if brownie_config.exists() else None,
        },
        "python": {
            "requires_python": _python_requirement(pyproject_text) if pyproject.exists() else None,
            "version_file": (
                _read(root_path / ".python-version").strip()
                if (root_path / ".python-version").exists()
                else None
            ),
            "uv_available": bool(shutil.which("uv")),
            "venv": str(root_path / ".venv") if (root_path / ".venv").is_dir() else None,
            "declared_dependencies": _pyproject_dependencies(pyproject_text) if pyproject.exists() else [],
        },
        "submodules": _git_submodules(root_path),
        "sources": {
            "solidity": len(sol_files),
            "vyper": len(vy_files),
        },
        "source_roots": candidate_roots,
    }


def _candidate_paths(importer: Path, raw: str, root: Path, language: str) -> list[Path]:
    clean = raw.strip().strip('"\'').replace("\\", "/")
    while clean.startswith("./"):
        clean = clean[2:]
    relative = Path(clean)
    candidates: list[Path] = []

    if language == "solidity":
        candidates.extend([importer.parent / relative, root / relative])
        if clean.startswith("@"):
            candidates.extend([root / "node_modules" / relative, root / "lib" / relative])
    else:
        module = clean.replace("/", ".")
        module_path = Path(*module.split(".")) if module else Path()
        candidates.extend([
            importer.parent / module_path,
            root / module_path,
            root / "contracts" / module_path,
            root / "interfaces" / module_path,
        ])

    expanded: list[Path] = []
    for candidate in candidates:
        expanded.append(candidate)
        if candidate.suffix == "":
            for suffix in (".sol", ".vy", ".vyi"):
                expanded.append(candidate.with_suffix(suffix))
    seen: set[Path] = set()
    result: list[Path] = []
    for path in expanded:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            result.append(resolved)
    return result


def _resolve_local_import(importer: Path, raw: str, root: Path, language: str) -> Path | None:
    for candidate in _candidate_paths(importer, raw, root, language):
        if candidate.is_file() and not any(part in EXCLUDED_DIRS for part in candidate.parts):
            return candidate
    return None


def _solidity_external_candidates(raw: str, root: Path) -> list[Path]:
    clean = raw.strip().strip('"\'').replace("\\", "/")
    parts = [part for part in clean.split("/") if part]
    candidates: list[Path] = []
    if parts:
        package_end = 2 if parts[0].startswith("@") and len(parts) >= 2 else 1
        package = "/".join(parts[:package_end])
        remainder = Path(*parts[package_end:]) if len(parts) > package_end else Path()
        candidates.append(root / "node_modules" / package / remainder)

        alias = parts[package_end - 1].split("@", 1)[0].lower()
        if alias:
            candidates.append(root / "node_modules" / alias / remainder)
            candidates.append(root / "lib" / alias / remainder)

        candidates.append(root / "lib" / parts[0] / Path(*parts[1:]))
    return candidates


def _resolve_solidity_import(importer: Path, raw: str, root: Path) -> Path | None:
    local = _resolve_local_import(importer, raw, root, "solidity")
    if local:
        return local
    for candidate in _solidity_external_candidates(raw, root):
        if candidate.is_file() and not any(part in {".git", ".audit", ".venv"} for part in candidate.parts):
            return candidate.resolve()
    return None


def _installed_package_root(root: Path, package: str) -> Path | None:
    venv = root / ".venv"
    if not venv.is_dir() or not package:
        return None
    for site in venv.glob("lib/python*/site-packages"):
        candidate = site / package
        if candidate.exists():
            return candidate.resolve()
    return None


def _imported_symbols(value: str | None) -> list[str]:
    if not value:
        return []
    symbols: list[str] = []
    for chunk in value.split(","):
        token = chunk.strip().split()
        if token and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token[0]):
            symbols.append(token[0])
    return symbols


def _resolve_vyper_import(
    importer: Path,
    raw: str,
    imported_names: str | None,
    root: Path,
) -> tuple[Path | None, Path | None]:
    local = _resolve_local_import(importer, raw, root, "vyper")
    if local:
        return local, None

    symbols = _imported_symbols(imported_names)
    module = raw.replace("/", ".")
    module_path = Path(*module.split(".")) if module else Path()
    local_dirs = [
        root / module_path,
        root / "contracts" / module_path,
        root / "interfaces" / module_path,
        importer.parent / module_path,
    ]
    for directory in local_dirs:
        if not directory.is_dir():
            continue
        for symbol in symbols:
            for suffix in (".vy", ".vyi"):
                candidate = directory / f"{symbol}{suffix}"
                if candidate.is_file() and not any(part in EXCLUDED_DIRS for part in candidate.parts):
                    return candidate.resolve(), None
        for path in sorted(directory.glob("*")):
            if path.suffix.lower() not in {".vy", ".vyi"} or not path.is_file():
                continue
            source = _read(path)
            if any(d.get("name") in symbols for d in _declarations(source, "vyper", path)):
                return path.resolve(), None

    package = module.split(".", 1)[0] if module else ""
    external_root = _installed_package_root(root, package)
    return None, external_root



def _solidity_imports(text: str) -> list[tuple[str, int, str]]:
    pattern = re.compile(r"""import\s+(?:[^;]*?\s+from\s+)?["']([^"']+)["']\s*;""")
    return [(match.group(1), text.count("\n", 0, match.start()) + 1, match.group(0).strip()) for match in pattern.finditer(text)]


def _vyper_imports(text: str) -> list[tuple[str, int, str, str | None]]:
    records: list[tuple[str, int, str, str | None]] = []
    for match in re.finditer(r'(?m)^\s*from\s+([A-Za-z0-9_./.-]+)\s+import\s+([^#\n]+)', text):
        records.append((
            match.group(1).strip(),
            text.count("\n", 0, match.start()) + 1,
            match.group(0).strip(),
            match.group(2).strip(),
        ))
    for match in re.finditer(r'(?m)^\s*import\s+([A-Za-z0-9_./.-]+)', text):
        records.append((
            match.group(1).strip(),
            text.count("\n", 0, match.start()) + 1,
            match.group(0).strip(),
            None,
        ))
    return records


def _declarations(text: str, language: str, path: Path) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    if language == "solidity":
        for match in re.finditer(r'\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+is\s+([^\{]+))?', text):
            values.append({
                "kind": match.group(1),
                "name": match.group(2),
                "inherits": [
                    item.strip().split()[0]
                    for item in (match.group(3) or "").split(",")
                    if item.strip()
                ],
                "line": text.count("\n", 0, match.start()) + 1,
            })
    else:
        for match in re.finditer(r'(?m)^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(', text):
            values.append({
                "kind": "function",
                "name": match.group(1),
                "inherits": [],
                "line": text.count("\n", 0, match.start()) + 1,
            })
        for match in re.finditer(r'(?m)^\s*interface\s+([A-Za-z_][A-Za-z0-9_]*)\s*:', text):
            values.append({
                "kind": "interface",
                "name": match.group(1),
                "inherits": [],
                "line": text.count("\n", 0, match.start()) + 1,
            })
    return values


def _call_sites(text: str, language: str) -> list[dict[str, Any]]:
    patterns = (
        [
            ("low-level-call", re.compile(r'\.(?:call|delegatecall|staticcall)\b[^\n]*')),
            ("external-call", re.compile(r'\.[A-Za-z_][A-Za-z0-9_]*\s*\(')),
        ]
        if language == "solidity"
        else [
            ("raw-call", re.compile(r'\braw_call\s*\([^\n]*')),
            ("external-call", re.compile(r'\b(?:extcall|staticcall)\s*[^\n]*')),
            ("value-transfer", re.compile(r'\bsend\s*\([^\n]*')),
            ("create", re.compile(r'\bcreate_(?:minimal_proxy_to|forwarder_to|from_blueprint)\b[^\n]*')),
        ]
    )
    calls: list[dict[str, Any]] = []
    for label, pattern in patterns:
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            calls.append({"kind": label, "line": line, "text": match.group(0).strip()})
    calls.sort(key=lambda item: (item["line"], item["kind"]))
    return calls


def build_dependency_graph(root: str | Path = ".") -> dict[str, Any]:
    root_path = project_root(root)
    files = project_source_files(root_path)
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []

    for path in files:
        language = "solidity" if path.suffix.lower() == ".sol" else "vyper"
        text = _read(path)
        rel = _relative(path, root_path)
        declarations = _declarations(text, language, path)
        nodes.append({
            "id": rel,
            "file": rel,
            "language": language,
            "declarations": declarations,
            "calls": _call_sites(text, language),
        })

        if language == "solidity":
            for raw, line, statement in _solidity_imports(text):
                local = _resolve_local_import(path, raw, root_path, language)
                resolved = _resolve_solidity_import(path, raw, root_path)
                edge = {
                    "from": rel,
                    "to": _relative(resolved, root_path) if resolved else raw,
                    "kind": "import",
                    "line": line,
                    "statement": statement,
                    "resolved": bool(resolved),
                    "external": local is None,
                }
                edges.append(edge)
                if not edge["resolved"]:
                    unresolved.append(edge)

            for declaration in declarations:
                for parent in declaration["inherits"]:
                    edges.append({
                        "from": rel,
                        "to": parent,
                        "kind": "inherits",
                        "line": declaration["line"],
                        "resolved": any(
                            d.get("name") == parent
                            for n in nodes
                            for d in n.get("declarations", [])
                        ),
                        "external": False,
                    })
        else:
            for raw, line, statement, imported_names in _vyper_imports(text):
                local = _resolve_local_import(path, raw, root_path, language)
                resolved, external_root = _resolve_vyper_import(
                    path, raw, imported_names, root_path
                )
                edge = {
                    "from": rel,
                    "to": _relative(resolved, root_path) if resolved else (
                        str(external_root) if external_root else raw
                    ),
                    "kind": "import",
                    "line": line,
                    "statement": statement,
                    "symbols": imported_names,
                    "resolved": bool(resolved or external_root),
                    "external": local is None and external_root is not None,
                }
                edges.append(edge)
                if not edge["resolved"]:
                    unresolved.append(edge)

    declaration_names = {
        declaration["name"]
        for node in nodes
        for declaration in node.get("declarations", [])
        if declaration.get("kind") in {"contract", "interface", "library"}
    }
    for edge in edges:
        if edge["kind"] == "inherits" and edge["to"] in declaration_names:
            edge["resolved"] = True

    return {
        "root": str(root_path),
        "nodes": nodes,
        "edges": edges,
        "unresolved": unresolved,
        "summary": {
            "files": len(nodes),
            "imports": sum(1 for edge in edges if edge["kind"] == "import"),
            "inheritance": sum(1 for edge in edges if edge["kind"] == "inherits"),
            "unresolved_imports": len(unresolved),
            "external_imports": sum(
                1 for edge in edges
                if edge["kind"] == "import" and edge.get("external")
            ),
            "external_call_sites": sum(len(node.get("calls", [])) for node in nodes),
        },
    }


def render_project_map(root: str | Path = ".") -> dict[str, Any]:
    project = detect_project(root)
    graph = build_dependency_graph(root)
    print("LOWKEY PROJECT")
    print("=" * 72)
    print(f"Root      : {project['root']}")
    print(f"Type      : {project['kind']}")
    print(f"Languages : {', '.join(project['languages']) or 'none detected'}")
    print(f"Toolchains: {', '.join(project['build_systems']) or 'none detected'}")
    print(
        f"Sources   : Solidity {project['sources']['solidity']} | "
        f"Vyper {project['sources']['vyper']}"
    )
    print(f"Roots     : {', '.join(project['source_roots'])}")
    python = project.get("python", {})
    if python.get("version_file"):
        print(f"Python    : {python['version_file']}")
    submodules = project.get("submodules", [])
    if submodules:
        ready = sum(1 for item in submodules if item.get("initialized"))
        print(f"Submodules: {ready}/{len(submodules)} initialized")
    print("\nSYSTEM GRAPH")
    print("-" * 72)
    for node in graph["nodes"]:
        declarations = ", ".join(
            f"{item['kind']} {item['name']}" for item in node.get("declarations", [])
        )
        print(f"{node['file']:<52} [{node['language']}]")
        if declarations:
            print(f"  declarations: {declarations}")
        for call in node.get("calls", []):
            print(f"  call-site: {call['kind']} @ line {call['line']}")
    for edge in graph["edges"]:
        marker = "OK" if edge.get("resolved") else "UNRESOLVED"
        print(f"  {marker:<10} {edge['from']} -> {edge['to']} ({edge['kind']})")
    external_edges = [
        edge for edge in graph["edges"]
        if edge["kind"] == "import" and edge.get("external")
    ]
    if external_edges:
        print("\nExternal imports:")
        for edge in external_edges:
            status = "RESOLVED" if edge.get("resolved") else "UNRESOLVED"
            print(f"  {status:<10} {edge['from']}:{edge['line']} -> {edge['to']}")
    if graph["unresolved"]:
        print("\nUnresolved imports:")
        for edge in graph["unresolved"]:
            print(f"  {edge['from']}:{edge['line']} -> {edge['to']}")
    return {"project": project, "graph": graph}


__all__ = [
    "build_dependency_graph",
    "detect_project",
    "project_root",
    "project_source_files",
    "render_project_map",
]
