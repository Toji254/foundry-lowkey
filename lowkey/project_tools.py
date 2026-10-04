#!/usr/bin/env python3
"""Project detection and source-graph helpers for Lowkey.

The module is deliberately dependency-light. It discovers the project's own
toolchain/configuration instead of assuming Foundry or a src/ directory.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import sys
import subprocess
from pathlib import Path

LOWKEY_MODULE_DIR = Path(__file__).resolve().parent
if str(LOWKEY_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(LOWKEY_MODULE_DIR))
from typing import Any, Iterable, Sequence

try:
    from analysis_adapters import inspect_repository
except ImportError:
    inspect_repository = None

try:
    from project_detection import project_root as detected_project_root
except ImportError:
    detected_project_root = None

def _python_module_available(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False

def _local_executable(root: Path, name: str) -> str | None:
    """Find a project-local executable before falling back to PATH."""
    candidates = [
        root / ".venv" / "bin" / name,
        root / "venv" / "bin" / name,
        root / "node_modules" / ".bin" / name,
    ]
    for candidate in candidates:
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        except OSError:
            continue
    return None

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
    "broadcast",
    "artifacts",
    "build",
    "dist",
}


def project_root(root: str | Path = ".") -> Path:
    """Use the same workspace-aware root resolver as the Lowkey CLI."""
    path = Path(root).expanduser().resolve()
    if detected_project_root is not None:
        try:
            return Path(detected_project_root(path)).resolve()
        except Exception:
            pass
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
    """Legacy fallback walker; canonical callers use analysis_adapters."""
    files: list[Path] = []
    root = root.resolve()
    for current, dirs, names in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRS)

        current_path = Path(current)
        for name in names:
            path = current_path / name
            if path.suffix.lower() in suffixes:
                files.append(path)

    return sorted(files)


def project_source_files(root: str | Path = ".", languages: Iterable[str] | None = None) -> list[Path]:
    """Return first-party source files through the canonical repository walker."""
    root_path = project_root(root)
    wanted = {str(item).lower().lstrip(".") for item in (languages or {"sol", "vy", "vyi"})}
    suffixes = {"." + item for item in wanted}
    try:
        from analysis_adapters import project_source_files as universal_source_files
        return list(universal_source_files(root_path, suffixes, include_support=True))
    except (ImportError, OSError):
        return _walk_files(root_path, suffixes)


def _strip_source_comments(text: str, language: str, mask_strings: bool = False) -> str:
    """Remove comments while preserving source line structure for triage."""
    try:
        from analysis_adapters import _strip_comments as _universal_strip
        return _universal_strip(text, language, mask_strings=mask_strings)
    except ImportError:
        pass
    line_token = "#" if language == "vyper" else "//"
    block_open, block_close = ("/*", "*/") if language == "solidity" else (None, None)
    chars = list(text)
    state = "code"
    quote = ""
    escape = False
    i = 0
    single_quotes = {"solidity", "vyper", "vyper-interface"}
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if block_open and ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                i += 2; state = "block"; continue
            if line_token == "#" and ch == "#":
                chars[i] = " "; i += 1; state = "line"; continue
            if line_token == "//" and ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "; i += 2; state = "line"; continue
            if ch == '"' or (ch == "'" and language in single_quotes):
                quote = ch; escape = False; state = "string"
            i += 1; continue
        if state == "line":
            if ch == "\n": state = "code"
            elif ch != "\n": chars[i] = " "
            i += 1; continue
        if state == "block":
            if block_close and ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "; i += 2; state = "code"; continue
            if ch != "\n": chars[i] = " "
            i += 1; continue
        if escape:
            escape = False
            if mask_strings and ch != "\n": chars[i] = " "
        elif ch == "\\":
            escape = True
            if mask_strings: chars[i] = " "
        elif ch == quote:
            quote = ""; state = "code"
        elif mask_strings and ch != "\n":
            chars[i] = " "
        i += 1
    return "".join(chars)


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
    return bool(re.search(r"(?im)(?:^|\s)(?:[\"'])?vyper(?:[\"']?)(?:[<>=!~\s]|$)", content))


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
        item["initialized"] = item["present"] and any(
            entry.name != ".git" for entry in sub_path.iterdir()
        )
    return records


def _vyper_compiler_version(root: Path) -> str | None:
    """Return the installed Vyper compiler version when available."""
    del root  # Project-local compiler discovery can be added when needed.
    binary = shutil.which("vyper")
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    lines = (result.stdout or result.stderr).strip().splitlines()
    return lines[0].strip() if lines and lines[0].strip() else None


def _solidity_compiler_versions(root: Path) -> list[str]:
    versions: set[str] = set()
    for path in project_source_files(root, {"sol"}):
        text = _read(path)
        match = re.search(r"(?m)\bpragma\s+solidity\s+([^;]+);", text)
        if not match:
            continue
        expression = match.group(1)
        for version in re.findall(r"\b0\.(?:[0-9]+)\.(?:[0-9]+)\b", expression):
            versions.add(version)

    # Some projects pin the compiler in Python deployment/test code rather
    # than Solidity pragmas. Capture that exact pin as additional evidence.
    for path in _walk_files(root, {".py"}):
        text = _read(path)
        for version in re.findall(r"""(?m)\bsolc_version\s*[=:]\s*["'](0\.[0-9]+\.[0-9]+)["']""", text):
            versions.add(version)
    return sorted(versions)


def detect_project(root: str | Path = ".") -> dict[str, Any]:
    """Return project metadata from the canonical repository analysis model."""
    root_path = project_root(root)

    try:
        analysis = inspect_repository(root_path) if inspect_repository is not None else {}
    except Exception as exc:
        analysis = {
            "root": str(root_path),
            "backend": "unknown",
            "stacks": [],
            "languages": {},
            "source_files": [],
            "coverage": "unknown",
            "analysis_status": "detection-error",
            "security_analyzers": [],
            "error": str(exc),
        }

    source_counts = dict(analysis.get("languages") or {})
    relative_sources = [str(item) for item in (analysis.get("source_files") or [])]
    sol_files = [
        root_path / item for item in relative_sources
        if Path(item).suffix.lower() == ".sol"
    ]
    vy_files = [
        root_path / item for item in relative_sources
        if Path(item).suffix.lower() in {".vy", ".vyi"}
    ]
    cairo_files = [
        root_path / item for item in relative_sources
        if Path(item).suffix.lower() == ".cairo"
    ]

    package_json = root_path / "package.json"
    pyproject = root_path / "pyproject.toml"
    package = {}
    package_text = _read(package_json)
    if package_json.is_file():
        try:
            loaded = json.loads(package_text)
            package = loaded if isinstance(loaded, dict) else {}
        except (TypeError, json.JSONDecodeError):
            package = {}

    stacks = list(analysis.get("stacks") or [])
    backend = str(analysis.get("backend") or "generic")
    has_foundry = "foundry" in stacks
    has_vyper = "vyper" in stacks or bool(source_counts.get("vyper") or source_counts.get("vyper-interface"))
    has_hardhat = "hardhat" in stacks
    has_anchor = "solana-anchor" in stacks
    has_move = "move" in stacks
    has_scarb = "cairo-starknet" in stacks or "cairo" in source_counts
    has_ape = any((root_path / name).is_file() for name in ("ape-config.yaml", "ape-config.yml"))
    has_brownie = any((root_path / name).is_file() for name in ("brownie-config.yaml", "brownie-config.yml"))
    has_uv = pyproject.is_file() and shutil.which("uv") is not None

    if has_foundry and has_vyper:
        kind = "mixed-foundry-vyper"
    elif len(stacks) > 1:
        kind = "multi-stack"
    elif stacks:
        kind = stacks[0]
    elif source_counts.get("solidity"):
        kind = "solidity-source"
    elif source_counts.get("vyper") or source_counts.get("vyper-interface"):
        kind = "vyper"
    elif source_counts.get("cairo"):
        kind = "cairo"
    elif source_counts.get("rust"):
        kind = "rust"
    elif source_counts.get("move"):
        kind = "move-source"
    elif source_counts:
        kind = "source-project"
    else:
        kind = "unknown"

    if backend in {"evm-source", "generic-source", "rust", "move-source", "unknown"}:
        legacy_backend = "generic"
    elif backend == "cairo":
        legacy_backend = "cairo-starknet"
    elif backend == "move-source":
        legacy_backend = "move"
    else:
        legacy_backend = backend

    if has_foundry and has_vyper:
        legacy_backend = "foundry"
    elif len(stacks) == 1 and has_scarb:
        legacy_backend = "cairo-starknet"
        kind = "cairo-starknet"
    elif len(stacks) == 1 and has_anchor:
        legacy_backend = "solana-anchor"
        kind = "solana-anchor"
    elif len(stacks) == 1 and has_move:
        legacy_backend = "move"
        kind = "move"
    elif len(stacks) == 1 and has_hardhat:
        legacy_backend = "hardhat"
        kind = "hardhat"
    elif len(stacks) == 1 and has_vyper:
        legacy_backend = "vyper"
        kind = "brownie" if has_brownie else "vyper"

    systems = list(dict.fromkeys(stacks))
    if has_scarb and "scarb" not in systems:
        systems.append("scarb")
    if has_anchor and "anchor" not in systems:
        systems.append("anchor")
    if has_ape and "ape" not in systems:
        systems.append("ape")
    if has_brownie and "brownie" not in systems:
        systems.append("brownie")
    if has_uv:
        systems.append("uv")
    if package_json.is_file() and "node" not in systems:
        systems.append("node")
    if pyproject.is_file() and "python" not in systems:
        systems.append("python")
    if root_path.joinpath("go.mod").is_file() or root_path.joinpath("go.work").is_file():
        systems.append("go")
    if root_path.joinpath("mix.exs").is_file():
        systems.append("mix")
    if root_path.joinpath("pom.xml").is_file() or root_path.joinpath("mvnw").is_file():
        systems.append("maven")
    if any(root_path.joinpath(name).is_file() for name in ("build.gradle", "build.gradle.kts", "gradlew")):
        systems.append("gradle")
    if root_path.joinpath("Package.swift").is_file():
        systems.append("swift")
    if root_path.joinpath("CMakeLists.txt").is_file():
        systems.append("cmake")

    build_backend = legacy_backend
    scripts = package.get("scripts", {}) if isinstance(package, dict) else {}
    if isinstance(scripts, dict) and (scripts.get("build") or scripts.get("test")) and not has_hardhat:
        build_backend = "node-script"
    elif "cargo" in stacks or "cosmwasm" in stacks or "solana-anchor" in stacks:
        build_backend = "cargo"
    elif "go" in systems:
        build_backend = "go"
    elif "mix" in systems:
        build_backend = "mix"
    elif "maven" in systems:
        build_backend = "maven"
    elif "gradle" in systems:
        build_backend = "gradle"
    elif "swift" in systems:
        build_backend = "swift"
    elif "cmake" in systems:
        build_backend = "cmake"

    languages: list[str] = []
    for language in sorted(source_counts):
        if language in {"javascript", "typescript"}:
            if "javascript/typescript" not in languages:
                languages.append("javascript/typescript")
        else:
            languages.append(language)
    if package_json.is_file() and "javascript/typescript" not in languages:
        languages.append("javascript/typescript")
    if pyproject.is_file() and "python" not in languages:
        languages.append("python")

    supporting = []
    if package_json.is_file():
        supporting.append("node")
    if pyproject.is_file():
        supporting.append("python")
    if "cargo" in stacks or (root_path / "Cargo.toml").is_file():
        supporting.append("cargo")
    if "go" in systems:
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
        "vyper": bool(shutil.which("vyper") or _local_executable(root_path, "vyper") or _python_module_available("vyper")),
        "pytest": bool(shutil.which("pytest") or _local_executable(root_path, "pytest") or _python_module_available("pytest")),
        "boa": _python_module_available("boa"),
        "ape": bool(shutil.which("ape")),
        "brownie": bool(shutil.which("brownie")),
        "hardhat": (root_path / "node_modules" / ".bin" / "hardhat").is_file(),
        "anchor": bool(shutil.which("anchor")),
        "aptos": bool(shutil.which("aptos")),
        "sui": bool(shutil.which("sui")),
        "cargo-audit": bool(shutil.which("cargo-audit")),
        "cargo-geiger": bool(shutil.which("cargo-geiger")),
    }

    candidate_roots: list[str] = []
    for relative in relative_sources:
        parts = Path(relative).parts
        if parts and parts[0] not in candidate_roots:
            candidate_roots.append(parts[0])
    candidate_roots = candidate_roots or ["."]
    
    return {
        "root": str(root_path),
        "kind": kind,
        "languages": languages,
        "build_systems": systems,
        "configs": {
            "foundry": "foundry.toml" if has_foundry else None,
            "pyproject": "pyproject.toml" if pyproject.is_file() else None,
            "uv_lock": "uv.lock" if (root_path / "uv.lock").exists() else None,
            "package_json": "package.json" if package_json.is_file() else None,
            "hardhat": next((name for name in ("hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts") if (root_path / name).is_file()), None),
            "brownie": next((name for name in ("brownie-config.yaml", "brownie-config.yml") if (root_path / name).is_file()), None),
            "scarb": "Scarb.toml" if (root_path / "Scarb.toml").is_file() else None,
        },
        "python": {
            "requires_python": _python_requirement(_read(pyproject)) if pyproject.is_file() else None,
            "version_file": _read(root_path / ".python-version").strip() if (root_path / ".python-version").exists() else None,
            "uv_available": bool(shutil.which("uv")),
            "venv": str(root_path / ".venv") if (root_path / ".venv").is_dir() else None,
            "declared_dependencies": _pyproject_dependencies(_read(pyproject)) if pyproject.is_file() else [],
        },
        "submodules": _git_submodules(root_path),
        "solidity_compilers": _solidity_compiler_versions(root_path),
        "vyper_compiler": _vyper_compiler_version(root_path),
        "sources": {
            "solidity": len(sol_files),
            "vyper": len(vy_files),
            "cairo": len(cairo_files),
            "rust": int(source_counts.get("rust", 0)),
            "move": int(source_counts.get("move", 0)),
        },
        "analysis": analysis,
        "security_analyzers": list(analysis.get("security_analyzers") or []),
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


def _solidity_remappings(root: Path) -> list[tuple[str, str]]:
    """Read Foundry remappings so dependency resolution matches Forge."""
    values: list[tuple[str, str]] = []
    remappings_file = root / "remappings.txt"
    try:
        lines = remappings_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#") or "=" not in value:
            continue
        prefix, destination = (part.strip() for part in value.split("=", 1))
        if prefix and destination:
            values.append((prefix, destination))

    forge = shutil.which("forge")
    if forge:
        try:
            result = subprocess.run(
                [forge, "remappings"],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in (result.stdout or "").splitlines():
                    value = line.strip()
                    if not value or "=" not in value:
                        continue
                    prefix, destination = (part.strip() for part in value.split("=", 1))
                    if prefix and destination:
                        values.append((prefix, destination))
        except (OSError, subprocess.SubprocessError):
            pass

    result = []
    seen: set[tuple[str, str]] = set()
    for item in values:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return sorted(result, key=lambda item: len(item[0]), reverse=True)


def _solidity_external_candidates(raw: str, root: Path) -> list[Path]:
    clean = raw.strip().strip('"\'').replace("\\", "/")
    parts = [part for part in clean.split("/") if part]
    candidates: list[Path] = []
    for prefix, destination in _solidity_remappings(root):
        if clean.startswith(prefix):
            suffix = clean[len(prefix):].lstrip("/")
            candidates.append(root / destination.rstrip("/") / suffix)
    if parts:
        package_end = 2 if parts[0].startswith("@") and len(parts) >= 2 else 1
        package = "/".join(parts[:package_end])
        remainder = Path(*parts[package_end:]) if len(parts) > package_end else Path()
        candidates.append(root / "node_modules" / package / remainder)

        alias = parts[package_end - 1].split("@", 1)[0].lower()
        if alias:
            candidates.append(root / "node_modules" / alias / remainder)
            candidates.append(root / "lib" / alias / remainder)
        if len(parts) >= 2:
            versioned_name = parts[1].split("@", 1)[0].lower()
            if "solidity" in versioned_name or "rlp" in versioned_name:
                # Handle owner/package@version imports such as
                # hamdiallam/Solidity-RLP@2.0.7/contracts/RLPReader.sol.
                owner_package_remainder = Path(*parts[2:]) if len(parts) > 2 else Path()
                candidates.append(root / "node_modules" / versioned_name / owner_package_remainder)
                candidates.append(root / "lib" / versioned_name / owner_package_remainder)
                candidates.append(root / "node_modules" / parts[1] / owner_package_remainder)
                candidates.append(root / "lib" / parts[1] / owner_package_remainder)

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
    text = _strip_source_comments(text, language, mask_strings=True)
    if language == "solidity":
        pattern = re.compile(
            r'\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s+is\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*))?\s*\{'
        )
        for match in pattern.finditer(text):
            values.append({
                "kind": match.group(1),
                "name": match.group(2),
                "inherits": [
                    item.strip()
                    for item in (match.group(3) or "").split(",")
                    if item.strip()
                ],
                "line": text.count("\n", 0, match.start()) + 1,
            })
    elif language == "vyper":
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
    else:
        patterns = {
            "rust": r'(?m)^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(',
            "cairo": r'(?m)^\s*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(',
            "move": r'(?m)^\s*(?:public\s+)?(?:entry\s+)?fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(',
        }
        pattern = patterns.get(language)
        if pattern:
            for match in re.finditer(pattern, text):
                values.append({
                    "kind": "function",
                    "name": match.group(1),
                    "inherits": [],
                    "line": text.count("\n", 0, match.start()) + 1,
                })
    return values


def _call_sites(text: str, language: str) -> list[dict[str, Any]]:
    text = _strip_source_comments(text, language, mask_strings=True)
    if language == "solidity":
        patterns = [
            ("low-level-call", re.compile(r'\.(?:call|delegatecall|staticcall)\b[^\n]*')),
            # Deliberately exclude .call/.delegatecall/.staticcall here: the
            # project map reports those separately as low-level calls.
            ("external-call", re.compile(r'\.(?!(?:call|delegatecall|staticcall)\b)[A-Za-z_][A-Za-z0-9_]*\s*\(')),
        ]
    elif language == "vyper":
        patterns = [
            ("raw-call", re.compile(r'\braw_call\s*\([^\n]*')),
            ("external-call", re.compile(r'\b(?:extcall|staticcall)\s*[^\n]*')),
            ("value-transfer", re.compile(r'\bsend\s*\([^\n]*')),
            ("create", re.compile(r'\bcreate_(?:minimal_proxy_to|forwarder_to|from_blueprint)\b[^\n]*')),
        ]
    else:
        patterns = []
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
    analysis_files = []
    try:
        if inspect_repository is not None:
            analysis = inspect_repository(root_path)
            analysis_files = [root_path / item for item in (analysis.get("source_files") or [])]
    except Exception:
        analysis_files = []
    if not files and analysis_files:
        files = [path for path in analysis_files if path.is_file()]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []

    for path in files:
        suffix = path.suffix.lower()
        language = "solidity" if suffix == ".sol" else "vyper" if suffix in {".vy", ".vyi"} else suffix.lstrip(".") or "unknown"
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
                    "raw": raw,
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
                    "raw": raw,
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


def _protocol_node(node: dict[str, Any]) -> bool:
    """Keep the default human graph focused on application code, not generated helpers."""
    rel = str(node.get("file") or "").replace("\\", "/").lstrip("./")
    first = rel.split("/", 1)[0] if rel else ""
    if first in {"test", "tests", "script", "scripts"}:
        return False
    return first in {"src", "contracts", "vyper", "interfaces"} or not first


def _display_name(node: dict[str, Any]) -> str:
    declarations = node.get("declarations") or []
    names = [str(item.get("name")) for item in declarations if item.get("name")]
    return ", ".join(names) or str(node.get("file") or "unknown")


def render_project_map(root: str | Path = ".") -> dict[str, Any]:
    project = detect_project(root)
    graph = build_dependency_graph(root)

    workspace_info = None
    try:
        from project_detection import workspace_context
        scope = workspace_context(project["root"])
        if len(scope.get("projects") or []) > 1:
            workspace_info = {
                "root": str(scope["workspace"]),
                "current_project": str(Path(project["root"]).resolve()),
                "active_project": str(scope["active"]) if scope.get("active") else None,
                "project_count": len(scope["projects"]),
                "projects": scope["projects"],
            }
    except Exception:
        workspace_info = None

    protocol_nodes = [node for node in graph["nodes"] if _protocol_node(node)]
    protocol_ids = {node["id"] for node in protocol_nodes}
    protocol_edges = [
        edge for edge in graph["edges"]
        if edge.get("from") in protocol_ids
        and (
            edge.get("kind") == "import"
            or edge.get("kind") == "inherits"
        )
    ]
    support_nodes = [node for node in graph["nodes"] if node not in protocol_nodes]
    support_paths = [str(node.get("file")) for node in support_nodes]

    contracts = []
    interfaces = []
    for node in protocol_nodes:
        for declaration in node.get("declarations", []):
            if declaration.get("kind") == "contract":
                contracts.append((declaration["name"], node["file"], declaration.get("inherits") or []))
            elif declaration.get("kind") == "interface":
                interfaces.append((declaration["name"], node["file"]))

    imports = [edge for edge in protocol_edges if edge.get("kind") == "import"]
    inheritance = [edge for edge in protocol_edges if edge.get("kind") == "inherits"]
    low_level = [
        call for node in protocol_nodes
        for call in node.get("calls", [])
        if call.get("kind") == "low-level-call"
    ]
    external_calls = [
        call for node in protocol_nodes
        for call in node.get("calls", [])
        if call.get("kind") == "external-call"
    ]
    unresolved = [edge for edge in imports if not edge.get("resolved")]
    resolved_external = [
        edge for edge in imports
        if edge.get("external") and edge.get("resolved")
    ]

    print("LOWKEY PROJECT MAP")
    print("=" * 72)
    print(f"Project       : {project['root']}")
    if workspace_info:
        current_rel = Path(project["root"]).resolve().relative_to(Path(workspace_info["root"]).resolve()).as_posix()
        print(f"Workspace     : {workspace_info['root']}")
        print(f"Workspace app : {current_rel}")
        print(f"Projects      : {workspace_info['project_count']}")
        active = workspace_info.get("active_project")
        if active:
            print(f"Active scope  : {Path(active).resolve().relative_to(Path(workspace_info['root']).resolve()).as_posix()}")
    print(f"Type          : {project['kind']}")
    analysis = project.get("analysis") or {}
    if isinstance(analysis, dict):
        print(
            f"Analysis      : {analysis.get('analysis_status', 'unknown')} "
            f"(coverage: {analysis.get('coverage', 'unknown')})"
        )
    compiler_versions = list(project.get("solidity_compilers") or [])
    vyper_compiler = project.get("vyper_compiler")
    if vyper_compiler:
        compiler_versions.append(f"vyper {vyper_compiler}")
    print(f"Compiler      : {', '.join(compiler_versions or ['not detected'])}")
    print()
    print("1. WHAT IS THE PROTOCOL?")
    print("-" * 72)
    if contracts:
        for name, file, parents in contracts:
            parent_text = f" (inherits {', '.join(parents)})" if parents else ""
            print(f"  {name}{parent_text}")
            print(f"    Source: {file}")
    elif int(analysis.get("source_file_count", 0) or 0) > 0:
        print("  Application source was detected.")
        print("  ABI-style contract declarations are not available for this language/backend.")
        print("  Absence of contract findings is not a clean result; see coverage above.")
    else:
        print("  No application source detected; protocol security was not analyzed.")

    print()
    print("2. HOW DOES IT DEPEND ON OTHER CODE?")
    print("-" * 72)
    if imports:
        for edge in imports:
            destination = str(edge.get("to") or "unknown")
            if edge.get("resolved") and edge.get("external"):
                label = "external dependency"
            elif edge.get("resolved"):
                label = "local dependency"
            else:
                label = "NOT RESOLVED"
            print(f"  {edge['from']} -> {destination} [{label}]")
    else:
        print("  No imports detected in application code.")

    if inheritance:
        print()
        print("  Inheritance:")
        for edge in inheritance:
            status = "local" if edge.get("resolved") else "external/unknown"
            print(f"    {edge['from']} inherits {edge['to']} [{status}]")

    print()
    print("3. WHERE ARE THE SECURITY-RELEVANT CALLS?")
    print("-" * 72)
    print(
        f"  Low-level calls (.call/.delegatecall/.staticcall): {len(low_level)} "
        "(meaning: exact source syntax matched; trust: HIGH for the presence of that syntax, "
        "LOW for whether it is actually unsafe)"
    )
    print(
        f"  Other call sites detected by the heuristic:        {len(external_calls)} "
        "(meaning: the source-pattern scanner found possible call sites outside low-level calls; "
        "trust: LOW — false positives/negatives are possible, inspect the listed source)"
    )
    if low_level:
        for call in low_level[:12]:
            print(f"    line {call['line']}: {call['text']}")
        if len(low_level) > 12:
            print(f"    ... and {len(low_level) - 12} more")

    print()
    print("4. DEPENDENCY HEALTH")
    print("-" * 72)
    print(f"  Resolved application imports : {len([e for e in imports if e.get('resolved') and not e.get('external')])}")
    print(f"  Resolved external imports   : {len(resolved_external)}")
    print(f"  Unresolved imports           : {len(unresolved)}")
    if unresolved:
        for edge in unresolved[:12]:
            print(f"    FIX ME: {edge['from']}:{edge['line']} -> {edge['to']}")
        if len(unresolved) > 12:
            print(f"    ... and {len(unresolved) - 12} more")
    elif protocol_nodes:
        print("  All imports used by analyzed application code were resolved.")
    elif int(analysis.get("source_file_count", 0) or 0) > 0:
        print("  Dependency graph is not implemented for the detected non-EVM source language; not assessed.")
    else:
        print("  Dependency resolution was not assessed because no application code was analyzed.")

    print()
    print("5. FILES LOWKEY IS NOT CALLING 'PROTOCOL CODE'")
    print("-" * 72)
    if support_paths:
        print("  Tests/scripts/helpers are kept out of the default protocol graph:")
        for path in support_paths[:15]:
            print(f"    - {path}")
        if len(support_paths) > 15:
            print(f"    ... and {len(support_paths) - 15} more")
    else:
        print("  None detected.")

    print()
    print("HOW TO READ THIS")
    print("-" * 72)
    print("  Start with the contract(s) under section 1.")
    print("  Follow their imports/inheritance under section 2.")
    print("  Review low-level calls under section 3.")
    print("  Fix anything under 'NOT RESOLVED' before trusting the map.")
    print("  Generated PoCs/tests/scripts are evidence and tooling, not protocol logic.")

    human_graph = {
        "contracts": contracts,
        "interfaces": interfaces,
        "imports": imports,
        "inheritance": inheritance,
        "low_level_calls": low_level,
        "heuristic_external_calls": external_calls,
        "unresolved": unresolved,
        "support_files": support_paths,
    }
    result = {"project": project, "graph": graph, "human": human_graph}
    if workspace_info:
        result["workspace"] = workspace_info
    return result


__all__ = [
    "build_dependency_graph",
    "detect_project",
    "project_root",
    "project_source_files",
    "render_project_map",
]
