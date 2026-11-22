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
import stat
import sys
import subprocess
from pathlib import Path
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None

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
    from project_detection import is_workspace_root as detected_is_workspace_root
    from project_detection import workspace_root as detected_workspace_root
except ImportError:
    detected_project_root = None
    detected_is_workspace_root = None
    detected_workspace_root = None

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
    """Resolve package roots normally, but preserve an explicitly requested workspace root."""
    path = Path(root).expanduser().resolve()
    if path.is_dir() and detected_workspace_root is not None and detected_is_workspace_root is not None:
        try:
            workspace = Path(detected_workspace_root(path)).resolve()
            if workspace == path and detected_is_workspace_root(path):
                return path
        except Exception:
            pass
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




# Solidity source inventory limits mirror the bounded source-inspection policy
# used by Godmode. They prevent one command from reading unbounded repositories.
SOLIDITY_SOURCE_MAX_FILE_BYTES = 2_000_000
SOLIDITY_SOURCE_MAX_TOTAL_BYTES = 128 * 1024 * 1024

_SOLIDITY_SUPPORT_DIRS = {
    "test": "tests",
    "tests": "tests",
    "script": "scripts",
    "scripts": "scripts",
    "deploy": "deployment",
    "deployment": "deployment",
    "migrations": "migrations",
    "fixture": "fixtures",
    "fixtures": "fixtures",
    "mock": "mocks",
    "mocks": "mocks",
    "harness": "harnesses",
    "harnesses": "harnesses",
    "benchmark": "benchmarks",
    "benchmarks": "benchmarks",
    "audit": "audit-support",
    "audits": "audit-support",
    "certora": "formal-verification",
    "docs": "documentation",
    "doc": "documentation",
}


def _solidity_source_scope(path: Path, project: Path) -> str:
    try:
        parts = path.absolute().relative_to(project.absolute()).parts[:-1]
    except ValueError:
        parts = path.parts[:-1]
    for part in parts:
        scope = _SOLIDITY_SUPPORT_DIRS.get(str(part).lower())
        if scope:
            return scope
    return "application"


def _solidity_declarations(source: str) -> tuple[list[dict[str, str]], str]:
    """Extract top-level Solidity type declarations for inventory grouping."""
    cleaned = _strip_source_comments(source, "solidity", mask_strings=True)
    declarations = []
    pattern = re.compile(
        r"(?m)^\s*(abstract\s+contract|contract|interface|library)\s+([A-Za-z_]\w*)\b"
    )
    for match in pattern.finditer(cleaned):
        kind = " ".join(match.group(1).split())
        declarations.append({"kind": kind, "name": match.group(2)})
    kinds = {item["kind"] for item in declarations}
    labels = {
        "contract": "contracts",
        "abstract contract": "abstract contracts",
        "interface": "interfaces",
        "library": "libraries",
    }
    if not kinds:
        group = "no recognized declarations"
    elif len(kinds) > 1:
        group = "mixed declarations"
    else:
        group = labels.get(next(iter(kinds)), "other declarations")
    return declarations, group


def solidity_source_inventory(
    root: str | Path = ".",
    *,
    max_file_bytes: int = SOLIDITY_SOURCE_MAX_FILE_BYTES,
    max_total_bytes: int = SOLIDITY_SOURCE_MAX_TOTAL_BYTES,
) -> dict[str, Any]:
    """Inventory first-party .sol files, preserving paths and inspection failures.

    Known dependency directories are pruned using the same remapping/submodule
    boundary logic as the canonical repository source walker. Tests, scripts,
    fixtures, mocks and docs are still discovered and classified; callers decide
    whether to display application files, support files, or both.
    """
    if not isinstance(max_file_bytes, int) or max_file_bytes < 1:
        raise ValueError("max_file_bytes must be a positive integer")
    if not isinstance(max_total_bytes, int) or max_total_bytes < 1:
        raise ValueError("max_total_bytes must be a positive integer")

    requested = Path(root).expanduser()
    try:
        requested = requested.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise FileNotFoundError(f"Cannot resolve source root {root}: {error}") from error

    single_file = requested if requested.is_file() else None
    if single_file is not None:
        if single_file.suffix.lower() != ".sol":
            raise ValueError(f"Source file is not Solidity: {single_file}")
        scan_root = single_file.parent
    elif requested.is_dir():
        scan_root = requested
    else:
        raise FileNotFoundError(f"Source root does not exist: {requested}")

    package_root = project_root(scan_root)
    if not package_root.is_dir():
        package_root = scan_root

    files: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    excluded_directories: list[dict[str, str]] = []
    files_discovered = 0
    bytes_read = 0

    def relative(path: Path) -> str:
        try:
            return path.absolute().relative_to(package_root.absolute()).as_posix()
        except ValueError:
            return path.as_posix()

    def failure(path: Path, phase: str, error: object) -> None:
        failures.append({
            "path": relative(path),
            "phase": phase,
            "error": str(error),
        })

    adapters = None
    dependency_prefixes: set[str] = set()
    try:
        import analysis_adapters as adapters
        dependency_prefixes = set(adapters._dependency_prefixes(package_root))
    except (ImportError, OSError, TypeError, ValueError) as error:
        # Continue with fixed build/cache exclusions, but do not call this
        # inventory complete when dependency boundaries could not be established.
        failure(package_root, "dependency-boundary", error)

    def inspect_file(path: Path, entry: object | None = None) -> None:
        nonlocal files_discovered, bytes_read
        files_discovered += 1
        try:
            metadata = (
                entry.stat(follow_symlinks=False)
                if entry is not None
                else path.stat()
            )
        except OSError as error:
            failure(path, "stat", error)
            return
        if not stat.S_ISREG(metadata.st_mode):
            failure(path, "stat", "Source entry is not a regular file.")
            return
        size = int(metadata.st_size)
        if size > max_file_bytes:
            failure(
                path,
                "size-limit",
                f"File is {size} bytes; per-file limit is {max_file_bytes} bytes.",
            )
            return
        if bytes_read + size > max_total_bytes:
            failure(
                path,
                "inventory-budget",
                f"Reading this file would exceed the {max_total_bytes}-byte inventory limit.",
            )
            return
        try:
            raw = path.read_bytes()
            if len(raw) > max_file_bytes:
                failure(
                    path,
                    "size-limit",
                    f"File grew to {len(raw)} bytes; per-file limit is {max_file_bytes} bytes.",
                )
                return
            if bytes_read + len(raw) > max_total_bytes:
                failure(
                    path,
                    "inventory-budget",
                    f"Reading this file would exceed the {max_total_bytes}-byte inventory limit.",
                )
                return
            source = raw.decode("utf-8-sig")
        except (OSError, UnicodeError) as error:
            failure(path, "read", error)
            return

        bytes_read += len(raw)
        declarations, type_group = _solidity_declarations(source)
        files.append({
            "path": relative(path),
            "scope": _solidity_source_scope(path, package_root),
            "bytes": len(raw),
            "declarations": declarations,
            "type_group": type_group,
        })

    if single_file is not None:
        inspect_file(single_file)
    else:
        pending = [scan_root]
        while pending:
            current = pending.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = sorted(list(iterator), key=lambda item: item.name.casefold())
            except OSError as error:
                failure(current, "enumerate", error)
                continue

            child_directories: list[Path] = []
            for entry in entries:
                path = Path(entry.path)
                try:
                    if entry.is_symlink():
                        # A link can hide a Solidity file or an entire source subtree.
                        # Never follow it implicitly; report it so coverage stays honest.
                        failure(
                            path,
                            "symlink",
                            "Symlink was not followed; inspect its target explicitly.",
                        )
                        continue

                    is_directory = entry.is_dir(follow_symlinks=False)
                except OSError as error:
                    failure(path, "stat", error)
                    continue

                if is_directory:
                    if entry.name in EXCLUDED_DIRS or entry.name.startswith(".git"):
                        continue
                    if adapters is not None:
                        try:
                            if adapters._should_prune_directory(
                                package_root, current, entry.name, dependency_prefixes
                            ):
                                if adapters.is_dependency_path(
                                    path, package_root, dependency_prefixes
                                ):
                                    excluded_directories.append({
                                        "path": relative(path),
                                        "reason": "recognized dependency boundary",
                                    })
                                continue
                        except (OSError, RuntimeError, TypeError, ValueError) as error:
                            failure(path, "dependency-boundary", error)
                            continue
                    child_directories.append(path)
                    continue

                if entry.name.lower().endswith(".sol"):
                    inspect_file(path, entry)

            # LIFO traversal in reverse order preserves ascending folder order.
            pending.extend(reversed(child_directories))

    files.sort(key=lambda item: item["path"].casefold())
    failures.sort(key=lambda item: (item["path"].casefold(), item["phase"]))
    excluded_directories.sort(key=lambda item: item["path"].casefold())

    return {
        "root": str(package_root),
        "scan_root": str(scan_root),
        "files_discovered": files_discovered,
        "files_inspected": len(files),
        "bytes_read": bytes_read,
        "files": files,
        "uninspected": failures,
        "excluded_directories": excluded_directories,
        "complete": not failures,
    }


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
    """Return the installed Vyper compiler version for Vyper source scopes."""
    root = Path(root)
    if not project_source_files(root, {"vy"}):
        return None
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
    root = Path(root).resolve()
    versions: set[str] = set()
    for path in project_source_files(root, {"sol"}):
        if _solidity_source_scope(path, root) != "application":
            continue
        text = _read(path)
        match = re.search(r"(?m)\bpragma\s+solidity\s+([^;]+);", text)
        if not match:
            continue
        expression = match.group(1)
        for version in re.findall(r"\b0\.(?:[0-9]+)\.(?:[0-9]+)\b", expression):
            versions.add(version)

    # Python deployment/build pins are useful only when they come from
    # application code, not examples or test fixtures.
    for path in _walk_files(root, {".py"}):
        if _solidity_source_scope(path, root) != "application":
            continue
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
        "scope_type": analysis.get("scope_type", "repository"),
        "source_file_count": int(analysis.get("source_file_count", len(relative_sources))),
        "workspace": bool(analysis.get("workspace", False)),
        "workspace_members": list(analysis.get("workspace_members") or []),
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
    """Read package-local Foundry remappings and then ask Forge for its effective set."""
    values: list[tuple[str, str]] = []
    remappings_file = root / "remappings.txt"
    try:
        lines = remappings_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    if tomllib is not None and (root / "foundry.toml").is_file():
        try:
            config = tomllib.loads((root / "foundry.toml").read_text(encoding="utf-8", errors="replace"))
        except (OSError, tomllib.TOMLDecodeError, ValueError):
            config = {}
        raw_values = config.get("remappings", [])
        if isinstance(raw_values, list):
            lines.extend(str(item) for item in raw_values)
        profiles = config.get("profile", {})
        if isinstance(profiles, dict):
            active_profile = os.environ.get("FOUNDRY_PROFILE", "default")
            selected = profiles.get(active_profile)
            if isinstance(selected, dict) and isinstance(selected.get("remappings"), list):
                lines.extend(str(item) for item in selected["remappings"])
            default_profile = profiles.get("default")
            if isinstance(default_profile, dict) and isinstance(default_profile.get("remappings"), list):
                lines.extend(str(item) for item in default_profile["remappings"])
    for line in lines:
        value = str(line).strip()
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


def _solidity_external_candidates(
    raw: str,
    root: Path,
    remappings: Sequence[tuple[str, str]] | None = None,
) -> list[Path]:
    clean = raw.strip().strip('"\'').replace("\\", "/")
    parts = [part for part in clean.split("/") if part]
    candidates: list[Path] = []
    for prefix, destination in (list(remappings) if remappings is not None else _solidity_remappings(root)):
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

def _resolve_solidity_import(
    importer: Path,
    raw: str,
    root: Path,
    remappings: Sequence[tuple[str, str]] | None = None,
) -> Path | None:
    local = _resolve_local_import(importer, raw, root, "solidity")
    if local:
        return local
    for candidate in _solidity_external_candidates(raw, root, remappings):
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


def _vyper_import_label(raw: str, imported_names: str | None) -> str:
    """Give relative Vyper imports a useful unresolved target label."""
    clean = raw.strip()
    if clean in {".", ".."} and imported_names:
        symbols = _imported_symbols(imported_names)
        if symbols:
            return ", ".join(symbols)
    return clean


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


def _workspace_root_for(root: Path) -> Path:
    if detected_workspace_root is not None:
        try:
            return Path(detected_workspace_root(root)).resolve()
        except Exception:
            pass
    return root.resolve()


def _is_declared_dependency(path: Path, package_root: Path) -> bool:
    try:
        from analysis_adapters import is_dependency_path
        return bool(is_dependency_path(path, package_root))
    except (ImportError, OSError, ValueError):
        return False


def _import_provenance(resolved: Path | None, package_root: Path) -> str:
    if resolved is None:
        return "unresolved"
    resolved = resolved.resolve()
    if _is_declared_dependency(resolved, package_root):
        return "third-party"
    try:
        resolved.relative_to(package_root.resolve())
        return "same-package"
    except ValueError:
        pass
    workspace = _workspace_root_for(package_root)
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return "third-party"
    # A sibling package may have its own remapped lib/ directory. Respect that
    # package's own Foundry configuration before calling the path first-party.
    for parent in (resolved.parent, *resolved.parents):
        if (parent / "foundry.toml").is_file():
            if _is_declared_dependency(resolved, parent):
                return "third-party"
            break
        if parent == workspace:
            break
    return "workspace"


def _graph_relative(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        workspace = _workspace_root_for(root)
        try:
            path.resolve().relative_to(workspace)
            return Path(os.path.relpath(path.resolve(), root.resolve())).as_posix()
        except ValueError:
            return str(path.resolve())


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

    # Add transitive first-party imports, including sibling workspace packages.
    # Third-party libraries remain edges, not protocol nodes.
    remappings = _solidity_remappings(root_path)
    queue = list(files)
    known = {path.resolve() for path in files}
    while queue:
        importer = queue.pop(0)
        language = "solidity" if importer.suffix.lower() == ".sol" else "vyper" if importer.suffix.lower() in {".vy", ".vyi"} else ""
        if not language:
            continue
        source_text = _read(importer)
        if language == "solidity":
            imports = [
                _resolve_solidity_import(importer, raw, root_path, remappings)
                for raw, _line, _statement in _solidity_imports(source_text)
            ]
        else:
            imports = [
                _resolve_vyper_import(importer, raw, names, root_path)[0]
                for raw, _line, _statement, names in _vyper_imports(source_text)
            ]
        for resolved in imports:
            if resolved is None or resolved.suffix.lower() not in {".sol", ".vy", ".vyi"}:
                continue
            provenance = _import_provenance(resolved, root_path)
            if provenance not in {"same-package", "workspace"}:
                continue
            candidate = resolved.resolve()
            if candidate not in known and candidate.is_file():
                known.add(candidate)
                files.append(candidate)
                queue.append(candidate)
    files = sorted({path.resolve() for path in files})
    nodes: list[dict[str, Any]] = [];
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
                resolved = _resolve_solidity_import(path, raw, root_path, remappings)
                provenance = _import_provenance(resolved, root_path)
                edge = {
                    "from": rel,
                    "to": _graph_relative(resolved, root_path) if resolved else raw,
                    "raw": raw,
                    "kind": "import",
                    "line": line,
                    "statement": statement,
                    "resolved": bool(resolved),
                    "external": provenance == "third-party",
                    "provenance": provenance,
                    "workspace_dependency": provenance == "workspace",
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
                resolved, external_root = _resolve_vyper_import(
                    path, raw, imported_names, root_path
                )
                provenance = _import_provenance(resolved, root_path) if resolved else (
                    "third-party" if external_root is not None else "unresolved"
                )
                edge = {
                    "from": rel,
                    "to": _graph_relative(resolved, root_path) if resolved else (
                        str(external_root) if external_root else _vyper_import_label(raw, imported_names)
                    ),
                    "raw": raw,
                    "kind": "import",
                    "line": line,
                    "statement": statement,
                    "symbols": imported_names,
                    "resolved": bool(resolved or external_root),
                    "external": provenance == "third-party",
                    "provenance": provenance,
                    "workspace_dependency": provenance == "workspace",
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
            "local_imports": sum(
                1 for edge in edges
                if edge["kind"] == "import" and edge.get("provenance") == "same-package"
            ),
            "workspace_imports": sum(
                1 for edge in edges
                if edge["kind"] == "import" and edge.get("provenance") == "workspace"
            ),
            "external_call_sites": sum(len(node.get("calls", [])) for node in nodes),
        },
    }


def _protocol_node(node: dict[str, Any]) -> bool:
    """Exclude only explicitly recognized support paths from first-party analysis.

    Unknown source locations stay in the graph so the overview can label them
    UNCLASSIFIED instead of silently pretending they are tests or tooling.
    """
    rel = str(node.get("file") or "").replace("\\", "/").lstrip("./")
    parts = [part for part in rel.split("/") if part]
    support = {
        "test", "tests", "script", "scripts", "deploy", "deployment",
        "fixtures", "fixture", "mocks", "mock", "harness", "harnesses",
        "benchmarks", "benchmark", "docs", "doc", "out", "cache",
        "artifacts", "broadcast", "node_modules", ".audit",
    }
    return not any(part.lower() in support for part in parts[:-1])


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
    print("1. CONTRACT DECLARATIONS IN THE APPLICATION GRAPH")
    print("-" * 72)
    print("  Includes reusable first-party base contracts; this is not a protocol-only inventory.")
    application_source_count = int(analysis.get("source_file_count", 0) or 0)
    application_languages = analysis.get("languages") or {}
    inventory_summary = ", ".join(
        f"{str(language).lower()} ({int(count)})"
        for language, count in sorted(application_languages.items())
        if str(count).strip().lstrip("-").isdigit() and int(count) > 0
    ) if isinstance(application_languages, dict) else ""

    if contracts:
        for name, file, parents in contracts:
            parent_text = f" (inherits {', '.join(parents)})" if parents else ""
            print(f"  {name}{parent_text}")
            print(f"    Source: {file}")
    elif protocol_nodes:
        print("  Application source nodes were mapped, but no Solidity contract declarations were found.")
        if inventory_summary:
            print(f"  First-party application source inventory: {inventory_summary}")
        print("  Contract findings are not available from this declaration view.")
        print("  Absence of contract findings is not a clean result; see coverage above.")
    elif application_source_count:
        print(
            "  First-party application source inventory: "
            f"{inventory_summary or str(application_source_count) + ' source file(s)'}"
        )
        print("  No application Solidity/Vyper source nodes were mapped.")
        print("  Contract structure and call-site analysis were not performed for this source set.")
        print("  This is not a clean security result.")
    else:
        print("  No application contract source detected; protocol security was not analyzed.")

    print()
    print("2. HOW DOES IT DEPEND ON OTHER CODE?")
    print("-" * 72)
    if imports:
        for edge in imports:
            destination = str(edge.get("to") or "unknown")
            if edge.get("resolved") and edge.get("external"):
                label = "EXTERNAL DEPENDENCY"
            elif edge.get("resolved"):
                label = "LOCAL DEPENDENCY"
            else:
                label = "UNRESOLVED"
            print(f"  {edge['from']} -> {destination} | {label}")
    elif protocol_nodes:
        print("  No imports detected in the mapped application source nodes.")
    elif application_source_count:
        print("  Not assessed: no application contract nodes were mapped for this source inventory.")
        print("  Imports in the detected application language(s) are not represented by this graph.")
    else:
        print("  No application contract imports were mapped.")

    if inheritance:
        print()
        print("  Inheritance:")
        for edge in inheritance:
            status = "local" if edge.get("resolved") else "external/unknown"
            print(f"    {edge['from']} inherits {edge['to']} [{status}]")

    print()
    print("3. WHERE ARE THE SECURITY-RELEVANT CALLS?")
    print("-" * 72)
    mapped_application_languages = {
        str(node.get("language") or "").lower() for node in protocol_nodes
    }
    if "solidity" not in mapped_application_languages:
        print("  Solidity call-site scan: NOT APPLICABLE — no application Solidity source nodes were mapped.")
        print("  Zero matches here do not say anything about Python or excluded support/test files.")
    else:
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
    elif application_source_count:
        print("  Not assessed: no application contract graph was mapped for the detected source inventory.")
    else:
        print("  Dependency resolution was not assessed because no application contract source was mapped.")

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
    if contracts:
        print("  Start with the application contracts under section 1.")
        print("  Follow their imports/inheritance under section 2.")
        print("  Review the Solidity call sites under section 3.")
    elif protocol_nodes:
        print("  Application source nodes exist, but this view found no Solidity contract declarations.")
        print("  Check the source-language coverage before treating empty contract sections as meaningful.")
    else:
        print("  No application Solidity/Vyper source nodes were mapped in this scope.")
        print("  Section 5 lists support, documentation and test sources kept out of the application graph.")
        print("  Select the actual protocol package before relying on contract dependency or call-site results.")
    print("  Review unresolved imports in section 4; support-only failures are not production dependency failures.")
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


_PROJECT_SUPPORT_PARTS = {
    "test", "tests", "script", "scripts", "deploy", "deployment",
    "fixtures", "fixture", "mocks", "mock", "harness", "harnesses",
    "benchmarks", "benchmark", "docs", "doc", "out", "cache",
    "artifacts", "broadcast", "node_modules", ".audit",
}
_PROJECT_INTERFACE_PARTS = {"interface", "interfaces"}
_PROJECT_LIBRARY_PARTS = {"lib", "libs", "library", "libraries"}
_PROJECT_INFRASTRUCTURE_PARTS = {
    "access", "base", "common", "helpers", "math", "primitives",
    "security", "shared", "standards", "token", "utils", "utility",
}


def _project_source_role(
    node: dict[str, Any],
    *,
    support_paths: set[str] | None = None,
) -> str:
    """Classify a graph node for navigation, not for security judgement.

    Classification uses source declarations and generic path conventions.
    It deliberately does not infer protocol-specific names or risk levels.
    """
    path = str(node.get("file") or "").replace("\\", "/").lstrip("./")
    if not path:
        return "unclassified"

    parts = [part.lower() for part in path.split("/") if part]
    directories = parts[:-1]
    if (support_paths and path in support_paths) or any(
        part in _PROJECT_SUPPORT_PARTS for part in directories
    ):
        return "support"

    declarations = [
        item for item in (node.get("declarations") or [])
        if isinstance(item, dict)
    ]
    kinds = {
        str(item.get("kind") or "").strip().lower()
        for item in declarations
        if item.get("kind")
    }

    # Explicit declaration kinds are strong enough to classify these roles
    # even when a repository uses a nonstandard directory layout.
    if "interface" in kinds or any(
        part in _PROJECT_INTERFACE_PARTS for part in directories
    ):
        return "interface"
    if "library" in kinds or any(
        part in _PROJECT_LIBRARY_PARTS for part in directories
    ):
        return "library"
    if any(part in _PROJECT_INFRASTRUCTURE_PARTS for part in directories):
        return "infrastructure"

    # A contract/function declaration alone does not prove that a file belongs
    # to the application's source scope. Require a recognized source root;
    # unfamiliar paths remain visible as unclassified rather than being
    # silently promoted into the production architecture.
    source_roots = {
        "src", "source", "sources", "contracts", "programs", "vyper",
    }
    if any(part in source_roots for part in directories):
        return "application"
    return "unclassified"


def _project_structural_navigation(result: dict[str, Any]) -> dict[str, Any]:
    """Rank application and shared units separately by source-graph connectivity."""
    graph = result.get("graph") or {}
    human = result.get("human") or {}
    nodes = [
        node for node in (graph.get("nodes") or [])
        if isinstance(node, dict) and node.get("file")
    ]
    by_file = {str(node["file"]): node for node in nodes}
    support = {str(path) for path in (human.get("support_files") or [])}
    roles = {
        path: _project_source_role(node, support_paths=support)
        for path, node in by_file.items()
    }

    declarations_by_name: dict[str, set[str]] = {}
    for path, node in by_file.items():
        for declaration in node.get("declarations") or []:
            if not isinstance(declaration, dict):
                continue
            name = str(declaration.get("name") or "").strip()
            if name:
                declarations_by_name.setdefault(name, set()).add(path)

    incoming: dict[str, set[str]] = {}
    outgoing: dict[str, set[str]] = {}
    for edge in graph.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        source = str(edge.get("from") or "")
        if source not in by_file:
            continue

        kind = str(edge.get("kind") or "")
        destinations: set[str] = set()
        if kind == "import" and edge.get("resolved"):
            destination = str(edge.get("to") or "").replace("\\", "/")
            if destination in by_file:
                destinations.add(destination)
        elif kind == "inherits":
            matches = declarations_by_name.get(str(edge.get("to") or ""), set())
            if len(matches) == 1:
                destinations.update(matches)

        for destination in destinations:
            if destination == source:
                continue
            outgoing.setdefault(source, set()).add(destination)
            incoming.setdefault(destination, set()).add(source)

    def rank_rows(allowed_roles: set[str]) -> list[dict[str, Any]]:
        rows = []
        for path, node in by_file.items():
            role = roles.get(path, "unclassified")
            if role not in allowed_roles:
                continue
            inbound = incoming.get(path, set())
            outbound = outgoing.get(path, set())
            connections = len(inbound) + len(outbound)
            if connections <= 0:
                continue
            names = [
                str(item.get("name"))
                for item in (node.get("declarations") or [])
                if isinstance(item, dict) and item.get("name")
            ]
            label = (
                ", ".join(names[:2]) + (" ..." if len(names) > 2 else "")
                if names else path
            )
            rows.append({
                "file": path,
                "label": label,
                "role": role,
                "incoming": sorted(inbound, key=str.casefold),
                "outgoing": sorted(outbound, key=str.casefold),
                "connections": connections,
            })
        rows.sort(
            key=lambda item: (
                -item["connections"],
                -len(item["incoming"]),
                -len(item["outgoing"]),
                item["file"].casefold(),
            )
        )
        return rows

    return {
        "rows": rank_rows({"application"}),
        "shared_rows": rank_rows({"interface", "library", "infrastructure"}),
        "other_rows": rank_rows({"unclassified"}),
        "roles": roles,
    }


def _project_pretty_kind(value: object) -> str:
    raw = str(value or "unknown").strip()
    if raw.lower() == "unknown":
        return "Unknown"
    return " ".join(part.capitalize() for part in raw.replace("_", "-").split("-"))


def _project_display_name(node: dict[str, Any] | None, fallback: str) -> str:
    if not node:
        return fallback
    declarations = node.get("declarations") or []
    names = [
        str(item.get("name"))
        for item in declarations
        if isinstance(item, dict) and item.get("name")
    ]
    return ", ".join(names[:2]) or fallback


def render_project_overview(result: dict[str, Any], *, verbosity: int = 0) -> None:
    """Render a useful, language-neutral project orientation report.

    verbosity=0 is the decision-oriented overview; verbosity=1 expands the
    architecture relationships. The legacy full report remains available
    from render_project_map(), and JSON output is assembled by the CLI.
    """
    if verbosity not in {0, 1}:
        raise ValueError("overview verbosity must be 0 or 1")

    result = result if isinstance(result, dict) else {}
    project = result.get("project") or {}
    graph = result.get("graph") or {}
    human = result.get("human") or {}
    graph_summary = graph.get("summary") or {}
    nodes = [
        node for node in (graph.get("nodes") or [])
        if isinstance(node, dict) and node.get("file")
    ]
    edges = [
        edge for edge in (graph.get("edges") or [])
        if isinstance(edge, dict)
    ]

    languages = project.get("languages") or sorted({
        str(node.get("language"))
        for node in nodes
        if node.get("language")
    })
    if isinstance(languages, str):
        languages = [languages]
    language_label = ", ".join(str(item) for item in languages) or "not detected"
    build_systems = project.get("build_systems") or []
    if isinstance(build_systems, str):
        build_systems = [build_systems]
    build_label = ", ".join(str(item) for item in build_systems) or "not detected"

    compiler_versions = [
        str(item) for item in (project.get("solidity_compilers") or [])
        if item
    ]
    vyper_compiler = project.get("vyper_compiler")
    compiler_parts = []
    if compiler_versions:
        compiler_parts.append("Solidity " + ", ".join(compiler_versions))
    if vyper_compiler:
        compiler_parts.append("Vyper " + str(vyper_compiler))
    compiler_label = "; ".join(compiler_parts) or "not detected"

    analysis = project.get("analysis") or {}
    analysis_status = str(analysis.get("analysis_status") or "not assessed")
    coverage = str(analysis.get("coverage") or "not recorded")
    source_units = int(graph_summary.get("files", len(nodes)) or 0)
    declared_units = sum(1 for node in nodes if node.get("declarations"))
    declared_symbols = sum(
        len(node.get("declarations") or []) for node in nodes
    )

    navigation = _project_structural_navigation(result)
    roles = navigation["roles"]
    role_counts = {
        role: sum(1 for value in roles.values() if value == role)
        for role in (
            "application", "interface", "library", "infrastructure",
            "support", "unclassified",
        )
    }

    import_edges = [edge for edge in edges if edge.get("kind") == "import"]
    production_roles = {"application", "interface", "library", "infrastructure"}
    support_import_edges = [
        edge for edge in import_edges
        if roles.get(str(edge.get("from") or ""), "unclassified") == "support"
    ]
    production_import_edges = [
        edge for edge in import_edges
        if roles.get(str(edge.get("from") or ""), "unclassified") in production_roles
    ]
    unclassified_import_edges = [
        edge for edge in import_edges
        if roles.get(str(edge.get("from") or ""), "unclassified") == "unclassified"
    ]

    def dependency_counts(items: list[dict[str, Any]]) -> tuple[int, int, int, int]:
        total = len(items)
        resolved = sum(1 for edge in items if edge.get("resolved"))
        unresolved = total - resolved
        external = sum(
            1 for edge in items
            if edge.get("external") and edge.get("resolved")
        )
        return total, resolved, unresolved, external

    production_counts = dependency_counts(production_import_edges)
    support_counts = dependency_counts(support_import_edges)
    unclassified_counts = dependency_counts(unclassified_import_edges)
    inheritance_edges = [
        edge for edge in edges if edge.get("kind") == "inherits"
        and roles.get(str(edge.get("from") or ""), "unclassified") in production_roles
    ]

    # Use the application-graph call inventory. An empty list is meaningful:
    # do not fall back to whole-graph calls or unresolved imports.
    low_level = list(human.get("low_level_calls", []) or [])
    heuristic_calls = list(human.get("heuristic_external_calls", []) or [])
    app_rows = navigation["rows"]
    shared_rows = navigation["shared_rows"]
    other_rows = navigation["other_rows"]

    print("LOWKEY PROJECT OVERVIEW")
    print("=" * 72)
    print(f"Project       : {project.get('root') or graph.get('root') or 'unknown'}")
    print(f"Type          : {_project_pretty_kind(project.get('kind'))}")
    print(f"Languages     : {language_label}")
    print(f"Build systems : {build_label}")
    print(f"Compiler(s)   : {compiler_label}")
    if result.get("workspace"):
        workspace = result["workspace"]
        print(
            f"Workspace     : {workspace.get('project_count', 0)} project(s) "
            f"under {workspace.get('root', 'unknown')}"
        )

    print("")
    print("ANALYSIS HEALTH")
    print("-" * 72)
    print(f"Status        : {analysis_status}")
    print(f"Coverage      : {coverage}")
    analysis_scope = (
        analysis.get("scope_type")
        or project.get("scope_type")
        or "repository"
    )
    print(f"Scope         : {_project_pretty_kind(analysis_scope)}")
    print(
        f"Source units  : {source_units} mapped | {declared_units} "
        f"with declarations | {declared_symbols} declared symbols"
    )
    analyzed_sources = project.get("source_file_count")
    if analyzed_sources is not None:
        inventory_languages = analysis.get("languages") or {}
        language_counts = []
        if isinstance(inventory_languages, dict):
            for language, count in sorted(inventory_languages.items()):
                try:
                    count = int(count)
                except (TypeError, ValueError):
                    continue
                if count > 0:
                    language_counts.append(f"{str(language).lower()}: {count}")
        inventory_detail = f" | {', '.join(language_counts)}" if language_counts else ""
        print(
            "Triage inventory: "
            f"{int(analyzed_sources)} first-party source file(s)"
            f"{inventory_detail}"
        )
    if analysis.get("unsupported_languages"):
        print(
            "Unsupported source languages: "
            + ", ".join(str(item) for item in analysis["unsupported_languages"])
        )
    capabilities = analysis.get("capabilities") or {}
    if capabilities:
        capability_names = ("build", "tests", "coverage", "slither", "live_evm", "live_native")
        capability_text = ", ".join(
            f"{name}={'yes' if capabilities.get(name) else 'no'}"
            for name in capability_names if name in capabilities
        )
        if capability_text:
            print(f"Native capabilities: {capability_text}")
    analyzer_names = project.get("security_analyzers") or analysis.get("security_analyzers") or []
    if analyzer_names:
        print("Available analyzers: " + ", ".join(str(item) for item in analyzer_names))

    print("")
    print("PROJECT STRUCTURE")
    print("-" * 72)
    if source_units:
        print(f"Application contracts/modules : {role_counts['application']}")
        print(f"Interfaces                    : {role_counts['interface']}")
        print(f"Libraries                     : {role_counts['library']}")
        print(f"Shared infrastructure          : {role_counts['infrastructure']}")
        print(f"Tests/support/tooling           : {role_counts['support']}")
        if role_counts["unclassified"]:
            print(f"Unclassified source units       : {role_counts['unclassified']}")
        print(
            "Roles are inferred from declarations and generic path conventions; "
            "they are navigation hints, not semantic guarantees."
        )
    elif analyzed_sources:
        print(
            "Source-role breakdown is unavailable: the detected language/backend "
            "did not produce source nodes for this dependency graph."
        )
    else:
        print("No application source files were mapped for this project scope.")

    print("")
    print("DEPENDENCY HEALTH")
    print("-" * 72)
    print(
        "Production graph imports : "
        f"{production_counts[0]} total | {production_counts[1]} resolved | "
        f"{production_counts[2]} unresolved | {production_counts[3]} external"
    )
    print(
        "Support/test imports     : "
        f"{support_counts[0]} total | {support_counts[1]} resolved | "
        f"{support_counts[2]} unresolved | {support_counts[3]} external"
    )
    print(
        "Unclassified imports     : "
        f"{unclassified_counts[0]} total | {unclassified_counts[1]} resolved | "
        f"{unclassified_counts[2]} unresolved | {unclassified_counts[3]} external "
        "(scope not assumed)"
    )
    print(f"Production inheritance   : {len(inheritance_edges)} relationship(s)")

    unresolved_production = [
        edge for edge in production_import_edges if not edge.get("resolved")
    ]
    unresolved_support = [
        edge for edge in support_import_edges if not edge.get("resolved")
    ]
    unresolved_unclassified = [
        edge for edge in unclassified_import_edges if not edge.get("resolved")
    ]
    if unresolved_production:
        print("Unresolved production imports:")
        for edge in unresolved_production[:3]:
            print(
                f"  - {edge.get('from', 'unknown')} -> "
                f"{edge.get('to', 'unknown')}"
            )
    if unresolved_support:
        print("Unresolved support/test imports (not production dependencies):")
        for edge in unresolved_support[:3]:
            print(
                f"  - {edge.get('from', 'unknown')} -> "
                f"{edge.get('to', 'unknown')}"
            )
    if unresolved_unclassified:
        print("Unresolved imports from unclassified source units (scope unknown):")
        for edge in unresolved_unclassified[:3]:
            print(
                f"  - {edge.get('from', 'unknown')} -> "
                f"{edge.get('to', 'unknown')}"
            )
    if not unresolved_production and not unresolved_support and not unresolved_unclassified:
        print("No unresolved imports were recorded in the mapped source graph.")

    print("")
    print("APPLICATION ARCHITECTURE")
    print("-" * 72)
    print(
        "Most connected application components "
        "(imports/inheritance only; not a risk ranking or severity score):"
    )
    limit = 8 if verbosity == 1 else 5
    if app_rows:
        for row in app_rows[:limit]:
            print(
                f"  - {row['label']} [{row['file']}] "
                f"({len(row['incoming'])} used by, "
                f"{len(row['outgoing'])} dependencies)"
            )
    elif not nodes and analyzed_sources:
        print("  Application sources were detected, but this backend has no mapped component graph.")
    else:
        print("  No connected application contracts/modules were identified.")
    print("")
    print("SHARED BUILDING BLOCKS")
    print("-" * 72)
    print("Interfaces, libraries and common infrastructure are shown separately:")
    if shared_rows:
        for row in shared_rows[:(6 if verbosity == 1 else 4)]:
            print(
                f"  - {row['label']} [{row['file']}] "
                f"({len(row['incoming'])} consumers, "
                f"{len(row['outgoing'])} dependencies; {row['role']})"
            )
    else:
        print("  No connected shared building blocks were identified.")

    if verbosity == 1:
        by_file = {str(node["file"]): node for node in nodes}

        def print_relationships(title: str, rows: list[dict[str, Any]], cap: int) -> None:
            print("")
            print(title)
            print("-" * 72)
            if not rows:
                print("  No resolved first-party relationships are available.")
                return
            for row in rows[:cap]:
                print(f"{row['label']} [{row['file']}]")
                dependencies = row["outgoing"][:5]
                consumers = row["incoming"][:4]
                if dependencies:
                    print("  Depends on:")
                    for path in dependencies:
                        target = by_file.get(path)
                        label = _project_display_name(target, path)
                        role = roles.get(path, "unclassified")
                        print(f"    -> {label} [{role}: {path}]")
                if consumers:
                    print("  Referenced by:")
                    for path in consumers:
                        source = by_file.get(path)
                        label = _project_display_name(source, path)
                        print(f"    <- {label} [{path}]")
                if not dependencies and not consumers:
                    print("  No resolved first-party links.")

        print_relationships("RELATIONSHIP DETAIL — APPLICATION COMPONENTS", app_rows, 8)
        print_relationships("SHARED COMPONENT RELATIONSHIPS", shared_rows, 6)
        if other_rows:
            print("")
            print("UNCLASSIFIED CONNECTED SOURCE UNITS")
            print("-" * 72)
            for row in other_rows[:5]:
                print(f"  - {row['label']} [{row['file']}]")

    print("")
    print("SECURITY ORIENTATION")
    print("-" * 72)
    detected_languages = {
        str(item).lower() for item in (languages or [])
    }
    if "solidity" in detected_languages:
        print(f"Low-level call syntax matches : {len(low_level)}")
        print(
            f"Heuristic call-like patterns : {len(heuristic_calls)} "
            "(leads only; not vulnerability findings)"
        )
        print(
            "A zero pattern count is not proof of safety; check source coverage, "
            "runtime reachability and test evidence."
        )
    else:
        print(
            "Solidity low-level call-site counts are not applicable to the "
            "detected language set; use its native analyzer and manual source review."
        )

    print("")
    print("WHERE TO START")
    print("-" * 72)
    starting_steps = []
    source_counts = project.get("sources") or {}
    if int(source_counts.get("solidity", 0) or 0) > 0:
        starting_steps.append((
            "lk sources --scope application",
            "List first-party Solidity application files before choosing entry points."
        ))
    graph_has_links = bool(production_import_edges or inheritance_edges)
    if graph_has_links and any(
        str(node.get("language") or "").lower() in {"solidity", "vyper"}
        for node in nodes
    ):
        starting_steps.append((
            "lk deps",
            "Follow first-party imports and inheritance from the selected package."
        ))
    if capabilities.get("build") or capabilities.get("tests"):
        starting_steps.append((
            "lk audit",
            "Run the detected project's native audit checks and inspect the reported coverage."
        ))
    if not starting_steps:
        starting_steps.append((
            "lk doctor",
            "Check which native build, test and security tools are available for this project."
        ))
    for command, reason in starting_steps[:3]:
        print(f"  {command}")
        print(f"    Why: {reason}")

    print("")
    print("HOW TO EXPAND")
    print("-" * 72)
    print("  lk project -v    Expanded component relationships and shared dependencies")
    print("  lk project -vv   Full technical map and call-site report")
    print("  lk project --json  Complete machine-readable graph")
    print("  Connectivity is a navigation aid, not a security or severity score.")


__all__ = [
    "build_dependency_graph",
    "detect_project",
    "project_root",
    "project_source_files",
    "render_project_map",
    "render_project_overview",
]
