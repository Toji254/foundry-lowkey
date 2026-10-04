#!/usr/bin/env python3
"""Repository-wide project inspection and capability routing for Lowkey.

This module is deliberately independent of the CLI and language-specific
analysis engines. It provides one stable contract for unfamiliar repositories:
detect what is present, choose an analysis scope, and report coverage honestly.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 compatibility
    tomllib = None

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".audit", ".venv", "venv", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
    ".idea", ".vscode", "node_modules", "vendor", "vendors",
    "out", "cache", "broadcast", "artifacts", "build", "dist", "target",
    "coverage", "coverage-html", ".gradle", ".next", ".turbo", ".direnv",
}


# Dependency paths are derived from repository evidence instead of treating
# conventional names such as `lib/` as dependencies automatically.
DEPENDENCY_CONTAINER_DIRS = {"lib", "libs"}

def _dependency_prefixes(root: Path) -> set[str]:
    prefixes: set[str] = set()
    gitmodules = root / ".gitmodules"
    if gitmodules.is_file():
        for line in _safe_read(gitmodules).splitlines():
            match = re.match(r"\s*path\s*=\s*(.+?)\s*$", line)
            if match:
                value = match.group(1).strip().replace("\\", "/").strip("./")
                if value:
                    prefixes.add(value)
    remappings = root / "remappings.txt"
    if remappings.is_file():
        for line in _safe_read(remappings).splitlines():
            value = line.strip()
            if not value or value.startswith("#") or "=" not in value:
                continue
            _prefix, destination = (part.strip() for part in value.split("=", 1))
            destination = destination.replace("\\", "/").strip("./")
            if destination:
                prefixes.add(destination.rstrip("/"))
    return prefixes

def _is_dependency_path(path: Path, root: Path, prefixes: set[str] | None = None) -> bool:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix().strip("./")
    except (OSError, ValueError):
        relative = path.as_posix().strip("./")
    if not relative:
        return False
    known = prefixes if prefixes is not None else _dependency_prefixes(root)
    for prefix in known:
        if relative == prefix or relative.startswith(prefix + "/"):
            return True
        # Never prune the container itself just because one of its children is
        # a known dependency. This keeps first-party lib/*.sol source visible.
        if prefix.startswith(relative + "/") and relative in DEPENDENCY_CONTAINER_DIRS:
            continue
    if any(
        relative.startswith(prefix + "/") and
        relative.split("/", 1)[0] in DEPENDENCY_CONTAINER_DIRS
        for prefix in known
    ):
        return True
    if relative in DEPENDENCY_CONTAINER_DIRS:
        return False
    first = relative.split("/", 1)[0]
    if first in DEPENDENCY_CONTAINER_DIRS:
        candidate = root / relative
        try:
            if (candidate / ".git").exists():
                return True
        except OSError:
            pass
    return False

# Public alias: other Lowkey modules import this boundary check as
# is_dependency_path (see analysis_adapters.__all__). Keep the leading
# underscore name working for internal callers, but expose the public symbol so
# the canonical control plane is not silently disabled by an ImportError.
is_dependency_path = _is_dependency_path

def _should_prune_directory(root: Path, current: Path, name: str, prefixes: set[str]) -> bool:
    if name in IGNORED_DIRS or name.startswith(".git"):
        return True
    candidate = current / name
    return _is_dependency_path(candidate, root, prefixes)

SUPPORT_PATH_PARTS = {
    "test", "tests", "script", "scripts", "deploy", "deployment",
    "migrations", "fixtures", "fixture", "mocks", "mock", "harness",
    "harnesses", "benchmarks", "benchmark", "audit", "audits", "certora",
    "docs", "doc",
}

SUFFIX_LANGUAGE = {
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
    ".yul": "yul",
    ".huff": "huff",
}

ADAPTERS = {
    "foundry": {
        "kind": "evm",
        "languages": {"solidity", "yul", "huff", "vyper"},
        "markers": {"foundry.toml"},
        "capabilities": {"build": True, "tests": True, "coverage": True, "slither": True, "live_evm": True, "live_native": False},
    },
    "hardhat": {
        "kind": "evm",
        "languages": {"solidity", "vyper", "typescript", "javascript"},
        "markers": {"hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts"},
        "capabilities": {"build": True, "tests": True, "coverage": True, "slither": True, "live_evm": True, "live_native": False},
    },
    "evm-source": {
        "kind": "evm",
        "languages": {"solidity", "vyper", "vyper-interface", "yul", "huff"},
        "markers": set(),
        "capabilities": {"build": False, "tests": False, "coverage": False, "slither": True, "live_evm": False, "live_native": False},
    },
    "vyper": {
        "kind": "evm",
        "languages": {"vyper", "vyper-interface"},
        "markers": {"ape-config.yaml", "ape-config.yml", "brownie-config.yaml", "brownie-config.yml"},
        "capabilities": {"build": True, "tests": True, "coverage": False, "slither": False, "live_evm": True, "live_native": False},
    },
    "cosmwasm": {
        "kind": "cosmwasm",
        "languages": {"rust"},
        "markers": {"Cargo.toml"},
        "capabilities": {"build": True, "tests": True, "coverage": False, "slither": False, "live_evm": False, "live_native": True},
    },
    "solana-anchor": {
        "kind": "solana",
        "languages": {"rust"},
        "markers": {"Anchor.toml"},
        "capabilities": {"build": True, "tests": True, "coverage": False, "slither": False, "live_evm": False, "live_native": True},
    },
    "cargo": {
        "kind": "rust",
        "languages": {"rust"},
        "markers": {"Cargo.toml"},
        "capabilities": {"build": True, "tests": True, "coverage": False, "slither": False, "live_evm": False, "live_native": True},
    },
    "cairo": {
        "kind": "cairo",
        "languages": {"cairo"},
        "markers": {"Scarb.toml"},
        "capabilities": {"build": True, "tests": True, "coverage": False, "slither": False, "live_evm": False, "live_native": True},
    },
    "move": {
        "kind": "move",
        "languages": {"move"},
        "markers": {"Move.toml"},
        "capabilities": {"build": True, "tests": True, "coverage": False, "slither": False, "live_evm": False, "live_native": True},
    },
}

EVM_MARKERS = {
    "REENTRANCY REVIEW": re.compile(r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()"),
    "ETH TRANSFER REVIEW": re.compile(r"\.(?:transfer|send)\s*\("),
    "TX.ORIGIN": re.compile(r"\btx\.origin\b"),
    "DELEGATECALL": re.compile(r"\bdelegatecall\b"),
    "SELFDESTRUCT": re.compile(r"\bselfdestruct\s*\("),
    "UNCHECKED": re.compile(r"\bunchecked\s*\{"),
    "ASSEMBLY": re.compile(r"\bassembly\s*\{"),
    "ENCODE_PACKED": re.compile(r"\babi\.encodePacked\s*\("),
    "TIMESTAMP": re.compile(r"\bblock\.timestamp\b"),
    "BLOCKHASH/PREVRANDAO": re.compile(r"\bblock\.hash\b|\bblockhash\s*\(|\bblock\.prevrandao\b"),
    "ECRECOVER": re.compile(r"\becrecover\s*\("),
    "CREATE2": re.compile(r"\bcreate2\b"),
}

VYPER_MARKERS = {
    "RAW_CALL": re.compile(r"\braw_call\s*\("),
    "EXTERNAL_CALL": re.compile(r"\b(?:extcall|staticcall)\b"),
    "ETH TRANSFER": re.compile(r"\bsend\s*\("),
    "CREATE": re.compile(r"\bcreate_(?:minimal_proxy_to|forwarder_to|from_blueprint)\b"),
    "SELFDESTRUCT": re.compile(r"\bselfdestruct\s*\("),
    "TX.ORIGIN": re.compile(r"\btx\.origin\b"),
    "TIMESTAMP": re.compile(r"\bblock\.timestamp\b"),
    "BLOCK NUMBER": re.compile(r"\bblock\.number\b"),
    "PREV HASH": re.compile(r"\bblock\.prevhash\b"),
}

RUST_MARKERS = {
    "UNSAFE": re.compile(r"\bunsafe\s*\{"),
    "RAW_POINTER": re.compile(r"\b(?:std::ptr|core::ptr|from_raw|as\s+\*mut|as\s+\*const)\b"),
    "FFI": re.compile(r"\bextern\s+\"C\"\b"),
    "POTENTIAL_PANIC": re.compile(r"\bunwrap\s*\(|\bexpect\s*\("),
    "RAW_SYSCALL": re.compile(r"\bsyscall\b|\binvoke_signed\b"),
}

CAIRO_MARKERS = {
    "UNSAFE": re.compile(r"\bunsafe\b"),
    "SYSCALL": re.compile(r"\bsyscall\b|\bcall_contract\b"),
    "RAW_CALL": re.compile(r"\bcall_contract_syscall\b|\bdeploy_syscall\b"),
}

MOVE_MARKERS = {
    "ENTRYPOINT": re.compile(r"\bpublic\s+entry\b"),
    "FRIEND": re.compile(r"\bfriend\b"),
    "TRANSFER": re.compile(r"\btransfer\b|\bpublic_transfer\b"),
    "ASSERT": re.compile(r"\bassert!\b|\babort!\b"),
}

def _is_lowkey_source_checkout(root: Path) -> bool:
    """Recognize Lowkey's own source checkout from a stable on-disk identity."""
    try:
        resolved = root.resolve()
    except OSError:
        resolved = root
    if not (resolved / "lowkey" / "lk.py").is_file():
        return False
    return (
        (resolved / "lowkey" / "project_detection.py").is_file()
        and (resolved / "install.sh").is_file()
    )

def _safe_resolve(root: str | os.PathLike[str]) -> Path:
    try:
        path = Path(root).expanduser().resolve()
    except OSError:
        path = Path(root).expanduser().absolute()
    return path

def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, UnicodeError):
        return ""

def _safe_walk_files(root: Path) -> Iterable[Path]:
    def onerror(_exc: OSError) -> None:
        return None
    prefixes = _dependency_prefixes(root)
    try:
        walker = os.walk(root, onerror=onerror, followlinks=False)
    except OSError:
        return
    for current, dirs, files in walker:
        current_path = Path(current)
        dirs[:] = sorted(
            name for name in dirs
            if not _should_prune_directory(root, current_path, name, prefixes)
        )
        current_path = Path(current)
        for name in sorted(files):
            try:
                yield current_path / name
            except OSError:
                continue

def _is_support_path(path: Path, root: Path) -> bool:
    try:
        parts = path.resolve().relative_to(root.resolve()).parts
    except (OSError, ValueError):
        parts = path.parts
    return any(part.lower() in SUPPORT_PATH_PARTS for part in parts[:-1])

def project_source_files(
    root: str | os.PathLike[str] = ".",
    extensions: set[str] | None = None,
    *,
    include_support: bool = True,
) -> list[Path]:
    """Return dependency-safe source files for graph/tooling consumers.

    Support directories such as scripts/tests remain visible by default because
    callers such as dependency-graph builders need them. Security triage uses
    the stricter internal _source_files() path instead.
    """
    requested = _safe_resolve(root)
    if requested.is_file():
        if requested.suffix.lower() not in (extensions or set(SUFFIX_LANGUAGE)):
            return []
        if not include_support and _is_support_path(requested, requested.parent):
            return []
        return [requested]
    paths = list(_safe_walk_files(requested))
    if extensions:
        paths = [path for path in paths if path.suffix.lower() in extensions]
    if not include_support:
        paths = [path for path in paths if not _is_support_path(path, requested)]
    return sorted(path for path in paths if path.suffix.lower() in set(SUFFIX_LANGUAGE))

def _source_files(root: Path) -> list[Path]:
    recognized = set(SUFFIX_LANGUAGE)
    if root.is_file():
        if root.suffix.lower() in recognized and not _is_support_path(root, root.parent):
            return [root]
        return []
    return sorted(
        path for path in _safe_walk_files(root)
        if path.suffix.lower() in recognized and not _is_support_path(path, root)
    )

def _source_counts(paths: Iterable[Path]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for path in paths:
        language = SUFFIX_LANGUAGE.get(path.suffix.lower())
        if language:
            counts[language] = counts.get(language, 0) + 1
    return dict(sorted(counts.items()))

def _json_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = json.loads(_safe_read(path))
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}

def _toml_object(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    content = _safe_read(path)
    if not content:
        return {}
    if tomllib is not None:
        try:
            value = tomllib.loads(content)
            return value if isinstance(value, dict) else {}
        except tomllib.TOMLDecodeError:
            return {}
    return {}

def _cargo_workspace(root: Path, cargo: dict[str, Any]) -> bool:
    if isinstance(cargo.get("workspace"), dict):
        return True
    # TOML parse failures must not become recursion/crash triggers.
    text = _safe_read(root / "Cargo.toml")
    return bool(re.search(r"(?m)^\s*\[workspace(?:\.[^\]]+)?\]\s*$", text))

def _package_workspace(package: dict[str, Any]) -> bool:
    workspaces = package.get("workspaces")
    return bool(workspaces)

def _manifest_stack(root: Path) -> tuple[list[str], list[str]]:
    package = _json_object(root / "package.json")
    cargo = _toml_object(root / "Cargo.toml")
    sources = _source_files(root)
    languages = {SUFFIX_LANGUAGE.get(path.suffix.lower()) for path in sources}
    languages.discard(None)

    stacks: list[str] = []
    # An EVM build toolchain is only meaningful when the repository actually
    # contains EVM source. A stray foundry.toml / hardhat config next to a
    # different ecosystem must not hijack backend selection or create a
    # no-op Forge "Nothing to compile" success.
    evm_source = bool(
        {"solidity", "vyper", "vyper-interface", "yul", "huff"} & languages
    )
    if (root / "foundry.toml").is_file() and evm_source:
        stacks.append("foundry")
    if evm_source and any((root / name).is_file() for name in (
        "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts"
    )):
        stacks.append("hardhat")
    cargo_dependencies = cargo.get("dependencies", {}) if isinstance(cargo, dict) else {}
    cargo_dev_dependencies = cargo.get("dev-dependencies", {}) if isinstance(cargo, dict) else {}
    cargo_dep_names = []
    for section in (cargo_dependencies, cargo_dev_dependencies):
        if isinstance(section, dict):
            cargo_dep_names.extend(str(name).lower() for name in section)
    cosmwasm_dependency = any(name.startswith("cosmwasm") for name in cargo_dep_names)
    if cosmwasm_dependency and (root / "Cargo.toml").is_file():
        stacks.append("cosmwasm")
    if (root / "Anchor.toml").is_file():
        stacks.append("solana-anchor")
    if (root / "Move.toml").is_file() or "move" in languages:
        stacks.append("move")
    if (root / "Scarb.toml").is_file() or "cairo" in languages:
        stacks.append("cairo-starknet")
    if ((root / "Cargo.toml").is_file() or "rust" in languages) and "cosmwasm" not in stacks and "solana-anchor" not in stacks:
        stacks.append("cargo")

    vyper = "vyper" in languages or "vyper-interface" in languages
    if vyper or any((root / name).is_file() for name in (
        "ape-config.yaml", "ape-config.yml", "brownie-config.yaml", "brownie-config.yml"
    )):
        stacks.append("vyper")
    package_sections = [
        package.get("dependencies", {}),
        package.get("devDependencies", {}),
        package.get("peerDependencies", {}),
        package.get("optionalDependencies", {}),
    ]
    hardhat_dependency = any(
        isinstance(section, dict)
        and any(
            key == "hardhat" or key.startswith("@nomicfoundation/hardhat")
            for key in section
        )
        for section in package_sections
    )
    hardhat_scripts = (
        any(
            isinstance(value, str) and "hardhat" in value.lower()
            for value in (package.get("scripts") or {}).values()
        )
        if isinstance(package.get("scripts"), dict)
        else False
    )
    if (hardhat_dependency or hardhat_scripts) and evm_source:
        if "hardhat" not in stacks:
            stacks.append("hardhat")

    # Add source-only EVM as a secondary adapter only after all manifest-backed
    # stacks have been discovered. This prevents a Hardhat dependency/script
    # from being classified as mixed merely because Solidity is present.
    if "solidity" in languages and not {"foundry", "hardhat"} & set(stacks):
        relative_solidity = [
            path.resolve().relative_to(root.resolve())
            for path in sources
            if path.suffix.lower() == ".sol"
        ]
        app_roots = {"src", "contracts", "solidity", "packages", "apps", "app"}
        if any(
            relative.parts and relative.parts[0].lower() in app_roots
            for relative in relative_solidity
        ):
            stacks.append("evm-source")

    return sorted(dict.fromkeys(stacks)), sorted(str(x) for x in languages)

def _choose_backend(stacks: list[str], sources: dict[str, int]) -> str:
    if len(stacks) == 1:
        stack = stacks[0]
        if stack == "cargo":
            return "cargo"
        return stack
    if len(stacks) > 1:
        # Prefer explicit protocol tooling over generic package-manager signals.
        for candidate in ("foundry", "hardhat", "cairo-starknet", "solana-anchor", "cosmwasm", "move", "vyper", "evm-source", "cargo"):
            if candidate in stacks and candidate != "cargo":
                return candidate if len([x for x in stacks if x != "cargo"]) == 1 else "multi"
        return "multi"
    if sources.get("solidity") or sources.get("vyper") or sources.get("vyper-interface"):
        return "evm-source"
    if sources.get("cairo"):
        return "cairo"
    if sources.get("move"):
        return "move-source"
    if sources.get("rust"):
        return "rust"
    if sources:
        return "generic-source"
    return "unknown"

def _capabilities(backend: str, stacks: list[str], languages: set[str]) -> dict[str, bool]:
    caps = {
        "project_detection": True,
        "source_inventory": bool(languages),
        "source_triage": bool(languages),
        "build": False,
        "tests": False,
        "coverage": False,
        "slither": False,
        "live_evm": False,
        "live_native": False,
        "workspace_scope": len(stacks) > 1,
    }
    for stack in stacks:
        spec = ADAPTERS.get(stack)
        if not spec:
            continue
        for key, value in spec["capabilities"].items():
            caps[key] = caps.get(key, False) or bool(value)
    return caps

def inspect_repository(root: str | os.PathLike[str] = ".") -> dict[str, Any]:
    requested = _safe_resolve(root)
    project_root = canonical_project_root(requested)
    scan_root = requested if requested.is_file() else project_root
    files = _source_files(scan_root)
    counts = _source_counts(files)
    stacks, language_names = _manifest_stack(project_root)

    # A directory that only contains multiple independent project roots is a
    # workspace aggregate, not a single auditable source scope. Surface the
    # child stacks and keep the aggregate explicitly partial.
    nested_projects = _nested_project_roots(project_root)
    nested_container = len(nested_projects) >= 2 and not stacks
    if nested_container:
        child_stacks: list[str] = []
        for child in nested_projects:
            child_stacks.extend(_manifest_stack(child)[0])
        stacks = sorted(dict.fromkeys(child_stacks))

    language_set = set(language_names)
    backend = _choose_backend(stacks, counts)

    package_path = project_root / "package.json"
    package = _json_object(package_path)
    cargo = _toml_object(project_root / "Cargo.toml")
    dependency_health: dict[str, Any] = {}

    if "hardhat" in stacks:
        sections = [package.get("dependencies", {}), package.get("devDependencies", {})]
        direct_deps = sorted({
            str(name) for section in sections if isinstance(section, dict) for name in section
        })
        if package_path.is_file() and not package and _safe_read(package_path):
            dependency_health["hardhat"] = {"status": "broken", "reason": "invalid package.json"}
        elif not direct_deps:
            dependency_health["hardhat"] = {"status": "not-applicable", "missing": []}
        elif not (project_root / "node_modules").is_dir():
            dependency_health["hardhat"] = {"status": "not-installed", "missing": []}
        else:
            missing = sorted(
                dep for dep in direct_deps
                if not (project_root / "node_modules" / dep).exists()
            )
            dependency_health["hardhat"] = {"status": "broken" if missing else "ok", "missing": missing}

    missing_remappings = sorted(
        prefix for prefix in _dependency_prefixes(project_root)
        if not (project_root / prefix).exists()
    )
    if missing_remappings:
        dependency_health["foundry"] = {"status": "broken", "missing": missing_remappings}

    workspace = (
        nested_container
        or _package_workspace(package)
        or _cargo_workspace(project_root, cargo)
        or (project_root / "pnpm-workspace.yaml").is_file()
        or (project_root / "go.work").is_file()
    )

    adapters = []
    for stack in stacks:
        if stack == "cargo" and "solana-anchor" in stacks:
            continue
        adapters.append(stack)
    if not adapters and backend in {"evm-source", "cairo", "move-source", "rust", "generic-source"}:
        adapters.append("source")

    supported = bool(files and any(
        language in {"solidity", "vyper", "vyper-interface", "cairo", "rust", "move"}
        for language in language_set
    ))
    unsupported_languages = sorted(
        language for language in language_set
        if language not in {"solidity", "vyper", "vyper-interface", "cairo", "rust", "move", "yul", "huff"}
    )

    dependency_broken = any(
        isinstance(value, dict) and value.get("status") == "broken"
        for value in dependency_health.values()
    )
    if files and supported:
        coverage = "full" if backend not in {
            "unknown", "generic-source", "rust", "move-source", "move",
            "cargo", "cosmwasm", "solana-anchor", "cairo-starknet",
            "evm-source", "multi",
        } else "partial"
    elif files:
        coverage = "unsupported"
    else:
        coverage = "none"

    if dependency_broken and coverage == "full":
        coverage = "partial"

    scope_type = "single-file" if requested.is_file() else "workspace" if workspace else "repository"
    if scope_type == "single-file" and coverage == "full":
        # A single file cannot establish repository-wide dependency/build/test coverage.
        coverage = "partial"
    if scope_type == "workspace" and coverage == "full":
        # A workspace root is an aggregate scope; it does not prove that every
        # member was independently buildable or security-analyzed.
        coverage = "partial"
    analysis_status = (
        "single-file" if scope_type == "single-file" and files else
        "workspace-aggregate" if scope_type == "workspace" and files else
        "ready" if coverage in {"full", "partial"} else
        "unsupported" if coverage == "unsupported" else
        "no-application-source"
    )

    return {
        "root": str(project_root),
        "backend": backend,
        "stacks": stacks,
        "workspace": workspace,
        "scope_type": scope_type,
        "languages": counts,
        "language_names": language_names,
        "source_files": [str(path.relative_to(project_root)) for path in files],
        "source_file_count": len(files),
        "adapters": adapters,
        "capabilities": _capabilities(backend, stacks, language_set),
        "security_analyzers": available_security_analyzers(project_root, stacks, language_set),
        "unsupported_languages": unsupported_languages,
        "dependency_health": dependency_health,
        "coverage": coverage,
        "analysis_status": analysis_status,
        "evidence": {
            "manifests": sorted(
                name for name in (
                    "foundry.toml", "hardhat.config.js", "hardhat.config.cjs",
                    "hardhat.config.mjs", "hardhat.config.ts", "Anchor.toml",
                    "Cargo.toml", "Scarb.toml", "Move.toml", "package.json",
                    "pyproject.toml", "go.mod", "go.work",
                ) if (project_root / name).is_file()
            ),
            "tooling_present": {
                name: bool(__import__("shutil").which(name))
                for name in (
                    "forge", "slither", "hardhat", "vyper", "scarb",
                    "snforge", "anchor", "cargo", "aptos", "sui",
                )
            },
        },
    }

def _strip_comments(text: str, language: str, mask_strings: bool = False) -> str:
    """Strip comments while optionally masking string-literal contents.

    Line structure is preserved so reported source locations remain stable.
    Solidity and Vyper accept both quote delimiters; Rust/Cairo/Move single
    quotes are not treated as string delimiters here.
    """
    chars = list(text)
    state = "code"
    quote = ""
    escape = False
    i = 0
    single_quote_languages = {"solidity", "vyper", "vyper-interface"}
    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if language in {"solidity", "vyper", "cairo", "rust", "move"} and ch == "/" and nxt == "/":
                chars[i] = chars[i + 1] = " "
                state = "line"; i += 2; continue
            if language in {"solidity", "rust", "move"} and ch == "/" and nxt == "*":
                chars[i] = chars[i + 1] = " "
                state = "block"; i += 2; continue
            if language == "vyper" and ch == "#":
                chars[i] = " "; state = "line"; i += 1; continue
            if language in {"cairo", "move"} and ch == "#":
                chars[i] = " "; state = "line"; i += 1; continue
            if ch == '"' or (ch == "'" and language in single_quote_languages):
                quote = ch; escape = False; state = "string"
            i += 1; continue
        if state == "line":
            if ch == "
": state = "code"
            elif ch != "
": chars[i] = " "
            i += 1; continue
        if state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "; i += 2; state = "code"; continue
            if ch != "
": chars[i] = " "
            i += 1; continue
        if escape:
            escape = False
            if mask_strings and ch != "
": chars[i] = " "
            i += 1; continue
        if ch == "\":
            escape = True
            if mask_strings: chars[i] = " "
            i += 1; continue
        if ch == quote:
            state = "code"; quote = ""
            i += 1; continue
        if mask_strings and ch != "
": chars[i] = " "
        i += 1
    return "".join(chars)


def _nested_project_roots(root: Path, max_depth: int = 5) -> list[Path]:
    markers = {
        "foundry.toml", "Scarb.toml", "Anchor.toml", "Move.toml",
        "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs",
        "hardhat.config.ts", "ape-config.yaml", "ape-config.yml",
        "brownie-config.yaml", "brownie-config.yml", "pyproject.toml",
        "requirements.txt", "requirements-dev.txt", "Pipfile", "Cargo.toml",
        "go.mod", "go.work", "mix.exs", "pom.xml", "build.gradle",
        "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
        "Package.swift", "CMakeLists.txt",
    }
    found: list[Path] = []
    prefixes = _dependency_prefixes(root)
    try:
        walker = os.walk(root, followlinks=False)
    except OSError:
        return []
    for current, dirs, _files in walker:
        current_path = Path(current)
        try:
            depth = len(current_path.relative_to(root).parts)
        except ValueError:
            continue
        dirs[:] = sorted(
            name for name in dirs
            if not _should_prune_directory(root, current_path, name, prefixes)
        )
        if depth == 0:
            continue
        if depth > max_depth:
            dirs[:] = []
            continue
        if any((current_path / marker).is_file() for marker in markers):
            found.append(current_path)
    return sorted(set(found))

def _workspace_manifest_member(root: Path) -> Path | None:
    package = _json_object(root / "package.json")
    workspaces = package.get("workspaces")
    if isinstance(workspaces, dict):
        patterns = workspaces.get("packages") or []
    elif isinstance(workspaces, list):
        patterns = workspaces
    else:
        patterns = []
    if not isinstance(patterns, list):
        return None

    candidates: list[Path] = []
    project_markers = {
        "foundry.toml", "Scarb.toml", "Anchor.toml", "Move.toml",
        "Cargo.toml", "go.mod", "pyproject.toml",
        "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs", "hardhat.config.ts",
        "ape-config.yaml", "ape-config.yml", "brownie-config.yaml", "brownie-config.yml",
    }
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern.strip():
            continue
        try:
            matches = root.glob(pattern)
        except (OSError, ValueError):
            continue
        for candidate in matches:
            if not candidate.is_dir():
                continue
            if any((candidate / name).is_file() for name in project_markers):
                candidates.append(candidate.resolve())

    unique = sorted(set(candidates))
    return unique[0] if len(unique) == 1 else None

def _workspace_selected_project(root: Path) -> Path | None:
    data = _json_object(root / ".audit" / "workspace.json")
    active = data.get("active_project")
    if not active:
        return None
    active_path = _safe_resolve(active)
    try:
        active_path.relative_to(root)
    except ValueError:
        return None
    return active_path if active_path.is_dir() and active_path != root else None

def canonical_project_root(start: str | os.PathLike[str] = ".") -> Path:
    """Resolve the canonical Lowkey project root without importing project_detection."""
    path = _safe_resolve(start)
    if path.is_file():
        path = path.parent

    if _is_lowkey_source_checkout(path):
        return path

    markers = (
        "foundry.toml", "Scarb.toml", "Anchor.toml", "Move.toml",
        "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.mjs",
        "hardhat.config.ts", "ape-config.yaml", "ape-config.yml",
        "brownie-config.yaml", "brownie-config.yml", "pyproject.toml",
        "requirements.txt", "requirements-dev.txt", "Pipfile", "package.json",
        "pnpm-workspace.yaml", "Cargo.toml", "go.mod", "go.work", "mix.exs", "pom.xml",
        "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
        "Package.swift", "CMakeLists.txt",
    )
    nearest = None
    for parent in (path, *path.parents):
        if any((parent / marker).is_file() for marker in markers):
            nearest = parent
            break
    if nearest is None:
        nested = _nested_project_roots(path)
        return nested[0] if len(nested) == 1 else path

    selected = _workspace_selected_project(nearest)
    if selected is not None:
        return selected

    manifest_member = _workspace_manifest_member(nearest)
    if manifest_member is not None:
        return manifest_member

    is_workspace = (
        (nearest / "pnpm-workspace.yaml").is_file()
        or (nearest / "go.work").is_file()
        or (
            (nearest / "package.json").is_file()
            and _package_workspace(_json_object(nearest / "package.json"))
        )
        or (
            (nearest / "Cargo.toml").is_file()
            and _cargo_workspace(nearest, _toml_object(nearest / "Cargo.toml"))
        )
    )
    if is_workspace and nearest == path:
        nested = _nested_project_roots(nearest)
        if len(nested) == 1:
            return nested[0]
    return nearest

def _evidence_root(path: Path) -> Path:
    """Place persisted evidence at the nearest recognizable repository root."""
    candidate = path if path.is_dir() else path.parent
    markers = (
        ".git",
        "foundry.toml",
        "hardhat.config.js",
        "hardhat.config.cjs",
        "hardhat.config.mjs",
        "hardhat.config.ts",
        "Cargo.toml",
        "Scarb.toml",
        "Move.toml",
        "package.json",
        "go.mod",
    )
    for current in (candidate, *candidate.parents):
        try:
            if any((current / marker).exists() for marker in markers):
                return current
        except OSError:
            continue
    return candidate


def _persist_universal_evidence(project_root: Path, payload: dict[str, Any]) -> None:
    try:
        evidence_dir = project_root / ".audit" / "evidence"
        evidence_dir.mkdir(parents=True, exist_ok=True)
        (evidence_dir / "universal_analysis.json").write_text(
            json.dumps(payload, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    except OSError:
        # Evidence persistence is best-effort; repository inspection must never
        # fail merely because the repository is read-only.
        return



def available_security_analyzers(
    root: Path,
    stacks: list[str] | None = None,
    languages: set[str] | None = None,
) -> list[str]:
    """Return only tools that are actually installed and relevant to this project."""
    stacks = set(stacks or [])
    languages = set(languages or set())
    tools: list[str] = []
    if ({"foundry", "hardhat", "evm-source"} & stacks) and shutil.which("slither"):
        tools.append("slither")
    if ({"cargo", "solana-anchor", "cosmwasm"} & stacks or "rust" in languages) and shutil.which("cargo-audit"):
        tools.append("cargo-audit")
    if ({"cargo", "solana-anchor", "cosmwasm"} & stacks or "rust" in languages) and shutil.which("cargo-geiger"):
        tools.append("cargo-geiger")
    if "move" in stacks and shutil.which("aptos"):
        tools.append("aptos-move-prove")
    return tools

def security_analysis_plan(
    info: dict[str, Any],
) -> list[dict[str, Any]]:
    """Build native, opt-in security-tool commands without inventing unavailable tools."""
    root = Path(str(info.get("root") or ".")).resolve()
    stacks = set(info.get("stacks") or [])
    languages = set(info.get("language_names") or info.get("languages") or [])
    plan: list[dict[str, Any]] = []
    available = set(available_security_analyzers(root, list(stacks), languages))
    if "slither" in available:
        plan.append({"name": "slither", "kind": "static-security", "command": ["slither", str(root)]})
    if "cargo-audit" in available:
        plan.append({"name": "cargo-audit", "kind": "dependency-security", "command": ["cargo", "audit", "--json"]})
    if "cargo-geiger" in available:
        plan.append({"name": "cargo-geiger", "kind": "unsafe-code-audit", "command": ["cargo", "geiger", "--output-format", "Json"]})
    if "aptos-move-prove" in available:
        plan.append({"name": "aptos-move-prove", "kind": "formal-verification", "command": ["aptos", "move", "prove"]})
    return plan

def run_security_analysis(info: dict[str, Any], timeout: int = 900) -> dict[str, Any]:
    """Run installed security tooling and preserve each tool's raw outcome as evidence."""
    root = Path(str(info.get("root") or ".")).resolve()
    plan = security_analysis_plan(info)
    results = []
    for item in plan:
        try:
            completed = subprocess.run(
                item["command"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = "\n".join(part for part in (completed.stdout, completed.stderr) if part).strip()
            results.append({
                **item,
                "exit_code": completed.returncode,
                "status": "passed" if completed.returncode == 0 else "failed",
                "output": output[-20000:],
            })
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({
                **item,
                "exit_code": 1,
                "status": "failed",
                "output": str(exc),
            })
    return {
        "tools_available": [item["name"] for item in plan],
        "results": results,
        "complete": bool(plan) and all(item["status"] == "passed" for item in results),
    }

def source_triage(root: str | os.PathLike[str] = ".") -> dict[str, Any]:
    info = inspect_repository(root)
    project_root = Path(info["root"])
    markers = []
    pattern_sets = {
        "solidity": EVM_MARKERS,
        "vyper": VYPER_MARKERS,
        "rust": RUST_MARKERS,
        "cairo": CAIRO_MARKERS,
        "move": MOVE_MARKERS,
    }
    for raw_path in info["source_files"]:
        path = project_root / raw_path
        language = SUFFIX_LANGUAGE.get(path.suffix.lower())
        patterns = pattern_sets.get(language)
        if not patterns:
            continue
        text = _strip_comments(_safe_read(path), language, mask_strings=True)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            for label, pattern in patterns.items():
                if pattern.search(line):
                    markers.append({
                        "file": str(raw_path),
                        "line": line_no,
                        "language": language,
                        "label": label,
                        "text": line.strip(),
                    })
    result = {
        "project": info,
        "files_scanned": len(info["source_files"]),
        "markers": markers,
        "count": len(markers),
        "status": "completed" if info["source_files"] else "not_analyzed",
        "interpretation": (
            "review markers are heuristic leads, not vulnerability verdicts"
            if markers else
            "no heuristic markers were found in the analyzed source scope"
        ),
    }
    _persist_universal_evidence(_evidence_root(project_root), result)
    return result

def render_scope(info: dict[str, Any]) -> str:
    caps = info.get("capabilities") or {}
    lines = [
        "LOWKEY ANALYSIS SCOPE",
        "=" * 72,
        f"Root       : {info.get('root')}",
        f"Backend    : {info.get('backend')}",
        f"Stacks     : {', '.join(info.get('stacks') or ['none detected'])}",
        f"Languages  : {', '.join(f'{k} ({v})' for k, v in (info.get('languages') or {}).items()) or 'none detected'}",
        f"Sources    : {info.get('source_file_count', 0)} application source file(s)",
        f"Coverage   : {info.get('coverage')}",
        f"Status     : {info.get('analysis_status')}",
        f"Adapters   : {', '.join(info.get('adapters') or ['none'])}",
        "",
        "CAPABILITIES",
        "-" * 72,
    ]
    for key in ("build", "tests", "coverage", "slither", "live_evm", "live_native"):
        lines.append(f"  {key:<12}: {'available' if caps.get(key) else 'not available'}")
    unsupported = info.get("unsupported_languages") or []
    if unsupported:
        lines += ["", f"Unsupported language(s): {', '.join(unsupported)}"]
    if not info.get("source_file_count"):
        lines += [
            "",
            "IMPORTANT: no application source was analyzed.",
            "This is not a clean security result.",
        ]
    elif info.get("coverage") != "full":
        lines += [
            "",
            "IMPORTANT: analysis is partial.",
            "Do not interpret absent findings as evidence of safety.",
        ]
    return "\n".join(lines)

def scan_repository(root: str | os.PathLike[str] = ".") -> int:
    result = source_triage(root)
    info = result["project"]
    security = run_security_analysis(info)
    result["security"] = security
    _persist_universal_evidence(_evidence_root(Path(info.get("root") or root)), result)
    print("SOURCE TRIAGE")
    print("=" * 72)
    print(f"Project       : {info.get('backend')}")
    print(f"Files         : {result['files_scanned']}")
    print(f"Coverage      : {info.get('coverage')}")
    print(f"Analysis      : {info.get('analysis_status')}")
    if info.get("stacks"):
        print(f"Adapters      : {', '.join(info['stacks'])}")
    for item in result["markers"]:
        print(
            f"{item['file']}:{item['line']}: "
            f"[{item['language']}:{item['label']}] {item['text']}"
        )
    print(f"\nReview markers: {result['count']}")
    print(f"Interpretation: {result['interpretation']}.")
    if info.get("coverage") == "full":
        print("Execution     : build/test/dependency evidence is not established by lk scan.")
        print("Note          : this command performs source/security triage; it is not a full audit verdict.")
    if security.get("results"):
        print("\nSECURITY TOOLING")
        print("----------------")
        for item in security["results"]:
            print(f"  {item['name']:<18} {item['status']} (exit {item['exit_code']})")
    if info.get("coverage") in {"none", "unsupported"}:
        print("RESULT: REVIEW NEEDED — Lowkey did not establish complete source coverage.")
        return 2
    if info.get("coverage") == "partial":
        # An explicitly requested source file is a complete requested scope,
        # even though it cannot establish repository-wide build/test/dependency
        # coverage. Repository/workspace scopes must remain review-required.
        if info.get("scope_type") == "single-file":
            print("RESULT: TRIAGE COMPLETE — requested single-file scope scanned; repository-wide coverage is not established.")
            return 0
        print("RESULT: REVIEW NEEDED — coverage is partial; missing coverage is not a clean result.")
        return 2
    if any(item.get("status") == "failed" for item in security.get("results", [])):
        print("RESULT: REVIEW NEEDED — an installed security analyzer reported a failure.")
        return 1
    print("RESULT: TRIAGE COMPLETE — markers require human verification.")
    return 0

__all__ = [
    "ADAPTERS",
    "available_security_analyzers",
    "canonical_project_root",
    "inspect_repository",
    "is_dependency_path",
    "project_source_files",
    "run_security_analysis",
    "security_analysis_plan",
    "render_scope",
    "scan_repository",
    "source_triage",
]
