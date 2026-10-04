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
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 compatibility
    tomllib = None

IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".audit", ".venv", "venv", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
    ".idea", ".vscode", "node_modules", "vendor", "vendors", "lib", "libs",
    "out", "cache", "broadcast", "artifacts", "build", "dist", "target",
    "coverage", "coverage-html", ".gradle", ".next", ".turbo", ".direnv",
}

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
    try:
        walker = os.walk(root, onerror=onerror, followlinks=False)
    except OSError:
        return
    for current, dirs, files in walker:
        dirs[:] = sorted(
            name for name in dirs
            if name not in IGNORED_DIRS
            and not name.startswith(".git")
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

def _source_files(root: Path) -> list[Path]:
    recognized = set(SUFFIX_LANGUAGE)
    if root.is_file():
        if root.suffix.lower() in recognized and not _is_support_path(root, root.parent):
            return [root]
        return []
    paths = [
        path for path in _safe_walk_files(root)
        if path.suffix.lower() in recognized and not _is_support_path(path, root)
    ]
    # Prefer security-relevant protocol languages over general application
    # glue (JS/TS/Python) when a repository contains multiple languages.
    protocol_suffixes = {".sol", ".vy", ".vyi", ".cairo", ".rs", ".move", ".yul", ".huff"}
    protocol_paths = [path for path in paths if path.suffix.lower() in protocol_suffixes]
    if protocol_paths:
        return sorted(protocol_paths)
    return sorted(paths)

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
    if (root / "foundry.toml").is_file():
        stacks.append("foundry")
    if any((root / name).is_file() for name in (
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
    if hardhat_dependency or hardhat_scripts:
        if "hardhat" not in stacks:
            stacks.append("hardhat")
    return sorted(dict.fromkeys(stacks)), sorted(str(x) for x in languages)

def _choose_backend(stacks: list[str], sources: dict[str, int]) -> str:
    if len(stacks) == 1:
        stack = stacks[0]
        if stack == "cargo":
            return "cargo"
        return stack
    if len(stacks) > 1:
        # Prefer explicit protocol tooling over generic package-manager signals.
        for candidate in ("foundry", "hardhat", "cairo-starknet", "solana-anchor", "cosmwasm", "move", "vyper", "cargo"):
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
    project_root = requested.parent if requested.is_file() else requested
    files = _source_files(requested)
    counts = _source_counts(files)
    stacks, language_names = _manifest_stack(project_root)
    language_set = set(language_names)
    backend = _choose_backend(stacks, counts)

    package = _json_object(project_root / "package.json")
    cargo = _toml_object(project_root / "Cargo.toml")
    workspace = (
        _package_workspace(package)
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

    if files and supported:
        coverage = "full" if backend not in {"unknown", "generic-source", "rust", "move-source", "cargo", "cosmwasm", "solana-anchor", "cairo-starknet", "multi"} else "partial"
    elif files:
        coverage = "unsupported"
    else:
        coverage = "none"

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
        "security_analyzers": (
            ["slither"]
            if (
                "solidity" in language_set
                or "vyper" in language_set
                or "foundry" in stacks
                or "hardhat" in stacks
            )
            and bool(__import__("shutil").which("slither"))
            else []
        ),\n        "unsupported_languages": unsupported_languages,\n        "coverage": coverage,
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

def _strip_comments(text: str, language: str) -> str:
    # Keep line numbers stable while avoiding comment-only heuristic matches.
    chars = list(text)
    state = "code"
    quote = ""
    escape = False
    i = 0
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
            if ch in {"'", '"'}:
                quote = ch; escape = False; state = "string"
            i += 1; continue
        if state == "line":
            if ch == "\n":
                state = "code"
            elif ch != "\n":
                chars[i] = " "
            i += 1; continue
        if state == "block":
            if ch == "*" and nxt == "/":
                chars[i] = chars[i + 1] = " "; i += 2; state = "code"; continue
            if ch != "\n":
                chars[i] = " "
            i += 1; continue
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == quote:
            state = "code"; quote = ""
        i += 1
    return "".join(chars)

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
        text = _strip_comments(_safe_read(path), language)
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
    if info.get("coverage") in {"none", "unsupported"}:
        print("RESULT: REVIEW NEEDED — Lowkey did not establish complete source coverage.")
    elif info.get("coverage") == "partial":
        print("RESULT: REVIEW NEEDED — coverage is partial; missing coverage is not a clean result.")
    else:
        print("RESULT: TRIAGE COMPLETE — markers require human verification.")
    return 0

__all__ = [
    "ADAPTERS",
    "inspect_repository",
    "render_scope",
    "scan_repository",
    "source_triage",
]
