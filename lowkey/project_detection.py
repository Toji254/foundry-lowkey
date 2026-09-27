#!/usr/bin/env python3
"""Project/toolchain detection for Lowkey audit routing.

Detection is evidence-driven:
- root manifests/configs identify the primary project stack;
- source extensions describe what is actually present;
- ignored dependency/build directories prevent vendored code from changing
  the project's identity.

This module intentionally does not claim that static markers are findings.
It only tells the audit command which execution/build backend is appropriate.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any, Iterable


IGNORED_DIRS = {
    ".git",
    ".audit",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "vendor",
    "vendors",
    "lib",
    "libs",
    "out",
    "cache",
    "broadcast",
    "artifacts",
    "target",
    "build",
    "dist",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".hypothesis",
    ".idea",
    ".vscode",
}

LANGUAGE_BY_EXTENSION = {
    ".sol": "solidity",
    ".vy": "vyper",
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

PRIMARY_STACKS = {
    "foundry": "foundry",
    "cairo": "cairo-starknet",
    "vyper": "vyper",
    "hardhat": "hardhat",
    "anchor": "solana-anchor",
    "move": "move",
    "ape": "ape",
    "brownie": "brownie",
}

TOOL_FOR_STACK = {
    "foundry": ("forge",),
    "cairo-starknet": ("scarb",),
    "vyper": ("vyper",),
    "hardhat": ("npx",),
    "solana-anchor": ("anchor",),
    "move": ("aptos", "sui"),
    "ape": ("ape",),
    "brownie": ("brownie",),
}


def project_root(start: str | os.PathLike[str] = ".") -> Path:
    """Find a project root from conventional root manifests.

    Falls back to the supplied directory so a source-only project still gets
    a stable .audit directory.
    """
    path = Path(start).expanduser().resolve()
    if path.is_file():
        path = path.parent

    markers = (
        "foundry.toml",
        "Scarb.toml",
        "Anchor.toml",
        "Move.toml",
        "hardhat.config.js",
        "hardhat.config.cjs",
        "hardhat.config.mjs",
        "hardhat.config.ts",
        "ape-config.yaml",
        "ape-config.yml",
        "brownie-config.yaml",
        "brownie-config.yml",
        "pyproject.toml",
        "package.json",
        "Cargo.toml",
        "go.mod",
    )
    for parent in (path, *path.parents):
        if any((parent / marker).is_file() for marker in markers):
            return parent
    return path


def _walk_files(root: Path) -> Iterable[Path]:
    """Yield source/config files while pruning dependency/build trees."""
    for current, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in IGNORED_DIRS)
        current_path = Path(current)
        for filename in sorted(files):
            yield current_path / filename


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _has(root: Path, *names: str) -> bool:
    return any((root / name).is_file() for name in names)


def _mentions_vyper(root: Path) -> bool:
    candidates = []
    for name in ("pyproject.toml", "requirements.txt", "requirements-dev.txt", "Pipfile", "setup.cfg"):
        path = root / name
        if path.is_file():
            candidates.append(_read_text(path).lower())
    return any("vyper" in text for text in candidates)


def _mentions_tool(root: Path, names: tuple[str, ...]) -> bool:
    for name in ("pyproject.toml", "package.json", "Cargo.toml", "Scarb.toml", "Anchor.toml", "Move.toml"):
        path = root / name
        if not path.is_file():
            continue
        text = _read_text(path).lower()
        if any(token.lower() in text for token in names):
            return True
    return False


def _source_counts(root: Path) -> tuple[dict[str, int], int]:
    counts: dict[str, int] = {}
    total = 0
    for path in _walk_files(root):
        language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
        if not language:
            continue
        counts[language] = counts.get(language, 0) + 1
        total += 1
    return dict(sorted(counts.items())), total


def _available_tools(toolchains: Iterable[str]) -> list[str]:
    tools = []
    candidates = []
    for stack in toolchains:
        candidates.extend(TOOL_FOR_STACK.get(stack, ()))
    for command in dict.fromkeys(candidates):
        if shutil.which(command):
            tools.append(command)
    return tools


def detect_project(start: str | os.PathLike[str] = ".") -> dict[str, Any]:
    """Return a stable, JSON-friendly project detection record."""
    root = project_root(start)
    languages, source_count = _source_counts(root)

    foundry = (root / "foundry.toml").is_file()
    cairo = (root / "Scarb.toml").is_file() or bool(languages.get("cairo"))
    hardhat = _has(
        root,
        "hardhat.config.js",
        "hardhat.config.cjs",
        "hardhat.config.mjs",
        "hardhat.config.ts",
    )
    anchor = (root / "Anchor.toml").is_file()
    move = (root / "Move.toml").is_file()
    ape = _has(root, "ape-config.yaml", "ape-config.yml") or (
        bool(languages.get("vyper")) and _mentions_tool(root, ("eth-ape", "ape", "[tool.ape]"))
    )
    brownie = _has(root, "brownie-config.yaml", "brownie-config.yml")
    vyper = bool(languages.get("vyper")) and (
        _mentions_vyper(root)
        or ape
        or brownie
        or not (foundry or cairo or hardhat or anchor or move)
    )

    stacks: list[str] = []
    if foundry:
        stacks.append("foundry")
    if cairo:
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

    # Tooling that accompanies a primary stack but should not by itself make a
    # project look like a different smart-contract stack.
    supporting_tools: list[str] = []
    if (root / "package.json").is_file():
        supporting_tools.append("node")
    if (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file():
        supporting_tools.append("python")
    if (root / "Cargo.toml").is_file():
        supporting_tools.append("cargo")
    if (root / "go.mod").is_file():
        supporting_tools.append("go")

    if not stacks:
        if languages.get("solidity"):
            project_type = "solidity-source"
        elif languages.get("vyper"):
            project_type = "vyper"
        elif languages.get("cairo"):
            project_type = "cairo"
        elif languages.get("rust"):
            project_type = "rust"
        elif languages.get("move"):
            project_type = "move-source"
        elif source_count:
            project_type = "source-project"
        else:
            project_type = "unknown"
    elif len(stacks) == 1:
        project_type = PRIMARY_STACKS[stacks[0]]
    else:
        project_type = "multi-stack"

    if not stacks:
        backend = "generic"
    elif len(stacks) == 1:
        backend = stacks[0]
    else:
        backend = "multi"

    return {
        "root": str(root),
        "type": project_type,
        "backend": backend,
        "stacks": stacks,
        "languages": languages,
        "source_count": source_count,
        "supporting_tools": supporting_tools,
        "available_tools": _available_tools(stacks),
        "manifests": {
            "foundry": foundry,
            "scarb": (root / "Scarb.toml").is_file(),
            "hardhat": hardhat,
            "vyper": bool(languages.get("vyper")),
            "anchor": anchor,
            "move": move,
            "ape": ape,
            "brownie": brownie,
        },
    }


def format_project_detection(info: dict[str, Any]) -> str:
    lines = [
        "=== LOWKEY PROJECT DETECTION ===",
        f"Root       : {info.get('root')}",
        f"Type       : {info.get('type')}",
        f"Backend    : {info.get('backend')}",
        f"Languages  : {', '.join(f'{k} ({v})' for k, v in info.get('languages', {}).items()) or 'none'}",
        f"Toolchains : {', '.join(info.get('stacks', [])) or 'none detected'}",
        f"Supporting : {', '.join(info.get('supporting_tools', [])) or 'none detected'}",
        f"Native     : {', '.join(info.get('available_tools', [])) or 'none detected'}",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    import json
    print(json.dumps(detect_project(), indent=2, sort_keys=True))
