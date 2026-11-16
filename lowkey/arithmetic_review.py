"""Conservative source detector for unsigned subtraction-before-check guards.

A match is a source-level candidate, not proof that a deployed path is reachable.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

_IGNORED_DIRS = {
    ".git", ".audit", ".venv", "venv", "__pycache__", ".pytest_cache",
    "node_modules", "out", "cache", "artifacts", "build", "dist", "target",
    "vendor", "coverage", "test", "tests", "script", "scripts", "fixtures",
    "mocks", "mock",
}
_MAX_SOURCE_BYTES = 2_000_000
_MAX_FILES = 500
_MAX_FINDINGS = 100

_OPERAND = r"[A-Za-z_$][A-Za-z0-9_$]*(?:\s*\[[^\]\n]+\])?"
_SUBTRACTION_GE_ZERO = re.compile(
    rf"^\s*\(?\s*(?P<left>{_OPERAND})\s*-\s*(?P<right>{_OPERAND})\s*\)?\s*>=\s*0\s*$"
)
_ZERO_LE_SUBTRACTION = re.compile(
    rf"^\s*0\s*<=\s*\(?\s*(?P<left>{_OPERAND})\s*-\s*(?P<right>{_OPERAND})\s*\)?\s*$"
)


def _mask_comments_and_strings(source: str) -> str:
    """Replace comments/string contents with spaces while preserving offsets/newlines."""
    chars = list(source)
    i = 0
    state = "code"
    quote = ""
    while i < len(chars):
        current = chars[i]
        following = chars[i + 1] if i + 1 < len(chars) else ""
        if state == "code":
            if current == "/" and following == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "line-comment"
                continue
            if current == "/" and following == "*":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "block-comment"
                continue
            if current in {"'", '"'}:
                quote = current
                chars[i] = " "
                state = "string"
        elif state == "line-comment":
            if current == "\n":
                state = "code"
            else:
                chars[i] = " "
        elif state == "block-comment":
            if current == "*" and following == "/":
                chars[i] = chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if current != "\n":
                chars[i] = " "
        elif state == "string":
            if current == "\\":
                chars[i] = " "
                if i + 1 < len(chars):
                    if chars[i + 1] != "\n":
                        chars[i + 1] = " "
                    i += 2
                    continue
            elif current == quote:
                chars[i] = " "
                state = "code"
            elif current != "\n":
                chars[i] = " "
        i += 1
    return "".join(chars)


def _matching_delimiter(source: str, start: int, opening: str, closing: str) -> int | None:
    if start < 0 or start >= len(source) or source[start] != opening:
        return None
    depth = 0
    for index in range(start, len(source)):
        char = source[index]
        if char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _guard_expressions(masked: str):
    """Yield (guard kind, expression start, expression text) for require/assert/if."""
    call = re.compile(r"\b(?P<kind>require|assert|if)\s*\(", re.I)
    for match in call.finditer(masked):
        opening = masked.find("(", match.start(), match.end())
        depth = 1
        index = opening + 1
        while index < len(masked) and depth:
            char = masked[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    break
            elif char == "," and depth == 1:
                break
            index += 1
        yield match.group("kind").lower(), opening + 1, masked[opening + 1:index]


def _uint_declarations(masked: str) -> tuple[set[str], set[str]]:
    uint_variables: set[str] = set()
    uint_mappings: set[str] = set()

    mapping_pattern = re.compile(
        r"\bmapping\s*\([^;{}]*=>\s*uint(?:[0-9]{1,3})?\s*\)\s*"
        r"(?:(?:public|private|internal|constant|immutable)\s+)*"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    uint_pattern = re.compile(
        r"\buint(?:[0-9]{1,3})?\s+"
        r"(?:(?:public|private|internal|constant|immutable|memory|calldata|storage)\s+)*"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    uint_mappings.update(match.group("name") for match in mapping_pattern.finditer(masked))
    uint_variables.update(match.group("name") for match in uint_pattern.finditer(masked))
    return uint_variables, uint_mappings


def _operand_base(operand: str) -> str:
    match = re.match(r"\s*([A-Za-z_$][A-Za-z0-9_$]*)", operand)
    return match.group(1) if match else ""


def _is_uint_operand(operand: str, uint_variables: set[str], uint_mappings: set[str]) -> bool:
    base = _operand_base(operand)
    if not base:
        return False
    if "[" in operand:
        return base in uint_mappings or base in uint_variables
    return base in uint_variables or base in uint_mappings


def _compiler_mode(masked: str, root: Path) -> str:
    """Infer wrapping only when the pragma/config makes that conclusion defensible."""
    configured = None
    config_path = root / "foundry.toml"
    if config_path.is_file():
        try:
            import tomllib
            config = tomllib.loads(config_path.read_text(encoding="utf-8", errors="replace"))
            profile_name = os.environ.get("FOUNDRY_PROFILE", "default")
            profile = config.get("profile", {}).get(profile_name, {})
            configured = profile.get("solc") or profile.get("solc_version") or config.get("solc") or config.get("solc_version")
        except Exception:
            configured = None
    if configured:
        version = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", str(configured))
        if version:
            major, minor, _patch = (int(part) for part in version.groups())
            if major == 0 and minor < 8:
                return "pre-0.8-wrapping"
            if major > 0 or (major == 0 and minor >= 8):
                return "0.8-checked"

    pragmas = re.findall(r"\bpragma\s+solidity\s+([^;]+);", masked, re.I)
    if not pragmas:
        return "unknown"
    modes = []
    for constraint in pragmas:
        constraint = " ".join(constraint.split())
        if re.search(r"<\s*0\.8(?:\.0)?\b", constraint) and not re.search(r">=\s*0\.8\b", constraint):
            modes.append("pre-0.8-wrapping")
            continue
        if re.fullmatch(r"[\^~]?\s*0\.[0-7]\.\d+", constraint):
            modes.append("pre-0.8-wrapping")
            continue
        if re.fullmatch(r"[\^~]?\s*0\.8\.\d+", constraint) or re.search(r">=\s*0\.8(?:\.0)?\b", constraint):
            modes.append("0.8-checked")
            continue
        modes.append("unknown")
    if modes and all(mode == modes[0] for mode in modes):
        return modes[0]
    return "unknown"


def _unchecked_ranges(masked: str) -> list[tuple[int, int]]:
    ranges = []
    for match in re.finditer(r"\bunchecked\s*\{", masked):
        opening = masked.find("{", match.start(), match.end())
        closing = _matching_delimiter(masked, opening, "{", "}")
        if closing is not None:
            ranges.append((opening, closing))
    return ranges


def _function_name_at(masked: str, offset: int) -> str | None:
    declaration = re.compile(r"\bfunction\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(")
    for match in declaration.finditer(masked):
        opening = masked.find("(", match.start(), match.end())
        closing = _matching_delimiter(masked, opening, "(", ")")
        if closing is None:
            continue
        body_open = masked.find("{", closing + 1)
        semicolon = masked.find(";", closing + 1)
        if body_open < 0 or (semicolon >= 0 and semicolon < body_open):
            continue
        body_close = _matching_delimiter(masked, body_open, "{", "}")
        if body_close is not None and body_open <= offset <= body_close:
            return match.group(1)
    return None


def _candidate_expression(expression: str) -> tuple[str, str] | None:
    expr = expression.strip()
    # Remove only parentheses that enclose the entire expression.
    while expr.startswith("(") and _matching_delimiter(expr, 0, "(", ")") == len(expr) - 1:
        expr = expr[1:-1].strip()
    match = _SUBTRACTION_GE_ZERO.fullmatch(expr) or _ZERO_LE_SUBTRACTION.fullmatch(expr)
    if not match:
        return None
    return match.group("left").strip(), match.group("right").strip()


def scan_source(source: str, path: str, root: Path) -> list[dict[str, Any]]:
    """Return conservative source candidates from one Solidity source unit."""
    masked = _mask_comments_and_strings(source)
    uint_variables, uint_mappings = _uint_declarations(masked)
    compiler_mode = _compiler_mode(masked, root)
    unchecked = _unchecked_ranges(masked)
    results = []

    for guard_kind, expression_offset, expression in _guard_expressions(masked):
        operands = _candidate_expression(expression)
        if not operands:
            continue
        left, right = operands
        if not (
            _is_uint_operand(left, uint_variables, uint_mappings)
            and _is_uint_operand(right, uint_variables, uint_mappings)
        ):
            continue

        offset = expression_offset
        line = source.count("\n", 0, offset) + 1
        function = _function_name_at(masked, offset)
        inside_unchecked = any(start <= offset <= end for start, end in unchecked)
        effective_mode = "unchecked-wrapping" if inside_unchecked else compiler_mode

        if effective_mode in {"pre-0.8-wrapping", "unchecked-wrapping"}:
            status = "WRAPAROUND_POSSIBLE"
            likely_exploitable = True
            explanation = (
                "Both operands are unsigned integers and the subtraction is compared with zero "
                "after it happens. In this arithmetic context, underflow can wrap to a huge "
                "positive value, so the intended insufficient-balance check can pass."
            )
        elif effective_mode == "0.8-checked":
            status = "CHECKED_ARITHMETIC_REVERTS_BEFORE_GUARD"
            likely_exploitable = False
            explanation = (
                "The guard is written in the unsafe order, but Solidity 0.8 checked arithmetic "
                "reverts on underflow before the comparison can pass. This exact wraparound "
                "exploit is not supported by the inferred compiler mode."
            )
        else:
            status = "COMPILER_SEMANTICS_UNKNOWN"
            likely_exploitable = None
            explanation = (
                "The unsigned subtraction is compared with zero afterwards, but the effective "
                "compiler arithmetic mode could not be established from the checked-in pragma/config."
            )

        source_lines = source.splitlines()
        original_line = source_lines[line - 1].strip() if line <= len(source_lines) else ""
        results.append({
            "kind": "unsigned-subtraction-compared-to-zero",
            "status": status,
            "confidence": "high" if likely_exploitable is True else "review",
            "likely_exploitable": likely_exploitable,
            "file": path,
            "line": line,
            "function": function,
            "guard": guard_kind,
            "expression": f"{left} - {right} >= 0",
            "compiler_mode": effective_mode,
            "text": original_line[:400],
            "explanation": explanation,
            "recommendation": "Check before subtracting: require(balance >= amount), then perform balance -= amount.",
            "evidence_level": "static-source-candidate",
            "verification_status": "UNVERIFIED",
        })
    return results


def _source_files(root: Path):
    count = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in _IGNORED_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(names):
            path = Path(current) / name
            if path.suffix.lower() != ".sol" or path.is_symlink():
                continue
            try:
                if path.stat().st_size > _MAX_SOURCE_BYTES:
                    continue
                count += 1
                if count > _MAX_FILES:
                    return
                yield path
            except OSError:
                continue


def scan_project(root: str | Path) -> list[dict[str, Any]]:
    project = Path(root).expanduser().resolve()
    findings = []
    for path in _source_files(project):
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        findings.extend(
            scan_source(source, path.relative_to(project).as_posix(), project)
        )
        if len(findings) >= _MAX_FINDINGS:
            break
    return findings[:_MAX_FINDINGS]
