#!/usr/bin/env python3
"""Conservative Solidity source relationship index for Lowkey.

This module performs bounded, read-only lexical analysis. It never compiles a
project and never treats static relationships as proof of runtime execution.
Every edge carries its source location, evidence class, and resolution state.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

try:
    import project_tools
except ImportError:  # pragma: no cover - package-style import
    from lowkey import project_tools


CACHE_VERSION = 2
MAX_CACHE_BYTES = 32 * 1024 * 1024
MAX_RELATIONSHIPS = 250_000
MAX_TRAVERSAL_DEPTH = 10

_BUILTIN_CALLS = {
    "if", "while", "for", "do", "return", "emit", "require", "assert",
    "revert", "keccak256", "sha256", "ripemd160", "ecrecover", "addmod",
    "mulmod", "abi", "type", "new", "delete", "unchecked", "assembly",
    "gasleft", "blockhash", "selfdestruct", "suicide",
}
_STORAGE_QUALIFIERS = {
    "public", "private", "internal", "external", "constant", "immutable",
    "transient", "override", "virtual",
}
_PARAMETER_QUALIFIERS = {"memory", "calldata", "storage", "indexed", "payable"}


class SourceIndexError(RuntimeError):
    """Raised when a source index cannot be built without hiding failures."""


def _line(source: str, offset: int) -> int:
    return source.count("\n", 0, max(0, offset)) + 1


def _brace_pairs(source: str) -> dict[int, int]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    for index, char in enumerate(source):
        if char == "{":
            stack.append(index)
        elif char == "}" and stack:
            pairs[stack.pop()] = index
    return pairs


def _matching(source: str, opening: int, left: str, right: str) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        char = source[index]
        if char == left:
            depth += 1
        elif char == right:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_top_level(value: str, separator: str = ",") -> list[str]:
    result: list[str] = []
    start = 0
    parens = brackets = braces = 0
    for index, char in enumerate(value):
        if char == "(":
            parens += 1
        elif char == ")":
            parens = max(0, parens - 1)
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets = max(0, brackets - 1)
        elif char == "{":
            braces += 1
        elif char == "}":
            braces = max(0, braces - 1)
        elif char == separator and parens == brackets == braces == 0:
            result.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        result.append(tail)
    return result


def _canonical_parameter(raw: str) -> str:
    value = re.sub(r"\b(memory|calldata|storage|indexed|payable)\b", " ", raw)
    value = re.sub(r"\s+", " ", value).strip()
    if not value:
        return "?"
    # The final identifier is a parameter name when a type precedes it.
    parts = value.split()
    if len(parts) > 1 and re.fullmatch(r"[A-Za-z_]\w*", parts[-1]):
        value = " ".join(parts[:-1])
    value = value.strip()
    value = re.sub(r"\buint\b", "uint256", value)
    value = re.sub(r"\bint\b", "int256", value)
    value = re.sub(r"\s+", "", value)
    return value or "?"


def _parameter_names(raw: str) -> set[str]:
    return {item["name"] for item in _parameter_descriptors(raw) if item.get("name")}


def _parameter_descriptors(raw: str) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for item in _split_top_level(raw):
        value = re.sub(r"\b(memory|calldata|storage|indexed)\b", " ", item)
        value = re.sub(r"\s+", " ", value).strip()
        parts = value.split()
        if not parts:
            continue
        name = ""
        type_name = value
        if len(parts) > 1 and re.fullmatch(r"[A-Za-z_]\w*", parts[-1]):
            name = parts[-1]
            type_name = " ".join(parts[:-1])
        result.append({
            "name": name,
            "type": _canonical_parameter(type_name),
            "declared_type": re.sub(r"\s+", " ", type_name).strip(),
        })
    return result


def _function_body_open(source: str, after_parameters: int) -> tuple[int | None, int | None]:
    """Find a function's body brace or declaration semicolon after its params."""
    parens = brackets = 0
    for index in range(after_parameters, len(source)):
        char = source[index]
        if char == "(":
            parens += 1
        elif char == ")":
            parens = max(0, parens - 1)
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets = max(0, brackets - 1)
        elif parens == 0 and brackets == 0:
            if char == "{":
                return index, None
            if char == ";":
                return None, index
            if char == "}":
                return None, None
    return None, None


def _top_level_statements(source: str, start: int, end: int):
    depth = 0
    statement_start = start
    for index in range(start, end):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
            if depth == 0:
                statement_start = index + 1
        elif char == ";" and depth == 0:
            statement = source[statement_start:index].strip()
            if statement:
                yield statement, statement_start
            statement_start = index + 1


def _state_declaration(statement: str) -> tuple[str, str] | None:
    value = statement.strip()
    if not value or re.match(
        r"^(function|modifier|event|error|using|pragma|import|return|emit|revert)\b",
        value,
    ):
        return None
    # Find the declared identifier at the end of the declaration prefix.
    prefix = value.split("=", 1)[0].strip()
    match = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
    if not match:
        return None
    name = match.group(1)
    raw_type = prefix[:match.start()].strip()
    raw_type = re.sub(
        r"\b(public|private|internal|constant|immutable|transient|override|virtual)\b",
        " ",
        raw_type,
    )
    raw_type = re.sub(r"\s+", " ", raw_type).strip()
    if not raw_type or raw_type in {"returns", "payable"}:
        return None
    if "(" in raw_type and not raw_type.startswith("mapping"):
        return None
    return name, raw_type


def _struct_fields(source: str, start: int, end: int, pairs: dict[int, int]):
    pattern = re.compile(r"\bstruct\s+([A-Za-z_]\w*)\s*\{")
    for match in pattern.finditer(source, start, end):
        opening = match.end() - 1
        closing = pairs.get(opening)
        if closing is None or closing > end:
            continue
        for statement, offset in _top_level_statements(source, opening + 1, closing):
            prefix = statement.split("=", 1)[0].strip()
            field_match = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
            if not field_match:
                continue
            field_type = prefix[:field_match.start()].strip()
            field_type = re.sub(r"\b(public|private|internal|memory|storage|calldata)\b", " ", field_type)
            field_type = re.sub(r"\s+", " ", field_type).strip()
            if field_type:
                yield match.group(1), field_match.group(1), field_type, offset


def _at_contract_depth(source: str, body_start: int, offset: int) -> bool:
    """Return true only for a declaration directly inside a contract body."""
    depth = 0
    for char in source[body_start:offset]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    return depth == 0


def _source_ref(path: str, source: str, offset: int) -> dict[str, Any]:
    before = source.rfind("\n", 0, offset)
    return {
        "file": path,
        "line": _line(source, offset),
        "column": offset - before,
    }


def _node_id(kind: str, path: str, qualified: str) -> str:
    return f"{kind}:{path}:{qualified}"


def _edge(
    kind: str,
    source_id: str,
    target_id: str,
    path: str,
    source: str,
    offset: int,
    *,
    resolution: str = "DIRECT",
    evidence: str = "LEXICAL_SOURCE",
    **extra: Any,
) -> dict[str, Any]:
    value = {
        "id": f"{kind}:{source_id}:{target_id}:{_line(source, offset)}:{offset}",
        "kind": kind,
        "from": source_id,
        "to": target_id,
        "resolution": resolution,
        "evidence": evidence,
        "source": _source_ref(path, source, offset),
    }
    value.update(extra)
    return value


def _cache_path(fingerprint: str) -> Path:
    return Path.home() / ".cache" / "lowkey" / "source-index" / f"{fingerprint}.json"


def _load_cache(path: Path, fingerprint: str) -> dict[str, Any] | None:
    try:
        if path.stat().st_size > MAX_CACHE_BYTES:
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            isinstance(payload, dict)
            and payload.get("cache_version") == CACHE_VERSION
            and payload.get("fingerprint") == fingerprint
            and isinstance(payload.get("nodes"), list)
            and isinstance(payload.get("edges"), list)
        ):
            return payload
    except (OSError, ValueError, TypeError):
        return None
    return None


def _save_cache(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if len(data.encode("utf-8")) > MAX_CACHE_BYTES:
            return
        fd, temporary = tempfile.mkstemp(prefix=".source-index-", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    except OSError:
        # Caching is an optimization. An unwritable cache must not break analysis.
        return


def _mapping_layout(type_name: str) -> tuple[list[str], str | None]:
    keys: list[str] = []
    current = type_name.strip()
    while current.startswith("mapping"):
        opening = current.find("(")
        if opening < 0:
            return keys, None
        closing = _matching(current, opening, "(", ")")
        if closing is None:
            return keys, None
        inside = current[opening + 1:closing]
        parts = re.split(r"\s*=>\s*", inside, maxsplit=1)
        if len(parts) < 2:
            return keys, None
        keys.append(parts[0].strip())
        current = parts[1].strip()
    return keys, current or None


def _mapping_inner_type(type_name: str) -> str | None:
    return _mapping_layout(type_name)[1]


def build_source_index(root: str | Path = ".", *, use_cache: bool = True) -> dict[str, Any]:
    """Build one shared source relationship graph for a Solidity project.

    Existing Lowkey project discovery/import resolution is reused. The index is
    read-only, bounded by project_tools' existing source inventory limits, and
    cached by the content hashes of all indexed files plus Foundry configuration.
    """
    root_path = project_tools.project_root(root).resolve()
    try:
        inventory = project_tools.solidity_source_inventory(root_path)
        base_graph = project_tools.build_dependency_graph(root_path)
    except Exception as error:
        raise SourceIndexError(f"Could not build the Solidity source inventory: {error}") from error

    source_units: list[tuple[str, str, Path]] = []
    source_provenance: dict[str, str] = {}
    failures = list(inventory.get("uninspected") or [])
    known_source_paths: set[Path] = set()
    for item in base_graph.get("nodes") or []:
        if item.get("language") != "solidity":
            continue
        relative = str(item.get("file") or "")
        path = Path(relative)
        if not path.is_absolute():
            path = (root_path / path).resolve()
        try:
            data = path.read_bytes()
            if len(data) > project_tools.SOLIDITY_SOURCE_MAX_FILE_BYTES:
                failures.append({"path": relative, "phase": "size-limit", "error": "Source exceeds the per-file inventory limit."})
                continue
            source = data.decode("utf-8-sig")
        except (OSError, UnicodeError) as error:
            failures.append({"path": relative, "phase": "read", "error": str(error)})
            continue
        try:
            display_path = path.relative_to(root_path).as_posix()
        except ValueError:
            display_path = os.path.relpath(path, root_path).replace(os.sep, "/")
        source_units.append((display_path, source, path))
        source_provenance[display_path] = "first-party"
        known_source_paths.add(path.resolve())

    # Load only Solidity files explicitly imported by indexed project files.
    # This makes imported libraries such as SafeERC20 navigable without scanning
    # all of lib/ or node_modules. Bound this extra dependency surface separately.
    external_total_bytes = 0
    external_file_count = 0
    for import_edge in base_graph.get("edges") or []:
        if import_edge.get("kind") != "import" or not import_edge.get("resolved") or not import_edge.get("external"):
            continue
        raw_target = str(import_edge.get("to") or "")
        target_path = Path(raw_target)
        if not target_path.is_absolute():
            target_path = root_path / target_path
        try:
            target_path = target_path.resolve(strict=True)
            if target_path in known_source_paths or target_path.suffix.lower() != ".sol" or not target_path.is_file():
                continue
            size = target_path.stat().st_size
            if size > project_tools.SOLIDITY_SOURCE_MAX_FILE_BYTES:
                failures.append({"path": raw_target, "phase": "dependency-size-limit", "error": "Imported dependency exceeds the per-file source limit."})
                continue
            if external_file_count >= 64 or external_total_bytes + size > 16 * 1024 * 1024:
                failures.append({"path": raw_target, "phase": "dependency-inventory-budget", "error": "Imported dependency source budget reached (64 files / 16 MiB)."})
                continue
            data = target_path.read_bytes()
            source = data.decode("utf-8-sig")
        except (OSError, UnicodeError, RuntimeError) as error:
            failures.append({"path": raw_target, "phase": "dependency-read", "error": str(error)})
            continue
        display_path = os.path.relpath(target_path, root_path).replace(os.sep, "/")
        source_units.append((display_path, source, target_path))
        source_provenance[display_path] = "third-party"
        known_source_paths.add(target_path)
        external_total_bytes += len(data)
        external_file_count += 1

    source_units.sort(key=lambda item: item[0].casefold())
    source_by_path = {path: source for path, source, _absolute in source_units}
    build_config = ""
    config_path = root_path / "foundry.toml"
    try:
        build_config = config_path.read_text(encoding="utf-8")
    except OSError:
        pass
    fingerprint_data = {
        "version": CACHE_VERSION,
        "root": str(root_path),
        "foundry": build_config,
        "sources": [(path, hashlib.sha256(source.encode("utf-8")).hexdigest()) for path, source, _ in source_units],
        "imports": base_graph.get("edges") or [],
    }
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_data, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    cached_path = _cache_path(fingerprint)
    if use_cache:
        cached = _load_cache(cached_path, fingerprint)
        if cached is not None:
            cached_inventory = cached.get("inventory") or {}
            cached_failures = cached_inventory.get("uninspected") or []
            merged_failures = failures + cached_failures
            cached["inventory"] = {
                "complete": not merged_failures,
                "uninspected": merged_failures,
                "files_inspected": len(source_units),
                "files_discovered": inventory.get("files_discovered", len(source_units)),
            }
            cached["cache"] = {"status": "HIT", "fingerprint": fingerprint}
            return cached

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    contracts: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    state_variables: list[dict[str, Any]] = []
    function_pointers: list[dict[str, Any]] = []
    structs: list[dict[str, Any]] =
    fields_by_struct: dict[tuple[str, str], list[dict[str, Any]]] = {}
    file_ids: dict[str, str] = {}
    contract_by_name: dict[str, list[dict[str, Any]]] = {}
    function_by_scope_name: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def add_node(value: dict[str, Any]) -> None:
        if len(nodes) >= MAX_RELATIONSHIPS:
            raise SourceIndexError(f"Source index reached the {MAX_RELATIONSHIPS}-node safety limit.")
        nodes.append(value)

    type_node_ids: set[str] = set()

    def ensure_type_node(path: str, type_name: str, source: str, offset: int) -> str:
        type_id = _node_id("type", path, type_name)
        if type_id not in type_node_ids:
            type_node_ids.add(type_id)
            add_node({
                "id": type_id, "kind": "type", "name": type_name,
                "qualified_name": type_name, "file": path,
                "line": _line(source, offset), "evidence": "LEXICAL_SOURCE",
            })
        return type_id

    for path, source, _absolute in source_units:
        clean = project_tools._strip_source_comments(source, "solidity", mask_strings=True)
        file_id = _node_id("file", path, path)
        file_ids[path] = file_id
        add_node({
            "id": file_id, "kind": "file", "name": path, "file": path,
            "line": 1, "evidence": "SOURCE_FILE",
            "provenance": source_provenance.get(path, "unclassified"),
        })
        pairs = _brace_pairs(clean)
        contract_pattern = re.compile(
            r"\b(?P<kind>abstract\s+contract|contract|interface|library)\s+"
            r"(?P<name>[A-Za-z_]\w*)\b(?P<header>[^{};]*)\{"
        )
        for match in contract_pattern.finditer(clean):
            opening = match.end() - 1
            closing = pairs.get(opening)
            if closing is None:
                failures.append({"path": path, "phase": "parse", "error": "Unclosed contract declaration."})
                continue
            name = match.group("name")
            qualified = f"{name}"
            contract_id = _node_id("contract", path, qualified)
            header = match.group("header") or ""
            bases = [
                part.strip().split("(", 1)[0].strip()
                for part in re.split(r",", header.split("is", 1)[1])
            ] if re.search(r"\bis\b", header) else []
            contract = {
                "id": contract_id, "kind": "contract", "name": name,
                "qualified_name": qualified, "file": path,
                "line": _line(source, match.start()), "offset": match.start(),
                "body_start": opening + 1, "body_end": closing,
                "bases": [base for base in bases if re.fullmatch(r"[A-Za-z_]\w*", base)],
                "source": source, "clean": clean,
                "declaration_kind": match.group("kind"),
                "provenance": source_provenance.get(path, "unclassified"),
                "using_libraries": [
                    {"library": using.group(1), "for_type": using.group(2), "offset": using.start()}
                    for using in re.finditer(
                        r"\busing\s+([A-Za-z_]\w*)\s+for\s+([A-Za-z_]\w*|\*)\s*;",
                        clean, opening + 1, closing,
                    )
                    if _at_contract_depth(clean, opening + 1, using.start())
                ],
            }
            contracts.append(contract)
            contract_by_name.setdefault(name, []).append(contract)
            add_node({
                "id": contract_id, "kind": "contract", "name": name,
                "qualified_name": qualified, "file": path,
                "line": contract["line"], "bases": contract["bases"],
                "declaration_kind": contract["declaration_kind"],
                "provenance": contract["provenance"],
                "using_libraries": contract["using_libraries"],
                "evidence": "LEXICAL_SOURCE",
            })
            edges.append(_edge("DECLARES", file_id, contract_id, path, source, match.start()))

            for field_struct, field_name, field_type, field_offset in _struct_fields(
                clean, opening + 1, closing, pairs
            ):
                struct_id = _node_id("struct", path, f"{name}.{field_struct}")
                if not any(item["id"] == struct_id for item in structs):
                    struct_node = {
                        "id": struct_id, "kind": "struct", "name": field_struct,
                        "qualified_name": f"{name}.{field_struct}", "contract": name,
                        "file": path, "line": _line(source, field_offset),
                    }
                    structs.append(struct_node)
                    add_node({**struct_node, "evidence": "LEXICAL_SOURCE"})
                field_id = _node_id("struct_field", path, f"{name}.{field_struct}.{field_name}")
                field_node = {
                    "id": field_id, "kind": "struct_field", "name": field_name,
                    "qualified_name": f"{name}.{field_struct}.{field_name}",
                    "contract": name, "struct": field_struct, "type": field_type,
                    "file": path, "line": _line(source, field_offset),
                }
                add_node({**field_node, "evidence": "LEXICAL_SOURCE"})
                fields_by_struct.setdefault((name, field_struct), []).append(field_node)
                edges.append(_edge("DECLARES", struct_id, field_id, path, source, field_offset))
                type_id = ensure_type_node(path, field_type, source, field_offset)
                edges.append(_edge("USES_TYPE", field_id, type_id, path, source, field_offset, type_name=field_type))

            for statement, statement_offset in _top_level_statements(clean, opening + 1, closing):
                pointer_match = re.match(
                    r"^function\s*\([^;]*\)\s*(?:external|internal)\b.*?\b(?P<name>[A-Za-z_]\w*)$",
                    statement.strip(),
                )
                if pointer_match:
                    pointer_name = pointer_match.group("name")
                    pointer_id = _node_id("function_pointer", path, f"{name}.{pointer_name}")
                    pointer_node = {
                        "id": pointer_id, "kind": "function_pointer",
                        "name": pointer_name, "qualified_name": f"{name}.{pointer_name}",
                        "contract": name, "file": path,
                        "line": _line(source, statement_offset),
                        "evidence": "LEXICAL_SOURCE",
                    }
                    function_pointers.append(pointer_node)
                    add_node(pointer_node)
                    edges.append(_edge("DECLARES", contract_id, pointer_id, path, source, statement_offset))
                    continue
                declaration = _state_declaration(statement)
                if declaration is None:
                    continue
                variable_name, variable_type = declaration
                mapping = variable_type.startswith("mapping")
                kind = "mapping" if mapping else "state_variable"
                variable_id = _node_id(kind, path, f"{name}.{variable_name}")
                variable = {
                    "id": variable_id, "kind": kind, "name": variable_name,
                    "qualified_name": f"{name}.{variable_name}", "contract": name,
                    "file": path, "line": _line(source, statement_offset),
                    "type": variable_type, "mapping_value_type": _mapping_inner_type(variable_type),
                    "mapping_keys": _mapping_layout(variable_type)[0] if mapping else [],
                    "scope": "state",
                }
                state_variables.append(variable)
                add_node({**variable, "evidence": "LEXICAL_SOURCE"})
                edges.append(_edge("DECLARES", contract_id, variable_id, path, source, statement_offset))
                inner_type = _mapping_inner_type(variable_type) if mapping else variable_type
                if inner_type:
                    clean_type = re.sub(r"\b(mapping|address|uint\d*|int\d*|bytes\d*|bool|string)\b", " ", inner_type)
                    for struct_name in re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", clean_type):
                        matches = [item for item in structs if item["contract"] == name and item["name"] == struct_name]
                        if matches:
                            edges.append(_edge("USES_TYPE", variable_id, matches[0]["id"], path, source, statement_offset, type_name=inner_type))

            # Enum declarations and their named members are first-class symbols.
            for enum_match in re.finditer(r"\benum\s+([A-Za-z_]\w*)\s*\{", clean, opening + 1, closing):
                if not _at_contract_depth(clean, opening + 1, enum_match.start()):
                    continue
                enum_open = enum_match.end() - 1
                enum_close = pairs.get(enum_open)
                if enum_close is None or enum_close > closing:
                    failures.append({"path": path, "phase": "parse", "error": f"Unclosed enum at line {_line(source, enum_match.start())}."})
                    continue
                enum_name = enum_match.group(1)
                enum_id = _node_id("enum", path, f"{name}.{enum_name}")
                enum_node = {
                    "id": enum_id, "kind": "enum", "name": enum_name,
                    "qualified_name": f"{name}.{enum_name}", "contract": name,
                    "file": path, "line": _line(source, enum_match.start()),
                    "evidence": "LEXICAL_SOURCE",
                }
                add_node(enum_node)
                edges.append(_edge("DECLARES", contract_id, enum_id, path, source, enum_match.start()))
                for enum_value in _split_top_level(clean[enum_open + 1:enum_close]):
                    value_name = enum_value.strip().split("=", 1)[0].strip()
                    if not re.fullmatch(r"[A-Za-z_]\w*", value_name):
                        continue
                    value_offset = clean.find(value_name, enum_open + 1, enum_close)
                    value_id = _node_id("enum_value", path, f"{name}.{enum_name}.{value_name}")
                    add_node({
                        "id": value_id, "kind": "enum_value", "name": value_name,
                        "qualified_name": f"{name}.{enum_name}.{value_name}",
                        "contract": name, "enum": enum_name, "file": path,
                        "line": _line(source, value_offset), "evidence": "LEXICAL_SOURCE",
                    })
                    edges.append(_edge("DECLARES", enum_id, value_id, path, source, value_offset))

            # Events and custom errors are declarations with their own nodes.
            for kind, pattern in (
                ("event", re.compile(r"\bevent\s+([A-Za-z_]\w*)\s*\(")),
                ("custom_error", re.compile(r"\berror\s+([A-Za-z_]\w*)\s*\(")),
            ):
                for declaration_match in pattern.finditer(clean, opening + 1, closing):
                    if not _at_contract_depth(clean, opening + 1, declaration_match.start()):
                        continue
                    symbol_id = _node_id(kind, path, f"{name}.{declaration_match.group(1)}")
                    add_node({
                        "id": symbol_id, "kind": kind, "name": declaration_match.group(1),
                        "qualified_name": f"{name}.{declaration_match.group(1)}",
                        "contract": name, "file": path,
                        "line": _line(source, declaration_match.start()),
                        "evidence": "LEXICAL_SOURCE",
                    })
                    edges.append(_edge("DECLARES", contract_id, symbol_id, path, source, declaration_match.start()))

            function_pattern = re.compile(
                r"\b(?P<kind>function|modifier|constructor|fallback|receive)\b"
                r"(?:\s+(?P<name>[A-Za-z_]\w*))?\s*\("
            )
            for function_match in function_pattern.finditer(clean, opening + 1, closing):
                if not _at_contract_depth(clean, opening + 1, function_match.start()):
                    continue
                params_open = function_match.end() - 1
                params_close = _matching(clean, params_open, "(", ")")
                if params_close is None:
                    failures.append({"path": path, "phase": "parse", "error": f"Unclosed parameter list at line {_line(source, function_match.start())}."})
                    continue
                body_open, declaration_end = _function_body_open(clean, params_close + 1)
                terminator = body_open if body_open is not None else declaration_end
                if terminator is None:
                    continue
                body_close = pairs.get(body_open) if body_open is not None else None
                if body_open is not None and body_close is None:
                    failures.append({"path": path, "phase": "parse", "error": f"Unclosed function body at line {_line(source, function_match.start())}."})
                    continue
                raw_kind = function_match.group("kind")
                function_name = function_match.group("name")
                if raw_kind == "function" and not function_name and body_open is None:
                    # A declaration like function(uint256) external callback;
                    # is a function pointer, not a named fallback function.
                    continue
                if raw_kind == "function" and not function_name:
                    function_name = "fallback"
                function_name = function_name or raw_kind
                raw_params = clean[params_open + 1:params_close]
                parameter_types = [_canonical_parameter(item) for item in _split_top_level(raw_params)]
                signature = f"{function_name}({','.join(parameter_types)})"
                function_id = _node_id("function", path, f"{name}.{signature}")
                header_text = clean[function_match.start():terminator]
                mutability_match = re.search(r"\b(payable|view|pure)\b", header_text)
                visibility_match = re.search(r"\b(public|external|internal|private)\b", header_text)
                func_kind = "modifier" if raw_kind == "modifier" else "function"
                func = {
                    "id": function_id, "kind": func_kind, "name": function_name,
                    "signature": signature, "qualified_name": f"{name}.{signature}",
                    "contract": name, "contract_kind": contract["declaration_kind"], "file": path,
                    "line": _line(source, function_match.start()),
                    "header": header_text,
                    "visibility": visibility_match.group(1) if visibility_match else "UNSPECIFIED",
                    "mutability": mutability_match.group(1) if mutability_match else "nonpayable",
                    "parameters": sorted(_parameter_names(raw_params)),
                    "parameter_types": {item["name"]: item["type"] for item in _parameter_descriptors(raw_params) if item.get("name")},
                    "parameter_declared_types": {item["name"]: item["declared_type"] for item in _parameter_descriptors(raw_params) if item.get("name")},
                    "body_start": body_open + 1 if body_open is not None else None,
                    "body_end": body_close,
                    "body": clean[body_open + 1:body_close] if body_open is not None and body_close is not None else "",
                    "source_offset": function_match.start(),
                    "bases": contract["bases"],
                }
                functions.append(func)
                function_by_scope_name.setdefault((name, function_name), []).append(func)
                add_node({
                    **{key: value for key, value in func.items() if key not in {"header", "body", "source_offset", "body_start", "body_end"}},
                    "evidence": "LEXICAL_SOURCE",
                })
                edges.append(_edge("DECLARES", contract_id, function_id, path, source, function_match.start()))

    # Reuse Lowkey's import/dependency graph. File-level import observations are
    # not upgraded to symbol-level implementation claims.
    for base_edge in base_graph.get("edges") or []:
        if base_edge.get("kind") != "import":
            continue
        from_path = str(base_edge.get("from") or "")
        to_path = str(base_edge.get("to") or "")
        from_id = file_ids.get(from_path)
        to_path_key = to_path
        if base_edge.get("resolved"):
            target_path = Path(to_path)
            if not target_path.is_absolute():
                target_path = root_path / target_path
            to_path_key = os.path.relpath(target_path.resolve(), root_path).replace(os.sep, "/")
        to_id = file_ids.get(to_path_key)
        if from_id is None:
            continue
        edges.append({
            "id": f"IMPORTS:{from_id}:{to_id or to_path}:{base_edge.get('line', 0)}",
            "kind": "IMPORTS", "from": from_id, "to": to_id or to_path,
            "resolution": "DIRECT" if base_edge.get("resolved") else "UNRESOLVED",
            "evidence": "PROJECT_IMPORT_RESOLVER",
            "source": {"file": from_path, "line": base_edge.get("line", 1), "column": 1},
            "raw": base_edge.get("raw"), "external": bool(base_edge.get("external")),
            "provenance": base_edge.get("provenance", "unresolved"),
        })

    # Explicit using-for directives connect extension calls to library source
    # only when the directive, receiver type, and library function are unique.
    for contract in contracts:
        for directive in contract.get("using_libraries") or []:
            matches = [
                item for item in contract_by_name.get(directive["library"], [])
                if item.get("declaration_kind") == "library"
            ]
            target = matches[0]["id"] if len(matches) == 1 else f"library-name:{directive['library']}"
            edges.append(_edge(
                "USES_LIBRARY", contract["id"], target, contract["file"],
                contract["source"], directive.get("offset", contract["offset"]),
                resolution="DIRECT" if len(matches) == 1 else "UNRESOLVED",
                library=directive["library"], for_type=directive["for_type"],
                candidates=[item["id"] for item in matches],
            ))

    # Resolve inheritance names only when exactly one indexed contract matches.
    for contract in contracts:
        for base_name in contract["bases"]:
            candidates = contract_by_name.get(base_name, [])
            target = candidates[0]["id"] if len(candidates) == 1 else f"contract-name:{base_name}"
            edges.append(_edge(
                "INHERITS", contract["id"], target, contract["file"],
                contract["source"], contract["offset"],
                resolution="DIRECT" if len(candidates) == 1 else "UNRESOLVED",
                candidates=[item["id"] for item in candidates],
                base=base_name,
            ))

    # Explicit override declarations link to a base implementation only
    # when the inherited signature identifies exactly one candidate.
    for contract in contracts:
        for func in functions:
            if func["contract"] != contract["name"] or func["file"] != contract["file"] or func["kind"] != "function":
                continue
            if not re.search(r"\boverride\b", func["header"]):
                continue
            candidates = [
                inherited for inherited in functions
                if inherited["contract"] in contract["bases"]
                and inherited["kind"] == "function"
                and inherited["signature"] == func["signature"]
            ]
            target = candidates[0]["id"] if len(candidates) == 1 else f"override:{contract['name']}.{func['signature']}"
            edges.append(_edge(
                "OVERRIDES", func["id"], target, func["file"],
                source_by_path.get(func["file"], ""), func["source_offset"],
                resolution="DIRECT" if len(candidates) == 1 else "UNRESOLVED",
                candidates=[item["id"] for item in candidates],
            ))

    # Direct state access, modifiers, events and function-to-function calls.
    function_nodes = {item["id"]: item for item in functions}
    for func in functions:
        if func["kind"] not in {"function", "modifier"}:
            continue
        path = func["file"]
        source = source_by_path.get(path, "")
        body = func["body"]
        if not body:
            continue
        body_absolute = (func["body_start"] or 0)
        scope = func["contract"]
        known_modifiers = [
            item for item in functions
            if item["kind"] == "modifier"
            and item["contract"] in {scope, *func["bases"]}
        ]
        params_shadow = set(func["parameters"])

        for modifier in known_modifiers:
            if re.search(rf"\b{re.escape(modifier['name'])}\b", func["header"]):
                edges.append(_edge(
                    "APPLIES_MODIFIER", func["id"], modifier["id"], path, source,
                    func["source_offset"],
                    resolution="DIRECT" if modifier["contract"] == scope else "INFERRED",
                ))

        local_functions = function_by_scope_name
        dynamic_pointer_names = {
            item["name"] for item in function_pointers
            if item["contract"] == scope and item["file"] == path
        }
        dynamic_pointer_names.update(
            name for name, type_name in (func.get("parameter_declared_types") or {}).items()
            if re.match(r"function\s*\(", type_name)
        )
        for pointer_match in re.finditer(
            r"function\s*\([^;]*?\)\s*(?:external|internal)\b[^;]*?\b([A-Za-z_]\w*)\s*(?:=|;)",
            body,
        ):
            dynamic_pointer_names.add(pointer_match.group(1))
        call_pattern = re.compile(r"(?<![A-Za-z0-9_.$])([A-Za-z_]\w*)\s*\(")
        for call in call_pattern.finditer(body):
            callee_name = call.group(1)
            if callee_name in dynamic_pointer_names:
                edges.append(_edge(
                    "CALLS", func["id"], f"function-pointer:{scope}.{callee_name}",
                    path, source, body_absolute + call.start(),
                    resolution="UNRESOLVED",
                    call_kind="dynamic-function-pointer",
                    detail="Function pointer target depends on runtime assignment or dispatch; no implementation is assumed.",
                ))
                continue
            if callee_name in _BUILTIN_CALLS:
                continue
            if callee_name in {"function", "modifier"}:
                continue
            candidates = [item for item in local_functions.get((scope, callee_name), []) if item["kind"] == "function" and item["file"] == path]
            if not candidates:
                inherited = []
                for base_name in func["bases"]:
                    inherited.extend(item for item in local_functions.get((base_name, callee_name), []) if item["kind"] == "function")
                candidates = inherited
            if len(candidates) == 1:
                target_func = candidates[0]
                edges.append(_edge(
                    "CALLS", func["id"], target_func["id"], path, source,
                    body_absolute + call.start(),
                    resolution="INFERRED" if target_func["contract"] != scope else "DIRECT",
                ))
            elif len(candidates) > 1:
                edges.append(_edge(
                    "CALLS", func["id"], f"function-name:{scope}.{callee_name}",
                    path, source, body_absolute + call.start(),
                    resolution="UNRESOLVED",
                    candidates=[item["id"] for item in candidates],
                    symbol=callee_name,
                ))

        member_pattern = re.compile(
            r"\b(?P<receiver>[A-Za-z_]\w*|this|super)\s*\.\s*(?P<name>[A-Za-z_]\w*)\s*\("
        )
        for call in member_pattern.finditer(body):
            receiver, method = call.group("receiver"), call.group("name")
            if method in {"call", "delegatecall", "staticcall"}:
                continue
            if receiver == "super":
                inherited = []
                for base_name in func["bases"]:
                    inherited.extend(item for item in local_functions.get((base_name, method), []) if item["kind"] == "function")
                if len(inherited) == 1:
                    edges.append(_edge("CALLS", func["id"], inherited[0]["id"], path, source, body_absolute + call.start(), resolution="INFERRED"))
                    continue

            # Resolve static Library.method(...) and using Library for Type
            # extension calls without pretending arbitrary interface calls are local.
            library_candidates: list[dict[str, Any]] = []
            library_resolution = "INFERRED"
            static_libraries = [
                item for item in contract_by_name.get(receiver, [])
                if item.get("declaration_kind") == "library"
            ]
            if static_libraries:
                library_candidates = [
                    item for item in local_functions.get((receiver, method), [])
                    if item["kind"] == "function"
                ]
                library_resolution = "DIRECT"
            else:
                receiver_vars = [
                    item for item in state_variables
                    if item["contract"] == scope and item["file"] == path and item["name"] == receiver
                ]
                contract_units = [
                    item for item in contracts
                    if item["name"] == scope and item["file"] == path
                ]
                if len(receiver_vars) == 1 and len(contract_units) == 1:
                    receiver_type = receiver_vars[0].get("type", "").replace(" payable", "").strip()
                    for directive in contract_units[0].get("using_libraries") or []:
                        if directive.get("for_type") not in {receiver_type, "*"}:
                            continue
                        library_candidates.extend(
                            item for item in local_functions.get((directive["library"], method), [])
                            if item["kind"] == "function"
                        )
            if len(library_candidates) == 1:
                edges.append(_edge(
                    "CALLS", func["id"], library_candidates[0]["id"], path, source,
                    body_absolute + call.start(), resolution=library_resolution,
                    call_kind="library" if library_resolution == "DIRECT" else "using-for extension",
                ))
                continue
            if len(library_candidates) > 1:
                edges.append(_edge(
                    "CALLS", func["id"], f"library-function:{receiver}.{method}",
                    path, source, body_absolute + call.start(),
                    resolution="UNRESOLVED", candidates=[item["id"] for item in library_candidates],
                    call_kind="library-or-extension",
                ))
                continue

            # A typed interface/contract call resolves to its declared method,
            # not the code executing at the target address. Keep implementation
            # resolution explicitly UNRESOLVED (proxy/dynamic dispatch may apply).
            receiver_vars = [
                item for item in state_variables
                if item["contract"] in {scope, *func["bases"]}
                and item["name"] == receiver
            ]
            declared_type = receiver_vars[0].get("type", "").replace(" payable", "").strip() if len(receiver_vars) == 1 else ""
            type_contracts = contract_by_name.get(declared_type, []) if declared_type else []
            typed_methods = [
                item for item in functions
                if item["contract"] == declared_type
                and item["name"] == method
                and item["kind"] == "function"
            ] if len(type_contracts) == 1 else []
            if len(typed_methods) == 1:
                typed = typed_methods[0]
                edges.append(_edge(
                    "EXTERNAL_CALL", func["id"], typed["id"], path, source,
                    body_absolute + call.start(),
                    resolution="DIRECT", receiver=receiver, method=method,
                    target_kind=typed.get("contract_kind", "declared-type"),
                    implementation_resolution="UNRESOLVED",
                    detail="The declared interface/contract method is identified; the implementation at the runtime address is not.",
                ))
                continue
            if len(typed_methods) > 1:
                edges.append(_edge(
                    "EXTERNAL_CALL", func["id"], f"external:{declared_type}.{method}",
                    path, source, body_absolute + call.start(),
                    resolution="UNRESOLVED", receiver=receiver, method=method,
                    candidates=[item["id"] for item in typed_methods],
                    implementation_resolution="UNRESOLVED",
                ))
                continue
            edges.append(_edge(
                "EXTERNAL_CALL", func["id"], f"external:{receiver}.{method}",
                path, source, body_absolute + call.start(),
                resolution="UNRESOLVED", receiver=receiver, method=method,
                implementation_resolution="UNRESOLVED",
            ))

        for low_level in re.finditer(r"\.\s*(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\(", body):
            edges.append(_edge(
                "EXTERNAL_CALL", func["id"], f"low-level:{low_level.group(1)}",
                path, source, body_absolute + low_level.start(),
                resolution="UNRESOLVED", operation=low_level.group(1),
            ))

        accessible_state = [
            item for item in state_variables
            if (item["contract"] == scope and item["file"] == path)
            or item["contract"] in func["bases"]
        ]
        accessible_name_counts: dict[str, int] = {}
        for item in accessible_state:
            accessible_name_counts[item["name"]] = accessible_name_counts.get(item["name"], 0) + 1

        # Resolve local storage-reference aliases such as:
        # Position storage p = positions[user][id];
        # The alias is a pointer to the declared state object, not a new slot.
        alias_pattern = re.compile(
            r"\b(?P<type>[A-Za-z_]\w*(?:\s*\[\s*\])*)\s+storage\s+"
            r"(?P<alias>[A-Za-z_]\w*)\s*=\s*(?P<base>[A-Za-z_]\w*)"
            r"(?P<indexes>(?:\s*\[[^\]]*\])*)\s*;"
        )
        storage_aliases: list[dict[str, Any]] = []
        alias_ranges: list[tuple[int, int]] = []
        for alias_match in alias_pattern.finditer(body):
            base_name = alias_match.group("base")
            candidates = [
                item for item in accessible_state
                if item["name"] == base_name
                and accessible_name_counts.get(base_name, 0) == 1
            ]
            if len(candidates) != 1:
                continue
            variable = candidates[0]
            indexes = re.findall(r"\[([^\]]*)\]", alias_match.group("indexes"))
            alias = {
                "name": alias_match.group("alias"),
                "type": alias_match.group("type").strip(),
                "variable": variable,
                "indexes": [item.strip() for item in indexes],
                "start": alias_match.start(),
                "end": alias_match.end(),
            }
            storage_aliases.append(alias)
            alias_ranges.append((alias_match.start(), alias_match.end()))
            edges.append(_edge(
                "ALIASES_STORAGE", func["id"], variable["id"], path, source,
                body_absolute + alias_match.start(),
                resolution="DIRECT" if variable["contract"] == scope else "INFERRED",
                alias=alias["name"], keys=alias["indexes"],
                access_path=base_name + "".join(f"[{item}]" for item in indexes),
                detail="Local storage reference aliases the declared state variable; it is not a separate storage slot.",
            ))

        for alias in storage_aliases:
            alias_pattern_usage = re.compile(rf"\b{re.escape(alias['name'])}\b")
            for access in alias_pattern_usage.finditer(body):
                if any(start <= access.start() < end for start, end in alias_ranges):
                    continue
                cursor = access.end()
                while cursor < len(body) and body[cursor].isspace():
                    cursor += 1
                member_name = None
                if cursor < len(body) and body[cursor] == ".":
                    member_match = re.match(r"\.\s*([A-Za-z_]\w*)", body[cursor:])
                    if member_match:
                        member_name = member_match.group(1)
                        cursor += member_match.end()
                        while cursor < len(body) and body[cursor].isspace():
                            cursor += 1
                before = body[max(0, access.start() - 12):access.start()]
                after = body[cursor:cursor + 4]
                assignment = re.match(r"(?:\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=(?!=|>))", after)
                prefix_assignment = re.search(r"(?:\+\+|--)\s*$", before)
                deletion = re.search(r"\bdelete\s*$", before)
                is_write = bool(assignment or prefix_assignment or deletion)
                is_compound = bool(assignment and assignment.group(0) != "=") or bool(prefix_assignment)
                relations = ["WRITES"] if is_write else ["READS"]
                if is_compound:
                    relations.append("READS")
                variable = alias["variable"]
                access_path = alias["name"] + (f".{member_name}" if member_name else "")
                for relation in relations:
                    edges.append(_edge(
                        relation, func["id"], variable["id"], path, source,
                        body_absolute + access.start(),
                        variable=variable["name"], alias=alias["name"],
                        member=member_name, access_path=access_path,
                        resolution="DIRECT" if variable["contract"] == scope else "INFERRED",
                        evidence="STORAGE_ALIAS_RESOLUTION",
                    ))
                    struct_type = variable.get("mapping_value_type") or variable.get("type") or alias["type"]
                    struct_names = re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", struct_type)
                    if member_name and struct_names:
                        fields = fields_by_struct.get((variable["contract"], struct_names[-1]), [])
                        field = next((item for item in fields if item["name"] == member_name), None)
                        if field:
                            edges.append(_edge(
                                relation, func["id"], field["id"], path, source,
                                body_absolute + access.start(),
                                variable=variable["name"], alias=alias["name"],
                                member=member_name, access_path=access_path,
                                resolution="DIRECT" if variable["contract"] == scope else "INFERRED",
                                evidence="STORAGE_ALIAS_RESOLUTION",
                            ))

        for variable in accessible_state:
            if accessible_name_counts.get(variable["name"], 0) > 1:
                # A state name is shadowed across the inheritance boundary.
                # Do not guess which storage declaration the unqualified name uses.
                continue
            if variable["name"] in params_shadow:
                continue
            if re.search(rf"\b(?:[A-Za-z_]\w*\s+)+(?:memory|storage|calldata\s+)?{re.escape(variable['name'])}\b", body):
                # A same-named local declaration may shadow state. Do not guess.
                continue
            access_pattern = re.compile(rf"\b{re.escape(variable['name'])}\b")
            for access in access_pattern.finditer(body):
                if any(start <= access.start() < end for start, end in alias_ranges):
                    continue
                cursor = access.end()
                while cursor < len(body) and body[cursor].isspace():
                    cursor += 1
                access_keys: list[str] = []
                if cursor < len(body) and body[cursor] == "[":
                    close_index = _matching(body, cursor, "[", "]")
                    while close_index is not None:
                        access_keys.append(body[cursor + 1:close_index].strip())
                        cursor = close_index + 1
                        while cursor < len(body) and body[cursor].isspace():
                            cursor += 1
                        if cursor < len(body) and body[cursor] == "[":
                            close_index = _matching(body, cursor, "[", "]")
                        else:
                            break
                member_name = None
                if cursor < len(body) and body[cursor] == ".":
                    member_match = re.match(r"\.\s*([A-Za-z_]\w*)", body[cursor:])
                    if member_match:
                        member_name = member_match.group(1)
                        cursor += member_match.end()
                        while cursor < len(body) and body[cursor].isspace():
                            cursor += 1
                before = body[max(0, access.start() - 12):access.start()]
                after = body[cursor:cursor + 4]
                assignment = re.match(r"(?:\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=(?!=|>))", after)
                prefix_assignment = re.search(r"(?:\+\+|--)\s*$", before)
                deletion = re.search(r"\bdelete\s*$", before)
                is_write = bool(assignment or prefix_assignment or deletion)
                is_compound = bool(assignment and assignment.group(0) != "=") or bool(prefix_assignment)
                relations = ["WRITES"] if is_write else ["READS"]
                if is_compound:
                    relations.append("READS")
                access_path = variable["name"] + "".join(f"[{item}]" for item in access_keys)
                if member_name:
                    access_path += f".{member_name}"
                for relation in relations:
                    edges.append(_edge(
                        relation, func["id"], variable["id"], path, source,
                        body_absolute + access.start(),
                        variable=variable["name"], keys=access_keys,
                        member=member_name, access_path=access_path,
                        resolution="DIRECT" if variable["contract"] == scope else "INFERRED",
                        evidence="LEXICAL_SOURCE" if variable["contract"] == scope else "INHERITED_STORAGE_RESOLUTION",
                    ))
                    struct_type = variable.get("mapping_value_type") or variable.get("type")
                    struct_names = re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", struct_type or "")
                    if member_name and struct_names:
                        fields = fields_by_struct.get((variable["contract"], struct_names[-1]), [])
                        field = next((item for item in fields if item["name"] == member_name), None)
                        if field:
                            edges.append(_edge(
                                relation, func["id"], field["id"], path, source,
                                body_absolute + access.start(),
                                variable=variable["name"], keys=access_keys,
                                member=member_name, access_path=access_path,
                                resolution="DIRECT" if variable["contract"] == scope else "INFERRED",
                                evidence="LEXICAL_SOURCE" if variable["contract"] == scope else "INHERITED_STORAGE_RESOLUTION",
                            ))

        for emitted in re.finditer(r"\bemit\s+([A-Za-z_]\w*)\s*\(", body):
            name = emitted.group(1)
            event_nodes = [
                node for node in nodes
                if node.get("kind") == "event" and node.get("contract") == scope and node.get("name") == name
            ]
            if len(event_nodes) == 1:
                edges.append(_edge("EMITS", func["id"], event_nodes[0]["id"], path, source, body_absolute + emitted.start()))
            else:
                edges.append(_edge("EMITS", func["id"], f"event-name:{scope}.{name}", path, source, body_absolute + emitted.start(), resolution="UNRESOLVED"))

    # Asset-flow observations distinguish capability, source-level attempts,
    # and unresolved low-level behavior. No static result is runtime proof.
    for func in functions:
        if func["kind"] != "function":
            continue
        body = func["body"]
        path = func["file"]
        source = source_by_path.get(path, "")
        offset = func["body_start"] or 0
        if func["mutability"] == "payable":
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                func["source_offset"], status="CAPABILITY", asset="eth",
                direction="in", detail="Payable entry point can receive ETH; this does not prove a particular execution supplied or retained ETH.",
            ))
        for value_use in re.finditer(r"\bmsg\s*\.\s*value\b", body):
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + value_use.start(), status="VALUE_USAGE", asset="eth",
                direction="in", detail="Function reads msg.value; actual value supplied must be confirmed from runtime evidence.",
            ))

        # Include direct state and inherited state token handles, plus typed
        # IERC20 parameters (for SafeERC20 and helper-library implementations).
        token_names = {
            item["name"] for item in state_variables
            if item["contract"] in {func["contract"], *func.get("bases", [])}
            and re.search(r"\b(?:I?ERC20|ERC20|IERC20Metadata)\b", item.get("type", ""))
        }
        token_names.update(
            name for name, type_name in (func.get("parameter_types") or {}).items()
            if re.search(r"\b(?:I?ERC20|ERC20|IERC20Metadata)\b", (func.get("parameter_declared_types") or {}).get(name, type_name))
        )

        eth_call = re.compile(
            r"(?P<recipient>payable\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
            r"|address\s*\(\s*this\s*\)|payable\s*\([^)]*\)|msg\.sender|tx\.origin|[A-Za-z_]\w*)"
            r"\s*\.\s*call\s*\{\s*value\s*:\s*(?P<amount>[^}]+)\}"
        )
        for match in eth_call.finditer(body):
            recipient = re.sub(r"\s+", "", match.group("recipient"))
            if recipient in {"address(this)", "payable(address(this))"}:
                continue
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + match.start(), asset="eth", direction="out",
                status="TRANSFER_ATTEMPT", recipient=match.group("recipient").strip(),
                amount=match.group("amount").strip(),
                detail="Source-level value-bearing CALL; verify the call result and actual balance movement at runtime.",
            ))

        # .transfer/.send are native-ETH flows only when the receiver is
        # explicitly payable or is a state/parameter address payable. ERC20
        # transfer methods are kept in the ERC20 section below.
        payable_names = {
            item["name"] for item in state_variables
            if item["contract"] in {func["contract"], *func.get("bases", [])}
            and re.search(r"\baddress\s+payable\b", item.get("type", ""))
        }
        payable_names.update(
            name for name, type_name in (func.get("parameter_types") or {}).items()
            if re.search(r"\baddress\s+payable\b", (func.get("parameter_declared_types") or {}).get(name, type_name))
        )
        native_receiver = r"payable\s*\(\s*address\s*\(\s*this\s*\)\s*\)|payable\s*\([^)]*\)|" + "|".join(
            re.escape(name) for name in sorted(payable_names, key=len, reverse=True)
        ) if payable_names else r"payable\s*\([^)]*\)"
        native_method = re.compile(
            rf"(?P<recipient>{native_receiver})\s*\.\s*(?P<method>transfer|send)\s*\(\s*(?P<amount>[^)]*)\)"
        )
        for match in native_method.finditer(body):
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + match.start(), asset="eth", direction="out",
                status="TRANSFER_ATTEMPT", recipient=match.group("recipient").strip(),
                amount=match.group("amount").strip(), method=match.group("method"),
                detail="Payable-address transfer/send attempt; transfer success and balance movement require runtime verification.",
            ))

        # Value-bearing contract creation transfers ETH to the newly created
        # instance. Constructor execution remains unverified statically.
        creation = re.compile(
            r"\bnew\s+(?P<contract>[A-Za-z_]\w*)\s*\{\s*value\s*:\s*(?P<amount>[^}]+)\}"
        )
        for match in creation.finditer(body):
            edges.append(_edge(
                "ASSET_FLOW", func["id"], f"asset:eth:new:{match.group('contract')}",
                path, source, offset + match.start(), asset="eth", direction="out",
                status="CREATION_VALUE_ATTEMPT", recipient=f"new {match.group('contract')}",
                amount=match.group("amount").strip(),
                detail="Value is attached to contract creation; constructor behavior and deployed address require runtime/build evidence.",
            ))

        # SELFDESTRUCT balance transfers remain fork-sensitive. Do not assume
        # pre-Cancun code deletion semantics or a particular execution occurred.
        for destruction in re.finditer(r"\b(?:selfdestruct|suicide)\s*\((?P<recipient>[^)]*)\)", body):
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + destruction.start(), asset="eth", direction="out",
                status="FORK_SEMANTIC_DEPENDENT",
                recipient=destruction.group("recipient").strip(),
                detail="SELFDESTRUCT can transfer the account balance; code-deletion semantics depend on the active EVM fork and account history.",
            ))

        token_call = re.compile(
            r"\b(?P<token>[A-Za-z_]\w*)\s*\.\s*"
            r"(?P<method>safeTransferFrom|transferFrom|safeTransfer|transfer)\s*"
            r"\((?P<args>[^;{}]*)\)"
        )
        for match in token_call.finditer(body):
            if match.group("token") not in token_names:
                continue
            method = match.group("method")
            args = _split_top_level(match.group("args"))
            direction = "out" if method in {"transfer", "safeTransfer"} else "unresolved"
            sender = "address(this)" if direction == "out" else "UNRESOLVED"
            recipient = args[0].strip() if args else "UNRESOLVED"
            if method in {"transferFrom", "safeTransferFrom"} and len(args) >= 2:
                sender, recipient = args[0].strip(), args[1].strip()
                sender_compact = re.sub(r"\s+", "", sender)
                recipient_compact = re.sub(r"\s+", "", recipient)
                from_contract = sender_compact in {"address(this)", "payable(address(this))"}
                to_contract = recipient_compact in {"address(this)", "payable(address(this))"}
                if from_contract and to_contract:
                    direction = "both"
                elif from_contract:
                    direction = "out"
                elif to_contract:
                    direction = "in"
            edges.append(_edge(
                "ASSET_FLOW", func["id"], f"asset:erc20:{match.group('token')}",
                path, source, offset + match.start(),
                asset="erc20", direction=direction,
                status="TRANSFER_ATTEMPT" if direction != "unresolved" else "UNRESOLVED",
                token=match.group("token"), method=method, sender=sender,
                recipient=recipient, amount=args[-1].strip() if args else "UNRESOLVED",
                detail="ERC20-typed handle invokes a token transfer method; direction is source-expression based and success is not proven.",
            ))

        # Raw EVM calls and CREATE opcodes need operand-level decoding. Keep
        # these visible instead of guessing the recipient, value, or slot.
        assembly_pattern = re.compile(r"\bassembly\b(?:\s*\([^)]*\))?\s*\{")
        for assembly_match in assembly_pattern.finditer(body):
            assembly_open = assembly_match.end() - 1
            assembly_close = _matching(body, assembly_open, "{", "}")
            if assembly_close is None:
                failures.append({
                    "path": path, "phase": "assembly-parse",
                    "error": f"Unclosed assembly block in {func['qualified_name']} at line {_line(source, offset + assembly_match.start())}.",
                })
                continue
            assembly_body = body[assembly_open + 1:assembly_close]
            for operation in re.finditer(
                r"\b(call|callcode|delegatecall|staticcall|create|create2|selfdestruct|sload|sstore)\s*\(",
                assembly_body,
            ):
                opcode = operation.group(1).lower()
                absolute_offset = offset + assembly_open + 1 + operation.start()
                if opcode in {"sload", "sstore"}:
                    edges.append(_edge(
                        "UNRESOLVED_STORAGE", func["id"], f"storage-slot:{opcode}",
                        path, source, absolute_offset, resolution="UNRESOLVED",
                        operation=opcode,
                        detail="Assembly storage access is visible, but the slot expression is not mapped to a Solidity declaration by this lexical pass.",
                    ))
                else:
                    edges.append(_edge(
                        "EXTERNAL_CALL", func["id"], f"assembly-opcode:{opcode}",
                        path, source, absolute_offset, resolution="UNRESOLVED",
                        operation=opcode,
                        detail="Assembly EVM operation requires operand and runtime-context decoding.",
                    ))
                    if opcode in {"call", "callcode", "delegatecall", "create", "create2", "selfdestruct"}:
                        edges.append(_edge(
                            "ASSET_FLOW", func["id"], f"asset:unknown:{opcode}",
                            path, source, absolute_offset, asset="unknown",
                            direction="unresolved", status="ASSEMBLY_UNRESOLVED",
                            operation=opcode,
                            detail="Assembly contains a potentially value-moving EVM operation; decode operands and runtime context before assigning asset direction.",
                        ))

    # Add inferred storage/asset relationships through bounded internal call chains.
    direct_calls: dict[str, list[dict[str, Any]]] = {}
    for item in edges:
        if item["kind"] == "CALLS" and item["resolution"] in {"DIRECT", "INFERRED"}:
            direct_calls.setdefault(item["from"], []).append(item)
    direct_effects: dict[str, list[dict[str, Any]]] = {}
    for item in edges:
        if item["kind"] in {"READS", "WRITES", "ASSET_FLOW"}:
            direct_effects.setdefault(item["from"], []).append(item)
    direct_modifiers: dict[str, list[dict[str, Any]]] = {}
    for item in edges:
        if item["kind"] == "APPLIES_MODIFIER" and item["resolution"] in {"DIRECT", "INFERRED"}:
            direct_modifiers.setdefault(item["from"], []).append(item)
    function_by_id = {item["id"]: item for item in functions}
    for start_id, start_func in function_by_id.items():
        queue: list[tuple[str, list[str], int]] = [(start_id, [start_id], 0)]
        # Modifiers execute as part of the decorated function. Seed their bodies
        # into the bounded traversal, but preserve APPLIES_MODIFIER as the edge.
        queue.extend(
            (item["to"], [start_id, item["to"]], 1)
            for item in direct_modifiers.get(start_id, [])
            if item["to"] in function_by_id
        )
        visited = {start_id}
        while queue:
            current, chain, depth = queue.pop(0)
            if depth >= MAX_TRAVERSAL_DEPTH:
                continue
            for call_edge in direct_calls.get(current, []):
                target = call_edge["to"]
                if target in visited or target not in function_by_id:
                    continue
                visited.add(target)
                next_chain = chain + [target]
                for effect in direct_effects.get(target, []):
                    if effect["kind"] == "ASSET_FLOW" and effect.get("status") == "CAPABILITY":
                        continue
                    duplicate = any(
                        existing["from"] == start_id
                        and existing["to"] == effect["to"]
                        and existing["kind"] == effect["kind"]
                        and existing.get("direction") == effect.get("direction")
                        for existing in edges
                    )
                    if not duplicate:
                        inherited = dict(effect)
                        inherited.update({
                            "id": f"INFERRED:{start_id}:{effect['to']}:{effect['kind']}",
                            "from": start_id,
                            "resolution": "INFERRED",
                            "evidence": "CALL_GRAPH_PROPAGATION",
                            "via": next_chain,
                            "detail": "Effect is reachable through an internal helper; inspect the call chain before concluding execution.",
                        })
                        edges.append(inherited)
                queue.append((target, next_chain, depth + 1))

    if len(edges) > MAX_RELATIONSHIPS:
        raise SourceIndexError(f"Source index reached the {MAX_RELATIONSHIPS}-relationship safety limit.")

    # Deduplicate graph edges while preserving deterministic order.
    unique_edges: dict[str, dict[str, Any]] = {}
    for item in edges:
        unique_edges.setdefault(item["id"], item)
    edges = list(unique_edges.values())

    index = {
        "schema_version": CACHE_VERSION,
        "root": str(root_path),
        "parser": "LEXICAL",
        "nodes": nodes,
        "edges": edges,
        "inventory": {
            "complete": not failures,
            "uninspected": failures,
            "files_inspected": len(source_units),
            "files_discovered": inventory.get("files_discovered", len(source_units)),
        },
        "summary": {
            "files": len(file_ids),
            "contracts": len(contracts),
            "functions": sum(1 for item in functions if item["kind"] == "function"),
            "modifiers": sum(1 for item in functions if item["kind"] == "modifier"),
            "storage": len(state_variables),
            "mappings": sum(1 for item in state_variables if item["kind"] == "mapping"),
            "relationships": len(edges),
            "unresolved": sum(1 for item in edges if item.get("resolution") == "UNRESOLVED"),
        },
        "cache": {"status": "MISS", "fingerprint": fingerprint},
    }
    if use_cache:
        _save_cache(cached_path, {
            "cache_version": CACHE_VERSION,
            "fingerprint": fingerprint,
            "schema_version": index["schema_version"],
            "root": index["root"],
            "parser": index["parser"],
            "nodes": nodes,
            "edges": edges,
            "summary": index["summary"],
            "inventory": index["inventory"],
        })
    return index


def find_symbols(index: dict[str, Any], target: str) -> list[dict[str, Any]]:
    """Resolve Contract, Contract.symbol, or Contract.function(signature)."""
    query = target.strip()
    if not query:
        return []
    contract_name = None
    symbol_name = query
    if "." in query:
        contract_name, symbol_name = query.split(".", 1)
    exact_signature = "(" in symbol_name and symbol_name.endswith(")")
    candidates: list[dict[str, Any]] = []
    for node in index.get("nodes") or []:
        if node.get("kind") not in {
            "contract", "function", "modifier", "mapping", "state_variable",
            "struct", "struct_field", "event", "custom_error", "enum", "enum_value", "function_pointer",
        }:
            continue
        if contract_name and node.get("contract", node.get("name")) != contract_name:
            continue
        if contract_name and "." in symbol_name and not exact_signature:
            if node.get("qualified_name") != f"{contract_name}.{symbol_name}":
                continue
        if exact_signature:
            wanted_name, wanted_sig = symbol_name.split("(", 1)
            wanted_sig = "(" + wanted_sig
            if node.get("name") != wanted_name or node.get("signature") != f"{wanted_name}{wanted_sig}":
                continue
        elif node.get("name") != symbol_name:
            continue
        candidates.append(node)
    return candidates
