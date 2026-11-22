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

try:
    import source_ast
except ImportError:  # pragma: no cover - package-style import
    try:
        from lowkey import source_ast
    except ImportError:  # older partial installations retain lexical-only behavior
        source_ast = None


CACHE_VERSION = 15
MAX_CACHE_BYTES = 32 * 1024 * 1024
MAX_RELATIONSHIPS = 250_000
MAX_TRAVERSAL_DEPTH = 10

_BUILTIN_CALLS = {
    "if", "while", "for", "do", "return", "emit", "require", "assert",
    "revert", "keccak256", "sha256", "ripemd160", "ecrecover", "addmod",
    "mulmod", "abi", "type", "new", "delete", "unchecked", "assembly",
    "gasleft", "blockhash", "selfdestruct", "suicide", "payable", "address",
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
    if value.startswith("function(") or value.startswith("function ("):
        return "function"
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
        if (
            len(parts) > 1
            and parts[-1] not in {"payable", "external", "internal", "view", "pure"}
            and re.fullmatch(r"[A-Za-z_]\w*", parts[-1])
        ):
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


def _top_level_assignment_offset(value: str) -> int | None:
    """Return a declaration initializer '=', ignoring => and nested expressions."""
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
        elif char == "=" and parens == brackets == braces == 0:
            before = value[index - 1] if index else ""
            after = value[index + 1] if index + 1 < len(value) else ""
            if before in {"=", "!", "<", ">"} or after in {"=", ">"}:
                continue
            return index
    return None


def _state_declaration(statement: str) -> tuple[str, str] | None:
    value = statement.strip()
    if not value or re.match(
        r"^(function|modifier|event|error|using|pragma|import|return|emit|revert)\b",
        value,
    ):
        return None
    # Find the declared identifier at the end of the declaration prefix.
    assignment_offset = _top_level_assignment_offset(value)
    prefix = value[:assignment_offset].strip() if assignment_offset is not None else value
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
            assignment_offset = _top_level_assignment_offset(statement)
            prefix = statement[:assignment_offset].strip() if assignment_offset is not None else statement.strip()
            field_match = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
            if not field_match:
                continue
            field_type = prefix[:field_match.start()].strip()
            field_type = re.sub(r"\b(public|private|internal|memory|storage|calldata)\b", " ", field_type)
            field_type = re.sub(r"\s+", " ", field_type).strip()
            if field_type:
                yield match.group(1), field_match.group(1), field_type, offset


def _at_source_level(source: str, offset: int) -> bool:
    depth = 0
    for char in source[:offset]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
    return depth == 0


def _at_contract_depth(source: str, body_start: int, offset: int) -> bool:
    """Return true only for a declaration directly inside a contract body."""
    braces = parens = brackets = 0
    for char in source[body_start:offset]:
        if char == "{":
            braces += 1
        elif char == "}":
            braces = max(0, braces - 1)
        elif char == "(":
            parens += 1
        elif char == ")":
            parens = max(0, parens - 1)
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets = max(0, brackets - 1)
    return braces == 0 and parens == 0 and brackets == 0



def _has_local_shadow(body: str, name: str) -> bool:
    """Detect a local declaration without confusing return/delete/emit expressions."""
    blocked = r"(?:return|delete|emit|revert|if|else|for|while|require|assert|throw)"
    pattern = re.compile(
        rf"(?:^|[;{{}}])\s*(?!{blocked}\b)"
        rf"(?:[A-Za-z_]\w*(?:\s*\[[^\]]*\])?\s+)+"
        rf"(?:(?:memory|storage|calldata)\s+)?{re.escape(name)}\s*(?:=|;|,|\))",
        re.MULTILINE,
    )
    return bool(pattern.search(body))


def _signature_parameter_types(signature: str) -> list[str]:
    opening = signature.find("(")
    closing = signature.rfind(")")
    if opening < 0 or closing < opening:
        return []
    return _split_top_level(signature[opening + 1:closing])


def _infer_expression_type(
    expression: str,
    function: dict[str, Any],
    state_variables: list[dict[str, Any]],
    contract: str,
    file_path: str,
    body: str,
    before_offset: int,
) -> str | None:
    """Infer only common, explicit Solidity expression types; otherwise return unknown."""
    value = expression.strip()
    while value.startswith("(") and value.endswith(")"):
        closing = _matching(value, 0, "(", ")")
        if closing != len(value) - 1:
            break
        value = value[1:-1].strip()

    cast = re.match(
        r"^(address|bool|string|bytes(?:[1-9]|[12]\d|3[0-2])?|u?int(?:\d+)?)\s*\(",
        value,
    )
    if cast:
        return _canonical_parameter(cast.group(1))
    if value in {"msg.sender", "tx.origin", "address(this)", "address(0)"}:
        return "address"
    if value == "msg.value":
        return "uint256"
    if value in {"true", "false"}:
        return "bool"
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        return "address"
    if re.fullmatch(r"0x[0-9a-fA-F]{64}", value):
        return "bytes32"

    parameter_types = function.get("parameter_types") or {}
    if value in parameter_types:
        return str(parameter_types[value])

    local_prefix = body[:before_offset]
    local_match = None
    for match in re.finditer(
        r"\b(?P<type>[A-Za-z_]\w*(?:\s*\[[^\]]*\])*)\s+"
        r"(?:(?:memory|storage|calldata)\s+)?(?P<name>[A-Za-z_]\w*)\b",
        local_prefix,
    ):
        if match.group("name") == value:
            local_match = match
    if local_match:
        return _canonical_parameter(local_match.group("type"))

    state_matches = [
        item for item in state_variables
        if item.get("contract") in {contract, *function.get("bases", [])}
        and item.get("name") == value
    ]
    if len(state_matches) == 1:
        return _canonical_parameter(str(state_matches[0].get("type", "")))
    return None


def _filter_overloads_by_arguments(
    candidates: list[dict[str, Any]],
    argument_types: list[str | None],
) -> list[dict[str, Any]]:
    if not candidates:
        return []
    matched: list[dict[str, Any]] = []
    for candidate in candidates:
        parameter_types = _signature_parameter_types(str(candidate.get("signature", "")))
        if len(parameter_types) != len(argument_types):
            continue
        if all(
            inferred is None or inferred == expected
            for inferred, expected in zip(argument_types, parameter_types)
        ):
            matched.append(candidate)
    if matched:
        return matched
    # If every argument type was inferred, a mismatch is meaningful: do not
    # silently fall back to an unrelated overload. With partial information,
    # keep candidates visible as unresolved possibilities.
    if argument_types and all(item is not None for item in argument_types):
        return []
    return candidates


def _select_callable_declarations(
    candidates: list[dict[str, Any]],
    function: dict[str, Any],
    scope: str,
    file_path: str,
    argument_types: list[str | None],
) -> list[dict[str, Any]]:
    """Prefer local declarations; otherwise nearest inherited declarations per signature."""
    if not candidates:
        return []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in candidates:
        grouped.setdefault(str(item.get("signature", "")), []).append(item)
    selected: list[dict[str, Any]] = []
    for group in grouped.values():
        local = [
            item for item in group
            if item.get("contract") == scope and item.get("file") == file_path
        ]
        if local:
            selected.extend(local)
        else:
            selected.extend(_nearest_inherited(
                group, function.get("ancestor_depths") or {}
            ))
    return _filter_overloads_by_arguments(selected, argument_types)


def _nearest_inherited(
    candidates: list[dict[str, Any]],
    ancestor_depths: dict[str, int],
) -> list[dict[str, Any]]:
    """Keep only the nearest inherited declaration(s); preserve same-depth ambiguity."""
    if not candidates:
        return []
    nearest = min(
        ancestor_depths.get(str(item.get("contract")), MAX_TRAVERSAL_DEPTH + 1)
        for item in candidates
    )
    return [
        item for item in candidates
        if ancestor_depths.get(str(item.get("contract")), MAX_TRAVERSAL_DEPTH + 1) == nearest
    ]


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
    candidate_ids = extra.get("candidates")
    if resolution == "UNRESOLVED" and isinstance(candidate_ids, list) and len(candidate_ids) > 1:
        resolution = "AMBIGUOUS"
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


def _storage_index_info(type_name: str) -> tuple[str, str | None, str]:
    """Classify one Solidity storage index using the declared current type."""
    value = re.sub(r"\b(memory|calldata|storage|payable)\b", " ", type_name)
    value = re.sub(r"\s+", " ", value).strip()
    if value.startswith("mapping"):
        opening = value.find("(")
        closing = _matching(value, opening, "(", ")") if opening >= 0 else None
        if closing is None:
            return "unresolved", None, ""
        parts = re.split(r"\s*=>\s*", value[opening + 1:closing], maxsplit=1)
        if len(parts) != 2:
            return "unresolved", None, ""
        return "mapping", parts[0].strip(), parts[1].strip()
    array_match = re.search(r"\[\s*(?:\d+)?\s*\]\s*$", value)
    if array_match:
        return "array", "uint256", value[:array_match.start()].strip()
    return "unresolved", None, ""


def _storage_type_after_index(type_name: str) -> str:
    """Return the value type after one mapping or array index operation."""
    value = re.sub(r"\b(memory|calldata|storage|payable)\b", " ", type_name)
    value = re.sub(r"\s+", " ", value).strip()
    if value.startswith("mapping"):
        opening = value.find("(")
        closing = _matching(value, opening, "(", ")") if opening >= 0 else None
        if closing is None:
            return ""
        parts = re.split(r"\s*=>\s*", value[opening + 1:closing], maxsplit=1)
        return parts[1].strip() if len(parts) == 2 else ""
    array_match = re.search(r"\[\s*(?:\d+)?\s*\]\s*$", value)
    if array_match:
        return value[:array_match.start()].strip()
    return ""


def _storage_terminal_type(type_name: str) -> str:
    """Extract a simple struct/enum type name from a storage type expression."""
    value = re.sub(r"\b(memory|calldata|storage|payable|struct|contract|enum)\b", " ", type_name)
    value = re.sub(r"\s+", " ", value).strip()
    while value.startswith("mapping"):
        value = _storage_type_after_index(value)
    value = re.sub(r"\[\s*(?:\d+)?\s*\]\s*$", "", value).strip()
    matches = re.findall(r"[A-Za-z_]\w*", value)
    return matches[-1] if matches else ""


def _storage_is_array(type_name: str) -> bool:
    value = re.sub(r"\b(memory|calldata|storage|payable)\b", " ", type_name)
    return bool(re.search(r"\[\s*(?:\d+)?\s*\]\s*$", value.strip()))


def _scan_storage_access(
    body: str,
    start: int,
    *,
    base_name: str,
    base_type: str,
    base_indexes: list[str],
    contract: str,
    fields_by_struct: dict[tuple[str, str], list[dict[str, Any]]],
    base_index_kinds: list[str] | None = None,
    base_index_types: list[str | None] | None = None,
) -> dict[str, Any]:
    """Follow a state access through nested mapping/array indices and struct fields.

    This is a conservative lexical expression walker. It records every parsed
    key/member and never guesses a struct field when the declared type is unknown.
    """
    path = base_name + "".join(f"[{item}]" for item in base_indexes)
    keys = list(base_indexes)
    index_kinds = list(base_index_kinds or [])
    index_types = list(base_index_types or [])
    while len(index_kinds) < len(keys):
        index_kinds.append("unresolved")
    while len(index_types) < len(keys):
        index_types.append(None)
    members: list[str] = []
    field_nodes: list[dict[str, Any]] = []
    current_type = base_type
    cursor = start
    array_method = None

    while cursor < len(body):
        while cursor < len(body) and body[cursor].isspace():
            cursor += 1
        if cursor >= len(body):
            break

        if body[cursor] == "[":
            close_index = _matching(body, cursor, "[", "]")
            if close_index is None:
                break
            key = body[cursor + 1:close_index].strip()
            index_kind, index_type, next_type = _storage_index_info(current_type)
            keys.append(key)
            index_kinds.append(index_kind)
            index_types.append(index_type)
            path += f"[{key}]"
            current_type = next_type
            cursor = close_index + 1
            continue

        if body[cursor] == ".":
            member_match = re.match(r"\.\s*([A-Za-z_]\w*)", body[cursor:])
            if not member_match:
                break
            member_name = member_match.group(1)
            member_end = cursor + member_match.end()
            lookahead = member_end
            while lookahead < len(body) and body[lookahead].isspace():
                lookahead += 1
            if lookahead < len(body) and body[lookahead] == "(":
                if member_name in {"push", "pop"} and _storage_is_array(current_type):
                    array_method = member_name
                break

            members.append(member_name)
            path += f".{member_name}"
            struct_name = _storage_terminal_type(current_type)
            field = next(
                (
                    item for item in fields_by_struct.get((contract, struct_name), [])
                    if item.get("name") == member_name
                ),
                None,
            ) if struct_name else None
            if field is None:
                current_type = ""
            else:
                field_nodes.append(field)
                current_type = str(field.get("type") or "")
            cursor = member_end
            continue

        break

    return {
        "access_path": path,
        "keys": keys,
        "members": members,
        "member": members[-1] if members else None,
        "field_nodes": field_nodes,
        "array_method": array_method,
        "end": cursor,
        "terminal_type": current_type,
        "index_kinds": index_kinds,
        "index_types": index_types,
        "mapping_key_types": [
            index_type for kind, index_type in zip(index_kinds, index_types)
            if kind == "mapping"
        ],
        "mapping_depth": sum(1 for kind in index_kinds if kind == "mapping"),
    }



def _tuple_assignment_for(body: str, position: int) -> bool:
    """Recognize a state variable on the left side of a simple tuple assignment."""
    statement_start = max(
        body.rfind(";", 0, position),
        body.rfind("{", 0, position),
        body.rfind("}", 0, position),
    ) + 1
    statement_end = body.find(";", position)
    if statement_end < 0:
        statement_end = len(body)
    statement = body[statement_start:statement_end]
    assignment = _top_level_assignment_offset(statement)
    if assignment is None or position - statement_start > assignment:
        return False
    return bool(re.search(r"\([^()]*,[^()]*\)\s*$", statement[:assignment]))


def build_source_index(root: str | Path = ".", *, use_cache: bool = True) -> dict[str, Any]:
    """Build one shared source relationship graph for a Solidity project.

    Existing Lowkey project discovery/import resolution is reused. The index is
    read-only, bounded by project_tools' existing source inventory limits, and
    cached by the content hashes of all indexed files plus Foundry configuration.
    """
    root_path = project_tools.project_root(root).resolve()
    try:
        inventory = project_tools.solidity_source_inventory(root_path)
    except Exception as error:
        raise SourceIndexError(f"Could not build the Solidity source inventory: {error}") from error

    failures = list(inventory.get("uninspected") or [])
    build_config = ""
    config_path = root_path / "foundry.toml"
    try:
        build_config = config_path.read_text(encoding="utf-8")
    except OSError:
        pass

    # Fingerprint the current first-party inventory before constructing the
    # dependency graph. This allows a repeat query to skip that graph entirely.
    root_manifest: list[dict[str, str]] = []
    inventory_bytes = 0
    for item in inventory.get("files") or []:
        relative = str(item.get("path") or "")
        absolute = (root_path / relative).resolve()
        try:
            raw = absolute.read_bytes()
        except OSError as error:
            failures.append({"path": relative, "phase": "cache-validation", "error": str(error)})
            continue
        inventory_bytes += len(raw)
        root_manifest.append({
            "path": str(absolute),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    root_manifest.sort(key=lambda item: item["path"])

    try:
        ast_build_manifest = (
            source_ast.build_info_manifest(root_path)
            if source_ast is not None
            else {"directory_present": False, "files": [], "skipped": []}
        )
    except Exception as error:
        ast_build_manifest = {
            "directory_present": False, "files": [],
            "skipped": [{"reason": f"manifest failed: {error}"}],
        }

    resolution_inputs: dict[str, str] = {}
    for config_name in ("remappings.txt", "soldeer.lock", ".gitmodules"):
        try:
            resolution_inputs[config_name] = (root_path / config_name).read_text(encoding="utf-8")
        except OSError:
            resolution_inputs[config_name] = ""

    fingerprint_data = {
        "version": CACHE_VERSION,
        "root": str(root_path),
        "foundry": build_config,
        "foundry_profile": os.environ.get("FOUNDRY_PROFILE", "default"),
        "resolution_inputs": resolution_inputs,
        "root_manifest": root_manifest,
        "solc_build_info_manifest": ast_build_manifest,
    }
    fingerprint = hashlib.sha256(
        json.dumps(fingerprint_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    cached_path = _cache_path(fingerprint)

    if use_cache and inventory.get("complete") and not failures:
        cached = _load_cache(cached_path, fingerprint)
        if cached is not None and cached.get("root_manifest") == root_manifest:
            cached_import_edges = [
                edge for edge in cached.get("edges") or []
                if edge.get("kind") == "IMPORTS"
            ]
            # An unresolved import can become resolvable without modifying a
            # file already in this cache, so do not use a cache with one.
            imports_are_resolved = all(
                edge.get("resolution") != "UNRESOLVED" for edge in cached_import_edges
            )
            manifest_valid = True
            for entry in cached.get("source_manifest") or []:
                try:
                    current_hash = hashlib.sha256(Path(entry["path"]).read_bytes()).hexdigest()
                except (OSError, KeyError, TypeError):
                    manifest_valid = False
                    break
                if current_hash != entry.get("sha256"):
                    manifest_valid = False
                    break
            if imports_are_resolved and manifest_valid:
                cached_inventory = cached.get("inventory") or {}
                cached_failures = cached_inventory.get("uninspected") or []
                merged_failures = failures + cached_failures
                cached["inventory"] = {
                    "complete": not merged_failures,
                    "uninspected": merged_failures,
                    "files_inspected": len(root_manifest),
                    "files_discovered": inventory.get("files_discovered", len(root_manifest)),
                }
                cached["cache"] = {"status": "HIT", "fingerprint": fingerprint}
                return cached

    try:
        base_graph = project_tools.build_dependency_graph(root_path)
    except Exception as error:
        raise SourceIndexError(f"Could not build the project dependency graph: {error}") from error

    source_units: list[tuple[str, str, Path]] = []
    source_provenance: dict[str, str] = {}
    known_source_paths: set[Path] = set()
    source_raw_hashes: dict[str, str] = {}
    dependency_import_edges: list[dict[str, Any]] = []
    source_total_bytes = 0
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
            if source_total_bytes + len(data) > project_tools.SOLIDITY_SOURCE_MAX_TOTAL_BYTES:
                failures.append({"path": relative, "phase": "inventory-budget", "error": "Source index would exceed the 128 MiB project source budget."})
                continue
            source_total_bytes += len(data)
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
        source_raw_hashes[str(path.resolve())] = hashlib.sha256(data).hexdigest()
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
            if source_total_bytes + len(data) > project_tools.SOLIDITY_SOURCE_MAX_TOTAL_BYTES:
                failures.append({"path": raw_target, "phase": "inventory-budget", "error": "Source index would exceed the 128 MiB total source budget."})
                continue
            source_total_bytes += len(data)
            source = data.decode("utf-8-sig")
        except (OSError, UnicodeError, RuntimeError) as error:
            failures.append({"path": raw_target, "phase": "dependency-read", "error": str(error)})
            continue
        display_path = os.path.relpath(target_path, root_path).replace(os.sep, "/")
        source_units.append((display_path, source, target_path))
        source_provenance[display_path] = "third-party"
        source_raw_hashes[str(target_path)] = hashlib.sha256(data).hexdigest()
        known_source_paths.add(target_path)
        external_total_bytes += len(data)
        external_file_count += 1

    # Follow imports made by the explicitly imported third-party files as well.
    # This remains a narrow transitive closure, not a scan of all dependency code.
    remappings = project_tools._solidity_remappings(root_path)
    dependency_queue = [
        path for display, _source, path in source_units
        if source_provenance.get(display) == "third-party"
    ]
    dependency_seen = {path.resolve() for path in dependency_queue}
    while dependency_queue:
        importer = dependency_queue.pop(0)
        importer_display = os.path.relpath(importer, root_path).replace(os.sep, "/")
        try:
            importer_source = next(source for display, source, path in source_units if path.resolve() == importer.resolve())
        except StopIteration:
            continue
        for raw_import, import_line, import_statement in project_tools._solidity_imports(importer_source):
            resolved = project_tools._resolve_solidity_import(importer, raw_import, root_path, remappings)
            if resolved is None:
                dependency_import_edges.append({
                    "from": importer_display, "to": raw_import, "raw": raw_import,
                    "line": import_line, "statement": import_statement, "resolved": False,
                })
                failures.append({
                    "path": importer_display, "phase": "dependency-import",
                    "error": f"Could not resolve imported source {raw_import!r} at line {import_line}.",
                })
                continue
            resolved = resolved.resolve()
            provenance = project_tools._import_provenance(resolved, root_path)
            if resolved.suffix.lower() != ".sol" or not resolved.is_file():
                continue
            display_path = os.path.relpath(resolved, root_path).replace(os.sep, "/")
            if resolved in known_source_paths:
                dependency_import_edges.append({
                    "from": importer_display, "to": display_path, "raw": raw_import,
                    "line": import_line, "statement": import_statement, "resolved": True,
                })
                continue
            try:
                size = resolved.stat().st_size
                if size > project_tools.SOLIDITY_SOURCE_MAX_FILE_BYTES:
                    failures.append({"path": str(resolved), "phase": "dependency-size-limit", "error": "Imported source exceeds the per-file source limit."})
                    dependency_import_edges.append({
                        "from": importer_display, "to": str(resolved), "raw": raw_import,
                        "line": import_line, "statement": import_statement, "resolved": False,
                    })
                    continue
                if provenance == "third-party" and (
                    external_file_count >= 64 or external_total_bytes + size > 16 * 1024 * 1024
                ):
                    failures.append({"path": str(resolved), "phase": "dependency-inventory-budget", "error": "Imported dependency source budget reached (64 files / 16 MiB)."})
                    dependency_import_edges.append({
                        "from": importer_display, "to": str(resolved), "raw": raw_import,
                        "line": import_line, "statement": import_statement, "resolved": False,
                    })
                    continue
                raw_data = resolved.read_bytes()
                if source_total_bytes + len(raw_data) > project_tools.SOLIDITY_SOURCE_MAX_TOTAL_BYTES:
                    failures.append({"path": str(resolved), "phase": "inventory-budget", "error": "Source index would exceed the 128 MiB total source budget."})
                    dependency_import_edges.append({
                        "from": importer_display, "to": str(resolved), "raw": raw_import,
                        "line": import_line, "statement": import_statement, "resolved": False,
                    })
                    continue
                source_total_bytes += len(raw_data)
                imported_source = raw_data.decode("utf-8-sig")
            except (OSError, UnicodeError, RuntimeError) as error:
                failures.append({"path": str(resolved), "phase": "dependency-read", "error": str(error)})
                dependency_import_edges.append({
                    "from": importer_display, "to": str(resolved), "raw": raw_import,
                    "line": import_line, "statement": import_statement, "resolved": False,
                })
                continue

            source_units.append((display_path, imported_source, resolved))
            source_provenance[display_path] = "third-party" if provenance == "third-party" else "first-party"
            source_raw_hashes[str(resolved)] = hashlib.sha256(raw_data).hexdigest()
            known_source_paths.add(resolved)
            dependency_import_edges.append({
                "from": importer_display, "to": display_path, "raw": raw_import,
                "line": import_line, "statement": import_statement, "resolved": True,
            })
            if provenance == "third-party":
                external_total_bytes += len(raw_data)
                external_file_count += 1
                if resolved not in dependency_seen:
                    dependency_seen.add(resolved)
                    dependency_queue.append(resolved)

    source_units.sort(key=lambda item: item[0].casefold())
    source_by_path = {path: source for path, source, _absolute in source_units}
    source_manifest = [
        {"path": path, "sha256": digest}
        for path, digest in sorted(source_raw_hashes.items())
    ]

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    contracts: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    state_variables: list[dict[str, Any]] = []
    function_pointers: list[dict[str, Any]] = []
    structs: list[dict[str, Any]] = []
    struct_node_ids: set[str] = set()
    events_by_contract_name: dict[tuple[str, str], list[dict[str, Any]]] = {}
    errors_by_contract_name: dict[tuple[str, str], list[dict[str, Any]]] = {}
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
                "line": _line(source, offset),
                "provenance": source_provenance.get(path, "unclassified"),
                "evidence": "LEXICAL_SOURCE",
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
        file_using_libraries = [
            {"library": using.group(1), "for_type": using.group(2), "offset": using.start()}
            for using in re.finditer(
                r"\busing\s+([A-Za-z_]\w*)\s+for\s+([A-Za-z_]\w*|\*)\s*(?:global\s*)?;",
                clean,
            )
            if _at_source_level(clean, using.start())
        ]
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
            inheritance_match = re.search(r"\bis\b", header)
            bases = [
                part.strip().split("(", 1)[0].strip()
                for part in _split_top_level(header[inheritance_match.end():])
            ] if inheritance_match else []
            contract = {
                "id": contract_id, "kind": "contract", "name": name,
                "qualified_name": qualified, "file": path,
                "line": _line(source, match.start()), "offset": match.start(),
                "body_start": opening + 1, "body_end": closing,
                "bases": [base for base in bases if re.fullmatch(r"[A-Za-z_]\w*", base)],
                "source": source, "clean": clean,
                "declaration_kind": match.group("kind"),
                "provenance": source_provenance.get(path, "unclassified"),
                "using_libraries": file_using_libraries + [
                    {"library": using.group(1), "for_type": using.group(2), "offset": using.start()}
                    for using in re.compile(
                        r"\busing\s+([A-Za-z_]\w*)\s+for\s+([A-Za-z_]\w*|\*)\s*(?:global\s*)?;"
                    ).finditer(clean, opening + 1, closing)
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
                if struct_id not in struct_node_ids:
                    struct_node_ids.add(struct_id)
                    struct_node = {
                        "id": struct_id, "kind": "struct", "name": field_struct,
                        "qualified_name": f"{name}.{field_struct}", "contract": name,
                        "file": path, "line": _line(source, field_offset),
                        "provenance": source_provenance.get(path, "unclassified"),
                    }
                    structs.append(struct_node)
                    add_node({**struct_node, "evidence": "LEXICAL_SOURCE"})
                    edges.append(_edge("DECLARES", contract_id, struct_id, path, source, field_offset))
                field_id = _node_id("struct_field", path, f"{name}.{field_struct}.{field_name}")
                field_node = {
                    "id": field_id, "kind": "struct_field", "name": field_name,
                    "qualified_name": f"{name}.{field_struct}.{field_name}",
                    "contract": name, "struct": field_struct, "type": field_type,
                    "file": path, "line": _line(source, field_offset),
                    "source_offset": field_offset,
                    "provenance": source_provenance.get(path, "unclassified"),
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
                        "provenance": source_provenance.get(path, "unclassified"),
                        "evidence": "LEXICAL_SOURCE",
                    }
                    function_pointers.append(pointer_node)
                    add_node(pointer_node)
                    pointer_storage = {
                        **pointer_node, "type": "function", "scope": "state",
                        "source_offset": statement_offset,
                        "initializer": statement.split("=", 1)[1].strip() if "=" in statement else None,
                    }
                    state_variables.append(pointer_storage)
                    edges.append(_edge("DECLARES", contract_id, pointer_id, path, source, statement_offset))
                    if pointer_storage["initializer"] is not None:
                        edges.append(_edge(
                            "INITIALIZES", contract_id, pointer_id, path, source, statement_offset,
                            initializer=pointer_storage["initializer"],
                        ))
                    continue
                declaration = _state_declaration(statement)
                if declaration is None:
                    continue
                variable_name, variable_type = declaration
                mapping = variable_type.startswith("mapping")
                kind = "mapping" if mapping else "state_variable"
                variable_id = _node_id(kind, path, f"{name}.{variable_name}")
                initializer_offset = _top_level_assignment_offset(statement)
                initializer = statement[initializer_offset + 1:].strip() if initializer_offset is not None else None
                storage_class = (
                    "constant" if re.search(r"\bconstant\b", statement)
                    else "immutable" if re.search(r"\bimmutable\b", statement)
                    else "transient" if re.search(r"\btransient\b", statement)
                    else "persistent"
                )
                variable = {
                    "id": variable_id, "kind": kind, "name": variable_name,
                    "qualified_name": f"{name}.{variable_name}", "contract": name,
                    "file": path, "line": _line(source, statement_offset),
                    "provenance": source_provenance.get(path, "unclassified"),
                    "initializer": initializer, "type": variable_type, "source_offset": statement_offset,
                    "mapping_value_type": _mapping_inner_type(variable_type),
                    "mapping_keys": _mapping_layout(variable_type)[0] if mapping else [],
                    "scope": "state", "storage_class": storage_class,
                    "persistence": storage_class,
                }
                state_variables.append(variable)
                add_node({**variable, "evidence": "LEXICAL_SOURCE"})
                edges.append(_edge("DECLARES", contract_id, variable_id, path, source, statement_offset))
                if initializer is not None:
                    edges.append(_edge(
                        "INITIALIZES", contract_id, variable_id, path, source, statement_offset,
                        initializer=initializer, operation="INITIALIZER",
                        mutation_kind="INITIALIZATION", persistence=storage_class,
                        detail="State declaration initializer; this is a potential construction-time initialization, not proof of deployed state.",
                    ))
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
                    "provenance": source_provenance.get(path, "unclassified"),
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
                        "line": _line(source, value_offset),
                        "provenance": source_provenance.get(path, "unclassified"),
                        "evidence": "LEXICAL_SOURCE",
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
                    symbol_node = {
                        "id": symbol_id, "kind": kind, "name": declaration_match.group(1),
                        "qualified_name": f"{name}.{declaration_match.group(1)}",
                        "contract": name, "file": path,
                        "line": _line(source, declaration_match.start()),
                        "provenance": source_provenance.get(path, "unclassified"),
                        "evidence": "LEXICAL_SOURCE",
                    }
                    add_node(symbol_node)
                    lookup = events_by_contract_name if kind == "event" else errors_by_contract_name
                    lookup.setdefault((name, declaration_match.group(1)), []).append(symbol_node)
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
                    "provenance": contract["provenance"],
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
                    **{key: value for key, value in func.items() if key not in {"header", "body", "body_start", "body_end"}},
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

    for dependency_edge in dependency_import_edges:
        importer_id = file_ids.get(dependency_edge["from"])
        target_id = file_ids.get(dependency_edge["to"])
        if importer_id is None:
            continue
        edges.append({
            "id": f"IMPORTS:{importer_id}:{target_id or dependency_edge['to']}:{dependency_edge['line']}",
            "kind": "IMPORTS", "from": importer_id,
            "to": target_id or dependency_edge["to"],
            "resolution": "DIRECT" if dependency_edge.get("resolved") and target_id else "UNRESOLVED",
            "evidence": "LEXICAL_DEPENDENCY_IMPORT",
            "source": {"file": dependency_edge["from"], "line": dependency_edge["line"], "column": 1},
            "raw": dependency_edge.get("raw"), "provenance": "third-party",
        })

    # Resolve transitive inheritance only across uniquely named contracts.
    # Ambiguous parents remain unresolved; no name-based guess is promoted.
    for contract in contracts:
        ancestors: list[str] = []
        ancestor_depths: dict[str, int] = {}

        def visit_base(base_name: str, depth: int) -> None:
            previous = ancestor_depths.get(base_name)
            if previous is not None and previous <= depth:
                return
            ancestor_depths[base_name] = depth
            matches = contract_by_name.get(base_name, [])
            if len(matches) != 1:
                return
            if base_name not in ancestors:
                ancestors.append(base_name)
            for parent in matches[0].get("bases") or []:
                visit_base(parent, depth + 1)

        for direct_base in contract.get("bases") or []:
            visit_base(direct_base, 1)
        contract["ancestors"] = ancestors
        contract["ancestor_depths"] = ancestor_depths
        for node in nodes:
            if node.get("id") == contract["id"]:
                node["ancestors"] = ancestors
                node["ancestor_depths"] = ancestor_depths
                break

    for func in functions:
        owning_contract = next(
            (
                item for item in contracts
                if item["name"] == func["contract"] and item["file"] == func["file"]
            ),
            None,
        )
        if owning_contract is not None:
            func["bases"] = list(owning_contract.get("ancestors") or [])
            func["ancestor_depths"] = dict(owning_contract.get("ancestor_depths") or {})

    # Resolve user-defined state and parameter types to a unique contract,
    # interface, library or struct declaration where possible.
    for variable in state_variables:
        type_name = re.sub(r"\s+payable\b", "", variable.get("type", "")).strip()
        type_name = re.sub(r"(?:\[\s*\])+$", "", type_name).strip()
        if variable.get("kind") == "mapping":
            type_name = variable.get("mapping_value_type") or ""
        type_name = type_name.strip()
        if re.fullmatch(r"[A-Za-z_]\w*", type_name):
            candidates = contract_by_name.get(type_name, [])
            if len(candidates) == 1:
                edges.append(_edge(
                    "USES_TYPE", variable["id"], candidates[0]["id"],
                    variable["file"], source_by_path.get(variable["file"], ""),
                    variable.get("source_offset", 0), type_name=type_name,
                ))

    # Struct fields and enum-typed storage are linked to their declared
    # user-defined type where the name is unique in the owning contract.
    for node in list(nodes):
        if node.get("kind") != "struct_field":
            continue
        field_type = re.sub(r"\s+(memory|calldata|storage|payable)\b", " ", node.get("type", ""))
        field_type = re.sub(r"(?:\[\s*\])+$", "", field_type)
        field_type = re.sub(r"\s+", " ", field_type).strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", field_type):
            continue
        typed_contracts = contract_by_name.get(field_type, [])
        enum_matches = [
            candidate for candidate in nodes
            if candidate.get("kind") == "enum"
            and candidate.get("name") == field_type
            and candidate.get("contract") == node.get("contract")
        ]
        candidates = typed_contracts if len(typed_contracts) == 1 else enum_matches
        if len(candidates) == 1:
            edges.append(_edge(
                "USES_TYPE", node["id"], candidates[0]["id"],
                node["file"], source_by_path.get(node["file"], ""),
                node.get("source_offset", 0),
                type_name=field_type,
            ))

    for variable in state_variables:
        type_name = re.sub(r"\s+payable\b", "", variable.get("type", "")).strip()
        type_name = re.sub(r"(?:\[\s*\])+$", "", type_name).strip()
        if variable.get("kind") == "mapping":
            type_name = variable.get("mapping_value_type") or ""
        if not re.fullmatch(r"[A-Za-z_]\w*", type_name):
            continue
        if any(
            edge.get("kind") == "USES_TYPE" and edge.get("from") == variable["id"]
            for edge in edges
        ):
            continue
        enum_matches = [
            candidate for candidate in nodes
            if candidate.get("kind") == "enum"
            and candidate.get("name") == type_name
            and candidate.get("contract") == variable.get("contract")
        ]
        if len(enum_matches) == 1:
            edges.append(_edge(
                "USES_TYPE", variable["id"], enum_matches[0]["id"],
                variable["file"], source_by_path.get(variable["file"], ""),
                variable.get("source_offset", 0), type_name=type_name,
            ))

    for func in functions:
        for parameter_name, declared_type in (func.get("parameter_declared_types") or {}).items():
            simple_type = re.sub(r"\b(memory|calldata|storage|payable|external|internal)\b", " ", declared_type)
            simple_type = re.sub(r"(?:\[\s*\])+$", "", simple_type)
            simple_type = re.sub(r"\s+", " ", simple_type).strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", simple_type):
                continue
            candidates = contract_by_name.get(simple_type, [])
            if len(candidates) == 1:
                edges.append(_edge(
                    "USES_TYPE", func["id"], candidates[0]["id"],
                    func["file"], source_by_path.get(func["file"], ""),
                    func["source_offset"], parameter=parameter_name,
                    type_name=simple_type,
                ))

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
                if inherited["contract"] in contract.get("ancestors", contract["bases"])
                and inherited["kind"] == "function"
                and inherited["signature"] == func["signature"]
            ]
            candidates = _nearest_inherited(candidates, contract.get("ancestor_depths") or {})
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

        # Inline Yul is a separate language. Do not infer Solidity identifiers,
        # function calls, or ordinary state-variable accesses from its contents.
        assembly_ranges: list[tuple[int, int]] = []
        for assembly_match in re.finditer(r"\bassembly\b(?:\s*\([^)]*\))?\s*\{", body):
            assembly_open = assembly_match.end() - 1
            assembly_close = _matching(body, assembly_open, "{", "}")
            assembly_ranges.append((
                assembly_open,
                (assembly_close + 1) if assembly_close is not None else len(body),
            ))

        def in_assembly(offset: int) -> bool:
            return any(start <= offset < end for start, end in assembly_ranges)

        if func["kind"] == "function":
            modifier_names = sorted({item["name"] for item in known_modifiers})
            for modifier_name in modifier_names:
                if not re.search(rf"\b{re.escape(modifier_name)}\b", func["header"]):
                    continue
                candidates = [
                    item for item in known_modifiers
                    if item["contract"] == scope and item["file"] == path
                    and item["name"] == modifier_name
                ]
                inherited_modifier = False
                if not candidates:
                    candidates = [
                        item for item in known_modifiers
                        if item["contract"] in func["bases"] and item["name"] == modifier_name
                    ]
                    candidates = _nearest_inherited(candidates, func.get("ancestor_depths") or {})
                    inherited_modifier = bool(candidates)
                if len(candidates) == 1:
                    edges.append(_edge(
                        "APPLIES_MODIFIER", func["id"], candidates[0]["id"], path, source,
                        func["source_offset"],
                        resolution="INFERRED" if inherited_modifier else "DIRECT",
                    ))
                elif len(candidates) > 1:
                    edges.append(_edge(
                        "APPLIES_MODIFIER", func["id"], f"modifier-name:{scope}.{modifier_name}",
                        path, source, func["source_offset"],
                        resolution="UNRESOLVED",
                        candidates=[item["id"] for item in candidates],
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
        user_type_names = {
            item["name"] for item in contracts
        } | {
            item.get("name") for item in nodes
            if item.get("kind") in {"struct", "enum"}
        }
        for call in call_pattern.finditer(body):
            if in_assembly(call.start()):
                continue
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
            if callee_name in user_type_names or callee_name in _BUILTIN_CALLS or re.fullmatch(
                r"(?:u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?|bytes(?:[1-9]|[12]\d|3[0-2])?|fixed(?:\d+x\d+)?|ufixed(?:\d+x\d+)?|bool|string|address)",
                callee_name,
            ):
                continue
            prefix = body[max(0, call.start() - 32):call.start()]
            if re.search(r"\b(?:emit|revert|new)\s*$", prefix):
                continue
            if callee_name in {"function", "modifier"}:
                continue
            params_open = call.end() - 1
            params_close = _matching(body, params_open, "(", ")")
            arguments = _split_top_level(body[params_open + 1:params_close]) if params_close is not None else []
            argument_types = [
                _infer_expression_type(
                    argument, func, state_variables, scope, path, body, call.start()
                )
                for argument in arguments
            ]
            callable_candidates = [
                item for item in functions
                if item["name"] == callee_name
                and item["kind"] == "function"
                and (
                    (item["contract"] == scope and item["file"] == path)
                    or item["contract"] in func.get("bases", [])
                )
            ]
            candidates = _select_callable_declarations(
                callable_candidates, func, scope, path, argument_types
            )
            if len(candidates) == 1:
                target_func = candidates[0]
                has_override = any(
                    edge.get("kind") == "OVERRIDES" and edge.get("to") == target_func["id"]
                    for edge in edges
                )
                virtual_dispatch = bool(re.search(r"\bvirtual\b", target_func.get("header", ""))) or has_override
                edges.append(_edge(
                    "CALLS", func["id"], target_func["id"], path, source,
                    body_absolute + call.start(),
                    resolution="INFERRED" if target_func["contract"] != scope or virtual_dispatch else "DIRECT",
                    implementation_resolution="UNRESOLVED" if virtual_dispatch else "DIRECT",
                    dispatch="VIRTUAL" if virtual_dispatch else "STATIC",
                    detail="Call names this declaration, but virtual dispatch may select an override at runtime." if virtual_dispatch else None,
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
            if in_assembly(call.start()):
                continue
            receiver, method = call.group("receiver"), call.group("name")
            member_open = call.end() - 1
            member_close = _matching(body, member_open, "(", ")")
            member_args = _split_top_level(body[member_open + 1:member_close]) if member_close is not None else []
            member_arg_types = [
                _infer_expression_type(
                    argument, func, state_variables, scope, path, body, call.start()
                )
                for argument in member_args
            ]
            if receiver == "abi" and method in {
                "encode", "encodePacked", "encodeWithSelector",
                "encodeWithSignature", "encodeCall", "decode",
            }:
                continue
            if method in {"call", "delegatecall", "staticcall", "push", "pop"}:
                continue
            if method in {"transfer", "send"}:
                receiver_vars = [
                    item for item in state_variables
                    if item["contract"] in {scope, *func["bases"]}
                    and item["name"] == receiver
                ]
                parameter_type = (func.get("parameter_declared_types") or {}).get(receiver, "")
                payable_receiver = (
                    len(receiver_vars) == 1
                    and bool(re.search(r"\baddress\s+payable\b", receiver_vars[0].get("type", "")))
                ) or bool(re.search(r"\baddress\s+payable\b", parameter_type))
                prefix = body[max(0, call.start() - 20):call.start()]
                legacy_msg_sender = bool(re.search(r"\bmsg\s*\.\s*$", prefix))
                legacy_tx_origin = bool(re.search(r"\btx\s*\.\s*$", prefix))
                if payable_receiver or legacy_msg_sender or legacy_tx_origin:
                    # This is a native ETH address operation, represented by
                    # ASSET_FLOW below rather than a generic contract call.
                    continue
            if receiver == "super":
                super_open = call.end() - 1
                super_close = _matching(body, super_open, "(", ")")
                super_args = _split_top_level(body[super_open + 1:super_close]) if super_close is not None else []
                super_arg_types = [
                    _infer_expression_type(
                        argument, func, state_variables, scope, path, body, call.start()
                    )
                    for argument in super_args
                ]
                inherited = [
                    item for item in functions
                    if item["contract"] in func["bases"]
                    and item["name"] == method
                    and item["kind"] == "function"
                ]
                inherited = _select_callable_declarations(
                    inherited, func, "", path, super_arg_types
                )
                if len(inherited) == 1:
                    edges.append(_edge("CALLS", func["id"], inherited[0]["id"], path, source, body_absolute + call.start(), resolution="DIRECT", dispatch="SUPER", implementation_resolution="DIRECT"))
                    continue
                if len(inherited) > 1 or not inherited:
                    edges.append(_edge(
                        "CALLS", func["id"], f"function-name:super.{method}",
                        path, source, body_absolute + call.start(),
                        resolution="UNRESOLVED", candidates=[item["id"] for item in inherited],
                        dispatch="SUPER",
                    ))
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
                library_candidates = _filter_overloads_by_arguments(
                    library_candidates, member_arg_types
                )
                library_resolution = "DIRECT"
            else:
                receiver_type = _infer_expression_type(
                    receiver, func, state_variables, scope, path, body, call.start()
                )
                contract_units = [
                    item for item in contracts
                    if item["name"] == scope and item["file"] == path
                ]
                if receiver_type and len(contract_units) == 1:
                    for directive in contract_units[0].get("using_libraries") or []:
                        if directive.get("for_type") not in {receiver_type, "*"}:
                            continue
                        extension_candidates = [
                            item for item in local_functions.get((directive["library"], method), [])
                            if item["kind"] == "function"
                        ]
                        receiver_type_for_overload = _canonical_parameter(receiver_type)
                        library_candidates.extend(_filter_overloads_by_arguments(
                            extension_candidates,
                            [receiver_type_for_overload, *member_arg_types],
                        ))
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
            declared_type = _infer_expression_type(
                receiver, func, state_variables, scope, path, body, call.start()
            ) or ""
            type_contracts = contract_by_name.get(declared_type, []) if declared_type else []
            typed_methods = [
                item for item in functions
                if item["contract"] == declared_type
                and item["name"] == method
                and item["kind"] == "function"
            ] if len(type_contracts) == 1 else []
            typed_methods = _filter_overloads_by_arguments(typed_methods, member_arg_types)
            if receiver == "this":
                own_methods = [
                    item for item in functions
                    if item["contract"] == scope and item["file"] == path
                    and item["name"] == method and item["kind"] == "function"
                    and item.get("visibility") in {"public", "external"}
                ]
                self_methods = _filter_overloads_by_arguments(own_methods, member_arg_types)
                if not self_methods:
                    inherited_methods = [
                        item for item in functions
                        if item["contract"] in func.get("bases", [])
                        and item["name"] == method
                        and item["kind"] == "function"
                        and item.get("visibility") in {"public", "external"}
                    ]
                    self_methods = _nearest_inherited(
                        _filter_overloads_by_arguments(inherited_methods, member_arg_types),
                        func.get("ancestor_depths") or {},
                    )
                if len(self_methods) == 1:
                    target_method = self_methods[0]
                    is_virtual = bool(re.search(r"\bvirtual\b", target_method.get("header", "")))
                    edges.append(_edge(
                        "EXTERNAL_CALL", func["id"], target_method["id"],
                        path, source, body_absolute + call.start(),
                        resolution="DIRECT", receiver="this", method=method,
                        implementation_resolution="UNRESOLVED" if is_virtual else "DIRECT",
                        detail="External self-call resolves to this declared public/external method; virtual implementation selection remains runtime-dependent when applicable.",
                    ))
                    continue
                if len(self_methods) > 1:
                    edges.append(_edge(
                        "EXTERNAL_CALL", func["id"], f"external:this.{method}",
                        path, source, body_absolute + call.start(),
                        resolution="UNRESOLVED", receiver="this", method=method,
                        candidates=[item["id"] for item in self_methods],
                    ))
                    continue
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
            if in_assembly(alias_match.start()):
                continue
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
            base_type = variable.get("type", "")
            base_index_kinds: list[str] = []
            base_index_types: list[str | None] = []
            for _index in indexes:
                index_kind, index_type, next_type = _storage_index_info(base_type)
                base_index_kinds.append(index_kind)
                base_index_types.append(index_type)
                base_type = next_type
            declared_alias_type = re.sub(r"\s+", "", alias_match.group("type"))
            expected_alias_type = re.sub(r"\s+", "", base_type)
            if declared_alias_type != expected_alias_type:
                # A lexical name match is not enough; the storage-reference
                # type must agree with the declared base/terminal storage type.
                continue
            alias = {
                "name": alias_match.group("alias"),
                "type": alias_match.group("type").strip(),
                "variable": variable,
                "indexes": [item.strip() for item in indexes],
                "index_kinds": base_index_kinds,
                "index_types": base_index_types,
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
                index_kinds=alias["index_kinds"], index_types=alias["index_types"],
                mapping_key_types=[
                    index_type for kind, index_type in zip(alias["index_kinds"], alias["index_types"])
                    if kind == "mapping"
                ],
                mapping_depth=sum(1 for kind in alias["index_kinds"] if kind == "mapping"),
                terminal_type=alias["type"],
                detail="Local storage reference aliases the declared state variable; it is not a separate storage slot.",
            ))

        for alias in storage_aliases:
            alias_pattern_usage = re.compile(rf"\b{re.escape(alias['name'])}\b")
            variable = alias["variable"]
            persistence = variable.get("storage_class", "persistent")
            for access in alias_pattern_usage.finditer(body):
                if in_assembly(access.start()) or any(start <= access.start() < end for start, end in alias_ranges):
                    continue
                access_info = _scan_storage_access(
                    body, access.end(),
                    base_name=variable["name"],
                    base_type=alias["type"],
                    base_indexes=alias["indexes"],
                    contract=variable["contract"],
                    fields_by_struct=fields_by_struct,
                    base_index_kinds=alias["index_kinds"],
                    base_index_types=alias["index_types"],
                )
                cursor = access_info["end"]
                before = body[max(0, access.start() - 12):access.start()]
                after = body[cursor:cursor + 5]
                assignment = re.match(r"(\*\*=|<<=|>>=|\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=(?!=|>))", after)
                prefix_assignment = re.search(r"(?:\+\+|--)\s*$", before)
                deletion = re.search(r"\bdelete\s*$", before)
                array_method = access_info.get("array_method")
                tuple_write = _tuple_assignment_for(body, access.start())
                is_write = bool(assignment or prefix_assignment or deletion or array_method or tuple_write)
                is_compound = bool(assignment and assignment.group(0) != "=") or bool(prefix_assignment) or array_method == "pop"
                operation = (
                    "delete" if deletion else "tuple=" if tuple_write else assignment.group(0) if assignment
                    else prefix_assignment.group(0).strip() if prefix_assignment
                    else f"array.{array_method}" if array_method else "read"
                )
                if deletion:
                    relations = ["DELETES"]
                elif is_write:
                    relations = ["WRITES"]
                else:
                    relations = ["READS"]
                if persistence == "transient":
                    relations = [
                        {"READS": "TRANSIENT_READS", "WRITES": "TRANSIENT_WRITES",
                         "DELETES": "TRANSIENT_DELETES"}.get(item, item)
                        for item in relations
                    ]
                if persistence == "constant":
                    relations = ["UNRESOLVED_MUTATION"] if is_write else ["READS_CONSTANT"]
                elif persistence == "immutable":
                    if is_write:
                        relations = ["INITIALIZES"] if func["name"] == "constructor" else ["UNRESOLVED_MUTATION"]
                    else:
                        relations = ["READS_IMMUTABLE"]
                if is_compound and persistence in {"persistent", "transient"}:
                    relations.append("TRANSIENT_READS" if persistence == "transient" else "READS")

                relation_targets = [(variable["id"], None)]
                relation_targets.extend((field["id"], field.get("name")) for field in access_info["field_nodes"])
                for target_id, field_name in relation_targets:
                    for relation in relations:
                        edges.append(_edge(
                            relation, func["id"], target_id, path, source,
                            body_absolute + access.start(),
                            variable=variable["name"], alias=alias["name"],
                            keys=access_info["keys"], member=field_name or access_info["member"],
                            access_path=access_info["access_path"],
                            index_kinds=access_info["index_kinds"],
                            index_types=access_info["index_types"],
                            mapping_key_types=access_info["mapping_key_types"],
                            mapping_depth=access_info["mapping_depth"],
                            terminal_type=access_info["terminal_type"],
                            resolution="DIRECT" if variable["contract"] == scope else "INFERRED",
                            evidence="STORAGE_ALIAS_RESOLUTION",
                            operation=operation,
                            mutation_kind=(
                                "INITIALIZATION" if relation == "INITIALIZES" else
                                "UNRESOLVED_MUTATION" if relation == "UNRESOLVED_MUTATION" else
                                "DELETE" if deletion else "TUPLE_ASSIGNMENT" if tuple_write
                                else "ARRAY_MUTATION" if array_method else "COMPOUND_ASSIGNMENT" if is_compound
                                else "ASSIGNMENT" if is_write else "READ"
                            ),
                            persistence=persistence,
                        ))

        for variable in accessible_state:
            if accessible_name_counts.get(variable["name"], 0) > 1:
                continue
            if variable["name"] in params_shadow:
                continue
            if _has_local_shadow(body, variable["name"]):
                continue
            access_pattern = re.compile(rf"\b{re.escape(variable['name'])}\b")
            for access in access_pattern.finditer(body):
                if in_assembly(access.start()) or any(start <= access.start() < end for start, end in alias_ranges):
                    continue
                access_info = _scan_storage_access(
                    body, access.end(),
                    base_name=variable["name"],
                    base_type=variable.get("type", ""),
                    base_indexes=[],
                    contract=variable["contract"],
                    fields_by_struct=fields_by_struct,
                )
                cursor = access_info["end"]
                before = body[max(0, access.start() - 12):access.start()]
                after = body[cursor:cursor + 5]
                assignment = re.match(r"(\*\*=|<<=|>>=|\+\+|--|\+=|-=|\*=|/=|%=|&=|\|=|\^=|=(?!=|>))", after)
                prefix_assignment = re.search(r"(?:\+\+|--)\s*$", before)
                deletion = re.search(r"\bdelete\s*$", before)
                array_method = access_info.get("array_method")
                tuple_write = _tuple_assignment_for(body, access.start())
                is_write = bool(assignment or prefix_assignment or deletion or array_method or tuple_write)
                is_compound = bool(assignment and assignment.group(0) != "=") or bool(prefix_assignment) or array_method == "pop"
                operation = (
                    "delete" if deletion else "tuple=" if tuple_write else assignment.group(0) if assignment
                    else prefix_assignment.group(0).strip() if prefix_assignment
                    else f"array.{array_method}" if array_method else "read"
                )
                persistence = variable.get("storage_class", "persistent")
                if deletion:
                    relations = ["DELETES"]
                elif is_write:
                    relations = ["WRITES"]
                else:
                    relations = ["READS"]
                if persistence == "transient":
                    relations = [
                        {"READS": "TRANSIENT_READS", "WRITES": "TRANSIENT_WRITES",
                         "DELETES": "TRANSIENT_DELETES"}.get(item, item)
                        for item in relations
                    ]
                if persistence == "constant":
                    relations = ["UNRESOLVED_MUTATION"] if is_write else ["READS_CONSTANT"]
                elif persistence == "immutable":
                    if is_write:
                        relations = ["INITIALIZES"] if func["name"] == "constructor" else ["UNRESOLVED_MUTATION"]
                    else:
                        relations = ["READS_IMMUTABLE"]
                if is_compound and persistence in {"persistent", "transient"}:
                    relations.append("TRANSIENT_READS" if persistence == "transient" else "READS")

                relation_targets = [(variable["id"], None)]
                relation_targets.extend((field["id"], field.get("name")) for field in access_info["field_nodes"])
                for target_id, field_name in relation_targets:
                    for relation in relations:
                        edges.append(_edge(
                            relation, func["id"], target_id, path, source,
                            body_absolute + access.start(),
                            variable=variable["name"], keys=access_info["keys"],
                            member=field_name or access_info["member"],
                            access_path=access_info["access_path"],
                            index_kinds=access_info["index_kinds"],
                            index_types=access_info["index_types"],
                            mapping_key_types=access_info["mapping_key_types"],
                            mapping_depth=access_info["mapping_depth"],
                            terminal_type=access_info["terminal_type"],
                            resolution="DIRECT" if variable["contract"] == scope else "INFERRED",
                            evidence="LEXICAL_SOURCE" if variable["contract"] == scope else "INHERITED_STORAGE_RESOLUTION",
                            operation=operation,
                            mutation_kind=(
                                "INITIALIZATION" if relation == "INITIALIZES" else
                                "UNRESOLVED_MUTATION" if relation == "UNRESOLVED_MUTATION" else
                                "DELETE" if deletion else "TUPLE_ASSIGNMENT" if tuple_write
                                else "ARRAY_MUTATION" if array_method else "COMPOUND_ASSIGNMENT" if is_compound
                                else "ASSIGNMENT" if is_write else "READ"
                            ),
                            persistence=persistence,
                        ))

        for emitted in re.finditer(r"\bemit\s+([A-Za-z_]\w*)\s*\(", body):
            name = emitted.group(1)
            event_nodes = [
                node
                for base_name in [scope, *func.get("bases", [])]
                for node in events_by_contract_name.get((base_name, name), [])
            ]
            if len(event_nodes) == 1:
                edges.append(_edge("EMITS", func["id"], event_nodes[0]["id"], path, source, body_absolute + emitted.start()))
            else:
                edges.append(_edge("EMITS", func["id"], f"event-name:{scope}.{name}", path, source, body_absolute + emitted.start(), resolution="UNRESOLVED"))

        for reverted in re.finditer(r"\brevert\s+([A-Za-z_]\w*)\s*\(", body):
            error_name = reverted.group(1)
            error_nodes = [
                node
                for base_name in [scope, *func.get("bases", [])]
                for node in errors_by_contract_name.get((base_name, error_name), [])
            ]
            if len(error_nodes) == 1:
                edges.append(_edge("REVERTS", func["id"], error_nodes[0]["id"], path, source, body_absolute + reverted.start()))
            else:
                edges.append(_edge("REVERTS", func["id"], f"error-name:{scope}.{error_name}", path, source, body_absolute + reverted.start(), resolution="UNRESOLVED"))

    # Asset-flow observations distinguish capability, source-level attempts,
    # and unresolved low-level behavior. No static result is runtime proof.
    erc20_type_names = {"IERC20", "IERC20Metadata", "ERC20"}

    def is_erc20_type(type_name: str) -> bool:
        simple = re.sub(r"\b(memory|calldata|storage|payable|external|internal)\b", " ", type_name)
        simple = re.sub(r"(?:\[\s*\])+$", "", simple)
        simple = re.sub(r"\s+", " ", simple).strip()
        if simple in erc20_type_names:
            return True
        candidates = contract_by_name.get(simple, [])
        if len(candidates) != 1:
            return False
        ancestors = set(candidates[0].get("ancestors") or candidates[0].get("bases") or [])
        return bool(ancestors & erc20_type_names)

    for func in functions:
        if func["kind"] not in {"function", "modifier"}:
            continue
        body = func["body"]
        path = func["file"]
        source = source_by_path.get(path, "")
        offset = func["body_start"] or 0
        # Yul CALL/CREATE/SELFDESTRUCT semantics are handled by the opcode
        # scanner below. Never classify them using Solidity-level regex rules.
        asset_assembly_ranges: list[tuple[int, int]] = []
        for assembly_match in re.finditer(r"\bassembly\b(?:\s*\([^)]*\))?\s*\{", body):
            assembly_open = assembly_match.end() - 1
            assembly_close = _matching(body, assembly_open, "{", "}")
            asset_assembly_ranges.append((
                assembly_open,
                (assembly_close + 1) if assembly_close is not None else len(body),
            ))

        def in_asset_assembly(position: int) -> bool:
            return any(start <= position < end for start, end in asset_assembly_ranges)

        if func["mutability"] == "payable":
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                func["source_offset"], status="CAPABILITY", asset="eth",
                direction="in", detail="Payable entry point can receive ETH; this does not prove a particular execution supplied or retained ETH.",
            ))
        for value_use in re.finditer(r"\bmsg\s*\.\s*value\b", body):
            if in_asset_assembly(value_use.start()):
                continue
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
            and is_erc20_type(item.get("type", ""))
        }
        token_names.update(
            name for name, type_name in (func.get("parameter_declared_types") or {}).items()
            if is_erc20_type(type_name)
        )
        for local_token in re.finditer(
            r"\b(?P<type>[A-Za-z_]\w*(?:\s*\[\s*\])?)\s+(?:memory\s+|calldata\s+)?(?P<name>[A-Za-z_]\w*)\s*=",
            body,
        ):
            if is_erc20_type(local_token.group("type")):
                token_names.add(local_token.group("name"))

        eth_call = re.compile(
            r"(?P<recipient>payable\s*\(\s*address\s*\(\s*this\s*\)\s*\)"
            r"|address\s*\(\s*this\s*\)|payable\s*\([^)]*\)|msg\.sender|tx\.origin|[A-Za-z_]\w*)"
            r"\s*\.\s*call\s*\{(?P<options>[^}]+)\}"
        )
        for match in eth_call.finditer(body):
            if in_asset_assembly(match.start()):
                continue
            value_option = re.search(r"\bvalue\s*:\s*([^,}]+)", match.group("options"))
            if value_option is None:
                continue
            recipient = re.sub(r"\s+", "", match.group("recipient"))
            if recipient in {"address(this)", "payable(address(this))"}:
                continue
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + match.start(), asset="eth", direction="out",
                status="TRANSFER_ATTEMPT", recipient=match.group("recipient").strip(),
                amount=value_option.group(1).strip(),
                detail="Source-level value-bearing CALL; verify the call result and actual balance movement at runtime.",
            ))

        # Solidity 0.5-style call.value(amount)(data) remains common in legacy
        # contracts. Keep it visible as a value-bearing attempt.
        legacy_eth_call = re.compile(
            r"(?P<recipient>msg\.sender|tx\.origin|payable\s*\([^)]*\)|[A-Za-z_]\w*)"
            r"\s*\.\s*call\s*\.\s*value\s*\((?P<amount>[^)]*)\)"
        )
        for match in legacy_eth_call.finditer(body):
            if in_asset_assembly(match.start()):
                continue
            recipient = re.sub(r"\s+", "", match.group("recipient"))
            if recipient in {"address(this)", "payable(address(this))"}:
                continue
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + match.start(), asset="eth", direction="out",
                status="TRANSFER_ATTEMPT", recipient=match.group("recipient").strip(),
                amount=match.group("amount").strip(), syntax="legacy-call-value",
                detail="Legacy call.value amount is attached to a low-level CALL; verify success and balance movement at runtime.",
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
        native_receiver_base = r"payable\s*\(\s*address\s*\(\s*this\s*\)\s*\)|payable\s*\([^)]*\)|msg\.sender|tx\.origin"
        native_receiver = native_receiver_base + (
            "|" + "|".join(re.escape(name) for name in sorted(payable_names, key=len, reverse=True))
            if payable_names else ""
        )
        native_method = re.compile(
            rf"(?P<recipient>{native_receiver})\s*\.\s*(?P<method>transfer|send)\s*\(\s*(?P<amount>[^)]*)\)"
        )
        for match in native_method.finditer(body):
            if in_asset_assembly(match.start()):
                continue
            if re.sub(r"\s+", "", match.group("recipient")) in {"address(this)", "payable(address(this))"}:
                continue
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
            if in_asset_assembly(match.start()):
                continue
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
            if in_asset_assembly(destruction.start()):
                continue
            recipient = destruction.group("recipient").strip()
            recipient_compact = re.sub(r"\s+", "", recipient)
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + destruction.start(), asset="eth",
                direction="unresolved" if recipient_compact in {"address(this)", "payable(address(this))"} else "out",
                status="FORK_SEMANTIC_DEPENDENT",
                recipient=recipient,
                detail="SELFDESTRUCT can transfer the account balance; code-deletion semantics depend on the active EVM fork and account history.",
            ))

        token_call = re.compile(
            r"\b(?P<token>[A-Za-z_]\w*)\s*\.\s*"
            r"(?P<method>safeTransferFrom|transferFrom|safeTransfer|transfer)\s*"
            r"\((?P<args>[^;{}]*)\)"
        )
        for match in token_call.finditer(body):
            if in_asset_assembly(match.start()):
                continue
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
                r"\b(call|callcode|delegatecall|staticcall|create|create2|selfdestruct|sload|sstore|tload|tstore)\s*\(",
                assembly_body,
            ):
                opcode = operation.group(1).lower()
                absolute_offset = offset + assembly_open + 1 + operation.start()
                if opcode in {"sload", "sstore", "tload", "tstore"}:
                    transient = opcode in {"tload", "tstore"}
                    write = opcode in {"sstore", "tstore"}
                    edge_kind = (
                        "TRANSIENT_WRITES" if opcode == "tstore" else
                        "TRANSIENT_READS" if opcode == "tload" else
                        "WRITES" if opcode == "sstore" else "READS"
                    )
                    edges.append(_edge(
                        edge_kind, func["id"], f"storage-slot:{opcode}",
                        path, source, absolute_offset, resolution="UNRESOLVED",
                        evidence="YUL_OPCODE_SCAN", operation=opcode,
                        persistence="transient" if transient else "persistent",
                        mutation_kind="UNRESOLVED_SLOT_WRITE" if write else "UNRESOLVED_SLOT_READ",
                        detail="Assembly storage access is visible, but the slot expression is not mapped to a Solidity declaration; no mapping or variable ownership is guessed.",
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

    # Compiler AST declaration references override resolved lexical call edges
    # when Foundry build-info is available and its embedded source is current.
    source_by_path = {display: content for display, content, _path in source_units}
    if source_ast is not None:
        ast_report = source_ast.apply_solc_ast_call_edges(
            root_path, source_by_path, nodes, edges, functions,
            manifest=ast_build_manifest,
        )
    else:
        ast_report = {
            "available": False, "build_info_files": 0, "matched_units": 0,
            "stale_units": 0, "functions": 0, "call_edges": 0,
            "modifier_edges": 0, "warnings": ["AST resolver is not installed; lexical analysis used."],
        }

    # Add inferred storage/asset relationships through bounded internal call chains.
    direct_calls: dict[str, list[dict[str, Any]]] = {}
    for item in edges:
        if item["kind"] == "CALLS" and item["resolution"] in {"DIRECT", "INFERRED"}:
            direct_calls.setdefault(item["from"], []).append(item)
    direct_effects: dict[str, list[dict[str, Any]]] = {}
    for item in edges:
        if item["kind"] in {
            "READS", "READS_CONSTANT", "READS_IMMUTABLE",
            "WRITES", "DELETES", "MUTATES",
            "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
            "ASSET_FLOW",
        }:
            direct_effects.setdefault(item["from"], []).append(item)
    direct_modifiers: dict[str, list[dict[str, Any]]] = {}
    for item in edges:
        if item["kind"] == "APPLIES_MODIFIER" and item["resolution"] in {"DIRECT", "INFERRED"}:
            direct_modifiers.setdefault(item["from"], []).append(item)
    function_by_id = {item["id"]: item for item in functions}
    # Deduplicate inherited effects by the concrete source edge, not just the
    # target variable. Two helper accesses may touch different mapping keys or
    # struct fields and both paths are valuable to an auditor.
    effect_keys = {(item.get("from"), item.get("id")) for item in edges}
    for start_id, start_func in function_by_id.items():
        queue: list[tuple[str, list[str], int]] = [(start_id, [start_id], 0)]
        # Modifiers execute as part of the decorated function. Their direct
        # reads/writes are effects of the decorated function, even when the
        # modifier makes no helper call (the common "guard += 1; _;" pattern).
        for modifier_edge in direct_modifiers.get(start_id, []):
            modifier_id = modifier_edge["to"]
            if modifier_id not in function_by_id:
                continue
            modifier_chain = [start_id, modifier_id]
            for effect in direct_effects.get(modifier_id, []):
                if effect["kind"] == "ASSET_FLOW" and effect.get("status") == "CAPABILITY":
                    continue
                effect_key = (start_id, effect.get("id"))
                if effect_key in effect_keys:
                    continue
                inherited = dict(effect)
                inherited.update({
                    "id": f"INFERRED:{start_id}:{effect['id']}",
                    "from": start_id,
                    "resolution": "INFERRED",
                    "evidence": "MODIFIER_EXECUTION_PROPAGATION",
                    "via": modifier_chain,
                    "detail": "Effect occurs in a modifier applied to this function; execution is still conditional on reaching the modifier body.",
                })
                edges.append(inherited)
                effect_keys.add(effect_key)
            queue.append((modifier_id, modifier_chain, 1))
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
                    effect_key = (start_id, effect.get("id"))
                    if effect_key not in effect_keys:
                        inherited = dict(effect)
                        inherited.update({
                            "id": f"INFERRED:{start_id}:{effect['id']}",
                            "from": start_id,
                            "resolution": "INFERRED",
                            "evidence": "CALL_GRAPH_PROPAGATION",
                            "via": next_chain,
                            "detail": "Effect is reachable through an internal helper; inspect the call chain before concluding execution.",
                        })
                        edges.append(inherited)
                        effect_keys.add(effect_key)
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
        "parser": "SOLC_AST+LEXICAL" if ast_report.get("functions") else "LEXICAL",
        "ast": ast_report,
        "analysis_mode": "STATIC_SOURCE",
        "mutation_semantics": "POTENTIAL_PATHS_NOT_RUNTIME_OBSERVATIONS",
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
            "persistent_storage": sum(1 for item in state_variables if item.get("storage_class", "persistent") == "persistent"),
            "transient_storage": sum(1 for item in state_variables if item.get("storage_class") == "transient"),
            "constants": sum(1 for item in state_variables if item.get("storage_class") == "constant"),
            "immutables": sum(1 for item in state_variables if item.get("storage_class") == "immutable"),
            "mappings": sum(1 for item in state_variables if item["kind"] == "mapping"),
            "relationships": len(edges),
            "ambiguous": sum(1 for item in edges if item.get("resolution") == "AMBIGUOUS"),
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
            "ast": ast_report,
            "analysis_mode": index["analysis_mode"],
            "mutation_semantics": index["mutation_semantics"],
            "nodes": nodes,
            "edges": edges,
            "summary": index["summary"],
            "inventory": index["inventory"],
            "root_manifest": root_manifest,
            "source_manifest": source_manifest,
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
