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


CACHE_VERSION = 1
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
    names: set[str] = set()
    for item in _split_top_level(raw):
        value = re.sub(r"\b(memory|calldata|storage|indexed|payable)\b", " ", item)
        parts = re.findall(r"[A-Za-z_]\w*", value)
        if len(parts) >= 2:
            names.add(parts[-1])
    return names


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
        "id": f"{kind}:{source_id}:{target_id}:{_line(source, offset)}",
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


def _mapping_inner_type(type_name: str) -> str | None:
    if not type_name.startswith("mapping"):
        return None
    opening = type_name.find("(")
    if opening < 0:
        return None
    closing = _matching(type_name, opening, "(", ")")
    if closing is None:
        return None
    inside = type_name[opening + 1:closing]
    parts = _split_top_level(inside, "=")
    if len(parts) < 2:
        return None
    # mapping key => value
    return parts[-1].strip()


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
    failures = list(inventory.get("uninspected") or [])
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

    source_units.sort(key=lambda item: item[0].casefold())
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
            cached["inventory"] = {
                "complete": not failures,
                "uninspected": failures,
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
    structs: list[dict[str, Any]] = []
    fields_by_struct: dict[tuple[str, str], list[dict[str, Any]]] = {}
    file_ids: dict[str, str] = {}
    contract_by_name: dict[str, list[dict[str, Any]]] = {}
    function_by_scope_name: dict[tuple[str, str], list[dict[str, Any]]] = {}

    def add_node(value: dict[str, Any]) -> None:
        if len(nodes) >= MAX_RELATIONSHIPS:
            raise SourceIndexError(f"Source index reached the {MAX_RELATIONSHIPS}-node safety limit.")
        nodes.append(value)

    for path, source, _absolute in source_units:
        clean = project_tools._strip_source_comments(source, "solidity", mask_strings=True)
        file_id = _node_id("file", path, path)
        file_ids[path] = file_id
        add_node({
            "id": file_id, "kind": "file", "name": path, "file": path,
            "line": 1, "evidence": "SOURCE_FILE",
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
            }
            contracts.append(contract)
            contract_by_name.setdefault(name, []).append(contract)
            add_node({
                "id": contract_id, "kind": "contract", "name": name,
                "qualified_name": qualified, "file": path,
                "line": contract["line"], "bases": contract["bases"],
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
                edges.append(_edge("USES_TYPE", field_id, _node_id("type", path, field_type), path, source, field_offset, type_name=field_type))

            for statement, statement_offset in _top_level_statements(clean, opening + 1, closing):
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

            # Events and custom errors are declarations with their own nodes.
            for kind, pattern in (
                ("event", re.compile(r"\bevent\s+([A-Za-z_]\w*)\s*\(")),
                ("custom_error", re.compile(r"\berror\s+([A-Za-z_]\w*)\s*\(")),
            ):
                for declaration_match in pattern.finditer(clean, opening + 1, closing):
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
                    "contract": name, "file": path,
                    "line": _line(source, function_match.start()),
                    "header": header_text,
                    "visibility": visibility_match.group(1) if visibility_match else "UNSPECIFIED",
                    "mutability": mutability_match.group(1) if mutability_match else "nonpayable",
                    "parameters": sorted(_parameter_names(raw_params)),
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
        to_id = file_ids.get(to_path)
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

    # Direct state access, modifiers, events and function-to-function calls.
    function_nodes = {item["id"]: item for item in functions}
    for func in functions:
        if func["kind"] != "function":
            continue
        path = func["file"]
        source = next((item[1] for item in source_units if item[0] == path), "")
        body = func["body"]
        if not body:
            continue
        body_absolute = (func["body_start"] or 0)
        scope = func["contract"]
        known_modifiers = [
            item for item in functions
            if item["kind"] == "modifier" and item["contract"] == scope
        ]
        params_shadow = set(func["parameters"])

        for modifier in known_modifiers:
            if re.search(rf"\b{re.escape(modifier['name'])}\b", func["header"]):
                edges.append(_edge(
                    "APPLIES_MODIFIER", func["id"], modifier["id"], path, source,
                    func["source_offset"],
                ))

        local_functions = function_by_scope_name
        call_pattern = re.compile(r"(?<![A-Za-z0-9_.$])([A-Za-z_]\w*)\s*\(")
        for call in call_pattern.finditer(body):
            callee_name = call.group(1)
            if callee_name in _BUILTIN_CALLS:
                continue
            if callee_name in {"function", "modifier"}:
                continue
            candidates = local_functions.get((scope, callee_name), [])
            if not candidates:
                inherited = []
                for base_name in func["bases"]:
                    inherited.extend(local_functions.get((base_name, callee_name), []))
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
            if receiver == "super":
                inherited = []
                for base_name in func["bases"]:
                    inherited.extend(local_functions.get((base_name, method), []))
                if len(inherited) == 1:
                    edges.append(_edge("CALLS", func["id"], inherited[0]["id"], path, source, body_absolute + call.start(), resolution="INFERRED"))
                    continue
            edges.append(_edge(
                "EXTERNAL_CALL", func["id"], f"external:{receiver}.{method}",
                path, source, body_absolute + call.start(),
                resolution="UNRESOLVED", receiver=receiver, method=method,
            ))

        for low_level in re.finditer(r"\.\s*(call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\(", body):
            edges.append(_edge(
                "EXTERNAL_CALL", func["id"], f"low-level:{low_level.group(1)}",
                path, source, body_absolute + low_level.start(),
                resolution="UNRESOLVED", operation=low_level.group(1),
            ))

        for variable in [item for item in state_variables if item["contract"] == scope]:
            if variable["name"] in params_shadow:
                continue
            if re.search(rf"\b(?:[A-Za-z_]\w*\s+)+(?:memory|storage|calldata\s+)?{re.escape(variable['name'])}\b", body):
                # A same-named local declaration may shadow state. Do not guess.
                continue
            access_pattern = re.compile(rf"\b{re.escape(variable['name'])}\b")
            for access in access_pattern.finditer(body):
                cursor = access.end()
                while cursor < len(body) and body[cursor].isspace():
                    cursor += 1
                if cursor < len(body) and body[cursor] == "[":
                    close_index = _matching(body, cursor, "[", "]")
                    while close_index is not None:
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
                for relation in relations:
                    edges.append(_edge(
                        relation, func["id"], variable["id"], path, source,
                        body_absolute + access.start(),
                        variable=variable["name"],
                    ))
                    if member_name and variable.get("mapping_value_type"):
                        struct_name = re.findall(r"\b[A-Z][A-Za-z0-9_]*\b", variable["mapping_value_type"])
                        if struct_name:
                            fields = fields_by_struct.get((scope, struct_name[-1]), [])
                            field = next((item for item in fields if item["name"] == member_name), None)
                            if field:
                                edges.append(_edge(
                                    relation, func["id"], field["id"], path, source,
                                    body_absolute + access.start(),
                                    variable=variable["name"], member=member_name,
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

    # Asset flow observations are deliberately distinct from payable capability.
    for func in functions:
        if func["kind"] != "function":
            continue
        body = func["body"]
        path = func["file"]
        source = next((item[1] for item in source_units if item[0] == path), "")
        offset = func["body_start"] or 0
        if func["mutability"] == "payable":
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                func["source_offset"], status="CAPABILITY", asset="eth",
                direction="in", detail="Payable entry point; does not prove ETH was retained or received in any execution.",
            ))
        eth_call = re.compile(
            r"(?P<recipient>msg\.sender|tx\.origin|address\s*\([^)]*\)|payable\s*\([^)]*\)|[A-Za-z_]\w*)"
            r"\s*\.\s*call\s*\{\s*value\s*:\s*(?P<amount>[^}]+)\}"
        )
        for match in eth_call.finditer(body):
            recipient = match.group("recipient").strip()
            if recipient.replace(" ", "") == "address(this)" or recipient.replace(" ", "") == "payable(address(this))":
                continue
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:eth", path, source,
                offset + match.start(), asset="eth", direction="out",
                status="TRANSFER_ATTEMPT", recipient=recipient,
                amount=match.group("amount").strip(),
                detail="Source-level value-bearing call; success requires runtime verification.",
            ))
        token_names = {
            item["name"] for item in state_variables
            if item["contract"] == func["contract"]
            and re.search(r"\b(?:I?ERC20|ERC20|IERC20Metadata)\b", item.get("type", ""))
        }
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
            recipient = args[0].strip() if args else "UNRESOLVED"
            if method in {"transferFrom", "safeTransferFrom"} and len(args) >= 2:
                sender, recipient = args[0].strip(), args[1].strip()
                if "address(this)" in sender.replace(" ", ""):
                    direction = "out"
                elif "address(this)" in recipient.replace(" ", ""):
                    direction = "in"
            edges.append(_edge(
                "ASSET_FLOW", func["id"], f"asset:erc20:{match.group('token')}",
                path, source, offset + match.start(),
                asset="erc20", direction=direction, status="TRANSFER_ATTEMPT" if direction != "unresolved" else "UNRESOLVED",
                token=match.group("token"), method=method, recipient=recipient,
                amount=args[-1].strip() if args else "UNRESOLVED",
                detail="Token call identified from an ERC20-typed state variable; transfer success is not proven.",
            ))
        if re.search(r"\bassembly\b", body) and re.search(r"\b(call|delegatecall|create|create2)\b", body):
            edges.append(_edge(
                "ASSET_FLOW", func["id"], "asset:unknown", path, source,
                offset + body.find("assembly"), asset="unknown",
                direction="unresolved", status="ASSEMBLY_UNRESOLVED",
                detail="Assembly performs a potentially value-moving operation; operands are not resolved by this lexical pass.",
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
    function_by_id = {item["id"]: item for item in functions}
    for start_id, start_func in function_by_id.items():
        queue: list[tuple[str, list[str], int]] = [(start_id, [start_id], 0)]
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
            "struct", "struct_field", "event", "custom_error",
        }:
            continue
        if contract_name and node.get("contract", node.get("name")) != contract_name:
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
