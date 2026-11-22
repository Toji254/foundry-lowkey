from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


MAX_BUILD_INFO_FILES = 24
MAX_BUILD_INFO_FILE_BYTES = 64 * 1024 * 1024
MAX_BUILD_INFO_TOTAL_BYTES = 128 * 1024 * 1024


def build_info_manifest(root: str | Path) -> dict[str, Any]:
    """Fingerprint bounded Foundry build-info inputs without compiling anything."""
    build_dir = Path(root).resolve() / "out" / "build-info"
    if not build_dir.is_dir():
        return {"directory_present": False, "files": [], "skipped": []}

    candidates = sorted(
        (item for item in build_dir.glob("*.json") if item.is_file()),
        key=lambda item: item.name,
    )
    files: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    total_bytes = 0

    for path in candidates:
        try:
            stat = path.stat()
        except OSError as error:
            skipped.append({"path": str(path), "reason": f"stat failed: {error}"})
            continue
        if len(files) >= MAX_BUILD_INFO_FILES:
            skipped.append({
                "path": str(path), "reason": "build-info file-count limit",
                "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            })
            continue
        if stat.st_size > MAX_BUILD_INFO_FILE_BYTES:
            skipped.append({
                "path": str(path), "reason": "build-info file-size limit",
                "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            })
            continue
        if total_bytes + stat.st_size > MAX_BUILD_INFO_TOTAL_BYTES:
            skipped.append({
                "path": str(path), "reason": "build-info aggregate-size limit",
                "size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            })
            continue
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError as error:
            skipped.append({"path": str(path), "reason": f"hash failed: {error}"})
            continue
        total_bytes += stat.st_size
        files.append({
            "path": str(path),
            "size": stat.st_size,
            "sha256": digest.hexdigest(),
        })

    return {
        "directory_present": True,
        "files": files,
        "skipped": skipped,
        "bytes_hashed": total_bytes,
    }


def _src_range(node: dict[str, Any]) -> tuple[int, int] | None:
    raw = node.get("src")
    if not isinstance(raw, str):
        return None
    parts = raw.split(":")
    if len(parts) != 3:
        return None
    try:
        start, length = int(parts[0]), int(parts[1])
    except (TypeError, ValueError):
        return None
    if start < 0 or length < 0:
        return None
    return start, length


def _byte_to_char_offset(source: str, byte_offset: int) -> int:
    raw = source.encode("utf-8")
    safe = raw[:max(0, min(byte_offset, len(raw)))]
    return len(safe.decode("utf-8", errors="ignore"))


def _line_column(source: str, char_offset: int) -> tuple[int, int]:
    prefix = source[:max(0, min(char_offset, len(source)))]
    line = prefix.count("\n") + 1
    column = len(prefix.rsplit("\n", 1)[-1]) + 1
    return line, column


def _referenced_id(node: Any) -> int | None:
    if not isinstance(node, dict):
        return None
    value = node.get("referencedDeclaration")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _unwrap_callee(expression: Any) -> dict[str, Any] | None:
    current = expression
    while isinstance(current, dict) and current.get("nodeType") in {
        "FunctionCallOptions", "FunctionCall",
    }:
        child = current.get("expression")
        if not isinstance(child, dict) or child is current:
            return None
        current = child
    return current if isinstance(current, dict) else None


def _ast_children(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield child
    elif isinstance(value, list):
        yield from value


def _match_function(
    graph_functions: list[dict[str, Any]],
    *,
    path: str,
    contract: str,
    ast_node: dict[str, Any],
    source: str,
) -> dict[str, Any] | None:
    span = _src_range(ast_node)
    if span is None:
        return None
    byte_start, _length = span
    char_start = _byte_to_char_offset(source, byte_start)
    line, _column = _line_column(source, char_start)
    ast_kind = str(ast_node.get("kind") or "function")
    name = str(ast_node.get("name") or ast_kind)
    expected_kind = "modifier" if ast_node.get("nodeType") == "ModifierDefinition" else "function"
    candidates = [
        item for item in graph_functions
        if item.get("file") == path
        and item.get("contract") == contract
        and item.get("kind") == expected_kind
        and item.get("name") == name
    ]
    if not candidates:
        return None
    exact = [item for item in candidates if item.get("source_offset") == char_start]
    if len(exact) == 1:
        return exact[0]
    on_line = [item for item in candidates if item.get("line") == line]
    if len(on_line) == 1:
        return on_line[0]
    # Multiple same-name declarations on one line are not safely mappable
    # without an exact source offset. Do not pick the nearest one.
    if len(on_line) > 1:
        return None
    return on_line[0] if on_line else None


def _load_matched_units(
    manifest: dict[str, Any],
    source_by_path: dict[str, str],
) -> tuple[list[dict[str, Any]], int, list[str]]:
    by_hash: dict[str, list[str]] = {}
    source_hashes: dict[str, str] = {}
    for path, content in source_by_path.items():
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        source_hashes[path] = digest
        by_hash.setdefault(digest, []).append(path)

    units: list[dict[str, Any]] = []
    stale = 0
    warnings: list[str] = []
    total_bytes = 0

    for entry in manifest.get("files") or []:
        path = Path(str(entry.get("path") or ""))
        try:
            size = path.stat().st_size
            if size > MAX_BUILD_INFO_FILE_BYTES or total_bytes + size > MAX_BUILD_INFO_TOTAL_BYTES:
                warnings.append(f"Skipped oversized build-info file: {path.name}")
                continue
            raw = path.read_bytes()
            total_bytes += len(raw)
            payload = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeError, ValueError, TypeError) as error:
            warnings.append(f"Could not read build-info {path.name}: {error}")
            continue

        input_sources = (payload.get("input") or {}).get("sources") or {}
        output_sources = (payload.get("output") or {}).get("sources") or {}
        if not isinstance(input_sources, dict) or not isinstance(output_sources, dict):
            warnings.append(f"Build-info has no usable source maps: {path.name}")
            continue

        for source_key, output in output_sources.items():
            if not isinstance(output, dict) or not isinstance(output.get("ast"), dict):
                continue
            input_entry = input_sources.get(source_key)
            content = input_entry.get("content") if isinstance(input_entry, dict) else None
            if not isinstance(content, str):
                stale += 1
                continue
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            normalized_key = str(source_key).replace("\\", "/").lstrip("./")
            match_path = normalized_key if normalized_key in source_by_path else None
            if match_path is not None and source_by_path[match_path] != content:
                match_path = None
            if match_path is None:
                candidates = by_hash.get(digest, [])
                if len(candidates) == 1:
                    match_path = candidates[0]
            if match_path is None or source_hashes.get(match_path) != digest:
                stale += 1
                continue
            units.append({
                "path": match_path,
                "source": content,
                "ast": output["ast"],
                "source_id": output.get("id"),
                "build_info": path.name,
            })

    # Keep compilation identity: declaration IDs are unique only within one
    # solc compilation, not across separate build-info JSON files.
    return units, stale, warnings



def _match_storage_declaration(
    candidates: list[dict[str, Any]],
    *,
    path: str,
    contract: str,
    name: str,
    ast_node: dict[str, Any],
    source: str,
) -> dict[str, Any] | None:
    span = _src_range(ast_node)
    if span is None:
        return None
    char_start = _byte_to_char_offset(source, span[0])
    line, _column = _line_column(source, char_start)
    matches = [
        item for item in candidates
        if item.get("file") == path
        and item.get("contract") == contract
        and item.get("name") == name
    ]
    exact = [item for item in matches if item.get("source_offset") == char_start]
    if len(exact) == 1:
        return exact[0]
    on_line = [item for item in matches if item.get("line") == line]
    return on_line[0] if len(on_line) == 1 else None


def _storage_expression(
    expression: Any,
    *,
    build_info: str,
    declarations: dict[tuple[str, int], dict[str, Any]],
    aliases: dict[tuple[str, int], dict[str, Any]],
    source: str,
) -> dict[str, Any] | None:
    if not isinstance(expression, dict):
        return None
    node_type = expression.get("nodeType")

    if node_type == "Identifier":
        declaration_id = _referenced_id(expression)
        if declaration_id is None:
            return None
        target = declarations.get((build_info, declaration_id))
        if target is not None and target.get("kind") in {
            "mapping", "state_variable", "function_pointer",
        }:
            return {
                "target": target,
                "path": str(target.get("name") or ""),
                "keys": [],
                "fields": [],
                "alias": None,
            }
        alias = aliases.get((build_info, declaration_id))
        if alias is not None:
            return {
                "target": alias["target"],
                "path": alias["path"],
                "keys": list(alias.get("keys") or []),
                "fields": list(alias.get("fields") or []),
                "alias": alias.get("alias"),
            }
        return None

    if node_type == "IndexAccess":
        base = _storage_expression(
            expression.get("baseExpression"),
            build_info=build_info, declarations=declarations,
            aliases=aliases, source=source,
        )
        if base is None:
            return None
        index_expression = expression.get("indexExpression")
        index_span = _src_range(index_expression) if isinstance(index_expression, dict) else None
        index_text = "?"
        if index_span is not None:
            start = _byte_to_char_offset(source, index_span[0])
            end = _byte_to_char_offset(source, index_span[0] + index_span[1])
            index_text = source[start:end].strip() or "?"
        base["path"] += f"[{index_text}]"
        base["keys"].append(index_text)
        return base

    if node_type == "MemberAccess":
        base = _storage_expression(
            expression.get("expression"),
            build_info=build_info, declarations=declarations,
            aliases=aliases, source=source,
        )
        if base is None:
            return None
        member_name = str(expression.get("memberName") or "")
        if not member_name:
            return None
        base["path"] += f".{member_name}"
        member_id = _referenced_id(expression)
        field = declarations.get((build_info, member_id)) if member_id is not None else None
        if field is not None and field.get("kind") == "struct_field":
            base["fields"].append(field)
        return base

    return None


def _emit_ast_storage_effects(
    function_ast: dict[str, Any],
    caller: dict[str, Any],
    *,
    unit: dict[str, Any],
    declarations: dict[tuple[str, int], dict[str, Any]],
    edges: list[dict[str, Any]],
    function_declarations: dict[tuple[str, int], dict[str, Any]] | None = None,
    call_contexts: list[dict[str, Any]] | None = None,
    context_aliases: dict[tuple[str, int], dict[str, Any]] | None = None,
    via_chain: list[str] | None = None,
) -> int:
    """Emit AST-backed storage reads/writes with referenced state declarations."""
    source = unit["source"]
    build_info = unit["build_info"]
    aliases: dict[tuple[str, int], dict[str, Any]] = dict(context_aliases or {})
    function_declarations = function_declarations or {}
    call_contexts = call_contexts if call_contexts is not None else []
    via_chain = list(via_chain or [])
    emitted = 0

    def emit(expression: dict[str, Any], mode: str, operation: str | None = None) -> None:
        nonlocal emitted
        access = _storage_expression(
            expression, build_info=build_info, declarations=declarations,
            aliases=aliases, source=source,
        )
        if access is None:
            return
        span = _src_range(expression)
        if span is None:
            return
        start = _byte_to_char_offset(source, span[0])
        line, column = _line_column(source, start)
        target = access["target"]
        persistence = str(target.get("storage_class") or "persistent")
        if persistence == "transient":
            mode = {
                "READS": "TRANSIENT_READS",
                "WRITES": "TRANSIENT_WRITES",
                "DELETES": "TRANSIENT_DELETES",
            }.get(mode, mode)
        relation_targets = [(target, None)] + [
            (field, field.get("name")) for field in access["fields"]
        ]
        for node, field_name in relation_targets:
            edge_kind = mode
            edge = {
                "id": (
                    f"SOLC_AST_STORAGE:{edge_kind}:{caller['id']}:"
                    f"{node['id']}:{unit['path']}:{start}:{column}:"
                    f"{hashlib.sha256((access['path'] + '|' + '|'.join(via_chain)).encode()).hexdigest()[:12]}"
                ),
                "kind": edge_kind,
                "from": caller["id"],
                "to": node["id"],
                "resolution": "INFERRED" if via_chain else "DIRECT",
                "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE",
                "source": {"file": unit["path"], "line": line, "column": column},
                "variable": target.get("name"),
                "access_path": access["path"],
                "keys": list(access["keys"]),
                "member": field_name,
                "operation": operation or ("read" if mode.endswith("READS") else "write"),
                "mutation_kind": (
                    "DELETE" if mode in {"DELETES", "TRANSIENT_DELETES"} else
                    "ARRAY_MUTATION" if operation and operation.startswith("array.") else
                    "COMPOUND_ASSIGNMENT" if operation in {"**=", "<<=", ">>=", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="} else
                    "TUPLE_ASSIGNMENT" if operation == "tuple=" else
                    "ASSIGNMENT" if mode.endswith("WRITES") else "READ"
                ),
                "persistence": persistence,
            }
            if access.get("alias"):
                edge["alias"] = access["alias"]
            if via_chain:
                edge["via"] = list(via_chain)
            edges.append(edge)
            emitted += 1

    def walk(value: Any, mode: str = "READS", operation: str | None = None) -> None:
        if isinstance(value, list):
            for child in value:
                walk(child, mode, operation)
            return
        if not isinstance(value, dict):
            return

        node_type = value.get("nodeType")
        if node_type == "VariableDeclarationStatement":
            initial = value.get("initialValue")
            for declaration in value.get("declarations") or []:
                if not isinstance(declaration, dict):
                    continue
                if declaration.get("storageLocation") != "storage":
                    continue
                declaration_id = declaration.get("id")
                initial_access = _storage_expression(
                    initial, build_info=build_info, declarations=declarations,
                    aliases=aliases, source=source,
                )
                if declaration_id is not None and initial_access is not None:
                    try:
                        aliases[(build_info, int(declaration_id))] = {
                            **initial_access, "alias": declaration.get("name"),
                        }
                        span = _src_range(value)
                        if span is not None:
                            start = _byte_to_char_offset(source, span[0])
                            line, column = _line_column(source, start)
                            edges.append({
                                "id": f"SOLC_AST_ALIAS:{caller['id']}:{initial_access['target']['id']}:{unit['path']}:{start}",
                                "kind": "ALIASES_STORAGE",
                                "from": caller["id"],
                                "to": initial_access["target"]["id"],
                                "resolution": "DIRECT",
                                "evidence": "SOLC_AST_STORAGE_DECLARATION_REFERENCE",
                                "source": {"file": unit["path"], "line": line, "column": column},
                                "alias": declaration.get("name"),
                                "access_path": initial_access["path"],
                            })
                            nonlocal_alias_count[0] += 1
                    except (TypeError, ValueError):
                        pass
            # A storage-reference initializer aliases a slot; it does not copy
            # the full stored value into a temporary local variable.
            if any(
                isinstance(item, dict) and item.get("storageLocation") == "storage"
                for item in value.get("declarations") or []
            ):
                for key, child in value.items():
                    if key not in {"initialValue", "declarations"}:
                        walk(child, mode, operation)
                return

        if node_type == "Assignment":
            operator = str(value.get("operator") or "=")
            left_hand_side = value.get("leftHandSide")
            write_operation = "tuple=" if isinstance(left_hand_side, dict) and left_hand_side.get("nodeType") == "TupleExpression" else operator
            walk(left_hand_side, "WRITES", write_operation)
            if operator != "=":
                walk(value.get("leftHandSide"), "READS", "read-for-update")
            walk(value.get("rightHandSide"), "READS", None)
            for key, child in value.items():
                if key not in {"leftHandSide", "rightHandSide"}:
                    walk(child, mode, operation)
            return

        if node_type == "UnaryOperation":
            operator = str(value.get("operator") or "")
            if operator == "delete":
                walk(value.get("subExpression"), "DELETES", "delete")
            elif operator in {"++", "--"}:
                walk(value.get("subExpression"), "WRITES", operator)
                walk(value.get("subExpression"), "READS", "read-for-update")
            else:
                walk(value.get("subExpression"), "READS", None)
            for key, child in value.items():
                if key != "subExpression":
                    walk(child, mode, operation)
            return

        if node_type == "FunctionCall":
            expression = value.get("expression")
            if isinstance(expression, dict) and expression.get("nodeType") == "MemberAccess":
                member_name = str(expression.get("memberName") or "")
                if member_name in {"push", "pop"}:
                    walk(expression.get("expression"), "WRITES", f"array.{member_name}")
                    for argument in value.get("arguments") or []:
                        walk(argument, "READS", None)
                    return

            callee = _unwrap_callee(expression)
            target_ast_id = _referenced_id(callee)
            target_record = function_declarations.get((build_info, target_ast_id)) if target_ast_id is not None else None
            storage_parameter_indexes: set[int] = set()
            storage_receiver_consumed = False
            if target_record is not None:
                parameters = (
                    (target_record.get("ast") or {}).get("parameters") or {}
                ).get("parameters") or []
                context: dict[tuple[str, int], dict[str, Any]] = {}
                arguments = value.get("arguments") or []

                # A using-for library extension passes its receiver as the first
                # storage parameter, even though it is not in FunctionCall.arguments.
                if (
                    isinstance(expression, dict)
                    and expression.get("nodeType") == "MemberAccess"
                    and parameters
                    and isinstance(parameters[0], dict)
                    and parameters[0].get("storageLocation") == "storage"
                ):
                    receiver_access = _storage_expression(
                        expression.get("expression"), build_info=build_info,
                        declarations=declarations, aliases=aliases, source=source,
                    )
                    if receiver_access is not None:
                        receiver_parameter = parameters[0]
                        try:
                            receiver_key = (build_info, int(receiver_parameter.get("id")))
                            context[receiver_key] = {
                                **receiver_access, "alias": receiver_parameter.get("name"),
                            }
                            storage_receiver_consumed = True
                        except (TypeError, ValueError):
                            pass

                parameter_offset = 1 if storage_receiver_consumed else 0
                for argument_index, argument in enumerate(arguments):
                    parameter_index = argument_index + parameter_offset
                    if parameter_index >= len(parameters):
                        continue
                    parameter = parameters[parameter_index]
                    if not isinstance(parameter, dict) or parameter.get("storageLocation") != "storage":
                        continue
                    resolved_argument = _storage_expression(
                        argument, build_info=build_info, declarations=declarations,
                        aliases=aliases, source=source,
                    )
                    if resolved_argument is None:
                        continue
                    parameter_id = parameter.get("id")
                    try:
                        parameter_key = (build_info, int(parameter_id))
                    except (TypeError, ValueError):
                        continue
                    context[parameter_key] = {
                        **resolved_argument, "alias": parameter.get("name"),
                    }
                    storage_parameter_indexes.add(argument_index)

                    argument_span = _src_range(argument) if isinstance(argument, dict) else None
                    if argument_span is not None:
                        argument_start = _byte_to_char_offset(source, argument_span[0])
                        argument_line, argument_column = _line_column(source, argument_start)
                        edges.append({
                            "id": (
                                f"SOLC_AST_STORAGE_ARGUMENT:{caller['id']}:"
                                f"{resolved_argument['target']['id']}:{unit['path']}:"
                                f"{argument_start}:"
                                f"{hashlib.sha256(resolved_argument['path'].encode()).hexdigest()[:10]}"
                            ),
                            "kind": "ALIASES_STORAGE",
                            "from": caller["id"],
                            "to": resolved_argument["target"]["id"],
                            "resolution": "DIRECT",
                            "evidence": "SOLC_AST_STORAGE_REFERENCE_ARGUMENT",
                            "source": {"file": unit["path"], "line": argument_line, "column": argument_column},
                            "alias": parameter.get("name"),
                            "access_path": resolved_argument["path"],
                            "detail": "Storage reference passed to a statically resolved internal/library function; inspect the callee's storage effects.",
                        })

                if storage_receiver_consumed:
                    receiver_parameter = parameters[0]
                    receiver_access = _storage_expression(
                        expression.get("expression"), build_info=build_info,
                        declarations=declarations, aliases=aliases, source=source,
                    )
                    receiver_span = _src_range(expression.get("expression"))
                    if receiver_access is not None and receiver_span is not None:
                        receiver_start = _byte_to_char_offset(source, receiver_span[0])
                        receiver_line, receiver_column = _line_column(source, receiver_start)
                        edges.append({
                            "id": (
                                f"SOLC_AST_STORAGE_RECEIVER:{caller['id']}:"
                                f"{receiver_access['target']['id']}:{unit['path']}:{receiver_start}"
                            ),
                            "kind": "ALIASES_STORAGE",
                            "from": caller["id"],
                            "to": receiver_access["target"]["id"],
                            "resolution": "DIRECT",
                            "evidence": "SOLC_AST_STORAGE_REFERENCE_ARGUMENT",
                            "source": {"file": unit["path"], "line": receiver_line, "column": receiver_column},
                            "alias": receiver_parameter.get("name"),
                            "access_path": receiver_access["path"],
                        })

                if context:
                    call_contexts.append({
                        "target": target_record,
                        "aliases": context,
                        "via": (via_chain or [caller["id"]]) + [target_record["graph"]["id"]],
                    })

            if isinstance(expression, dict) and expression.get("nodeType") == "MemberAccess":
                # A storage receiver consumed by an internal library extension is
                # a reference argument, not a value read. Other member-call receivers
                # (token, oracle, strategy) are read as ordinary state values.
                if not storage_receiver_consumed:
                    walk(expression.get("expression"), "READS", None)
            else:
                walk(expression, "READS", None)
            for argument_index, argument in enumerate(value.get("arguments") or []):
                if argument_index not in storage_parameter_indexes:
                    walk(argument, "READS", None)
            return

        if node_type in {"Identifier", "IndexAccess", "MemberAccess"}:
            access = _storage_expression(
                value, build_info=build_info, declarations=declarations,
                aliases=aliases, source=source,
            )
            if access is not None:
                # The outermost access expression emits the whole path. Its
                # base expression is visited only through index expressions.
                emit(value, mode, operation)

                def visit_index_expressions(access_node: Any) -> None:
                    if not isinstance(access_node, dict):
                        return
                    access_kind = access_node.get("nodeType")
                    if access_kind == "IndexAccess":
                        visit_index_expressions(access_node.get("baseExpression"))
                        walk(access_node.get("indexExpression"), "READS", None)
                    elif access_kind == "MemberAccess":
                        visit_index_expressions(access_node.get("expression"))

                visit_index_expressions(value)
                return

        for child in _ast_children(value):
            walk(child, mode, operation)

    # This mutable counter is kept separate from effect edges because aliases
    # are useful graph evidence even though they are not themselves mutations.
    nonlocal_alias_count = [0]
    walk(function_ast)
    return emitted + nonlocal_alias_count[0]



def apply_solc_ast_call_edges(
    root: str | Path,
    source_by_path: dict[str, str],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    functions: list[dict[str, Any]],
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Use valid Foundry AST declaration references to replace resolved lexical calls.

    The overlay only trusts ASTs whose embedded source text exactly matches the
    current indexed file. Functions without a matching AST declaration retain
    their lexical analysis. This function never invokes forge or solc.
    """
    try:
        manifest = manifest if manifest is not None else build_info_manifest(root)
    except Exception as error:
        return {
            "available": False, "build_info_files": 0, "matched_units": 0,
            "stale_units": 0, "functions": 0, "call_edges": 0,
            "modifier_edges": 0, "warnings": [f"Could not inspect build-info: {error}"],
        }

    units, stale_units, warnings = _load_matched_units(manifest, source_by_path)
    graph_functions = [
        item for item in nodes
        if item.get("kind") in {"function", "modifier"}
    ]
    graph_nodes = {item.get("id"): item for item in nodes}
    declaration_map: dict[tuple[str, int], dict[str, Any]] = {}
    ast_function_declarations: dict[tuple[str, int], dict[str, Any]] = {}
    ast_function_records: list[dict[str, Any]] = []
    ast_covered: set[str] = set()
    ast_virtual: dict[str, bool] = {}
    matched_contracts = 0

    def collect_contract(contract_ast: dict[str, Any], unit: dict[str, Any]) -> None:
        nonlocal matched_contracts
        contract_name = str(contract_ast.get("name") or "")
        contract_graph = next(
            (
                item for item in nodes
                if item.get("kind") == "contract"
                and item.get("file") == unit["path"]
                and item.get("name") == contract_name
            ),
            None,
        )
        if contract_graph is None:
            return
        matched_contracts += 1
        contract_ast_id = contract_ast.get("id")
        try:
            declaration_map[(unit["build_info"], int(contract_ast_id))] = contract_graph
        except (TypeError, ValueError):
            pass

        contract_children = contract_ast.get("nodes") or []
        state_candidates = [
            item for item in nodes
            if item.get("file") == unit["path"]
            and item.get("contract") == contract_name
            and item.get("kind") in {"mapping", "state_variable", "function_pointer"}
        ]
        for child in contract_children:
            if not isinstance(child, dict):
                continue
            if child.get("nodeType") == "VariableDeclaration" and child.get("stateVariable"):
                graph_storage = _match_storage_declaration(
                    state_candidates, path=unit["path"], contract=contract_name,
                    name=str(child.get("name") or ""), ast_node=child,
                    source=unit["source"],
                )
                if graph_storage is not None:
                    try:
                        declaration_map[(unit["build_info"], int(child.get("id")))] = graph_storage
                    except (TypeError, ValueError):
                        pass
            elif child.get("nodeType") == "StructDefinition":
                struct_name = str(child.get("name") or "")
                field_candidates = [
                    item for item in nodes
                    if item.get("kind") == "struct_field"
                    and item.get("file") == unit["path"]
                    and item.get("contract") == contract_name
                    and item.get("struct") == struct_name
                ]
                for member in child.get("members") or []:
                    if not isinstance(member, dict) or member.get("nodeType") != "VariableDeclaration":
                        continue
                    graph_field = _match_storage_declaration(
                        field_candidates, path=unit["path"], contract=contract_name,
                        name=str(member.get("name") or ""), ast_node=member,
                        source=unit["source"],
                    )
                    if graph_field is not None:
                        try:
                            declaration_map[(unit["build_info"], int(member.get("id")))] = graph_field
                        except (TypeError, ValueError):
                            pass

        for child in contract_children:
            if not isinstance(child, dict):
                continue
            if child.get("nodeType") not in {"FunctionDefinition", "ModifierDefinition"}:
                continue
            graph_function = _match_function(
                graph_functions,
                path=unit["path"],
                contract=contract_name,
                ast_node=child,
                source=unit["source"],
            )
            if graph_function is None:
                continue
            ast_id = child.get("id")
            try:
                declaration_map[(unit["build_info"], int(ast_id))] = graph_function
            except (TypeError, ValueError):
                continue
            ast_covered.add(graph_function["id"])
            ast_virtual[graph_function["id"]] = bool(child.get("virtual"))
            ast_record = {
                "ast": child,
                "graph": graph_function,
                "contract": contract_graph,
                "unit": unit,
            }
            ast_function_records.append(ast_record)
            ast_function_declarations[(unit["build_info"], int(ast_id))] = ast_record

    for unit in units:
        root_ast = unit.get("ast") or {}
        for item in root_ast.get("nodes") or []:
            if isinstance(item, dict) and item.get("nodeType") == "ContractDefinition":
                collect_contract(item, unit)

    # Several build profiles can contain the same unchanged source. Keep
    # one AST record per graph function so calls are not double-counted.
    records_by_function: dict[str, dict[str, Any]] = {}
    for record in ast_function_records:
        records_by_function.setdefault(record["graph"]["id"], record)
    ast_function_records = list(records_by_function.values())

    if not ast_covered:
        return {
            "available": bool(manifest.get("files")),
            "build_info_files": len(manifest.get("files") or []),
            "matched_units": len(units),
            "stale_units": stale_units,
            "contracts": matched_contracts,
            "functions": 0,
            "call_edges": 0,
            "modifier_edges": 0,
            "storage_edges": 0,
            "warnings": warnings,
        }

    ast_edges: list[dict[str, Any]] = []
    ast_sites: set[tuple[str, str, int, int, str, str]] = set()
    ast_call_edges = 0
    ast_modifier_edges = 0
    ast_storage_edges = 0
    storage_call_contexts: list[dict[str, Any]] = []

    for record in ast_function_records:
        function_ast = record["ast"]
        caller = record["graph"]
        contract_graph = record["contract"]
        unit = record["unit"]
        content = unit["source"]

        def walk(value: Any) -> None:
            nonlocal ast_call_edges, ast_modifier_edges
            if isinstance(value, list):
                for child in value:
                    walk(child)
                return
            if not isinstance(value, dict):
                return

            node_type = value.get("nodeType")
            if node_type == "FunctionCall":
                callee = _unwrap_callee(value.get("expression"))
                target_ast_id = _referenced_id(callee)
                target = declaration_map.get((unit["build_info"], target_ast_id)) if target_ast_id is not None else None
                if target is not None and target.get("kind") in {"function", "modifier"}:
                    span = _src_range(value)
                    if span is not None:
                        start = _byte_to_char_offset(content, span[0])
                        line, column = _line_column(content, start)
                        expression = callee or {}
                        is_member = expression.get("nodeType") == "MemberAccess"
                        receiver = expression.get("expression") or {}
                        receiver_name = str(receiver.get("name") or "") if isinstance(receiver, dict) else ""
                        target_contract_kind = str(target.get("contract_kind") or "")
                        target_visibility = str(target.get("visibility") or "")
                        is_library_internal = (
                            target_contract_kind == "library"
                            and target_visibility in {"internal", "private"}
                        )
                        is_library_external = (
                            target_contract_kind == "library"
                            and target_visibility in {"public", "external"}
                        )
                        internal_dispatch = receiver_name == "super" or is_library_internal
                        is_external = (is_member and not internal_dispatch) or is_library_external
                        if receiver_name == "this":
                            is_external = True
                        kind = "EXTERNAL_CALL" if is_external else "CALLS"
                        edge = {
                            "id": f"SOLC_AST:{kind}:{caller['id']}:{target['id']}:{unit['path']}:{start}",
                            "kind": kind,
                            "from": caller["id"],
                            "to": target["id"],
                            "resolution": "DIRECT",
                            "evidence": "SOLC_AST_DECLARATION_REFERENCE",
                            "source": {"file": unit["path"], "line": line, "column": column},
                            "ast_declaration_id": target_ast_id,
                            "call_kind": "solc-ast",
                        }
                        if kind == "EXTERNAL_CALL":
                            edge.update({
                                "receiver": receiver_name or "dynamic",
                                "method": str(expression.get("memberName") or target.get("name") or ""),
                                "implementation_resolution": "UNRESOLVED",
                                "detail": "The compiler resolves the declared callable; the implementation at the runtime address is not assumed.",
                            })
                        elif ast_virtual.get(target["id"]):
                            edge.update({
                                "dispatch": "VIRTUAL",
                                "implementation_resolution": "UNRESOLVED",
                            })
                        ast_edges.append(edge)
                        ast_sites.add((caller["id"], unit["path"], line, column, kind, target["id"]))
                        ast_call_edges += 1

            elif node_type == "ModifierInvocation":
                modifier_name = value.get("modifierName")
                target_ast_id = _referenced_id(modifier_name)
                target = declaration_map.get((unit["build_info"], target_ast_id)) if target_ast_id is not None else None
                if target is not None and target.get("kind") == "modifier":
                    span = _src_range(value)
                    if span is not None:
                        start = _byte_to_char_offset(content, span[0])
                        line, column = _line_column(content, start)
                        ast_edges.append({
                            "id": f"SOLC_AST:APPLIES_MODIFIER:{caller['id']}:{target['id']}:{unit['path']}:{start}",
                            "kind": "APPLIES_MODIFIER",
                            "from": caller["id"],
                            "to": target["id"],
                            "resolution": "DIRECT",
                            "evidence": "SOLC_AST_DECLARATION_REFERENCE",
                            "source": {"file": unit["path"], "line": line, "column": column},
                            "ast_declaration_id": target_ast_id,
                        })
                        ast_sites.add((caller["id"], unit["path"], line, column, "APPLIES_MODIFIER", target["id"]))
                        ast_modifier_edges += 1

            for child in _ast_children(value):
                walk(child)

        walk(function_ast)
        ast_storage_edges += _emit_ast_storage_effects(
            function_ast, caller, unit=unit,
            declarations=declaration_map, edges=edges,
            function_declarations=ast_function_declarations,
            call_contexts=storage_call_contexts,
        )

    # Follow storage-reference parameters across bounded internal/library calls.
    # A callee may be called with several different storage paths; keep contexts
    # separate and cap the total amount of repeated AST traversal.
    context_seen: set[tuple[str, tuple[tuple[str, str], ...], tuple[str, ...]]] = set()
    processed_contexts = 0
    while storage_call_contexts and processed_contexts < 64:
        context = storage_call_contexts.pop(0)
        target_record = context["target"]
        aliases = context["aliases"]
        via = context["via"]
        alias_key = tuple(sorted(
            (str(key[1]), str(value.get("path") or ""))
            for key, value in aliases.items()
        ))
        context_key = (target_record["graph"]["id"], alias_key, tuple(via))
        if context_key in context_seen or len(via) > 7:
            continue
        context_seen.add(context_key)
        processed_contexts += 1
        ast_storage_edges += _emit_ast_storage_effects(
            target_record["ast"], target_record["graph"],
            unit=target_record["unit"], declarations=declaration_map,
            edges=edges, function_declarations=ast_function_declarations,
            call_contexts=storage_call_contexts, context_aliases=aliases,
            via_chain=via,
        )

    # Remove a lexical relationship only when an AST-resolved declaration
    # occupies the same caller/source site. This also corrects a lexical edge
    # that resolved to the wrong same-named declaration.
    ast_locations = {
        (caller_id, path, line, column, kind)
        for caller_id, path, line, column, kind, _target_id in ast_sites
    }
    ast_line_counts: dict[tuple[str, str, int, str], int] = {}
    for caller_id, path, line, _column, kind, _target_id in ast_sites:
        bucket = (caller_id, path, line, kind)
        ast_line_counts[bucket] = ast_line_counts.get(bucket, 0) + 1
    lexical_line_counts: dict[tuple[str, str, int, str], int] = {}
    for edge in edges:
        if edge.get("kind") not in {"CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER"}:
            continue
        source_ref = edge.get("source") or {}
        bucket = (
            str(edge.get("from") or ""),
            str(source_ref.get("file") or ""),
            int(source_ref.get("line") or 0),
            str(edge.get("kind") or ""),
        )
        lexical_line_counts[bucket] = lexical_line_counts.get(bucket, 0) + 1

    ast_storage_sites = {
        (
            edge.get("from"),
            str((edge.get("source") or {}).get("file") or ""),
            int((edge.get("source") or {}).get("line") or 0),
            int((edge.get("source") or {}).get("column") or 0),
        )
        for edge in edges
        if edge.get("evidence") in {
            "SOLC_AST_STORAGE_DECLARATION_REFERENCE",
            "SOLC_AST_STORAGE_REFERENCE_ARGUMENT",
        }
    }

    filtered_edges = []
    for edge in edges:
        source_ref = edge.get("source") or {}
        storage_site = (
            edge.get("from"),
            str(source_ref.get("file") or ""),
            int(source_ref.get("line") or 0),
            int(source_ref.get("column") or 0),
        )
        if (
            edge.get("from") in ast_covered
            and edge.get("evidence") != "SOLC_AST_STORAGE_DECLARATION_REFERENCE"
            and edge.get("kind") in {
                "READS", "WRITES", "DELETES", "MUTATES",
                "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
                "ALIASES_STORAGE",
            }
            and storage_site in ast_storage_sites
        ):
            continue
        bucket = (
            str(edge.get("from") or ""),
            str(source_ref.get("file") or ""),
            int(source_ref.get("line") or 0),
            str(edge.get("kind") or ""),
        )
        exact_site = bucket[:3] + (int(source_ref.get("column") or 0),) + bucket[3:]
        if (
            edge.get("from") in ast_covered
            and edge.get("kind") in {"CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER"}
            and edge.get("resolution") in {"DIRECT", "INFERRED"}
            and (
                exact_site in ast_locations
                or (
                    ast_line_counts.get(bucket) == 1
                    and lexical_line_counts.get(bucket) == 1
                )
            )
        ):
            continue
        filtered_edges.append(edge)
    edges[:] = filtered_edges + ast_edges

    return {
        "available": bool(manifest.get("files")),
        "build_info_files": len(manifest.get("files") or []),
        "matched_units": len(units),
        "stale_units": stale_units,
        "contracts": matched_contracts,
        "functions": len(ast_covered),
        "call_edges": ast_call_edges,
        "modifier_edges": ast_modifier_edges,
        "storage_edges": ast_storage_edges,
        "warnings": warnings + [
            f"Skipped {len(manifest.get('skipped') or [])} build-info file(s) due to configured bounds."
        ] if manifest.get("skipped") else warnings,
    }
