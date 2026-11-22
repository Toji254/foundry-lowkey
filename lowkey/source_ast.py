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
    if on_line:
        return min(on_line, key=lambda item: abs(int(item.get("source_offset") or 0) - char_start))
    return None


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

    # Prefer the first stable build-info result for each identical current source.
    unique: dict[str, dict[str, Any]] = {}
    for unit in units:
        unique.setdefault(unit["path"], unit)
    return list(unique.values()), stale, warnings


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
    declaration_map: dict[int, dict[str, Any]] = {}
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
            declaration_map[int(contract_ast_id)] = contract_graph
        except (TypeError, ValueError):
            pass

        for child in contract_ast.get("nodes") or []:
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
                declaration_map[int(ast_id)] = graph_function
            except (TypeError, ValueError):
                continue
            ast_covered.add(graph_function["id"])
            ast_virtual[graph_function["id"]] = bool(child.get("virtual"))
            ast_function_records.append({
                "ast": child,
                "graph": graph_function,
                "contract": contract_graph,
                "unit": unit,
            })

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
            "warnings": warnings,
        }

    ast_edges: list[dict[str, Any]] = []
    ast_sites: set[tuple[str, str, int, int, str, str]] = set()
    ast_call_edges = 0
    ast_modifier_edges = 0

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
                target = declaration_map.get(target_ast_id) if target_ast_id is not None else None
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
                        is_library = target_contract_kind == "library"
                        internal_dispatch = receiver_name == "super" or is_library
                        is_external = is_member and not internal_dispatch
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
                target = declaration_map.get(target_ast_id) if target_ast_id is not None else None
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

    # Remove a lexical edge only when the AST resolves the same declaration at
    # the same source site. Other lexical unresolved/dynamic edges remain intact.
    ast_site_counts: dict[tuple[str, str, int, str, str], int] = {}
    for caller_id, path, line, _column, kind, target_id in ast_sites:
        bucket = (caller_id, path, line, kind, target_id)
        ast_site_counts[bucket] = ast_site_counts.get(bucket, 0) + 1
    lexical_bucket_counts: dict[tuple[str, str, int, str, str], int] = {}
    for edge in edges:
        if edge.get("kind") not in {"CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER"}:
            continue
        source_ref = edge.get("source") or {}
        bucket = (
            str(edge.get("from") or ""),
            str(source_ref.get("file") or ""),
            int(source_ref.get("line") or 0),
            str(edge.get("kind") or ""),
            str(edge.get("to") or ""),
        )
        lexical_bucket_counts[bucket] = lexical_bucket_counts.get(bucket, 0) + 1

    filtered_edges = []
    for edge in edges:
        source_ref = edge.get("source") or {}
        bucket = (
            str(edge.get("from") or ""),
            str(source_ref.get("file") or ""),
            int(source_ref.get("line") or 0),
            str(edge.get("kind") or ""),
            str(edge.get("to") or ""),
        )
        exact_site = bucket[:1] + bucket[1:3] + (
            int(source_ref.get("column") or 0),
        ) + bucket[3:]
        ast_has_same_site = exact_site in ast_sites
        if (
            edge.get("from") in ast_covered
            and edge.get("kind") in {"CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER"}
            and edge.get("resolution") in {"DIRECT", "INFERRED"}
            and (
                ast_has_same_site
                or (
                    ast_site_counts.get(bucket) == 1
                    and lexical_bucket_counts.get(bucket) == 1
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
        "warnings": warnings + [
            f"Skipped {len(manifest.get('skipped') or [])} build-info file(s) due to configured bounds."
        ] if manifest.get("skipped") else warnings,
    }
