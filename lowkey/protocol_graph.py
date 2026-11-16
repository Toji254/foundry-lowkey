"""Compiler-backed Solidity protocol graph and trace-observed call graph.

Compiler AST edges are static source relationships. They are not runtime reachability.
Runtime edges come only from validated canonical TraceEvent v2 artifacts. State
read/write edges are compiler-derived dependencies, not full SSA proofs.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

try:
    from .trace_schema import build_trace_event
except ImportError:
    from trace_schema import build_trace_event

MAX_BUILD_INFO_FILES = 64
MAX_BUILD_INFO_BYTES = 32 * 1024 * 1024
MAX_AUDIT_TRACE_FILES = 2500
MAX_TRACE_BYTES = 16 * 1024 * 1024

AST_GRAPH_LIMITATIONS = [
    "Compiler AST is static source structure, not runtime reachability.",
    "Function and state dependency edges are AST-derived candidates, not full SSA or path-sensitive data-flow proofs.",
    "Dynamic dispatch, delegatecall targets and assembly storage semantics require separate runtime or semantic evidence.",
    "Build-info is accepted only when literal source content still matches the current project files.",
]


class ProtocolGraphError(ValueError):
    """A fail-closed error while deriving compiler or runtime graph evidence."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _inside(root: Path, raw: str) -> Path | None:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        return None
    candidate = (root / raw).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return None
    return candidate


def _walk(node: Any, *, write_context: bool = False):
    if isinstance(node, list):
        for child in node:
            yield from _walk(child, write_context=write_context)
        return
    if not isinstance(node, dict):
        return
    kind = node.get("nodeType")
    for key, value in node.items():
        child_write = write_context
        if kind == "Assignment" and key == "leftHandSide":
            child_write = True
        elif kind == "UnaryOperation" and key == "subExpression" and (
            node.get("operator") in {"++", "--", "delete"} or node.get("isLValue") is True
        ):
            child_write = True
        yield from _walk(value, write_context=child_write)
    yield node, write_context


def _safe_type(node: Any) -> str:
    if not isinstance(node, dict):
        return "unknown"
    details = node.get("typeDescriptions")
    if isinstance(details, dict):
        value = details.get("typeString")
        if isinstance(value, str) and value:
            return value[:240]
    return "unknown"


def _source_entry_current(root: Path, source_name: str, source_input: Any) -> tuple[bool, str | None]:
    path = _inside(root, source_name)
    if path is None:
        return False, "compiler source path escapes the project or is not relative"
    if not isinstance(source_input, dict):
        return False, "compiler input source entry is malformed"
    compiler_content = source_input.get("content")
    if not isinstance(compiler_content, str):
        return False, "compiler build info does not retain literal source content"
    try:
        current = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False, "source file is missing or unreadable"
    if current != compiler_content:
        return False, "source changed since the compiler AST was produced"
    return True, None


def compiler_ast_graph(
    root: str | Path,
    *,
    build_info_dir: str | Path = "out/build-info",
) -> dict[str, Any]:
    """Read Foundry's standard-JSON build-info without triggering a rebuild."""
    base = Path(root).expanduser().resolve()
    raw_dir = Path(build_info_dir)
    directory = (base / raw_dir).resolve() if not raw_dir.is_absolute() else raw_dir.resolve()
    if not directory.is_relative_to(base) or not directory.is_dir():
        return {
            "status": "AST_UNAVAILABLE",
            "reason": "Foundry build-info directory is unavailable; run forge build --build-info.",
            "build_info_files": 0,
            "nodes": [],
            "edges": [],
            "rejected_sources": [],
            "limitations": list(AST_GRAPH_LIMITATIONS),
        }
    paths = sorted(path for path in directory.glob("*.json") if path.is_file() and not path.is_symlink())
    if len(paths) > MAX_BUILD_INFO_FILES:
        return {
            "status": "AST_REFUSED",
            "reason": f"Build-info file count exceeds safety limit {MAX_BUILD_INFO_FILES}.",
            "build_info_files": len(paths),
            "nodes": [],
            "edges": [],
            "rejected_sources": [],
            "limitations": list(AST_GRAPH_LIMITATIONS),
        }

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    rejected_sources: list[dict[str, str]] = []
    compiler_versions: set[str] = set()
    build_count = 0

    for info_path in paths:
        try:
            if info_path.stat().st_size > MAX_BUILD_INFO_BYTES:
                rejected_sources.append({
                    "build_info": info_path.name,
                    "reason": "build-info file exceeds the configured byte limit",
                })
                continue
            payload = json.loads(info_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            rejected_sources.append({"build_info": info_path.name, "reason": f"invalid build-info: {exc}"})
            continue
        if not isinstance(payload, dict):
            rejected_sources.append({"build_info": info_path.name, "reason": "build-info root is not an object"})
            continue
        compiler_input = payload.get("input")
        compiler_output = payload.get("output")
        if not isinstance(compiler_input, dict) or not isinstance(compiler_output, dict):
            rejected_sources.append({"build_info": info_path.name, "reason": "input/output compiler objects are missing"})
            continue
        input_sources = compiler_input.get("sources")
        output_sources = compiler_output.get("sources")
        if not isinstance(input_sources, dict) or not isinstance(output_sources, dict):
            rejected_sources.append({"build_info": info_path.name, "reason": "compiler sources object is missing"})
            continue
        version = payload.get("solcVersion") or payload.get("compilerVersion")
        if isinstance(version, str):
            compiler_versions.add(version)

        current_sources: dict[str, dict[str, Any]] = {}
        source_ok = True
        for source_name, source_out in output_sources.items():
            source_in = input_sources.get(source_name)
            valid, reason = _source_entry_current(base, source_name, source_in)
            ast = source_out.get("ast") if isinstance(source_out, dict) else None
            if not valid or not isinstance(ast, dict) or ast.get("nodeType") != "SourceUnit":
                source_ok = False
                rejected_sources.append({
                    "build_info": info_path.name,
                    "source": str(source_name),
                    "reason": reason or "compiler output does not contain a Solidity SourceUnit AST",
                })
                continue
            current_sources[str(source_name)] = {
                "ast": ast,
                "source_sha256": _sha256(source_in["content"].encode("utf-8")),
            }
        if not current_sources:
            continue
        build_count += 1

        contract_by_id: dict[int, dict[str, Any]] = {}
        function_by_id: dict[int, dict[str, Any]] = {}
        modifier_by_id: dict[int, dict[str, Any]] = {}
        state_variable_by_id: dict[int, dict[str, Any]] = {}

        for source_name, source_data in current_sources.items():
            ast = source_data["ast"]
            for child in ast.get("nodes", []):
                if not isinstance(child, dict):
                    continue
                kind = child.get("nodeType")
                if kind == "ContractDefinition":
                    name = str(child.get("name") or "<anonymous>")
                    contract_id = child.get("id")
                    key = f"{source_name}:{name}"
                    contract_node = {
                        "id": key,
                        "kind": "contract",
                        "name": name,
                        "source": source_name,
                        "source_sha256": source_data["source_sha256"],
                        "source_span": child.get("src"),
                        "contract_kind": child.get("contractKind"),
                        "abstract": bool(child.get("abstract", False)),
                        "linearized_base_ids": child.get("linearizedBaseContracts", []),
                    }
                    nodes[key] = contract_node
                    if isinstance(contract_id, int):
                        contract_by_id[contract_id] = contract_node
                    for member in child.get("nodes", []):
                        if not isinstance(member, dict):
                            continue
                        member_kind = member.get("nodeType")
                        if member_kind == "VariableDeclaration" and member.get("stateVariable") is True:
                            variable_id = member.get("id")
                            variable = {
                                "id": f"{key}::state::{member.get('name')}",
                                "kind": "state_variable",
                                "name": str(member.get("name") or "<anonymous>"),
                                "contract": key,
                                "source": source_name,
                                "source_sha256": source_data["source_sha256"],
                                "source_span": member.get("src"),
                                "type": _safe_type(member),
                                "visibility": member.get("visibility"),
                                "storage_location": member.get("storageLocation"),
                            }
                            nodes[variable["id"]] = variable
                            if isinstance(variable_id, int):
                                state_variable_by_id[variable_id] = variable
                        elif member_kind == "ModifierDefinition":
                            modifier_id = member.get("id")
                            modifier_name = str(member.get("name") or "<anonymous>")
                            modifier_key = f"{key}::modifier::{modifier_name}"
                            modifier_node = {
                                "id": modifier_key,
                                "kind": "modifier",
                                "name": modifier_name,
                                "contract": key,
                                "source": source_name,
                                "source_sha256": source_data["source_sha256"],
                                "source_span": member.get("src"),
                            }
                            nodes[modifier_key] = modifier_node
                            if isinstance(modifier_id, int):
                                modifier_by_id[modifier_id] = modifier_node
                        elif member_kind == "FunctionDefinition":
                            parameters = member.get("parameters", {}).get("parameters", [])
                            signature = str(member.get("name") or member.get("kind") or "function") + "(" + ",".join(
                                _safe_type(item) for item in parameters if isinstance(item, dict)
                            ) + ")"
                            function_id = member.get("id")
                            function_key = key + "::" + signature
                            fn = {
                                "id": function_key,
                                "kind": "function",
                                "name": str(member.get("name") or member.get("kind") or "function"),
                                "signature": signature,
                                "contract": key,
                                "source": source_name,
                                "source_sha256": source_data["source_sha256"],
                                "source_span": member.get("src"),
                                "visibility": member.get("visibility"),
                                "state_mutability": member.get("stateMutability"),
                                "implemented": member.get("implemented") is True,
                                "reads": [],
                                "writes": [],
                            }
                            nodes[function_key] = fn
                            if isinstance(function_id, int):
                                function_by_id[function_id] = fn

        for contract_id, contract_node in contract_by_id.items():
            ast_node = next(
                (item for data in current_sources.values()
                 for item in data["ast"].get("nodes", [])
                 if isinstance(item, dict) and item.get("nodeType") == "ContractDefinition"
                 and item.get("id") == contract_id),
                None,
            )
            if not isinstance(ast_node, dict):
                continue
            for base_item in ast_node.get("baseContracts", []):
                base_name = base_item.get("baseName") if isinstance(base_item, dict) else None
                base_id = base_name.get("referencedDeclaration") if isinstance(base_name, dict) else None
                parent = contract_by_id.get(base_id) if isinstance(base_id, int) else None
                if parent:
                    edges.append({
                        "kind": "inheritance_candidate",
                        "source": contract_node["id"],
                        "target": parent["id"],
                        "evidence": "compiler_ast",
                        "source_sha256": contract_node["source_sha256"],
                    })

        for source_name, source_data in current_sources.items():
            for contract_ast in source_data["ast"].get("nodes", []):
                if not isinstance(contract_ast, dict) or contract_ast.get("nodeType") != "ContractDefinition":
                    continue
                contract_name = str(contract_ast.get("name") or "<anonymous>")
                contract_key = f"{source_name}:{contract_name}"
                for member in contract_ast.get("nodes", []):
                    if not isinstance(member, dict) or member.get("nodeType") != "FunctionDefinition":
                        continue
                    function_id = member.get("id")
                    function_node = function_by_id.get(function_id) if isinstance(function_id, int) else None
                    if function_node is None:
                        continue
                    reads: set[str] = set()
                    writes: set[str] = set()
                    for ast_child, in_write_context in _walk(member):
                        if ast_child.get("nodeType") == "Identifier":
                            reference = ast_child.get("referencedDeclaration")
                            variable = state_variable_by_id.get(reference) if isinstance(reference, int) else None
                            if variable:
                                (writes if in_write_context else reads).add(variable["id"])
                        if ast_child.get("nodeType") == "FunctionCall":
                            expression = ast_child.get("expression")
                            reference = expression.get("referencedDeclaration") if isinstance(expression, dict) else None
                            target_fn = function_by_id.get(reference) if isinstance(reference, int) else None
                            if target_fn:
                                edges.append({
                                    "kind": "compiler_call_candidate",
                                    "source": function_node["id"],
                                    "target": target_fn["id"],
                                    "evidence": "compiler_ast",
                                    "source_sha256": function_node["source_sha256"],
                                    "source_span": ast_child.get("src"),
                                })
                    function_node["reads"] = sorted(reads)
                    function_node["writes"] = sorted(writes)
                    for modifier_ref in member.get("modifiers", []):
                        modifier_name = modifier_ref.get("modifierName") if isinstance(modifier_ref, dict) else None
                        reference = modifier_name.get("referencedDeclaration") if isinstance(modifier_name, dict) else None
                        modifier_node = modifier_by_id.get(reference) if isinstance(reference, int) else None
                        if modifier_node:
                            edges.append({
                                "kind": "uses_modifier",
                                "source": function_node["id"],
                                "target": modifier_node["id"],
                                "evidence": "compiler_ast",
                                "source_sha256": function_node["source_sha256"],
                                "source_span": modifier_ref.get("src"),
                            })
                    for variable_id in function_node["reads"]:
                        edges.append({
                            "kind": "reads_state_variable",
                            "source": function_node["id"],
                            "target": variable_id,
                            "evidence": "compiler_ast",
                            "source_span": function_node.get("source_span"),
                        })
                    for variable_id in function_node["writes"]:
                        edges.append({
                            "kind": "writes_state_variable",
                            "source": function_node["id"],
                            "target": variable_id,
                            "evidence": "compiler_ast",
                            "source_span": function_node.get("source_span"),
                        })

    # A write-to-read pair is an AST-derived dependency candidate, not proof of
    # reaching-definition or execution order. It remains explicitly qualified.
    writers: dict[str, list[str]] = {}
    readers: dict[str, list[str]] = {}
    for node in nodes.values():
        if node.get("kind") != "function":
            continue
        for variable_id in node.get("writes", []):
            writers.setdefault(variable_id, []).append(node["id"])
        for variable_id in node.get("reads", []):
            readers.setdefault(variable_id, []).append(node["id"])
    for variable_id, sources in writers.items():
        for source in sources:
            for target in readers.get(variable_id, []):
                if source != target:
                    edges.append({
                        "kind": "state_dependency_candidate",
                        "source": source,
                        "target": target,
                        "via": variable_id,
                        "evidence": "compiler_ast_state_access",
                        "certainty": "candidate_only",
                        "source_span": nodes[source].get("source_span"),
                    })

    edges.sort(key=lambda row: (
        row.get("kind", ""), row.get("source", ""), row.get("target", ""), row.get("via", "")
    ))
    return {
        "status": "AST_OBSERVED" if nodes else "AST_UNAVAILABLE",
        "build_info_files": len(paths),
        "accepted_builds": build_count,
        "compiler_versions": sorted(compiler_versions),
        "nodes": sorted(nodes.values(), key=lambda row: row["id"]),
        "edges": edges,
        "rejected_sources": rejected_sources,
        "limitations": list(AST_GRAPH_LIMITATIONS),
    }


def _find_trace_streams(value: Any, *, path: str = "$"):
    if isinstance(value, dict):
        events = value.get("canonical_trace_events")
        if isinstance(events, list):
            yield path, value, events
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                yield from _find_trace_streams(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                yield from _find_trace_streams(child, path=f"{path}[{index}]")


def runtime_trace_graph(root: str | Path) -> dict[str, Any]:
    """Build only call edges evidenced by saved canonical TraceEvent v2 streams."""
    base = Path(root).expanduser().resolve()
    audit_root = base / ".audit"
    if not audit_root.is_dir():
        return {"status": "RUNTIME_TRACE_UNAVAILABLE", "streams": 0, "edges": [], "rejected": []}
    files = sorted(path for path in audit_root.rglob("*.json") if path.is_file() and not path.is_symlink())
    if len(files) > MAX_AUDIT_TRACE_FILES:
        return {
            "status": "RUNTIME_TRACE_REFUSED",
            "streams": 0, "edges": [],
            "rejected": [{"path": ".audit", "reason": "artifact count exceeds safety limit"}],
        }

    edges: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    streams = 0
    for path in files:
        try:
            if path.stat().st_size > MAX_TRACE_BYTES:
                continue
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        for stream_path, owner, events in _find_trace_streams(payload):
            normalized = []
            try:
                for index, event in enumerate(events):
                    if not isinstance(event, dict):
                        raise ProtocolGraphError(f"event #{index} is not an object")
                    normalized.append(build_trace_event(
                        seq=event.get("seq"),
                        backend=event.get("backend"),
                        kind=event.get("kind"),
                        accessor=event.get("accessor"),
                        account=event.get("account"),
                        depth=event.get("depth"),
                        value=event.get("value"),
                        selector=event.get("selector"),
                        calldata=event.get("calldata"),
                        reverted=event.get("reverted"),
                        storage=event.get("storage"),
                        storage_support=event.get("storage_support"),
                    ))
                if any(event["seq"] != index for index, event in enumerate(normalized)):
                    raise ProtocolGraphError("event seq values are not contiguous and ordered")
            except (ProtocolGraphError, TypeError, ValueError) as exc:
                rejected.append({
                    "path": path.relative_to(base).as_posix(),
                    "stream": stream_path,
                    "reason": str(exc),
                })
                continue
            streams += 1
            run_id = owner.get("run_id") or owner.get("transaction_hash") or owner.get("tx_hash")
            for event in normalized:
                if not event.get("accessor") or not event.get("account"):
                    continue
                edges.append({
                    "kind": "runtime_call_observed",
                    "source": event["accessor"],
                    "target": event["account"],
                    "depth": event["depth"],
                    "selector": event["selector"],
                    "backend": event["backend"],
                    "reverted": event["reverted"],
                    "run_id": str(run_id) if run_id is not None else None,
                    "artifact": path.relative_to(base).as_posix(),
                    "stream": stream_path,
                    "seq": event["seq"],
                })

    status = "RUNTIME_TRACE_OBSERVED" if streams else "RUNTIME_TRACE_UNAVAILABLE"
    return {
        "status": status,
        "streams": streams,
        "edges": edges,
        "rejected": rejected,
        "limitations": [
            "Runtime edges are observed only for the saved executions represented in these trace artifacts.",
            "Missing or null caller/target fields are not inferred.",
            "A trace-derived call graph is not a reachability proof for all protocol states.",
        ],
    }


def build_full_protocol_graph(root: str | Path) -> dict[str, Any]:
    """Combine compiler AST, static source candidates and saved runtime traces."""
    base = Path(root).expanduser().resolve()
    ast_graph = compiler_ast_graph(base)
    runtime_graph = runtime_trace_graph(base)
    return {
        "schema_version": 1,
        "compiler_ast": ast_graph,
        "runtime_call_graph": runtime_graph,
        "state_dependency_graph": {
            "status": "AST_CANDIDATES" if ast_graph["status"] == "AST_OBSERVED" else "UNAVAILABLE",
            "edges": [
                edge for edge in ast_graph["edges"]
                if edge.get("kind") in {"reads_state_variable", "writes_state_variable", "state_dependency_candidate"}
            ],
            "limitations": ast_graph["limitations"],
        },
    }
