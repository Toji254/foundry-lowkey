#!/usr/bin/env python3
"""CLI for Lowkey's shared static source relationship index."""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from source_index import SourceIndexError, build_source_index, find_symbols
except ImportError:  # pragma: no cover - package-style import
    from lowkey.source_index import SourceIndexError, build_source_index, find_symbols


ONLY_KINDS = {
    "calls": {"CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER", "OVERRIDES", "EMITS", "REVERTS"},
    "storage": {
        "READS", "WRITES", "DELETES", "MUTATES", "TRANSIENT_READS",
        "TRANSIENT_WRITES", "TRANSIENT_DELETES", "USES_TYPE",
        "ALIASES_STORAGE", "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION", "INITIALIZES",
    },
    "reads": {"READS", "TRANSIENT_READS", "READS_CONSTANT", "READS_IMMUTABLE"},
    "writes": {
        "WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES",
        "TRANSIENT_DELETES", "INITIALIZES", "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION",
    },
    "imports": {"IMPORTS", "INHERITS", "USES_LIBRARY"},
    "assets": {"ASSET_FLOW"},
}


def _node_map(index: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["id"]: item for item in index.get("nodes") or []}


def _location(value: dict[str, Any]) -> str:
    source = value.get("source") or {}
    file_name = source.get("file", value.get("file", "?"))
    line = source.get("line", value.get("line", "?"))
    return f"{file_name}:{line}"


def _symbol_label(node: dict[str, Any]) -> str:
    kind = node.get("kind", "symbol")
    if kind == "function":
        return node.get("qualified_name") or node.get("signature") or node.get("name", "?")
    if kind == "contract":
        declaration_kind = str(node.get("declaration_kind") or "contract").replace("_", " ")
        return f"{node.get('name', '?')} ({declaration_kind})"
    return node.get("qualified_name") or node.get("name", "?")


def _edge_groups(node: dict[str, Any], edges: list[dict[str, Any]], nodes: dict[str, dict[str, Any]]):
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if edge.get("from") == node["id"]:
            outgoing[edge["kind"]].append(edge)
        if edge.get("to") == node["id"]:
            incoming[edge["kind"]].append(edge)
    return outgoing, incoming


def _storage_index_shape(edge: dict[str, Any]) -> str | None:
    kinds = edge.get("index_kinds") or []
    types = edge.get("index_types") or []
    if not kinds:
        return None
    parts = []
    for index, kind in enumerate(kinds):
        type_name = types[index] if index < len(types) else None
        type_label = str(type_name or "?")
        if kind == "mapping":
            parts.append(f"mapping[{type_label}]")
        elif kind == "array":
            parts.append(f"array[{type_label}]")
        else:
            parts.append("index[unresolved]")
    return " -> ".join(parts)


def _edge_label(edge: dict[str, Any], nodes: dict[str, dict[str, Any]]) -> str:
    target = nodes.get(edge.get("to"), {})
    label = _symbol_label(target) if target else str(edge.get("to", "UNRESOLVED"))
    resolution = edge.get("resolution", "UNRESOLVED")
    detail = ""
    if edge.get("kind") == "ASSET_FLOW":
        asset = str(edge.get("asset", "unknown")).upper()
        direction = str(edge.get("direction", "unresolved")).upper()
        status = str(edge.get("status", "UNKNOWN")).replace("_", " ")
        detail = f" [{asset} {direction} · {status}]"
        if edge.get("recipient"):
            detail += f" to {edge['recipient']}"
        if edge.get("amount"):
            detail += f" amount={edge['amount']}"
    elif edge.get("kind") == "EXTERNAL_CALL":
        detail = f" [{edge.get('receiver', 'target')}.{edge.get('method', edge.get('operation', 'call'))}]"
        if edge.get("implementation_resolution"):
            detail += f" · implementation {edge['implementation_resolution']}"
    elif edge.get("kind") == "CALLS" and edge.get("implementation_resolution"):
        detail = f" · dispatch {edge.get('dispatch', 'unknown')} / implementation {edge['implementation_resolution']}"
    elif edge.get("kind") in {
        "READS", "READS_CONSTANT", "READS_IMMUTABLE", "WRITES", "DELETES", "MUTATES", "TRANSIENT_READS",
        "TRANSIENT_WRITES", "TRANSIENT_DELETES", "ALIASES_STORAGE",
    } and edge.get("access_path"):
        detail = f" [{edge['access_path']}]"
        if edge.get("operation"):
            detail += f" · op={edge['operation']}"
        if edge.get("persistence"):
            detail += f" · {edge['persistence']}"
        if edge.get("alias"):
            detail += f" (via storage alias {edge['alias']})"
        if edge.get("via"):
            via_names = [nodes.get(item, {}).get("qualified_name", item) for item in edge["via"]]
            detail += " · via " + " -> ".join(via_names)
    elif edge.get("via"):
        via_names = [nodes.get(item, {}).get("qualified_name", item) for item in edge["via"]]
        detail = " via " + " -> ".join(via_names)
    if edge.get("kind") == "INITIALIZES":
        initializer = nodes.get(str(edge.get("from") or ""), {})
        initializer_contract = initializer.get("contract") or initializer.get("name")
        if initializer_contract:
            detail += f" · initialization context={initializer_contract}"
    index_shape = _storage_index_shape(edge)
    if index_shape:
        detail += f" · indexes={index_shape}"
        if edge.get("mapping_depth") is not None:
            detail += f" · mapping-depth={edge['mapping_depth']}"
        if edge.get("terminal_type"):
            detail += f" · value-type={edge['terminal_type']}"
    elif edge.get("terminal_type"):
        detail += f" · value-type={edge['terminal_type']}"
    return f"{label}{detail}  [{resolution}]  {_location(edge)}"


def _selected_edges(
    node: dict[str, Any],
    edges: list[dict[str, Any]],
    *,
    only: str | None,
    depth: int,
) -> list[dict[str, Any]]:
    allowed = ONLY_KINDS.get(only) if only else None
    selected: dict[str, dict[str, Any]] = {}
    frontier = {node["id"]}
    visited = set(frontier)
    traversal_levels = max(1, depth + 1) if node.get("kind") == "contract" else max(1, depth)
    for _level in range(traversal_levels):
        next_frontier: set[str] = set()
        for edge in edges:
            if edge.get("via") and len(edge.get("via") or []) > depth + 1:
                continue
            declaration_traversal = (
                node.get("kind") == "contract"
                and _level == 0
                and edge.get("kind") == "DECLARES"
                and edge.get("from") == node["id"]
            )
            if allowed is not None and edge.get("kind") not in allowed and not declaration_traversal:
                continue
            if edge.get("from") in frontier or edge.get("to") in frontier:
                if not declaration_traversal or allowed is None:
                    selected[edge["id"]] = edge
                if edge.get("kind") == "CALLS":
                    other = edge.get("to") if edge.get("from") in frontier else edge.get("from")
                    if other not in visited:
                        next_frontier.add(other)
                elif declaration_traversal:
                    # A contract overview starts traversal from its declared functions.
                    if edge.get("to") not in visited:
                        next_frontier.add(edge.get("to"))
        visited.update(next_frontier)
        frontier = next_frontier
        if not frontier:
            break
    return sorted(selected.values(), key=lambda item: (
        item.get("source", {}).get("file", ""),
        item.get("source", {}).get("line", 0),
        item.get("kind", ""),
        item.get("to", ""),
    ))



def _depth_has_more_calls(node: dict[str, Any], edges: list[dict[str, Any]], depth: int) -> bool:
    """Return whether bounded call traversal stopped before a known next hop."""
    if node.get("kind") == "contract":
        starts = [
            edge.get("to") for edge in edges
            if edge.get("kind") == "DECLARES" and edge.get("from") == node.get("id")
        ]
        queue = [(item, 0) for item in starts if item]
    else:
        queue = [(node.get("id"), 0)]
    visited = {item for item, _ in queue}
    while queue:
        current, level = queue.pop(0)
        outgoing = [
            edge for edge in edges
            if edge.get("kind") == "CALLS" and edge.get("from") == current
            and edge.get("resolution") in {"DIRECT", "INFERRED"}
        ]
        if level >= depth and any(edge.get("to") not in visited for edge in outgoing):
            return True
        if level >= depth:
            continue
        for edge in outgoing:
            target = edge.get("to")
            if target and target not in visited:
                visited.add(target)
                queue.append((target, level + 1))
    return False


def _print_inventory_warning(index: dict[str, Any]) -> None:
    inventory = index.get("inventory") or {}
    failures = inventory.get("uninspected") or []
    if inventory.get("complete", True):
        return
    print(f"WARNING: SOURCE COVERAGE INCOMPLETE ({len(failures)} uninspected item(s))")
    for item in failures[:10]:
        print(f"  {item.get('path', '?')} [{item.get('phase', 'unknown')}]: {item.get('error', 'not inspected')}")
    if len(failures) > 10:
        print(f"  ... {len(failures) - 10} more uninspected item(s)")


def _render_call_tree(
    selected: dict[str, Any],
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    *,
    depth: int,
    limit: int,
) -> None:
    """Render a bounded call tree without following dynamic or external targets."""
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if edge.get("kind") == "CALLS":
            outgoing[str(edge.get("from") or "")].append(edge)

    def ordered(parent_id: str) -> list[dict[str, Any]]:
        return sorted(outgoing.get(parent_id, []), key=lambda edge: (
            (edge.get("source") or {}).get("file", ""),
            (edge.get("source") or {}).get("line", 0),
            (edge.get("source") or {}).get("column", 0),
            nodes.get(str(edge.get("to") or ""), {}).get("qualified_name", str(edge.get("to") or "")),
        ))

    if not ordered(str(selected.get("id") or "")):
        return

    print("CALL CHAIN")
    print(f"  {_symbol_label(selected)}")
    emitted = 0
    depth_limited = False
    output_limited = False
    expanded: set[str] = {str(selected.get("id") or "")}

    def walk(parent_id: str, level: int, prefix: str, stack: tuple[str, ...]) -> None:
        nonlocal emitted, depth_limited, output_limited
        children = ordered(parent_id)
        for index, edge in enumerate(children):
            if emitted >= limit:
                output_limited = True
                return
            is_last = index == len(children) - 1
            branch = "└──" if is_last else "├──"
            target_id = str(edge.get("to") or "")
            target = nodes.get(target_id)
            resolution = str(edge.get("resolution") or "UNRESOLVED")
            if target is None:
                label = f"UNRESOLVED TARGET {target_id}"
            else:
                label = _symbol_label(target)
            print(f"{prefix}{branch} {label}  [{resolution}]  {_location(edge)}")
            emitted += 1
            if target is None:
                continue
            if target_id in stack:
                print(f"{prefix}{'    ' if is_last else '│   '}↳ recursive cycle; traversal stopped")
                continue
            child_edges = ordered(target_id)
            if not child_edges:
                continue
            if level >= depth:
                depth_limited = True
                continue
            if target_id in expanded:
                print(f"{prefix}{'    ' if is_last else '│   '}↳ also reached through another call path")
                continue
            expanded.add(target_id)
            child_prefix = prefix + ("    " if is_last else "│   ")
            walk(target_id, level + 1, child_prefix, stack + (target_id,))
            if output_limited:
                return

    walk(str(selected.get("id") or ""), 1, "  ", (str(selected.get("id") or ""),))
    if depth_limited:
        print(f"  DEPTH: additional nested calls exist beyond --depth {depth}; increase the depth to follow them.")
    if output_limited:
        print(f"  OUTPUT: call tree limited to {limit} edge(s); increase --limit to expand it.")


def render_link(index: dict[str, Any], target: str, *, only: str | None = None, depth: int | None = None, limit: int = 80, as_json: bool = False) -> int:
    candidates = find_symbols(index, target)
    if not candidates:
        print(f"UNRESOLVED: no source symbol matched '{target}'.")
        print("Use a contract name, Contract.symbol, or Contract.function(type,...) signature.")
        return 2
    if len(candidates) > 1:
        print(f"AMBIGUOUS: '{target}' matches {len(candidates)} source symbols.")
        for item in candidates[:20]:
            print(f"  {_symbol_label(item)}  {_location(item)}")
        if len(candidates) > 20:
            print(f"  ... {len(candidates) - 20} additional matches")
        print("Specify the contract and, for overloaded functions, the full signature.")
        return 2

    selected = candidates[0]
    if depth is None:
        # Function investigations should reveal a useful nested call chain by
        # default; contract overviews stay shallow and summarized.
        depth = 3 if selected.get("kind") in {"function", "modifier"} else 1
    nodes = _node_map(index)
    edges = _selected_edges(selected, index.get("edges") or [], only=only, depth=depth)
    if as_json:
        print(json.dumps({
            "target": selected,
            "edges": edges[:limit],
            "inventory": index.get("inventory"),
            "summary": index.get("summary"),
            "parser": index.get("parser"),
            "ast": index.get("ast"),
            "mutation_semantics": index.get("mutation_semantics"),
        }, indent=2, sort_keys=True))
        return 0

    print("LOWKEY // SOURCE LINK")
    print(f"TARGET    {_symbol_label(selected)}")
    print(f"SOURCE    {_location(selected)}")
    if selected.get("provenance"):
        print(f"ORIGIN    {str(selected['provenance']).upper()}")
    print(f"KIND      {selected.get('kind', 'symbol').upper()}")
    if selected.get("storage_class"):
        persistence = str(selected["storage_class"])
        print(f"PERSISTENCE {persistence.upper()}")
        if persistence in {"constant", "immutable"}:
            print("NOTE      This value is not an ordinary persistent EVM storage slot.")
    print(f"EVIDENCE  {index.get('parser', 'UNKNOWN')} static source analysis (not runtime execution)")
    ast_report = index.get("ast") or {}
    if ast_report:
        print(
            "AST       "
            f"{ast_report.get('functions', 0)} function(s), "
            f"{ast_report.get('call_edges', 0)} call edge(s), "
            f"{ast_report.get('modifier_edges', 0)} modifier edge(s), "
            f"{ast_report.get('storage_edges', 0)} storage edge(s) "
            "from matched build-info"
        )
        for warning in (ast_report.get("warnings") or [])[:4]:
            print(f"AST NOTE  {warning}")
    print(f"CACHE     {(index.get('cache') or {}).get('status', 'UNKNOWN')}")
    summary = index.get("summary") or {}
    if summary:
        print(
            "INDEX     "
            f"files={summary.get('files', 0)} "
            f"contracts={summary.get('contracts', 0)} "
            f"functions={summary.get('functions', 0)} "
            f"relationships={summary.get('relationships', 0)}"
        )
        print(
            "STATE     "
            f"persistent={summary.get('persistent_storage', 0)} "
            f"transient={summary.get('transient_storage', 0)} "
            f"constants={summary.get('constants', 0)} "
            f"immutables={summary.get('immutables', 0)}"
        )
        print(
            "RESOLUTION "
            f"ambiguous={summary.get('ambiguous', 0)} "
            f"unresolved={summary.get('unresolved', 0)}"
        )
    if selected.get("type"):
        print(f"TYPE      {selected['type']}")
    if selected.get("signature"):
        print(f"SIGNATURE {selected['signature']}")
    if selected.get("visibility"):
        print(f"VISIBILITY {selected['visibility']}  MUTABILITY {selected.get('mutability', 'unknown')}")
    if selected.get("bases"):
        print("BASES     " + ", ".join(selected["bases"]))
    print()

    if selected.get("kind") == "contract":
        declared = [edge for edge in edges if edge.get("kind") == "DECLARES"]
        if only == "storage":
            declared = [
                edge for edge in (index.get("edges") or [])
                if edge.get("kind") == "DECLARES" and edge.get("from") == selected["id"]
                and nodes.get(edge.get("to"), {}).get("kind") in {"mapping", "state_variable", "function_pointer", "struct", "struct_field"}
                and nodes.get(edge.get("to"), {}).get("storage_class") not in {"constant", "immutable"}
            ]
        elif only == "calls":
            declared = [
                edge for edge in (index.get("edges") or [])
                if edge.get("kind") == "DECLARES" and edge.get("from") == selected["id"]
                and nodes.get(edge.get("to"), {}).get("kind") in {"function", "modifier"}
            ]
        elif only in {"reads", "writes"}:
            effect_kinds = ONLY_KINDS[only]
            affected_functions = {
                edge.get("from") for edge in (index.get("edges") or [])
                if edge.get("kind") in effect_kinds and edge.get("from") in nodes
            }
            declared = [
                edge for edge in (index.get("edges") or [])
                if edge.get("kind") == "DECLARES" and edge.get("from") == selected["id"]
                and edge.get("to") in affected_functions
            ]
        elif only == "assets":
            asset_functions = {
                edge.get("from") for edge in (index.get("edges") or [])
                if edge.get("kind") == "ASSET_FLOW"
            }
            declared = [
                edge for edge in (index.get("edges") or [])
                if edge.get("kind") == "DECLARES" and edge.get("from") == selected["id"]
                and edge.get("to") in asset_functions
            ]
        elif only == "imports":
            declared = []
        for title, kinds in (
            ("FUNCTIONS", {"function"}),
            ("MODIFIERS", {"modifier"}),
            ("STORAGE", {"mapping", "state_variable", "function_pointer"}),
            ("TRANSIENT STORAGE", {"mapping", "state_variable", "function_pointer"}),
            ("CONSTANTS / IMMUTABLES", {"state_variable"}),
            ("STRUCTURES", {"struct", "struct_field"}),
            ("ENUMS", {"enum", "enum_value"}),
            ("EVENTS / ERRORS", {"event", "custom_error"}),
        ):
            items = [
                nodes.get(edge["to"], {}) for edge in declared
                if nodes.get(edge["to"], {}).get("kind") in kinds
                and (
                    title == "CONSTANTS / IMMUTABLES"
                    and nodes.get(edge["to"], {}).get("storage_class") in {"constant", "immutable"}
                    or title == "TRANSIENT STORAGE"
                    and nodes.get(edge["to"], {}).get("storage_class") == "transient"
                    or title == "STORAGE"
                    and nodes.get(edge["to"], {}).get("storage_class") not in {"constant", "immutable", "transient"}
                    or title not in {"CONSTANTS / IMMUTABLES", "TRANSIENT STORAGE", "STORAGE"}
                )
            ]
            if items:
                print(title)
                for item in items[:limit]:
                    print(f"  {_symbol_label(item)}  {_location(item)}")
                if len(items) > limit:
                    print(f"  ... {len(items) - limit} more item(s)")
        file_node = next((item for item in nodes.values() if item.get("kind") == "file" and item.get("name") == selected.get("file")), None)
        file_imports = [
            edge for edge in (index.get("edges") or [])
            if file_node and edge.get("kind") == "IMPORTS"
            and edge.get("from") == file_node.get("id")
            and (only is None or only == "imports")
        ]
        imports = [edge for edge in edges if edge.get("kind") == "IMPORTS"] + file_imports
        imported_by = [
            edge for edge in (index.get("edges") or [])
            if file_node and edge.get("kind") == "IMPORTS"
            and edge.get("to") == file_node.get("id")
            and (only is None or only == "imports")
        ]
        inheritance = [edge for edge in edges if edge.get("kind") == "INHERITS"]
        inherits = [edge for edge in inheritance if edge.get("from") == selected["id"]]
        inherited_by = [edge for edge in inheritance if edge.get("to") == selected["id"]]
        libraries = [edge for edge in edges if edge.get("kind") == "USES_LIBRARY"]
        library_uses = [edge for edge in libraries if edge.get("from") == selected["id"]]
        library_used_by = [edge for edge in libraries if edge.get("to") == selected["id"]]
        _render_edges("INHERITS", inherits[:limit], nodes)
        _render_edges("INHERITED BY", inherited_by[:limit], nodes, reverse=True)
        _render_edges("IMPORTS", imports[:limit], nodes)
        _render_edges("IMPORTED BY", imported_by[:limit], nodes, reverse=True)
        _render_edges("LIBRARY EXTENSIONS", library_uses[:limit], nodes)
        _render_edges("USED BY", library_used_by[:limit], nodes, reverse=True)
        related_contracts = {
            selected.get("name"),
            *(selected.get("ancestors") or []),
        }
        related_functions = {
            item["id"] for item in nodes.values()
            if item.get("kind") in {"function", "modifier"}
            and item.get("contract") in related_contracts
        }
        inherited_functions = [
            item for item in nodes.values()
            if item.get("kind") == "function"
            and item.get("contract") in set(selected.get("ancestors") or [])
        ]
        if inherited_functions and only in (None, "calls"):
            print("INHERITED FUNCTIONS")
            for item in sorted(inherited_functions, key=lambda value: (value.get("contract", ""), value.get("line", 0), value.get("qualified_name", "")))[:limit]:
                print(f"  {_symbol_label(item)}  {_location(item)}")
        contract_edges = [
            edge for edge in (index.get("edges") or [])
            if edge.get("from") in related_functions
            and (not edge.get("via") or len(edge.get("via") or []) <= depth + 1)
        ]
        # Include direct function relationships in the contract overview. A
        # larger --depth additionally exposes nested helper relationships.
        if depth > 1:
            contract_edges.extend(
                edge for edge in edges
                if edge.get("from") not in related_functions
                and edge.get("kind") in {
                "CALLS", "READS", "WRITES", "DELETES", "MUTATES",
                "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
                "INITIALIZES", "UNRESOLVED_MUTATION", "ASSET_FLOW", "EXTERNAL_CALL",
            }
            )
        calls = [edge for edge in contract_edges if edge.get("kind") == "CALLS"]
        storage_reads = [edge for edge in contract_edges if edge.get("kind") == "READS"]
        value_references = [
            edge for edge in contract_edges
            if edge.get("kind") in {"READS_CONSTANT", "READS_IMMUTABLE"}
        ]
        storage_writes = [
            edge for edge in contract_edges
            if edge.get("kind") in {"WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES", "TRANSIENT_DELETES", "UNRESOLVED_MUTATION"}
        ]
        related_contract_ids = {
            item["id"] for item in nodes.values()
            if item.get("kind") == "contract"
            and item.get("name") in related_contracts
        }
        constructor_ids = {
            item["id"] for item in nodes.values()
            if item.get("kind") == "function"
            and item.get("name") == "constructor"
            and item.get("contract") in related_contracts
        }
        state_initializers = [
            edge for edge in (index.get("edges") or [])
            if edge.get("kind") == "INITIALIZES"
            and (
                edge.get("from") in related_contract_ids
                or edge.get("from") in constructor_ids
            )
        ]
        transient_reads = [edge for edge in contract_edges if edge.get("kind") == "TRANSIENT_READS"]
        if only in (None, "calls"):
            _render_edges("INTERNAL CALLS", calls[:limit], nodes)
        if only in (None, "storage", "reads"):
            _render_edges("STORAGE READS", storage_reads[:limit], nodes)
            _render_edges("TRANSIENT READS", transient_reads[:limit], nodes)
        if only in (None, "reads"):
            _render_edges("CONSTANT / IMMUTABLE REFERENCES", value_references[:limit], nodes)
        if only in (None, "storage", "writes"):
            _render_edges("STATE MUTATIONS / WRITES", storage_writes[:limit], nodes)
            _render_edges("STATE INITIALIZERS", state_initializers[:limit], nodes)
        extras = [
            edge for edge in contract_edges
            if edge.get("kind") in {"EXTERNAL_CALL", "ASSET_FLOW"}
            and (only is None or edge.get("kind") in ONLY_KINDS.get(only, set()))
        ]
        _render_edges("EXTERNAL INTERACTIONS / ASSET PATHS", extras[:limit], nodes)
        unresolved = [
            edge for edge in edges + extras + file_imports
            if edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"}
        ]
        _render_edges("UNRESOLVED", unresolved[:limit], nodes)
    elif selected.get("kind") in {"function", "modifier"}:
        group_map = [
            ("CALLED BY", "CALLS", "incoming"),
            ("CALLS", "CALLS", "outgoing"),
            ("EXTERNAL CALLS", "EXTERNAL_CALL", "outgoing"),
            ("MODIFIERS", "APPLIES_MODIFIER", "outgoing"),
            ("APPLIED TO", "APPLIES_MODIFIER", "incoming"),
            ("OVERRIDES", "OVERRIDES", "outgoing"),
            ("OVERRIDDEN BY", "OVERRIDES", "incoming"),
            ("STORAGE READS", "READS", "outgoing"),
            ("CONSTANT REFERENCES", "READS_CONSTANT", "outgoing"),
            ("IMMUTABLE REFERENCES", "READS_IMMUTABLE", "outgoing"),
            ("STORAGE WRITES", "WRITES", "outgoing"),
            ("DELETES", "DELETES", "outgoing"),
            ("TRANSIENT WRITES", "TRANSIENT_WRITES", "outgoing"),
            ("TRANSIENT DELETES", "TRANSIENT_DELETES", "outgoing"),
            ("TRANSIENT READS", "TRANSIENT_READS", "outgoing"),
            ("UNRESOLVED MUTATIONS", "UNRESOLVED_MUTATION", "outgoing"),
            ("INITIALIZES", "INITIALIZES", "outgoing"),
            ("EMITS", "EMITS", "outgoing"),
            ("REVERTS", "REVERTS", "outgoing"),
            ("STORAGE ALIASES", "ALIASES_STORAGE", "outgoing"),
            ("UNRESOLVED ASSEMBLY STORAGE", "UNRESOLVED_STORAGE", "outgoing"),
            ("ASSET FLOW / CAPABILITY", "ASSET_FLOW", "outgoing"),
        ]
        for heading, kind, direction in group_map:
            values = [
                edge for edge in edges if edge.get("kind") == kind
                and ((direction == "outgoing" and edge.get("from") == selected["id"])
                     or (direction == "incoming" and edge.get("to") == selected["id"]))
            ]
            _render_edges(heading, values[:limit], nodes, reverse=(direction == "incoming"))
        _render_call_tree(
            selected, index.get("edges") or [], nodes, depth=depth, limit=limit,
        )
        unresolved = [
            edge for edge in edges
            if edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"}
        ]
        _render_edges("UNRESOLVED TARGETS", unresolved[:limit], nodes)
    elif selected.get("kind") in {"mapping", "state_variable", "function_pointer"}:
        for heading, kind, direction in (
            ("READ BY", "READS", "incoming"),
            ("CONSTANT REFERENCED BY", "READS_CONSTANT", "incoming"),
            ("IMMUTABLE REFERENCED BY", "READS_IMMUTABLE", "incoming"),
            ("TRANSIENTLY READ BY", "TRANSIENT_READS", "incoming"),
            ("WRITTEN BY", "WRITES", "incoming"),
            ("DELETED BY", "DELETES", "incoming"),
            ("TRANSIENTLY WRITTEN BY", "TRANSIENT_WRITES", "incoming"),
            ("TRANSIENTLY DELETED BY", "TRANSIENT_DELETES", "incoming"),
            ("INITIALIZED BY", "INITIALIZES", "incoming"),
            ("ALIASED BY", "ALIASES_STORAGE", "incoming"),
            ("UNRESOLVED ASSEMBLY STORAGE", "UNRESOLVED_STORAGE", "outgoing"),
            ("USES TYPE", "USES_TYPE", "outgoing"),
        ):
            values = [
                edge for edge in edges if edge.get("kind") == kind
                and ((direction == "outgoing" and edge.get("from") == selected["id"])
                     or (direction == "incoming" and edge.get("to") == selected["id"]))
            ]
            _render_edges(heading, values[:limit], nodes, reverse=(direction == "incoming"))
        type_edges = [edge for edge in edges if edge.get("kind") == "USES_TYPE" and edge.get("from") == selected["id"]]
        struct_ids = {edge.get("to") for edge in type_edges}
        struct_fields = [edge for edge in index.get("edges") or [] if edge.get("kind") == "DECLARES" and edge.get("from") in struct_ids]
        _render_edges("STRUCT FIELDS", struct_fields, nodes)
        if selected.get("mapping_keys"):
            print("MAPPING KEYS       " + " -> ".join(selected["mapping_keys"]))
        if selected.get("mapping_value_type"):
            print(f"MAPPING VALUE TYPE  {selected['mapping_value_type']}")
            print("NOTE: declared mapping type is not a runtime storage-slot calculation.")
    else:
        outgoing, incoming = _edge_groups(selected, edges, nodes)
        for kind, values in sorted(outgoing.items()):
            _render_edges(kind.replace("_", " "), values[:limit], nodes)
        for kind, values in sorted(incoming.items()):
            _render_edges("REFERENCED BY " + kind.replace("_", " "), values[:limit], nodes, reverse=True)

    print()
    print(f"GRAPH     {index.get('summary', {}).get('relationships', 0)} relationship(s) indexed across {index.get('summary', {}).get('files', 0)} Solidity file(s)")
    if selected.get("kind") in {"contract", "function"} and _depth_has_more_calls(selected, index.get("edges") or [], depth):
        print(f"DEPTH     Additional nested call relationships exist beyond --depth {depth}; increase --depth to follow them.")
    print("LIMITS    Static source links do not prove execution, success, storage-slot identity, or an external implementation.")
    _print_inventory_warning(index)
    if len(edges) > limit:
        print(f"OUTPUT    Showing {limit} of {len(edges)} selected relationship(s); use --limit to increase.")
    return 0


def _render_edges(heading: str, edges: list[dict[str, Any]], nodes: dict[str, dict[str, Any]], *, reverse: bool = False) -> None:
    if not edges:
        return
    print(heading)
    for edge in edges:
        if reverse:
            target = nodes.get(edge.get("from"), {})
            label = _symbol_label(target) if target else str(edge.get("from", "?"))
            details = []
            if edge.get("access_path"):
                details.append(str(edge["access_path"]))
            elif edge.get("keys"):
                details.append("keys=" + ", ".join(str(item) for item in edge["keys"]))
            if edge.get("member") and not edge.get("access_path"):
                details.append("field=" + str(edge["member"]))
            if edge.get("alias"):
                details.append("storage alias " + str(edge["alias"]))
            index_shape = _storage_index_shape(edge)
            if index_shape:
                details.append("indexes=" + index_shape)
            if edge.get("mapping_depth") is not None:
                details.append("mapping-depth=" + str(edge["mapping_depth"]))
            if edge.get("terminal_type"):
                details.append("value-type=" + str(edge["terminal_type"]))
            detail_text = "  " + " · ".join(details) if details else ""
            print(f"  {label}{detail_text}  [{edge.get('resolution', 'UNRESOLVED')}]  {_location(edge)}")
        else:
            print("  " + _edge_label(edge, nodes))


def _link_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lk link",
        description="Navigate static Solidity source relationships. No compile or transaction execution is performed.",
        add_help=False,
    )
    parser.add_argument("target", nargs="?")
    parser.add_argument("--root", default=".")
    parser.add_argument("--depth", type=int, default=None)
    parser.add_argument("--only", choices=sorted(ONLY_KINDS))
    parser.add_argument("--limit", type=int, default=80)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-h", "--h", "--help", action="help", help="show this help")
    return parser


def run_link(argv: list[str]) -> int:
    parser = _link_parser()
    args = parser.parse_args(argv)
    if not args.target:
        parser.print_help()
        return 2
    if args.depth is not None and (args.depth < 1 or args.depth > 10):
        parser.error("--depth must be between 1 and 10")
    if args.limit < 1 or args.limit > 500:
        parser.error("--limit must be between 1 and 500")
    try:
        index = build_source_index(args.root)
    except (SourceIndexError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return render_link(index, args.target, only=args.only, depth=args.depth, limit=args.limit, as_json=args.json)


def run_flow(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lk fn",
        description="Filter the shared static asset-flow graph. Static transfer attempts are not runtime proof.",
        add_help=False,
    )
    parser.add_argument("-h", "--h", "--help", action="help", help="show this help")
    parser.add_argument("--flow", choices=("in", "out", "both"), required=True)
    parser.add_argument("--asset", choices=("eth", "erc20", "all"), default="all")
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        index = build_source_index(args.root)
    except (SourceIndexError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    nodes = _node_map(index)
    functions = {key: item for key, item in nodes.items() if item.get("kind") in {"function", "modifier"}}
    flows = [edge for edge in index.get("edges") or [] if edge.get("kind") == "ASSET_FLOW"]
    selected = []
    for edge in flows:
        asset = edge.get("asset", "unknown")
        direction = edge.get("direction", "unresolved")
        if args.asset != "all" and asset != args.asset:
            continue
        if args.flow == "in" and direction not in {"in", "both"}:
            continue
        if args.flow == "out" and direction not in {"out", "both"}:
            continue
        selected.append(edge)
    selected.sort(key=lambda item: (
        item.get("asset", ""), item.get("direction", ""),
        item.get("source", {}).get("file", ""),
        item.get("source", {}).get("line", 0),
    ))

    if args.json:
        print(json.dumps([
            {"function": functions.get(item["from"]), **item}
            for item in selected
        ], indent=2, sort_keys=True))
        return 0

    print("LOWKEY // ASSET FLOW FILTER")
    print(f"FILTER    flow={args.flow}  asset={args.asset}")
    print("EVIDENCE  Static source analysis. This is not proof that a transfer executed or succeeded.")
    print()
    if not selected:
        print("No statically identified paths matched this filter.")
    for edge in selected:
        function = functions.get(edge.get("from"), {})
        asset = str(edge.get("asset", "unknown")).upper()
        direction = str(edge.get("direction", "unresolved")).upper()
        status = str(edge.get("status", "UNKNOWN")).replace("_", " ")
        print(f"{asset:<7} {direction:<10} {status:<20} {_symbol_label(function)}")
        print(f"  {_location(edge)}")
        if edge.get("detail"):
            print(f"  {edge['detail']}")
        if edge.get("recipient"):
            print(f"  recipient={edge['recipient']} amount={edge.get('amount', 'unknown')}")
        if edge.get("resolution") == "INFERRED" and edge.get("via"):
            print("  via " + " -> ".join(nodes.get(item, {}).get("qualified_name", item) for item in edge["via"]))
    _print_inventory_warning(index)
    return 0


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if not values or values[0] in {"-h", "--h", "--help", "help"}:
        print("Usage: lk link TARGET [--depth N] [--only calls|storage|reads|writes|imports|assets]")
        print("       lk fn --flow in|out|both --asset eth|erc20|all")
        return 0 if values else 2
    command, rest = values[0], values[1:]
    if command == "link":
        return run_link(rest)
    if command == "flow":
        return run_flow(rest)
    print(f"Unknown source-relationship command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
