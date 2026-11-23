#!/usr/bin/env python3
"""CLI for Lowkey's shared static source relationship index."""
from __future__ import annotations

import argparse
import json
import shlex
import sys
import textwrap
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
            if edge.get("kind") in {"CALLS", "APPLIES_MODIFIER"} and edge.get("from") == current
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
                label = f"{resolution} TARGET {target_id}"
            else:
                label = _symbol_label(target)
            status_parts = [resolution]
            if edge.get("dispatch"):
                status_parts.append(f"dispatch {str(edge['dispatch']).lower()}")
            if edge.get("implementation_resolution"):
                status_parts.append(f"implementation {str(edge['implementation_resolution']).lower()}")
            status = " · ".join(status_parts)
            print(f"{prefix}{branch} {label}  [{status}]  {_location(edge)}")
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



def _short_function_label(node: dict[str, Any]) -> str:
    label = _symbol_label(node)
    contract = node.get("contract")
    if contract and label.startswith(contract + "."):
        return label[len(contract) + 1:]
    return label


def _render_contract_overview(
    selected: dict[str, Any],
    index: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
    *,
    limit: int,
) -> None:
    """Render the deliberately small, first-screen contract navigation view."""
    all_edges = index.get("edges") or []
    declared_edges = [
        edge for edge in all_edges
        if edge.get("kind") == "DECLARES" and edge.get("from") == selected["id"]
    ]
    declared = [nodes[edge["to"]] for edge in declared_edges if edge.get("to") in nodes]

    print(f"CONTRACT: {selected.get('name', '?')}")
    print(f"SOURCE:   {_location(selected)}")
    if selected.get("provenance"):
        print(f"ORIGIN:   {str(selected['provenance']).upper()}")
    print("EVIDENCE: static source relationships; not runtime execution")
    print()

    base_nodes = {
        item.get("name"): item for item in nodes.values()
        if item.get("kind") == "contract"
    }
    bases = list(selected.get("bases") or [])
    if bases:
        print("INHERITANCE")
        visited_bases = set()

        def render_bases(names: list[str], prefix: str, depth: int = 0) -> None:
            for index, name in enumerate(names):
                last = index == len(names) - 1
                connector = "└──" if last else "├──"
                print(f"{prefix}{connector} {name}")
                if name in visited_bases or depth >= 8:
                    continue
                visited_bases.add(name)
                base_node = base_nodes.get(name, {})
                nested = list(base_node.get("bases") or [])
                if nested:
                    render_bases(nested, prefix + ("    " if last else "│   "), depth + 1)

        render_bases(bases, "  ")
        print()

    file_node = next(
        (
            item for item in nodes.values()
            if item.get("kind") == "file"
            and item.get("name") == selected.get("file")
        ),
        None,
    )
    imports = [
        edge for edge in all_edges
        if edge.get("kind") == "IMPORTS"
        and file_node
        and edge.get("from") == file_node.get("id")
    ]
    imported_labels = []
    for edge in imports:
        imported_file = nodes.get(edge.get("to"), {})
        imported_path = imported_file.get("name") or imported_file.get("file")
        declarations = [
            item for item in nodes.values()
            if item.get("kind") == "contract" and item.get("file") == imported_path
        ]
        labels = [item.get("name") for item in declarations if item.get("name")]
        if not labels and imported_path:
            labels = [Path(str(imported_path)).stem]
        for label in labels:
            if label not in imported_labels:
                imported_labels.append(label)
    if imported_labels:
        print("IMPORTS")
        for label in imported_labels[:limit]:
            print(f"  ├── {label}")
        if len(imported_labels) > limit:
            print(f"  └── ... {len(imported_labels) - limit} more")
        print()

    inherited_by = [
        edge for edge in all_edges
        if edge.get("kind") == "INHERITS" and edge.get("to") == selected["id"]
    ]
    if inherited_by:
        print("INHERITED BY")
        for edge in inherited_by[:limit]:
            print(f"  └── {_symbol_label(nodes.get(edge.get('from'), {}))}")
        print()

    used_by = [
        edge for edge in all_edges
        if edge.get("kind") == "USES_LIBRARY" and edge.get("to") == selected["id"]
    ]
    if used_by:
        print("USED BY")
        for edge in used_by[:limit]:
            print(f"  └── {_symbol_label(nodes.get(edge.get('from'), {}))}")
        print()

    functions = sorted(
        (item for item in declared if item.get("kind") == "function"),
        key=lambda item: (
            item.get("visibility") not in {"external", "public"},
            item.get("line", 0),
            item.get("name", ""),
        ),
    )
    if functions:
        print(f"FUNCTIONS ({len(functions)} total)")
        for item in functions[:limit]:
            print(f"  ├── {_short_function_label(item)}")
        if len(functions) > limit:
            print(f"  └── ... {len(functions) - limit} more")
        print()

    related_contracts = {selected.get("name"), *(selected.get("ancestors") or [])}
    inherited_declarations = [
        item for item in nodes.values()
        if item.get("contract") in related_contracts
    ]
    storage = [
        item for item in inherited_declarations
        if item.get("kind") in {"mapping", "state_variable", "function_pointer"}
        and item.get("storage_class") not in {"constant", "immutable", "transient"}
    ]
    transient = [
        item for item in inherited_declarations
        if item.get("kind") in {"mapping", "state_variable", "function_pointer"}
        and item.get("storage_class") == "transient"
    ]
    constants = [
        item for item in inherited_declarations
        if item.get("kind") == "state_variable"
        and item.get("storage_class") in {"constant", "immutable"}
    ]
    print("AT A GLANCE")
    print(f"  {len(functions)} declared functions · {len(storage)} persistent state items · {len(transient)} transient items · {len(constants)} constants / immutables")
    print()

    for heading, values in (
        ("STORAGE", storage),
        ("TRANSIENT STORAGE", transient),
        ("CONSTANTS / IMMUTABLES", constants),
    ):
        if values:
            print(f"{heading} ({len(values)} total)")
            for item in values[:limit]:
                print(f"  ├── {item.get('name', '?')}")
            if len(values) > limit:
                print(f"  └── ... {len(values) - limit} more")
            print()

    related_contracts = {selected.get("name"), *(selected.get("ancestors") or [])}
    related_functions = {
        item.get("id") for item in nodes.values()
        if item.get("kind") in {"function", "modifier"}
        and item.get("contract") in related_contracts
    }
    external_edges = [
        edge for edge in all_edges
        if edge.get("kind") == "EXTERNAL_CALL"
        and edge.get("from") in related_functions
    ]
    external_targets = []
    for edge in external_edges:
        target = nodes.get(edge.get("to"), {})
        label = (
            edge.get("receiver")
            or target.get("contract")
            or target.get("name")
            or edge.get("method")
            or "unresolved external target"
        )
        if label not in external_targets:
            external_targets.append(label)
    if external_targets:
        print("EXTERNAL INTERACTIONS")
        for label in external_targets[:limit]:
            print(f"  ├── {label}")
        if len(external_targets) > limit:
            print(f"  └── ... {len(external_targets) - limit} more")
        print()

    asset_edges = [
        edge for edge in all_edges
        if edge.get("kind") == "ASSET_FLOW"
        and edge.get("from") in related_functions
    ]
    asset_groups = set()
    for edge in asset_edges:
        asset = str(edge.get("asset") or "unknown").upper()
        direction = str(edge.get("direction") or "unresolved").lower()
        if direction in {"in", "both"}:
            asset_groups.add(f"Potential {asset} inflows")
        if direction in {"out", "both"}:
            asset_groups.add(f"Potential {asset} outflows")
        if direction not in {"in", "out", "both"}:
            asset_groups.add(f"Potential {asset} movement (direction unresolved)")
    if asset_groups:
        print("ASSET MOVEMENT")
        for label in sorted(asset_groups):
            print(f"  ├── {label}")
        print()

    unresolved = [
        edge for edge in all_edges
        if edge.get("from") in related_functions
        and (
            edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"}
            or edge.get("kind") in {"UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION"}
            or edge.get("implementation_resolution") in {"UNRESOLVED", "AMBIGUOUS"}
        )
    ]
    if unresolved:
        print("UNRESOLVED")
        seen = set()
        for edge in unresolved[:limit]:
            source = nodes.get(edge.get("from"), {})
            detail = (
                edge.get("receiver")
                or edge.get("detail")
                or edge.get("operation")
                or edge.get("kind", "relationship").replace("_", " ").lower()
            )
            label = f"{_short_function_label(source)}: {detail}"
            if label not in seen:
                print(f"  └── {label}")
                seen.add(label)
        if len(unresolved) > limit:
            print(f"  ... {len(unresolved) - limit} more unresolved relationship(s)")
        print()

    print("EXPLORE")
    print(f"  lk link {selected.get('name', '?')} --only calls")
    print(f"  lk link {selected.get('name', '?')} --only storage")
    print(f"  lk link {selected.get('name', '?')} --only reads")
    print(f"  lk link {selected.get('name', '?')} --only writes")
    print(f"  lk link {selected.get('name', '?')} --only imports")
    print(f"  lk link {selected.get('name', '?')} --only assets")
    print()
    if not any((bases, imported_labels, inherited_by, used_by, functions, storage, transient, constants, external_targets, asset_groups, unresolved)):
        print("No declared relationships were found for this contract.")
    _print_inventory_warning(index)


def _render_mapping_view(
    selected: dict[str, Any],
    index: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
    *,
    limit: int,
) -> None:
    """Render a mapping/state variable as a compact declaration/access map."""
    all_edges = index.get("edges") or []
    heading = "MAPPING" if selected.get("kind") == "mapping" else "STATE VARIABLE"
    print(f"{heading}: {selected.get('qualified_name') or selected.get('name', '?')}")
    print()
    print("TYPE")
    print(f"  {selected.get('type') or 'unknown'}")
    if selected.get("mapping_keys"):
        print()
        print("KEY TYPES")
        print("  " + " -> ".join(selected["mapping_keys"]))
    print()
    print("DECLARED")
    print(f"  {_location(selected)}")

    access_edges = [
        edge for edge in all_edges
        if edge.get("to") == selected.get("id")
        and edge.get("kind") in {
            "READS", "WRITES", "DELETES", "MUTATES",
            "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
        }
    ]
    read_edges = [edge for edge in access_edges if edge.get("kind") in {"READS", "TRANSIENT_READS"}]
    write_edges = [edge for edge in access_edges if edge.get("kind") in {"WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES", "TRANSIENT_DELETES"}]

    key_examples = sorted({str(edge.get("access_path")) for edge in access_edges if edge.get("access_path")})
    if key_examples:
        print()
        print("KEY EXAMPLES")
        for example in key_examples[:limit]:
            print(f"  ├── {example}")

    def render_access(heading: str, values: list[dict[str, Any]]) -> None:
        if not values:
            return
        print()
        print(heading)
        seen = set()
        for edge in values:
            function = nodes.get(edge.get("from"), {})
            label = _short_function_label(function) if function else "unresolved function"
            if label in seen:
                continue
            seen.add(label)
            print(f"  ├── {label}")
            if len(seen) >= limit:
                break

    render_access("READ BY", read_edges)
    render_access("WRITTEN BY", write_edges)

    value_type = selected.get("mapping_value_type")
    if value_type:
        struct_nodes = [
            item for item in nodes.values()
            if item.get("kind") == "struct"
            and (item.get("name") == value_type or (item.get("qualified_name") or "").endswith("." + value_type))
            and item.get("contract") == selected.get("contract")
        ]
        if not struct_nodes:
            struct_nodes = [item for item in nodes.values() if item.get("kind") == "struct" and item.get("name") == value_type]
        if struct_nodes:
            struct_node = struct_nodes[0]
            fields = [
                nodes[edge["to"]] for edge in all_edges
                if edge.get("kind") == "DECLARES" and edge.get("from") == struct_node.get("id")
                and edge.get("to") in nodes
            ]
            print()
            print(f"STRUCT: {value_type}")
            for field in fields[:limit]:
                print(f"  ├── {field.get('name', '?')}")
            if len(fields) > limit:
                print(f"  └── ... {len(fields) - limit} more")
    print()
    if selected.get("kind") == "mapping":
        print("NOTE: key expressions are source-level access paths, not computed EVM storage slots.")
    _print_inventory_warning(index)


READ_EDGE_KINDS = {"READS", "TRANSIENT_READS"}
CONSTANT_EDGE_KINDS = {"READS_CONSTANT"}
IMMUTABLE_EDGE_KINDS = {"READS_IMMUTABLE"}
WRITE_EDGE_KINDS = {
    "WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
}
EXECUTION_EDGE_KINDS = {"CALLS", "APPLIES_MODIFIER"}


def _analysis_basis(index: dict[str, Any]) -> str:
    """Describe the evidence actually used for this source index."""
    ast = index.get("ast") or {}
    functions = int(ast.get("functions") or 0)
    if functions:
        return (
            "AST ENRICHMENT IN INDEX "
            f"({functions} matched function(s); edge evidence is labelled in detail views)"
        )
    if not ast.get("available"):
        return "LEXICAL ONLY (no compatible Foundry compiler build-info was available)"
    stale = int(ast.get("stale_units") or 0)
    if stale:
        return f"LEXICAL ONLY ({stale} stale compiler source unit(s) ignored)"
    matched = int(ast.get("matched_units") or 0)
    if not matched:
        return "LEXICAL ONLY (compiler build-info did not match the current source files)"
    return "LEXICAL ONLY (no compiler AST function declarations matched this source inventory)"


def _function_execution_scope(
    selected: dict[str, Any],
    index: dict[str, Any],
    *,
    depth: int,
) -> tuple[dict[str, int], dict[str, list[str]]]:
    """Return functions/modifiers reachable from this entrypoint via resolved local edges."""
    nodes = _node_map(index)
    executable_ids = {
        node_id for node_id, node in nodes.items()
        if node.get("kind") in {"function", "modifier"}
    }
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in index.get("edges") or []:
        if (
            edge.get("kind") in EXECUTION_EDGE_KINDS
            and edge.get("resolution") in {"DIRECT", "INFERRED"}
            and edge.get("from") in executable_ids
            and edge.get("to") in executable_ids
        ):
            outgoing[str(edge["from"])].append(edge)

    root_id = str(selected.get("id") or "")
    levels = {root_id: 0}
    paths = {root_id: [root_id]}
    queue = [root_id]
    while queue:
        current = queue.pop(0)
        current_depth = levels[current]
        if current_depth >= depth:
            continue
        ordered = sorted(
            outgoing.get(current, []),
            key=lambda edge: (
                (edge.get("source") or {}).get("file", ""),
                (edge.get("source") or {}).get("line", 0),
                str(edge.get("to") or ""),
            ),
        )
        for edge in ordered:
            target = str(edge.get("to") or "")
            if target in levels:
                continue
            levels[target] = current_depth + 1
            paths[target] = paths[current] + [target]
            queue.append(target)
    return levels, paths


def _function_scope_edges(
    index: dict[str, Any],
    reachable: dict[str, int],
) -> list[dict[str, Any]]:
    """Use original source edges from reachable functions; omit propagated clones."""
    propagation_evidence = {
        "CALL_GRAPH_PROPAGATION",
        "MODIFIER_EXECUTION_PROPAGATION",
    }
    return [
        edge for edge in (index.get("edges") or [])
        if edge.get("from") in reachable
        and edge.get("evidence") not in propagation_evidence
    ]


def _group_effects(
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    root_id: str,
    paths: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Group source accesses by declaration, retaining counts and source evidence."""
    groups: dict[str, dict[str, Any]] = {}
    for edge in values:
        target_id = str(edge.get("to") or "")
        target = nodes.get(target_id, {})
        key = target_id or str(edge.get("access_path") or edge.get("id") or "unresolved")
        group = groups.setdefault(key, {
            "target": target,
            "edges": [],
            "access_paths": [],
            "helpers": [],
            "call_paths": [],
            "locations": [],
            "direct": 0,
            "helper": 0,
        })
        group["edges"].append(edge)
        access_path = str(edge.get("access_path") or "")
        if access_path and access_path not in group["access_paths"]:
            group["access_paths"].append(access_path)
        source_function = str(edge.get("from") or "")
        if source_function == root_id:
            group["direct"] += 1
        else:
            group["helper"] += 1
            helper = nodes.get(source_function, {})
            helper_label = _short_function_label(helper) if helper else source_function
            if helper_label not in group["helpers"]:
                group["helpers"].append(helper_label)
            call_path = paths.get(source_function, [])
            path_label = " -> ".join(
                _short_function_label(nodes.get(item, {}))
                for item in call_path[1:]
            )
            if path_label and path_label not in group["call_paths"]:
                group["call_paths"].append(path_label)
        location = _location(edge)
        if location not in group["locations"]:
            group["locations"].append(location)

    result = list(groups.values())
    result.sort(key=lambda group: (
        str(group["target"].get("qualified_name") or group["target"].get("name") or ""),
        group["locations"][0] if group["locations"] else "",
    ))
    return result


def _edge_evidence_label(values: list[dict[str, Any]]) -> str:
    evidence = [str(edge.get("evidence") or "") for edge in values]
    has_ast = any(item.startswith("SOLC_AST") for item in evidence)
    has_other = any(item and not item.startswith("SOLC_AST") for item in evidence)
    if has_ast and has_other:
        return "AST + lexical"
    if has_ast:
        return "AST"
    if has_other:
        return "lexical"
    return "unclassified"


def _render_grouped_effects(
    heading: str,
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    root_id: str,
    paths: dict[str, list[str]],
    *,
    limit: int,
) -> int:
    if not values:
        return 0
    groups = _group_effects(values, nodes, root_id, paths)
    access_count = sum(len(group["edges"]) for group in groups)
    print(f"{heading}  ({len(groups)} variable(s) · {access_count} access(es))")
    for group in groups[:limit]:
        target = group["target"]
        label = (
            str(target.get("qualified_name") or target.get("name"))
            if target else str(group["access_paths"][0] if group["access_paths"] else "unresolved storage target")
        )
        detail_counts = []
        if group["direct"]:
            detail_counts.append(f"{group['direct']} direct")
        if group["helper"]:
            detail_counts.append(f"{group['helper']} via helpers")
        suffix = " · ".join(detail_counts) or f"{len(group['edges'])} access(es)"
        evidence_label = _edge_evidence_label(group["edges"])
        print(f"  • {label}  ({suffix})  [{evidence_label}]")
        if group["access_paths"]:
            print("      path: " + " | ".join(group["access_paths"][:3]))
            if len(group["access_paths"]) > 3:
                print(f"      ... {len(group['access_paths']) - 3} more access path(s)")
        if group["helpers"]:
            print("      in:   " + ", ".join(group["helpers"][:4]))
            if len(group["helpers"]) > 4:
                print(f"      ... {len(group['helpers']) - 4} more helper(s)")
        if group["locations"]:
            print("      at:   " + ", ".join(group["locations"][:3]))
            if len(group["locations"]) > 3:
                print(f"      ... {len(group['locations']) - 3} more source location(s)")
    if len(groups) > limit:
        print(f"  ... {len(groups) - limit} more variable(s); increase --limit to expand.")
    print()
    return len(groups)


def _print_wrapped_field(label: str, value: str, *, width: int = 96) -> None:
    prefix = f"{label:<10}"
    wrapped = textwrap.wrap(
        value,
        width=max(40, width),
        initial_indent=prefix,
        subsequent_indent=" " * len(prefix),
        break_long_words=False,
        break_on_hyphens=False,
    )
    for line in wrapped or [prefix.rstrip()]:
        print(line)


def _render_summary_effects(
    heading: str,
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    root_id: str,
    paths: dict[str, list[str]],
    *,
    limit: int = 5,
) -> None:
    """Show unique state targets without forensic paths on the first screen."""
    if not values:
        return
    groups = _group_effects(values, nodes, root_id, paths)
    labels = []
    for group in groups[:limit]:
        target = group["target"]
        label = str(target.get("qualified_name") or target.get("name") or "unresolved target")
        if group["direct"] and group["helper"]:
            label += " [direct + helper]"
        elif group["helper"]:
            label += " [helper]"
        else:
            label += " [direct]"
        labels.append(label)
    if len(groups) > limit:
        labels.append(f"+{len(groups) - limit} more")
    print(f"{heading}  ({len(groups)} unique): " + "; ".join(labels))

def _render_function_header(
    selected: dict[str, Any],
    index: dict[str, Any],
    *,
    detail: str,
) -> None:
    print("LOWKEY // SOURCE TRACE" if detail == "summary" else "LOWKEY // SOURCE LINK")
    contract = str(selected.get("contract") or "")
    name = str(selected.get("name") or "unknown")
    function_name = f"{contract}.{name}" if contract else name
    _print_wrapped_field("FUNCTION", function_name)
    signature = str(selected.get("signature") or "")
    if signature:
        _print_wrapped_field("SIGNATURE", signature.replace(",", ", "))
    print(f"SOURCE    {_location(selected)}")
    if selected.get("provenance"):
        print(f"ORIGIN    {str(selected['provenance']).upper()}")
    visibility = selected.get("visibility") or "unknown"
    mutability = selected.get("mutability") or "unknown"
    print(f"ENTRY     {visibility} · {mutability}")
    _print_wrapped_field("ANALYSIS", _analysis_basis(index))
    print()


def _render_modifiers(
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    root_id: str,
    *,
    limit: int,
) -> None:
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in values:
        key = (str(edge.get("from") or ""), str(edge.get("to") or ""))
        unique.setdefault(key, edge)
    if not unique:
        return
    print(f"MODIFIERS / GUARDS  ({len(unique)} relationship(s))")
    for edge in list(unique.values())[:limit]:
        owner = nodes.get(str(edge.get("from") or ""), {})
        modifier = nodes.get(str(edge.get("to") or ""), {})
        owner_label = "entrypoint" if edge.get("from") == root_id else _short_function_label(owner)
        modifier_label = _symbol_label(modifier) if modifier else str(edge.get("to") or "unresolved modifier")
        print(f"  • {owner_label}  →  {modifier_label}  [{edge.get('resolution', 'UNRESOLVED')}]")
    if len(unique) > limit:
        print(f"  ... {len(unique) - limit} more modifier relationship(s)")
    print()


def _render_external_boundaries(
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    paths: dict[str, list[str]],
    *,
    limit: int,
) -> None:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for edge in values:
        receiver = str(edge.get("receiver") or "external target")
        method = str(edge.get("method") or edge.get("operation") or "call")
        target = str(edge.get("to") or "")
        grouped.setdefault((receiver, method, target), []).append(edge)
    if not grouped:
        return
    print(f"EXTERNAL BOUNDARIES  ({len(grouped)} unique boundary/boundaries)")
    for (receiver, method, target), group in list(grouped.items())[:limit]:
        first = group[0]
        destination = nodes.get(target, {})
        resolution = str(first.get("implementation_resolution") or first.get("resolution") or "UNRESOLVED")
        print(f"  • {receiver}.{method}  [{resolution}]")
        if destination:
            print(f"      declared interface: {_symbol_label(destination)}")
        owners = []
        for edge in group:
            owner_id = str(edge.get("from") or "")
            owner = nodes.get(owner_id, {})
            label = "entrypoint" if not paths.get(owner_id, [owner_id])[1:] else _short_function_label(owner)
            if label not in owners:
                owners.append(label)
        print("      from: " + ", ".join(owners[:4]))
        locations = list(dict.fromkeys(_location(edge) for edge in group))
        if locations:
            print("      at:   " + ", ".join(locations[:3]))
    if len(grouped) > limit:
        print(f"  ... {len(grouped) - limit} more external boundary/boundaries")
    print()


def _render_asset_flows(values: list[dict[str, Any]], *, limit: int) -> None:
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for edge in values:
        key = (
            str(edge.get("asset") or "unknown").upper(),
            str(edge.get("direction") or "unresolved").upper(),
            str(edge.get("status") or "unknown").upper(),
        )
        grouped.setdefault(key, []).append(edge)
    if not grouped:
        return
    print(f"ASSET FLOW / CAPABILITY  ({len(grouped)} distinct path type(s))")
    for (asset, direction, status), group in list(grouped.items())[:limit]:
        print(f"  • {asset} {direction} · {status}  ({len(group)} source site(s))")
        locations = list(dict.fromkeys(_location(edge) for edge in group))
        if locations:
            print("      at: " + ", ".join(locations[:3]))
    if len(grouped) > limit:
        print(f"  ... {len(grouped) - limit} more asset path type(s)")
    print()


def _render_event_and_revert_edges(
    heading: str,
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    *,
    limit: int,
) -> None:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for edge in values:
        target = nodes.get(str(edge.get("to") or ""), {})
        label = _symbol_label(target) if target else str(edge.get("detail") or edge.get("to") or "unknown")
        grouped.setdefault(label, []).append(edge)
    if not grouped:
        return
    total = sum(len(group) for group in grouped.values())
    print(f"{heading}  ({len(grouped)} unique target(s) · {total} source site(s))")
    for label, group in list(grouped.items())[:limit]:
        locations = list(dict.fromkeys(_location(edge) for edge in group))
        print(f"  • {label}  ({len(group)} site(s))")
        if locations:
            print("      at: " + ", ".join(locations[:3]))
    if len(grouped) > limit:
        print(f"  ... {len(grouped) - limit} more target(s)")
    print()


def _render_unresolved_relationships(
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    *,
    limit: int,
) -> None:
    relevant = [
        edge for edge in values
        if edge.get("kind") in {
            "CALLS", "APPLIES_MODIFIER", "EXTERNAL_CALL",
            "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION",
        }
        and (
            edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"}
            or edge.get("implementation_resolution") in {"UNRESOLVED", "AMBIGUOUS"}
        )
    ]
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edge in relevant:
        key = (
            str(edge.get("kind") or ""),
            str(edge.get("to") or ""),
            _location(edge),
            str(edge.get("method") or edge.get("operation") or ""),
        )
        unique.setdefault(key, edge)
    if not unique:
        print("UNRESOLVED TARGETS  none in this function's reachable scope")
        print()
        return
    print(f"UNRESOLVED TARGETS  ({len(unique)} in reachable scope)")
    for edge in list(unique.values())[:limit]:
        target = str(edge.get("to") or "unknown target")
        kind = str(edge.get("kind") or "relationship").replace("_", " ").lower()
        note = str(edge.get("detail") or edge.get("symbol") or "")
        resolution = str(edge.get("implementation_resolution") or edge.get("resolution") or "UNRESOLVED")
        print(f"  • {kind}: {target}  [{resolution}]  {_location(edge)}")
        if note:
            print(f"      {note}")
    if len(unique) > limit:
        print(f"  ... {len(unique) - limit} more unresolved relationship(s)")
    print()


def _render_function_glance(
    *,
    root_id: str,
    root_calls: list[dict[str, Any]],
    helpers: list[str],
    depth: int,
    read_groups: list[dict[str, Any]],
    constant_groups: list[dict[str, Any]],
    immutable_groups: list[dict[str, Any]],
    write_groups: list[dict[str, Any]],
    external_keys: set[tuple[str, str, str]],
    asset_keys: set[tuple[str, str, str]],
    modifiers: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
) -> None:
    """Give both summary and full views the same concise orientation."""
    print("AT A GLANCE")
    print(
        f"  FLOW      {len({str(edge.get('to') or edge.get('id')) for edge in root_calls})} direct call target(s) "
        f"· {len(helpers)} reachable helper/modifier(s) · depth {depth}"
    )
    print(
        f"  STATE     {len(read_groups) + len(constant_groups) + len(immutable_groups)} unique read target(s) "
        f"· {len(write_groups)} unique write target(s)"
    )
    if external_keys or asset_keys:
        print(f"  EXTERNAL  {len(external_keys)} boundary/boundaries · {len(asset_keys)} asset path type(s)")
    root_modifiers = [edge for edge in modifiers if edge.get("from") == root_id]
    guard_names = list(dict.fromkeys(
        _symbol_label(nodes.get(str(edge.get("to") or ""), {})) for edge in root_modifiers
    ))
    if guard_names:
        print("  GUARDS    " + ", ".join(guard_names[:4]))
    print()


def _render_function_view(
    selected: dict[str, Any],
    index: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
    *,
    detail: str,
    depth: int,
    limit: int,
) -> None:
    """Render a scoped function investigation; group repeated state by declaration."""
    root_id = str(selected.get("id") or "")
    reachable, paths = _function_execution_scope(selected, index, depth=depth)
    scoped_edges = _function_scope_edges(index, reachable)
    root_calls = [
        edge for edge in scoped_edges
        if edge.get("from") == root_id and edge.get("kind") == "CALLS"
    ]
    helpers = [item for item in reachable if item != root_id]
    modifiers = [edge for edge in scoped_edges if edge.get("kind") == "APPLIES_MODIFIER"]

    read_values = [edge for edge in scoped_edges if edge.get("kind") in READ_EDGE_KINDS]
    constant_values = [edge for edge in scoped_edges if edge.get("kind") in CONSTANT_EDGE_KINDS]
    immutable_values = [edge for edge in scoped_edges if edge.get("kind") in IMMUTABLE_EDGE_KINDS]
    write_values = [edge for edge in scoped_edges if edge.get("kind") in WRITE_EDGE_KINDS]
    external_values = [edge for edge in scoped_edges if edge.get("kind") == "EXTERNAL_CALL"]
    asset_values = [edge for edge in scoped_edges if edge.get("kind") == "ASSET_FLOW"]
    event_values = [edge for edge in scoped_edges if edge.get("kind") == "EMITS"]
    revert_values = [edge for edge in scoped_edges if edge.get("kind") == "REVERTS"]

    read_groups = _group_effects(read_values, nodes, root_id, paths)
    constant_groups = _group_effects(constant_values, nodes, root_id, paths)
    immutable_groups = _group_effects(immutable_values, nodes, root_id, paths)
    write_groups = _group_effects(write_values, nodes, root_id, paths)
    external_keys = {
        (str(edge.get("receiver") or ""), str(edge.get("method") or edge.get("operation") or ""), str(edge.get("to") or ""))
        for edge in external_values
    }
    asset_keys = {
        (str(edge.get("asset") or "unknown"), str(edge.get("direction") or "unresolved"), str(edge.get("status") or "unknown"))
        for edge in asset_values
    }

    if detail == "summary":
        _render_function_glance(
            root_id=root_id, root_calls=root_calls, helpers=helpers, depth=depth,
            read_groups=read_groups, constant_groups=constant_groups,
            immutable_groups=immutable_groups, write_groups=write_groups,
            external_keys=external_keys, asset_keys=asset_keys,
            modifiers=modifiers, nodes=nodes,
        )
        print("CALL FLOW")
        if root_calls:
            _render_call_tree(
                selected, index.get("edges") or [], nodes,
                depth=min(depth, 2), limit=min(limit, 8),
            )
        else:
            print("  No internal calls were statically identified.")
        print()

        _render_summary_effects("READS", read_values, nodes, root_id, paths)
        _render_summary_effects("CONSTANTS", constant_values, nodes, root_id, paths)
        _render_summary_effects("IMMUTABLES", immutable_values, nodes, root_id, paths)
        _render_summary_effects("WRITES", write_values, nodes, root_id, paths)
        if external_values:
            _render_external_boundaries(external_values, nodes, paths, limit=3)
        if asset_values:
            _render_asset_flows(asset_values, limit=3)
        if event_values:
            event_names = list(dict.fromkeys(
                _symbol_label(nodes.get(str(edge.get("to") or ""), {})) for edge in event_values
            ))
            print(f"EVENTS  ({len(event_names)}): " + ", ".join(event_names[:5]))
        if revert_values:
            revert_names = list(dict.fromkeys(
                str(edge.get("detail") or edge.get("to") or "revert condition") for edge in revert_values
            ))
            print(f"REVERTS ({len(revert_names)}): " + "; ".join(revert_names[:3]))
        print("NEXT")
        label = _symbol_label(selected)
        for view in ("calls", "storage", "external", "all"):
            _print_wrapped_field("  lk", f"link '{label}' --detail {view}")
        print()
        print("EVIDENCE  Static source relationships only; this does not prove execution or success.")
        if _depth_has_more_calls(selected, index.get("edges") or [], depth):
            print(f"SCOPE     Additional resolved call paths exist beyond --depth {depth}.")
        _print_inventory_warning(index)
        return

    if detail == "all":
        _render_function_glance(
            root_id=root_id, root_calls=root_calls, helpers=helpers, depth=depth,
            read_groups=read_groups, constant_groups=constant_groups,
            immutable_groups=immutable_groups, write_groups=write_groups,
            external_keys=external_keys, asset_keys=asset_keys,
            modifiers=modifiers, nodes=nodes,
        )

    if detail in {"calls", "all"}:
        callers = [
            edge for edge in (index.get("edges") or [])
            if edge.get("kind") == "CALLS" and edge.get("to") == root_id
        ]
        if callers:
            _render_edges("CALLED BY", callers[:limit], nodes, reverse=True)
        print("INTERNAL CALLS / CALL FLOW")
        if root_calls:
            _render_call_tree(selected, index.get("edges") or [], nodes, depth=depth, limit=limit)
        else:
            print("  No internal calls were statically identified.")
        print()
        _render_modifiers(modifiers, nodes, root_id, limit=limit)
        if detail == "calls":
            unresolved_calls = [
                edge for edge in scoped_edges
                if edge.get("kind") in {"CALLS", "APPLIES_MODIFIER"}
            ]
            _render_unresolved_relationships(unresolved_calls, nodes, limit=limit)

    if detail in {"storage", "all"}:
        _render_grouped_effects("STORAGE READS", read_values, nodes, root_id, paths, limit=limit)
        _render_grouped_effects("CONSTANT REFERENCES", constant_values, nodes, root_id, paths, limit=limit)
        _render_grouped_effects("IMMUTABLE REFERENCES", immutable_values, nodes, root_id, paths, limit=limit)
        _render_grouped_effects("STORAGE WRITES", write_values, nodes, root_id, paths, limit=limit)
        unresolved_storage = [
            edge for edge in scoped_edges
            if edge.get("kind") in {"UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION"}
        ]
        if unresolved_storage:
            _render_unresolved_relationships(unresolved_storage, nodes, limit=limit)

    if detail in {"external", "all"}:
        _render_external_boundaries(external_values, nodes, paths, limit=limit)
        _render_asset_flows(asset_values, limit=limit)
        _render_event_and_revert_edges("EVENTS", event_values, nodes, limit=limit)
        _render_event_and_revert_edges("REVERT CONDITIONS", revert_values, nodes, limit=limit)
        if detail == "external":
            unresolved_external = [
                edge for edge in scoped_edges
                if edge.get("kind") == "EXTERNAL_CALL"
            ]
            _render_unresolved_relationships(unresolved_external, nodes, limit=limit)

    if detail == "all":
        _render_unresolved_relationships(scoped_edges, nodes, limit=limit)

    print("ANALYSIS LIMITS")
    print("  Relationships are static source findings, not proof of runtime execution, success, or deployed external implementation.")
    print(f"  Scope: entrypoint plus {len(helpers)} resolved local function/modifier target(s), maximum depth {depth}.")
    _print_inventory_warning(index)


def render_link(index: dict[str, Any], target: str, *, only: str | None = None, depth: int | None = None, limit: int = 24, as_json: bool = False, detail: str = "summary") -> int:
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
    if only is not None and selected.get("kind") in {"function", "modifier"}:
        print("OPTION ERROR: --only filters contract relationships; use --detail for function views.")
        return 2
    if detail != "summary" and selected.get("kind") not in {"function", "modifier"}:
        print("DETAIL OPTION: --detail applies to function or modifier targets; use --only for contract views.")
        return 2
    if depth is None:
        # Function investigations should reveal a useful nested call chain by
        # default; contract overviews stay shallow and summarized.
        depth = 3 if selected.get("kind") in {"function", "modifier"} else 1
    nodes = _node_map(index)
    edges = _selected_edges(selected, index.get("edges") or [], only=only, depth=depth)
    function_target = selected.get("kind") in {"function", "modifier"}
    if as_json:
        json_edges = edges
        if function_target:
            reachable, _paths = _function_execution_scope(selected, index, depth=depth)
            json_edges = _function_scope_edges(index, reachable)
        print(json.dumps({
            "target": selected,
            "edges": json_edges[:limit],
            "scope": {
                "kind": "reachable_local_call_and_modifier_graph" if function_target else "selected_relationship_graph",
                "max_depth": depth,
            },
            "inventory": index.get("inventory"),
            "summary": index.get("summary"),
            "parser": index.get("parser"),
            "ast": index.get("ast"),
            "mutation_semantics": index.get("mutation_semantics"),
            "effect_propagation": index.get("effect_propagation"),
        }, indent=2, sort_keys=True))
        return 0

    if function_target:
        _render_function_header(selected, index, detail=detail)
    elif not (selected.get("kind") == "contract" and only is None):
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

    if selected.get("kind") == "contract" and only is None:
        _render_contract_overview(selected, index, nodes, limit=min(limit, 8))
    elif selected.get("kind") == "contract":
        # Explicit filters remain detailed: they are intentional drill-downs.
        declared = [edge for edge in (index.get("edges") or []) if edge.get("kind") == "DECLARES" and edge.get("from") == selected["id"]]
        for title, kinds in (
            ("FUNCTIONS", {"function"}),
            ("STORAGE", {"mapping", "state_variable", "function_pointer"}),
            ("STRUCTURES", {"struct", "struct_field"}),
            ("ENUMS", {"enum", "enum_value"}),
            ("EVENTS / ERRORS", {"event", "custom_error"}),
        ):
            items = [nodes.get(edge["to"], {}) for edge in declared if nodes.get(edge["to"], {}).get("kind") in kinds]
            if items:
                print(title)
                for item in items[:limit]:
                    print(f"  {_symbol_label(item)}  {_location(item)}")
        _render_edges("INHERITS", [edge for edge in edges if edge.get("kind") == "INHERITS" and edge.get("from") == selected["id"]][:limit], nodes)
        _render_edges("IMPORTS", [edge for edge in edges if edge.get("kind") == "IMPORTS"][:limit], nodes)
        related_contracts = {selected.get("name"), *(selected.get("ancestors") or [])}
        related_functions = {
            item["id"] for item in nodes.values()
            if item.get("kind") in {"function", "modifier"} and item.get("contract") in related_contracts
        }
        if only == "writes":
            related_contract_ids = {item["id"] for item in nodes.values() if item.get("kind") == "contract" and item.get("name") in related_contracts}
            constructor_nodes = [
                item for item in nodes.values()
                if item.get("kind") == "function" and item.get("name") == "constructor"
                and item.get("contract") in related_contracts
            ]
            constructor_ids = {item["id"] for item in constructor_nodes}
            initializers = [edge for edge in (index.get("edges") or []) if edge.get("kind") == "INITIALIZES" and (edge.get("from") in related_contract_ids or edge.get("from") in constructor_ids)]
            _render_edges("STATE INITIALIZERS", initializers[:limit], nodes)
            constructor_writes = [
                edge for edge in (index.get("edges") or [])
                if edge.get("from") in constructor_ids
                and edge.get("kind") in {"WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES", "TRANSIENT_DELETES"}
            ]
            _render_edges("CONSTRUCTOR WRITES", constructor_writes[:limit], nodes, reverse=True)
        contract_edges = [edge for edge in index.get("edges") or [] if edge.get("from") in related_functions]
        if only in (None, "calls"):
            _render_edges("INTERNAL CALLS", [edge for edge in contract_edges if edge.get("kind") == "CALLS"][:limit], nodes)
        if only in (None, "storage", "reads"):
            _render_edges("STORAGE READS", [edge for edge in contract_edges if edge.get("kind") in {"READS", "TRANSIENT_READS"}][:limit], nodes)
        if only in (None, "storage", "writes"):
            _render_edges("STATE MUTATIONS / WRITES", [edge for edge in contract_edges if edge.get("kind") in {"WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES", "TRANSIENT_DELETES"}][:limit], nodes)
        if only in (None, "assets"):
            _render_edges("EXTERNAL INTERACTIONS / ASSET PATHS", [edge for edge in contract_edges if edge.get("kind") in {"EXTERNAL_CALL", "ASSET_FLOW"}][:limit], nodes)
    elif function_target:
        _render_function_view(
            selected, index, nodes, detail=detail, depth=depth, limit=limit,
        )
    elif selected.get("kind") == "mapping":
        _render_mapping_view(selected, index, nodes, limit=min(limit, 24))
    elif selected.get("kind") in {"state_variable", "function_pointer"}:
        _render_mapping_view(selected, index, nodes, limit=min(limit, 24))
    else:
        outgoing, incoming = _edge_groups(selected, edges, nodes)
        for kind, values in sorted(outgoing.items()):
            _render_edges(kind.replace("_", " "), values[:limit], nodes)
        for kind, values in sorted(incoming.items()):
            _render_edges("REFERENCED BY " + kind.replace("_", " "), values[:limit], nodes, reverse=True)

    if not (selected.get("kind") == "contract" and only is None) and not function_target:
        print()
        print(f"GRAPH     {index.get('summary', {}).get('relationships', 0)} relationship(s) indexed across {index.get('summary', {}).get('files', 0)} Solidity file(s)")
        if selected.get("kind") in {"contract", "function"} and _depth_has_more_calls(selected, index.get("edges") or [], depth):
            print(f"DEPTH     Additional nested call relationships exist beyond --depth {depth}; increase --depth to follow them.")
        print("LIMITS    Static source links do not prove execution, success, storage-slot identity, or an external implementation.")
        _print_inventory_warning(index)
        propagation = index.get("effect_propagation") or {}
        if propagation.get("truncated_frontiers"):
            print(
                "EFFECTS   Helper/modifier propagation reached the "
                f"depth cap ({propagation.get('max_depth', '?')}) at "
                f"{propagation['truncated_frontiers']} frontier(s); deeper effects may be missing."
            )
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
        description=(
            "Browse a Solidity project or inspect one contract, function, modifier, "
            "mapping, or state variable. The default screens stay compact; detail is opt-in."
        ),
        epilog="""QUICK START
  lk link                                      Browse the source map (24 per page).
  lk link Vault                                See the contract overview.
  lk link Vault.positions                      Inspect a mapping and its readers/writers.
  lk link ContractName.mappingName              Inspect mapping keys, readers and writers.
  lk trace source Vault.increasePosition       Trace source calls and state touchpoints.

SOURCE MAP OPTIONS  (use without TARGET)
  --root DIR       Scan another project. Example: lk link --root ../protocol
  --search TEXT    Find by declaration name or file path. Example: lk link --search Vault
  --type KIND      Keep contract, interface, or library declarations only.
                   Example: lk link --type interface
  --page N         Move through the 24-item pages. Example: lk link --page 2
  --all            Show every matching declaration in one compact list.
                   Use it when you need the complete filtered inventory.
                   Example: lk link --all

TARGET OPTIONS
  --only FILTER    Narrow a contract's relationships:
                   calls = internal calls; storage = reads and writes;
                   reads = reads only; writes = mutations and initializers;
                   imports = imports and inheritance; assets = external/asset paths.
                   Example: lk link Vault --only writes
  --depth N        Bound source-call traversal (1-10). Function default is 3;
                   contract default is 1. Increase it to follow deeper helpers.
                   Example: lk link Vault --depth 3

FUNCTION / MODIFIER OPTIONS
  --detail VIEW    summary (default), calls, storage, external, or all.
                   Use calls for caller/callee flow, storage for state effects,
                   external for boundaries/events/assets, or all for the full view.
                   Example: lk trace source Vault.increasePosition --detail storage
  --limit N        Cap items shown in each detail section (1-500; default: 24).
                   Increase it when a section reports omitted entries.
                   Example: lk link Vault --only writes --limit 60

OUTPUT
  --json           Emit structured JSON for scripts and downstream tooling.
                   Example: lk link --search Vault --json
  -h, --h, --help  Show this reference.

COMMON INVESTIGATION SEQUENCE
  lk link --search Position
  lk link PositionManager
  lk link PositionManager --only writes --depth 3
  lk trace source PositionManager.increasePosition --detail all --depth 4

RULES
  --search, --type, --page and --all are source-map options and cannot be
  combined with TARGET. --detail applies only to functions and modifiers.
  Source links are static analysis: they do not prove execution, success,
  storage-slot identity, or the implementation behind an external address.
  Incomplete source coverage is reported; unresolved relationships stay visible.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    parser.add_argument(
        "target", nargs="?",
        help="contract, function, modifier, mapping, or state variable; omit to browse the source map",
    )
    parser.add_argument(
        "--root", metavar="DIR", default=".",
        help="project root to scan (default: current directory); use outside the project root",
    )
    parser.add_argument(
        "--depth", metavar="N", type=int, default=None,
        help="maximum call traversal depth, 1-10 (function default 3; contract default 1)",
    )
    parser.add_argument(
        "--only", metavar="FILTER", choices=sorted(ONLY_KINDS),
        help="contract relationship filter: calls, storage, reads, writes, imports, or assets",
    )
    parser.add_argument(
        "--detail", metavar="VIEW",
        choices=("summary", "calls", "storage", "external", "all"), default="summary",
        help="function view: summary (default), calls, storage, external, or all",
    )
    parser.add_argument(
        "--limit", metavar="N", type=int, default=24,
        help="maximum items per detail section, 1-500 (default: 24)",
    )
    parser.add_argument(
        "--search", metavar="TEXT",
        help="source-map filter by declaration name or source path (requires no TARGET)",
    )
    parser.add_argument(
        "--type", dest="declaration_type", metavar="KIND",
        choices=("contract", "interface", "library"),
        help="source-map filter by declaration kind (requires no TARGET)",
    )
    page_group = parser.add_mutually_exclusive_group()
    page_group.add_argument(
        "--page", metavar="N", type=int,
        help="source-map page number (requires no TARGET)",
    )
    page_group.add_argument(
        "--all", dest="show_all", action="store_true",
        help="show all matching source-map declarations (requires no TARGET)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="emit machine-readable JSON instead of terminal formatting",
    )
    parser.add_argument("-h", "--h", "--help", action="help", help="show this help")
    return parser

def render_project_index(
    index: dict[str, Any], *, limit: int = 24, page: int = 1,
    search: str | None = None, declaration_type: str | None = None,
    show_all: bool = False, as_json: bool = False,
) -> int:
    """Browse a searchable, paginated source map without dumping the whole index."""
    nodes = _node_map(index)
    all_nodes = list(nodes.values())
    contracts = sorted(
        (item for item in all_nodes if item.get("kind") == "contract"),
        key=lambda item: (str(item.get("file") or ""), int(item.get("line") or 0), str(item.get("name") or "")),
    )
    entries = []
    for contract in contracts:
        name = str(contract.get("name") or "?")
        declared = [
            item for item in all_nodes
            if item.get("contract") == name and item.get("file") == contract.get("file")
        ]
        function_count = sum(item.get("kind") in {"function", "modifier"} for item in declared)
        storage_count = sum(
            item.get("kind") in {"mapping", "state_variable", "function_pointer"}
            and item.get("storage_class") not in {"constant", "immutable", "transient"}
            for item in declared
        )
        declaration_kind = str(contract.get("declaration_kind") or "contract").replace("_", " ")
        entries.append({
            "name": name, "declaration_kind": declaration_kind, "source": _location(contract),
            "functions": function_count, "storage_items": storage_count,
            "origin": contract.get("provenance") or "unknown",
        })

    needle = str(search or "").strip().casefold()
    filtered = [
        entry for entry in entries
        if (not needle or needle in entry["name"].casefold() or needle in entry["source"].casefold())
        and (not declaration_type or declaration_type.casefold() in entry["declaration_kind"].casefold())
    ]
    total = len(filtered)
    pages = max(1, (total + limit - 1) // limit)
    if show_all:
        limit, page, pages = max(1, total), 1, 1
    if page < 1 or page > pages:
        print(f"PAGE OUT OF RANGE: choose a page between 1 and {pages}.")
        return 2
    visible = filtered[(page - 1) * limit:(page - 1) * limit + limit]
    summary = index.get("summary") or {}

    if as_json:
        print(json.dumps({
            "contracts": visible, "total_contracts": len(entries), "filtered_contracts": total,
            "shown": len(visible), "page": page, "pages": pages,
            "search": search, "type": declaration_type,
            "summary": {"files": summary.get("files", 0), "functions": summary.get("functions", 0)},
            "inventory": index.get("inventory"),
        }, indent=2, sort_keys=True))
        return 0

    print("LOWKEY // SOURCE MAP")
    print(f"{summary.get('files', 0)} Solidity files · {len(entries)} declarations · {summary.get('functions', 0)} functions")
    print("AVAILABLE CONTRACTS")
    filters = []
    if needle:
        filters.append(f"search: {search}")
    if declaration_type:
        filters.append(f"type: {declaration_type}")
    print("FILTER  " + (" · ".join(filters) if filters else "all declarations"))
    if total == 0:
        print("No declarations matched. Try a shorter name or remove a filter.")
        print()
        print("Examples: lk link --search Vault  |  lk link --type interface")
        _print_inventory_warning(index)
        return 0

    print(f"PAGE    {page}/{pages} · showing {len(visible)} of {total} matching declarations")
    print()
    current_folder = None
    for entry in visible:
        source_path, _, line = entry["source"].rpartition(":")
        folder = str(Path(source_path).parent).replace("\\", "/")
        if folder != current_folder:
            current_folder = folder
            print(f"{folder}/")
        file_name = Path(source_path).name
        label = f"{entry['name']} ({entry['declaration_kind']})"
        print(f"  {label:<42} {entry['functions']:>3} fn  {entry['storage_items']:>3} state  {file_name}:{line}")

    filter_args = []
    if search:
        filter_args.extend(["--search", shlex.quote(str(search))])
    if declaration_type:
        filter_args.extend(["--type", str(declaration_type)])
    suffix = (" " + " ".join(filter_args)) if filter_args else ""
    print()
    if page < pages:
        print(f"NEXT PAGE   lk link --page {page + 1}{suffix}")
    if page > 1:
        print(f"PREVIOUS    lk link --page {page - 1}{suffix}")
    if total > len(visible):
        print(f"SHOW ALL    lk link --all{suffix}")
    print("EXPLORE")
    if not needle:
        print("  FIND      lk link --search Vault")
    if not declaration_type:
        print("  FILTER    lk link --type interface")
    print("  CONTRACT  lk link ContractName")
    print("  FUNCTION  lk trace source ContractName.functionName")
    print("  MAPPING   lk link ContractName.mappingName")
    print()
    print("EVIDENCE    Static source relationships; not runtime execution.")
    _print_inventory_warning(index)
    return 0


def run_project_index_args(args: argparse.Namespace) -> int:
    try:
        index = build_source_index(args.root)
    except (SourceIndexError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return render_project_index(
        index, limit=args.limit, page=args.page or 1, search=args.search,
        declaration_type=args.declaration_type, show_all=args.show_all, as_json=args.json,
    )


def run_link(argv: list[str]) -> int:
    parser = _link_parser()
    args = parser.parse_args(argv)
    if args.depth is not None and (args.depth < 1 or args.depth > 10):
        parser.error("--depth must be between 1 and 10")
    if args.limit < 1 or args.limit > 500:
        parser.error("--limit must be between 1 and 500")
    if not args.target:
        if args.depth is not None or args.only is not None or args.detail != "summary":
            parser.error("--depth, --only, and --detail require a target; run 'lk link' to browse")
        if args.page is not None and args.page < 1:
            parser.error("--page must be at least 1")
        return run_project_index_args(args)
    if args.page is not None or args.show_all or args.search or args.declaration_type:
        parser.error("--page, --all, --search, and --type are source-map options; omit TARGET")
    if args.detail != "summary" and args.only is not None:
        parser.error("--detail is for function views; use --only for contract filters")
    try:
        index = build_source_index(args.root)
    except (SourceIndexError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return render_link(
        index=index, target=args.target, only=args.only, depth=args.depth,
        limit=args.limit, as_json=args.json, detail=args.detail,
    )



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
        print("Usage: lk link [TARGET] [--detail summary|calls|storage|external|all]")
        print("       lk link [--search TEXT] [--type contract|interface|library] [--page N|--all]")
        print("       lk trace source TARGET [--detail calls|storage|external|all]")
        print("       lk fn --flow in|out|both --asset eth|erc20|all")
        return 0 if values else 2
    command, rest = values[0], values[1:]
    if command == "link":
        return run_link(rest)
    if command == "trace" and rest and rest[0] == "source":
        return run_link(rest[1:])
    if command == "flow":
        return run_flow(rest)
    print(f"Unknown source-relationship command: {command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
