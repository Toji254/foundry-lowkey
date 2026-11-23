#!/usr/bin/env python3
"""CLI for Lowkey's shared static source relationship index."""
from __future__ import annotations

import argparse
import json
import shlex
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
                label = f"{resolution} TARGET {target_id}"
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


def _render_function_summary(
    selected: dict[str, Any], index: dict[str, Any], edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]], *, depth: int, limit: int,
) -> None:
    """Render the first-screen function investigation; keep full evidence opt-in."""
    all_edges = index.get("edges") or []
    direct = [edge for edge in all_edges if edge.get("from") == selected.get("id")]
    read_kinds = {"READS", "READS_CONSTANT", "READS_IMMUTABLE", "TRANSIENT_READS"}
    write_kinds = {"WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES", "TRANSIENT_DELETES", "INITIALIZES"}
    calls = [edge for edge in direct if edge.get("kind") == "CALLS"]
    external = [edge for edge in direct if edge.get("kind") == "EXTERNAL_CALL"]
    modifiers = [edge for edge in direct if edge.get("kind") == "APPLIES_MODIFIER"]
    reads = [edge for edge in direct if edge.get("kind") in read_kinds]
    writes = [edge for edge in direct if edge.get("kind") in write_kinds]
    emits = [edge for edge in direct if edge.get("kind") == "EMITS"]
    asset_flows = [edge for edge in direct if edge.get("kind") == "ASSET_FLOW"]
    unresolved = [
        edge for edge in direct
        if edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"}
        or edge.get("implementation_resolution") in {"UNRESOLVED", "AMBIGUOUS"}
        or edge.get("kind") in {"UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION"}
    ]
    propagated = [edge for edge in edges if selected.get("id") in (edge.get("via") or [])]
    helper_reads = sum(edge.get("kind") in read_kinds for edge in propagated)
    helper_writes = sum(edge.get("kind") in write_kinds for edge in propagated)

    print("AT A GLANCE")
    print(f"  Internal calls       {len(calls)}")
    print(f"  External boundaries  {len(external)}")
    print(f"  State reads          {len(reads)}")
    print(f"  State writes         {len(writes)}")
    print(f"  Events emitted       {len(emits)}")
    print(f"  Modifiers            {len(modifiers)}")
    if helper_reads or helper_writes:
        print(f"  Helper effects       {helper_reads} reads · {helper_writes} writes (within depth {depth})")
    if asset_flows:
        potential = sorted({
            f"{str(edge.get('asset') or 'unknown').upper()} {str(edge.get('direction') or 'unresolved').upper()}"
            for edge in asset_flows
        })
        print("  Asset paths          " + ", ".join(potential[:3]))
    if unresolved:
        print(f"  Unresolved targets   {len(unresolved)} (inspect before relying on the path)")
    print()

    if calls:
        print(f"CALL FLOW  (up to depth {min(depth, 2)}; first {min(limit, 8)} links)")
        _render_call_tree(selected, all_edges, nodes, depth=1, limit=min(limit, 4))
    else:
        print("CALL FLOW")
        print("  No internal calls were statically identified.")
    print()

    def distinct_paths(values: list[dict[str, Any]]) -> list[str]:
        result: list[str] = []
        for edge in values:
            label = str(edge.get("access_path") or "")
            if not label:
                target = nodes.get(str(edge.get("to") or ""), {})
                label = str(target.get("qualified_name") or target.get("name") or "")
            if label and label not in result:
                result.append(label)
        return result

    read_paths = distinct_paths(reads)
    write_paths = distinct_paths(writes)
    if read_paths or write_paths:
        print("STATE TOUCHPOINTS  (direct effects in this function)")
        for heading, paths, total in (("Reads", read_paths, len(reads)), ("Writes", write_paths, len(writes))):
            if not paths:
                continue
            print(f"  {heading} ({total} access(es))")
            for path in paths[:4]:
                print(f"    - {path}")
            if len(paths) > 4:
                print(f"    - ... {len(paths) - 4} more distinct item(s)")
        print()

    if external:
        print("EXTERNAL BOUNDARIES")
        for edge in external[:4]:
            receiver = str(edge.get("receiver") or "external target")
            method = str(edge.get("method") or edge.get("operation") or "call")
            resolution = str(edge.get("implementation_resolution") or edge.get("resolution") or "UNRESOLVED")
            print(f"  {receiver}.{method}  [{resolution}]  {_location(edge)}")
        if len(external) > 4:
            print(f"  ... {len(external) - 4} more boundary/boundaries")
        print()

    if emits:
        event_names = []
        for edge in emits:
            label = _symbol_label(nodes.get(str(edge.get("to") or ""), {}))
            if label not in event_names:
                event_names.append(label)
        print("EVENTS")
        for label in event_names[:4]:
            print(f"  - {label}")
        print()

    label = _symbol_label(selected)
    print("DRILL DOWN")
    print("  OPTIONS    --detail calls · --detail storage · --detail external · --detail all")
    print(f"  EXAMPLE    lk trace source '{label}' --detail all --depth {min(10, max(depth + 1, 4))}")
    print()
    print("EVIDENCE  Static source analysis only; this does not prove execution or success.")
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
    if detail != "summary" and selected.get("kind") not in {"function", "modifier"}:
        print("DETAIL OPTION: --detail applies to function or modifier targets; use --only for contract views.")
        return 2
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
            "effect_propagation": index.get("effect_propagation"),
        }, indent=2, sort_keys=True))
        return 0

    compact_function = selected.get("kind") in {"function", "modifier"} and detail == "summary" and only is None
    if compact_function:
        print("LOWKEY // SOURCE TRACE")
        print(f"TARGET    {_symbol_label(selected)}")
        print(f"SOURCE    {_location(selected)}")
        if selected.get("provenance"):
            print(f"ORIGIN    {str(selected['provenance']).upper()}")
        visibility = selected.get("visibility")
        mutability = selected.get("mutability")
        if visibility or mutability:
            print(f"ENTRY     {visibility or 'unknown'} · {mutability or 'unknown'}")
        modifiers = [
            edge for edge in (index.get("edges") or [])
            if edge.get("kind") == "APPLIES_MODIFIER" and edge.get("from") == selected.get("id")
        ]
        if modifiers:
            names = [_symbol_label(nodes.get(str(edge.get("to") or ""), {})) for edge in modifiers[:4]]
            print("GUARDS    " + ", ".join(names))
        ast_report = index.get("ast") or {}
        ast_values = [int(ast_report.get(key) or 0) for key in ("functions", "call_edges", "modifier_edges", "storage_edges")]
        parser_name = str(index.get("parser") or "unknown").upper()
        method = f"{parser_name} source scan"
        method += " · AST enrichment unavailable" if not any(ast_values) else " + AST enrichment"
        print(f"METHOD    {method}")
        print()
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
    elif selected.get("kind") in {"function", "modifier"}:
        if detail == "summary" and only is None:
            _render_function_summary(selected, index, edges, nodes, depth=depth, limit=min(limit, 12))
        else:
            active_detail = "all" if detail == "summary" else detail
            group_map = [
                ("CALLED BY", "CALLS", "incoming", "calls"),
                ("CALLS", "CALLS", "outgoing", "calls"),
                ("EXTERNAL CALLS", "EXTERNAL_CALL", "outgoing", "external"),
                ("MODIFIERS", "APPLIES_MODIFIER", "outgoing", "calls"),
                ("APPLIED TO", "APPLIES_MODIFIER", "incoming", "calls"),
                ("OVERRIDES", "OVERRIDES", "outgoing", "calls"),
                ("OVERRIDDEN BY", "OVERRIDES", "incoming", "calls"),
                ("STORAGE READS", "READS", "outgoing", "storage"),
                ("CONSTANT REFERENCES", "READS_CONSTANT", "outgoing", "storage"),
                ("IMMUTABLE REFERENCES", "READS_IMMUTABLE", "outgoing", "storage"),
                ("STORAGE WRITES", "WRITES", "outgoing", "storage"),
                ("DELETES", "DELETES", "outgoing", "storage"),
                ("TRANSIENT WRITES", "TRANSIENT_WRITES", "outgoing", "storage"),
                ("TRANSIENT DELETES", "TRANSIENT_DELETES", "outgoing", "storage"),
                ("TRANSIENT READS", "TRANSIENT_READS", "outgoing", "storage"),
                ("UNRESOLVED MUTATIONS", "UNRESOLVED_MUTATION", "outgoing", "storage"),
                ("INITIALIZES", "INITIALIZES", "outgoing", "storage"),
                ("EMITS", "EMITS", "outgoing", "external"),
                ("REVERTS", "REVERTS", "outgoing", "external"),
                ("STORAGE ALIASES", "ALIASES_STORAGE", "outgoing", "storage"),
                ("UNRESOLVED ASSEMBLY STORAGE", "UNRESOLVED_STORAGE", "outgoing", "storage"),
                ("ASSET FLOW / CAPABILITY", "ASSET_FLOW", "outgoing", "external"),
            ]
            for heading, kind, direction, category in group_map:
                if active_detail != "all" and category != active_detail:
                    continue
                values = [
                    edge for edge in edges if edge.get("kind") == kind
                    and ((direction == "outgoing" and edge.get("from") == selected["id"])
                         or (direction == "incoming" and edge.get("to") == selected["id"]))
                ]
                _render_edges(heading, values[:limit], nodes, reverse=(direction == "incoming"))
            if active_detail in {"calls", "all"}:
                _render_call_tree(selected, index.get("edges") or [], nodes, depth=depth, limit=limit)
            if active_detail == "all":
                unresolved = [edge for edge in edges if edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"}]
                _render_edges("UNRESOLVED / AMBIGUOUS TARGETS", unresolved[:limit], nodes)
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

    if not (selected.get("kind") == "contract" and only is None) and not compact_function:
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
        description="Explore Solidity declarations, relationships, and source-level effects.",
        epilog="""Examples:
  lk link                              Browse the source map (24 entries per page).
  lk link --search Vault               Find matching contracts and files.
  lk link --type interface             Show interfaces only.
  lk link --page 2                     Continue through the source map.
  lk link --all                        Print every declaration in a compact list.
  lk link Vault                        Show a compact contract overview.
  lk trace source Vault.increasePosition
  lk trace source Vault.increasePosition --detail storage
  lk trace source Vault.increasePosition --detail all --depth 4

Use --detail calls|storage|external|all to expand a function investigation.
Static analysis only: source relationships do not prove runtime execution.""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    parser.add_argument("target", nargs="?", help="contract, function, mapping, or state variable; omit to browse the source map")
    parser.add_argument("--root", default=".")
    parser.add_argument("--depth", type=int, default=None)
    parser.add_argument("--only", choices=sorted(ONLY_KINDS))
    parser.add_argument("--detail", choices=("summary", "calls", "storage", "external", "all"), default="summary",
                        help="function view: summary (default), calls, storage, external, or all")
    parser.add_argument("--limit", type=int, default=24, help="maximum items per detail section (default: 24)")
    parser.add_argument("--search", help="filter the source map by declaration name or file path")
    parser.add_argument("--type", dest="declaration_type", choices=("contract", "interface", "library"),
                        help="filter the source map by declaration kind")
    page_group = parser.add_mutually_exclusive_group()
    page_group.add_argument("--page", type=int, help="source-map page number")
    page_group.add_argument("--all", dest="show_all", action="store_true",
                            help="show all matching source-map entries")
    parser.add_argument("--json", action="store_true")
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
    if not needle:
        print("FIND        lk link --search Vault")
    if not declaration_type:
        print("FILTER      lk link --type interface")
    print("OPEN        lk link ContractName")
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
