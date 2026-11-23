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


def _function_scope_edges(
    node: dict[str, Any],
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    *,
    depth: int,
) -> list[dict[str, Any]]:
    """Return only relationships belonging to the selected function's execution scope.

    Calls are traversed from caller to callee. Incoming callers are retained only
    for the selected entrypoint; they are never used to expand the investigation.
    Modifiers are execution edges and are traversed in the same direction.
    """
    root_id = str(node.get("id") or "")
    reachable = {root_id}
    queue: list[tuple[str, int]] = [(root_id, 0)]
    executable_kinds = {"CALLS", "APPLIES_MODIFIER"}

    while queue:
        current, level = queue.pop(0)
        if level >= max(1, depth):
            continue
        for edge in edges:
            if edge.get("from") != current or edge.get("kind") not in executable_kinds:
                continue
            if edge.get("resolution") not in {"DIRECT", "INFERRED"}:
                continue
            target_id = str(edge.get("to") or "")
            target = nodes.get(target_id)
            if not target or target.get("kind") not in {"function", "modifier"}:
                continue
            if target_id in reachable:
                continue
            reachable.add(target_id)
            queue.append((target_id, level + 1))

    selected: dict[str, dict[str, Any]] = {}
    for edge in edges:
        if edge.get("from") in reachable:
            selected[str(edge.get("id") or id(edge))] = edge
        elif (
            edge.get("to") == root_id
            and edge.get("kind") in {"CALLS", "APPLIES_MODIFIER", "OVERRIDES"}
        ):
            # Show direct callers/decorators of the selected function without
            # pulling their other calls, storage effects, or unresolved targets.
            selected[str(edge.get("id") or id(edge))] = edge

    return sorted(selected.values(), key=lambda item: (
        item.get("source", {}).get("file", ""),
        item.get("source", {}).get("line", 0),
        item.get("source", {}).get("column", 0),
        item.get("kind", ""),
        item.get("to", ""),
    ))


def _selected_edges(
    node: dict[str, Any],
    edges: list[dict[str, Any]],
    *,
    only: str | None,
    depth: int,
    nodes: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if node.get("kind") in {"function", "modifier"}:
        scoped = _function_scope_edges(node, edges, nodes or {}, depth=depth)
        allowed = ONLY_KINDS.get(only) if only else None
        if allowed is not None:
            scoped = [
                edge for edge in scoped
                if edge.get("kind") in allowed
                or (edge.get("to") == node.get("id") and edge.get("kind") in {"CALLS", "APPLIES_MODIFIER"})
            ]
        return scoped

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


def _function_analysis_label(index: dict[str, Any]) -> str:
    """Describe the evidence actually available for this source index."""
    report = index.get("ast") or {}
    matched_functions = int(report.get("functions") or 0)
    if matched_functions:
        return f"PROJECT AST AVAILABLE · {matched_functions} function(s) matched; target coverage not asserted"
    build_info_files = int(report.get("build_info_files") or 0)
    if not report.get("available") or build_info_files == 0:
        return "LEXICAL ONLY · no Foundry build-info found"
    if int(report.get("stale_units") or 0):
        return "LEXICAL ONLY · build-info source did not match current files"
    return "LEXICAL ONLY · no compiler AST declarations matched"


def _render_function_header(
    selected: dict[str, Any], index: dict[str, Any],
    nodes: dict[str, dict[str, Any]], *, depth: int,
) -> None:
    """Render a compact and truthful header shared by summary and detail views."""
    print("LOWKEY // SOURCE TRACE")
    contract = str(selected.get("contract") or "")
    function_name = str(selected.get("name") or _symbol_label(selected))
    concise_target = f"{contract}.{function_name}" if contract else function_name
    print(f"TARGET    {concise_target}")
    if selected.get("signature"):
        print(f"SIGNATURE {selected['signature']}")
    print(f"SOURCE    {_location(selected)}")
    if selected.get("provenance"):
        print(f"ORIGIN    {str(selected['provenance']).upper()}")
    visibility = selected.get("visibility")
    mutability = selected.get("mutability")
    if visibility or mutability:
        print(f"ENTRY     {visibility or 'unknown'} · {mutability or 'unknown'}")

    modifiers = [
        edge for edge in (index.get("edges") or [])
        if edge.get("kind") == "APPLIES_MODIFIER"
        and edge.get("from") == selected.get("id")
    ]
    guard_names = []
    for edge in modifiers:
        label = _symbol_label(nodes.get(str(edge.get("to") or ""), {}))
        if label not in guard_names:
            guard_names.append(label)
    if guard_names:
        print("GUARDS    " + ", ".join(guard_names[:4]))
        if len(guard_names) > 4:
            print(f"          ... {len(guard_names) - 4} more")

    print(f"ANALYSIS  {_function_analysis_label(index)}")
    print(f"SCOPE     entrypoint + resolved calls/modifiers · depth {depth}; callers are context only")
    print()


def _effect_groups(
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group every access to the same declaration into one auditor-readable row."""
    grouped: dict[str, dict[str, Any]] = {}
    seen_sites: set[tuple[str, str, str, int, int, str]] = set()
    for edge in values:
        target_id = str(edge.get("to") or "")
        kind = str(edge.get("kind") or "UNKNOWN")
        source = edge.get("source") or {}
        access_path = str(edge.get("access_path") or "")
        site = (
            kind, target_id, str(source.get("file") or ""),
            int(source.get("line") or 0), int(source.get("column") or 0),
            access_path,
        )
        if site in seen_sites:
            continue
        seen_sites.add(site)
        key = target_id or access_path or str(edge.get("id") or "unknown")
        group = grouped.setdefault(key, {
            "kinds": set(),
            "target": nodes.get(target_id, {}),
            "label": "",
            "access_paths": [],
            "locations": [],
            "resolutions": set(),
            "accesses": 0,
        })
        group["kinds"].add(kind)
        group["accesses"] += 1
        if access_path and access_path not in group["access_paths"]:
            group["access_paths"].append(access_path)
        location = _location(edge)
        if location not in group["locations"]:
            group["locations"].append(location)
        group["resolutions"].add(str(edge.get("resolution") or "UNKNOWN"))
        group["label"] = _symbol_label(group["target"]) if group["target"] else (
            access_path or target_id or "unresolved state reference"
        )

    return sorted(grouped.values(), key=lambda item: item.get("label", ""))


_EFFECT_OPERATION_LABELS = {
    "READS": "READ",
    "READS_CONSTANT": "CONSTANT READ",
    "READS_IMMUTABLE": "IMMUTABLE READ",
    "WRITES": "WRITE",
    "DELETES": "DELETE",
    "MUTATES": "MUTATE",
    "TRANSIENT_READS": "TRANSIENT READ",
    "TRANSIENT_WRITES": "TRANSIENT WRITE",
    "TRANSIENT_DELETES": "TRANSIENT DELETE",
    "INITIALIZES": "INITIALIZE",
    "ALIASES_STORAGE": "STORAGE ALIAS",
    "UNRESOLVED_STORAGE": "UNRESOLVED SLOT ACCESS",
    "UNRESOLVED_MUTATION": "UNRESOLVED MUTATION",
}


def _render_grouped_effects(
    heading: str,
    values: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    *,
    limit: int,
) -> None:
    if not values:
        return
    groups = _effect_groups(values, nodes)
    accesses = sum(item["accesses"] for item in groups)
    print(f"{heading}  ({len(groups)} state item(s) · {accesses} access(es))")
    for group in groups[:limit]:
        operations = sorted({
            _EFFECT_OPERATION_LABELS.get(kind, kind.replace("_", " "))
            for kind in group["kinds"]
        })
        parts = [f"{group['label']} · {' / '.join(operations)} · {group['accesses']} access(es)"]
        paths = group["access_paths"][:3]
        locations = group["locations"][:3]
        if paths:
            parts.append("paths " + ", ".join(paths))
        if locations:
            parts.append("at " + ", ".join(locations))
        resolutions = group["resolutions"]
        if "UNRESOLVED" in resolutions or "AMBIGUOUS" in resolutions:
            status = "INCLUDES UNRESOLVED"
        elif "INFERRED" in resolutions and "DIRECT" in resolutions:
            status = "MIXED EVIDENCE"
        elif "INFERRED" in resolutions:
            status = "INFERRED"
        else:
            status = "DIRECT"
        parts.append(status)
        if len(group["access_paths"]) > len(paths):
            parts.append(f"+{len(group['access_paths']) - len(paths)} more paths")
        if len(group["locations"]) > len(locations):
            parts.append(f"+{len(group['locations']) - len(locations)} more locations")
        print(textwrap.fill(
            " · ".join(parts), width=112,
            initial_indent="  ", subsequent_indent="    ",
        ))
    if len(groups) > limit:
        print(f"  ... {len(groups) - limit} more state item(s)")
    print()



def _function_scope_ids(
    selected: dict[str, Any],
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
) -> set[str]:
    """Resolve the forward-only function/modifier execution scope in a scoped edge set."""
    root_id = str(selected.get("id") or "")
    result = {root_id}
    queue = [root_id]
    while queue:
        current = queue.pop(0)
        for edge in edges:
            if (
                edge.get("from") != current
                or edge.get("kind") not in {"CALLS", "APPLIES_MODIFIER"}
                or edge.get("resolution") not in {"DIRECT", "INFERRED"}
            ):
                continue
            target_id = str(edge.get("to") or "")
            target = nodes.get(target_id)
            if (
                target_id and target_id not in result and target
                and target.get("kind") in {"function", "modifier"}
            ):
                result.add(target_id)
                queue.append(target_id)
    return result


def _render_function_summary(
    selected: dict[str, Any], index: dict[str, Any], edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]], *, depth: int, limit: int,
) -> None:
    """Render the first screen as a concise audit map, not a relationship dump."""
    selected_id = str(selected.get("id") or "")
    function_ids = _function_scope_ids(selected, edges, nodes)
    direct = [
        edge for edge in edges
        if edge.get("from") == selected_id and not edge.get("via")
    ]
    calls = [edge for edge in direct if edge.get("kind") == "CALLS"]
    external = [
        edge for edge in edges
        if edge.get("from") in function_ids and edge.get("kind") == "EXTERNAL_CALL"
    ]
    events = [
        edge for edge in edges
        if edge.get("from") in function_ids and edge.get("kind") == "EMITS"
    ]
    effect_kinds = set(_EFFECT_OPERATION_LABELS)
    effects = [
        edge for edge in edges
        if edge.get("from") in function_ids and edge.get("kind") in effect_kinds
    ]
    groups = _effect_groups(effects, nodes)
    read_kinds = {"READS", "READS_CONSTANT", "READS_IMMUTABLE", "TRANSIENT_READS"}
    write_kinds = {
        "WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES",
        "TRANSIENT_DELETES", "INITIALIZES",
    }
    read_count = sum(bool(group["kinds"] & read_kinds) for group in groups)
    write_count = sum(bool(group["kinds"] & write_kinds) for group in groups)
    modifiers = [edge for edge in direct if edge.get("kind") == "APPLIES_MODIFIER"]
    asset_flows = [
        edge for edge in edges
        if edge.get("from") in function_ids and edge.get("kind") == "ASSET_FLOW"
    ]
    helper_ids: set[str] = set()
    for edge in effects:
        via = [str(item) for item in (edge.get("via") or [])]
        if selected_id in via:
            root_position = via.index(selected_id)
            helper_ids.update(via[root_position + 1:])
        source_id = str(edge.get("from") or "")
        if source_id != selected_id and source_id in nodes:
            helper_ids.add(source_id)
    helper_names = sorted({
        str(nodes.get(helper_id, {}).get("name") or "")
        for helper_id in helper_ids
    } - {""})

    print("AT A GLANCE")
    print(
        f"  {len(calls)} internal call(s) · {len(external)} external boundary/boundaries · "
        f"{read_count} state item(s) read · {write_count} written"
    )
    print(
        f"  {len(modifiers)} entry guard(s) · {len(events)} event emission(s)"
        + (f" · helper effects from {len(helper_names)} function(s)" if helper_names else "")
    )
    if asset_flows:
        assets = sorted({
            f"{str(edge.get('asset') or 'unknown').upper()} "
            f"{str(edge.get('direction') or 'unresolved').upper()}"
            for edge in asset_flows
        })
        print("  Asset movement: " + ", ".join(assets[:3]))
    print()

    print("CALL FLOW  (first hop; expand with --detail calls)")
    if calls:
        _render_call_tree(selected, index.get("edges") or [], nodes, depth=1, limit=min(limit, 4))
    else:
        print("  No internal calls were statically identified.")
    print()

    if effects:
        _render_grouped_effects(
            "STATE TOUCHPOINTS", effects, nodes, limit=min(limit, 4)
        )

    if external:
        print("EXTERNAL BOUNDARIES")
        seen_external = set()
        for edge in external[:min(limit, 3)]:
            key = (
                edge.get("receiver"), edge.get("method"), _location(edge),
                edge.get("from"),
            )
            if key in seen_external:
                continue
            seen_external.add(key)
            function_name = _short_function_label(nodes.get(str(edge.get("from") or ""), {}))
            receiver = str(edge.get("receiver") or "external target")
            method = str(edge.get("method") or edge.get("operation") or "call")
            print(f"  {function_name}: {receiver}.{method} · {_location(edge)}")
        print()

    if events:
        names = sorted({
            _symbol_label(nodes.get(str(edge.get("to") or ""), {}))
            for edge in events
        })
        print("EVENTS")
        for name in names[:3]:
            print(f"  {name}")
        print()

    label = _symbol_label(selected)
    depth_hint = min(10, max(depth + 1, 4))
    print("DRILL DOWN")
    print("  --detail calls · --detail storage · --detail external · --detail all")
    print(f"  lk trace source '{label}' --detail all --depth {depth_hint}")
    print()
    print("LIMITS  Static source analysis; reachability is not proof of execution or success.")
    _print_inventory_warning(index)



def _render_function_details(
    selected: dict[str, Any],
    index: dict[str, Any],
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    *,
    depth: int,
    limit: int,
    detail: str,
) -> None:
    """Render expanded details, scoped to the selected entrypoint and its callees."""
    active = "all" if detail == "summary" else detail
    selected_id = str(selected.get("id") or "")
    function_ids = _function_scope_ids(selected, edges, nodes)

    if active in {"calls", "all"}:
        callers = [
            edge for edge in edges
            if edge.get("to") == selected_id and edge.get("kind") == "CALLS"
        ]
        _render_edges("CALLED BY", callers[:limit], nodes, reverse=True)
        calls = [
            edge for edge in edges
            if edge.get("from") == selected_id and edge.get("kind") == "CALLS"
        ]
        _render_edges("CALLS", calls[:limit], nodes)
        modifiers = [
            edge for edge in edges
            if edge.get("kind") == "APPLIES_MODIFIER"
            and edge.get("from") in function_ids
        ]
        _render_edges("SECURITY GATES / MODIFIERS", modifiers[:limit], nodes)
        applied_to = [
            edge for edge in edges
            if edge.get("kind") == "APPLIES_MODIFIER"
            and edge.get("to") == selected_id
        ]
        _render_edges("APPLIED TO", applied_to[:limit], nodes, reverse=True)
        overrides = [
            edge for edge in edges
            if edge.get("kind") == "OVERRIDES"
            and edge.get("from") == selected_id
        ]
        overridden_by = [
            edge for edge in edges
            if edge.get("kind") == "OVERRIDES"
            and edge.get("to") == selected_id
        ]
        _render_edges("OVERRIDES", overrides[:limit], nodes)
        _render_edges("OVERRIDDEN BY", overridden_by[:limit], nodes, reverse=True)
        if calls or any(edge.get("kind") == "CALLS" for edge in edges if edge.get("from") != selected_id):
            _render_call_tree(selected, index.get("edges") or [], nodes, depth=depth, limit=limit)
        print()

    if active in {"storage", "all"}:
        state_edges = [
            edge for edge in edges
            if edge.get("from") in function_ids
            and edge.get("kind") in _EFFECT_OPERATION_LABELS
        ]
        _render_grouped_effects(
            "STATE EFFECTS",
            state_edges,
            nodes,
            limit=limit,
        )

    if active in {"external", "all"}:
        external = [
            edge for edge in edges
            if edge.get("from") in function_ids and edge.get("kind") == "EXTERNAL_CALL"
        ]
        if external:
            print(f"EXTERNAL CALLS ({len(external)} site(s))")
            seen = set()
            for edge in external:
                function_name = _short_function_label(nodes.get(str(edge.get("from") or ""), {}))
                receiver = str(edge.get("receiver") or "external target")
                method = str(edge.get("method") or edge.get("operation") or "call")
                location = _location(edge)
                key = (function_name, receiver, method, location)
                if key in seen:
                    continue
                seen.add(key)
                resolution = str(edge.get("implementation_resolution") or edge.get("resolution") or "UNRESOLVED")
                print(textwrap.fill(
                    f"{function_name}: {receiver}.{method} · {location} · {resolution}",
                    width=112, initial_indent="  ", subsequent_indent="    ",
                ))
            print()

        events = [
            edge for edge in edges
            if edge.get("from") in function_ids and edge.get("kind") == "EMITS"
        ]
        if events:
            names = sorted({
                _symbol_label(nodes.get(str(edge.get("to") or ""), {}))
                for edge in events
            })
            print("EVENTS")
            for name in names[:limit]:
                print(f"  {name}")
            print()

        reverts = [
            edge for edge in edges
            if edge.get("from") in function_ids and edge.get("kind") == "REVERTS"
        ]
        if reverts:
            _render_edges("REVERTS / CUSTOM ERRORS", reverts[:limit], nodes)

        assets = [
            edge for edge in edges
            if edge.get("from") in function_ids and edge.get("kind") == "ASSET_FLOW"
        ]
        if assets:
            _render_edges("ASSET FLOW / CAPABILITY", assets[:limit], nodes)

    if active == "all":
        unresolved = [
            edge for edge in edges
            if edge.get("from") in function_ids
            and (
                edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"}
                or edge.get("implementation_resolution") in {"UNRESOLVED", "AMBIGUOUS"}
                or edge.get("kind") in {"UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION"}
            )
        ]
        if unresolved:
            print(f"UNRESOLVED WITHIN THIS CALL PATH ({len(unresolved)} relationship(s))")
            seen = set()
            for edge in unresolved[:limit]:
                function_name = _short_function_label(nodes.get(str(edge.get("from") or ""), {}))
                detail_text = (
                    edge.get("receiver")
                    or edge.get("detail")
                    or edge.get("operation")
                    or edge.get("kind", "relationship").replace("_", " ").lower()
                )
                key = (function_name, str(detail_text), _location(edge), edge.get("kind"))
                if key in seen:
                    continue
                seen.add(key)
                resolution = str(edge.get("implementation_resolution") or edge.get("resolution") or "UNRESOLVED")
                print(textwrap.fill(
                    f"{function_name}: {detail_text} · {_location(edge)} · {resolution}",
                    width=112, initial_indent="  ", subsequent_indent="    ",
                ))
            print()

        report = index.get("ast") or {}
        warnings = report.get("warnings") or []
        if warnings:
            print("ANALYSIS NOTES")
            for warning in warnings[:2]:
                print(textwrap.fill(str(warning), width=112, initial_indent="  ", subsequent_indent="    "))
            print()

    print("LIMITS  Static source relationships; no runtime execution or success is established.")
    _print_inventory_warning(index)
    propagation = index.get("effect_propagation") or {}
    if propagation.get("truncated_frontiers"):
        print(
            "NOTE     Helper/modifier propagation reached its configured depth cap; "
            "deeper effects may be missing."
        )



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
    edges = _selected_edges(selected, index.get("edges") or [], only=only, depth=depth, nodes=nodes)
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
    if selected.get("kind") in {"function", "modifier"}:
        _render_function_header(selected, index, nodes, depth=depth)
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
            _render_function_details(
                selected, index, edges, nodes,
                depth=depth, limit=limit, detail=active_detail,
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

    if selected.get("kind") not in {"function", "modifier"} and not (selected.get("kind") == "contract" and only is None):
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
