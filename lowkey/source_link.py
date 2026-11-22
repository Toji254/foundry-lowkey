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
    print("EVIDENCE: static source relationships; not runtime execution")
    print()

    inheritance = [
        edge for edge in all_edges
        if edge.get("kind") == "INHERITS" and edge.get("from") == selected["id"]
    ]
    if inheritance:
        print("INHERITANCE")
        for edge in inheritance[:limit]:
            target = nodes.get(edge.get("to"), {})
            print(f"  └── {_symbol_label(target)}")
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
    if imports:
        print("IMPORTS")
        for edge in imports[:limit]:
            print(f"  ├── {_symbol_label(nodes.get(edge.get('to'), {}))}")
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
        print("FUNCTIONS")
        for item in functions[:limit]:
            print(f"  ├── {_short_function_label(item)}")
        if len(functions) > limit:
            print(f"  └── ... {len(functions) - limit} more")
        print()

    storage = [
        item for item in declared
        if item.get("kind") in {"mapping", "state_variable", "function_pointer"}
        and item.get("storage_class") not in {"constant", "immutable", "transient"}
    ]
    transient = [
        item for item in declared
        if item.get("kind") in {"mapping", "state_variable", "function_pointer"}
        and item.get("storage_class") == "transient"
    ]
    constants = [
        item for item in declared
        if item.get("kind") == "state_variable"
        and item.get("storage_class") in {"constant", "immutable"}
    ]
    for heading, values in (
        ("STORAGE", storage),
        ("TRANSIENT STORAGE", transient),
        ("CONSTANTS / IMMUTABLES", constants),
    ):
        if values:
            print(heading)
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

    if not any((inheritance, imports, functions, storage, transient, constants, external_targets, asset_groups, unresolved)):
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
            "effect_propagation": index.get("effect_propagation"),
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

    if selected.get("kind") == "contract" and only is None:
        _render_contract_overview(selected, index, nodes, limit=min(limit, 24))
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
            constructor_ids = {item["id"] for item in nodes.values() if item.get("kind") == "function" and item.get("name") == "constructor" and item.get("contract") in related_contracts}
            initializers = [edge for edge in (index.get("edges") or []) if edge.get("kind") == "INITIALIZES" and (edge.get("from") in related_contract_ids or edge.get("from") in constructor_ids)]
            _render_edges("STATE INITIALIZERS", initializers[:limit], nodes)
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
