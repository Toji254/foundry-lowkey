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
    "calls": {"CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER"},
    "storage": {"READS", "WRITES", "USES_TYPE"},
    "imports": {"IMPORTS", "INHERITS"},
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
        return f"{node.get('name', '?')} (contract)"
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
    elif edge.get("via"):
        via_names = [nodes.get(item, {}).get("qualified_name", item) for item in edge["via"]]
        detail = " via " + " -> ".join(via_names)
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
    for _level in range(max(1, depth)):
        next_frontier: set[str] = set()
        for edge in edges:
            if allowed is not None and edge.get("kind") not in allowed:
                continue
            if edge.get("from") in frontier or edge.get("to") in frontier:
                selected[edge["id"]] = edge
                if edge.get("kind") == "CALLS":
                    other = edge.get("to") if edge.get("from") in frontier else edge.get("from")
                    if other not in visited:
                        next_frontier.add(other)
                elif node.get("kind") == "contract" and _level == 0 and edge.get("kind") == "DECLARES" and edge.get("from") == node["id"]:
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


def render_link(index: dict[str, Any], target: str, *, only: str | None = None, depth: int = 1, limit: int = 80, as_json: bool = False) -> int:
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
    nodes = _node_map(index)
    edges = _selected_edges(selected, index.get("edges") or [], only=only, depth=depth)
    if as_json:
        print(json.dumps({
            "target": selected,
            "edges": edges[:limit],
            "inventory": index.get("inventory"),
            "summary": index.get("summary"),
            "parser": index.get("parser"),
        }, indent=2, sort_keys=True))
        return 0

    print("LOWKEY // SOURCE LINK")
    print(f"TARGET    {_symbol_label(selected)}")
    print(f"SOURCE    {_location(selected)}")
    print(f"KIND      {selected.get('kind', 'symbol').upper()}")
    print(f"EVIDENCE  {index.get('parser', 'UNKNOWN')} static source analysis (not runtime execution)")
    print(f"CACHE     {(index.get('cache') or {}).get('status', 'UNKNOWN')}")
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
        for title, kinds in (
            ("FUNCTIONS", {"function"}),
            ("MODIFIERS", {"modifier"}),
            ("STORAGE", {"mapping", "state_variable"}),
            ("STRUCTURES", {"struct", "struct_field"}),
            ("EVENTS / ERRORS", {"event", "custom_error"}),
        ):
            items = [
                nodes.get(edge["to"], {}) for edge in declared
                if nodes.get(edge["to"], {}).get("kind") in kinds
            ]
            if items:
                print(title)
                for item in items:
                    print(f"  {_symbol_label(item)}  {_location(item)}")
        file_node = next((item for item in nodes.values() if item.get("kind") == "file" and item.get("name") == selected.get("file")), None)
        file_imports = [edge for edge in (index.get("edges") or []) if file_node and edge.get("kind") == "IMPORTS" and edge.get("from") == file_node.get("id")]
        imports = [edge for edge in edges if edge.get("kind") == "IMPORTS"] + file_imports
        inheritance = [edge for edge in edges if edge.get("kind") == "INHERITS"]
        _render_edges("INHERITANCE", inheritance, nodes)
        _render_edges("IMPORTS", imports, nodes)
        contract_file = selected.get("file")
        related_functions = {
            item["id"] for item in nodes.values()
            if item.get("kind") == "function" and item.get("contract") == selected.get("name")
        }
        extras = [
            edge for edge in index.get("edges") or []
            if edge.get("from") in related_functions
            and edge.get("kind") in {"EXTERNAL_CALL", "ASSET_FLOW"}
        ]
        _render_edges("EXTERNAL INTERACTIONS / ASSET PATHS", extras[:limit], nodes)
        unresolved = [
            edge for edge in edges + extras
            if edge.get("resolution") == "UNRESOLVED"
        ]
        _render_edges("UNRESOLVED", unresolved[:limit], nodes)
    elif selected.get("kind") in {"function", "modifier"}:
        group_map = [
            ("CALLED BY", "CALLS", "incoming"),
            ("CALLS", "CALLS", "outgoing"),
            ("EXTERNAL CALLS", "EXTERNAL_CALL", "outgoing"),
            ("MODIFIERS", "APPLIES_MODIFIER", "outgoing"),
            ("STORAGE READS", "READS", "outgoing"),
            ("STORAGE WRITES", "WRITES", "outgoing"),
            ("EMITS", "EMITS", "outgoing"),
            ("ASSET FLOW / CAPABILITY", "ASSET_FLOW", "outgoing"),
        ]
        for heading, kind, direction in group_map:
            values = [
                edge for edge in edges if edge.get("kind") == kind
                and ((direction == "outgoing" and edge.get("from") == selected["id"])
                     or (direction == "incoming" and edge.get("to") == selected["id"]))
            ]
            _render_edges(heading, values, nodes, reverse=(direction == "incoming"))
        unresolved = [edge for edge in edges if edge.get("resolution") == "UNRESOLVED"]
        _render_edges("UNRESOLVED TARGETS", unresolved, nodes)
    elif selected.get("kind") in {"mapping", "state_variable"}:
        for heading, kind, direction in (
            ("READ BY", "READS", "incoming"),
            ("WRITTEN BY", "WRITES", "incoming"),
            ("USES TYPE", "USES_TYPE", "outgoing"),
        ):
            values = [
                edge for edge in edges if edge.get("kind") == kind
                and ((direction == "outgoing" and edge.get("from") == selected["id"])
                     or (direction == "incoming" and edge.get("to") == selected["id"]))
            ]
            _render_edges(heading, values, nodes, reverse=(direction == "incoming"))
        if selected.get("mapping_value_type"):
            print(f"MAPPING VALUE TYPE  {selected['mapping_value_type']}")
            print("NOTE: declared mapping type is not a runtime storage-slot calculation.")
    else:
        outgoing, incoming = _edge_groups(selected, edges, nodes)
        for kind, values in sorted(outgoing.items()):
            _render_edges(kind.replace("_", " "), values, nodes)
        for kind, values in sorted(incoming.items()):
            _render_edges("REFERENCED BY " + kind.replace("_", " "), values, nodes, reverse=True)

    print()
    print(f"GRAPH     {index.get('summary', {}).get('relationships', 0)} relationship(s) indexed across {index.get('summary', {}).get('files', 0)} Solidity file(s)")
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
            print(f"  {label}  [{edge.get('resolution', 'UNRESOLVED')}]  {_location(edge)}")
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
    parser.add_argument("--depth", type=int, default=1)
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
    if args.depth < 1 or args.depth > 10:
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
    )
    parser.add_argument("--flow", choices=("in", "out", "both"), required=True)
    parser.add_argument("--asset", choices=("eth", "erc20", "all"), default="all")
    parser.add_argument("--root", default=".")
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.depth < 1 or args.depth > 10:
        parser.error("--depth must be between 1 and 10")
    try:
        index = build_source_index(args.root)
    except (SourceIndexError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    nodes = _node_map(index)
    functions = {key: item for key, item in nodes.items() if item.get("kind") == "function"}
    flows = [edge for edge in index.get("edges") or [] if edge.get("kind") == "ASSET_FLOW"]
    selected = []
    for edge in flows:
        asset = edge.get("asset", "unknown")
        direction = edge.get("direction", "unresolved")
        if args.asset != "all" and asset != args.asset:
            continue
        if args.flow == "in" and direction != "in":
            continue
        if args.flow == "out" and direction != "out":
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
        print("Usage: lk link TARGET [--depth N] [--only calls|storage|imports|assets]")
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
