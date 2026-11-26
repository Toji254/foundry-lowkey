#!/usr/bin/env python3
"""Read-only native ETH-flow reconnaissance over Lowkey's shared source index."""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict, deque
from typing import Any

try:
    from source_index import SourceIndexError, build_source_index
except ImportError:  # pragma: no cover - package-style import
    from lowkey.source_index import SourceIndexError, build_source_index


HELP_FLAGS = {"--h", "--help", "-h", "help"}
CALL_KINDS = {"CALLS", "APPLIES_MODIFIER", "EXTERNAL_CALL"}
RESOLVED = {"DIRECT", "INFERRED"}
ACCOUNTING_KINDS = {"READS", "WRITES", "DELETES", "MUTATES"}


def _help() -> str:
    return "\n".join([
        "LOWKEY HELP  •  lk flow eth",
        "=" * 72,
        "What it does: Map native ETH entry points, value-bearing calls, reachable exit sites, and the source call paths between them.",
        "When to use: Run this when you open an unfamiliar Solidity project and need a quick, repository-wide picture of where ETH can enter and leave.",
        "Usage: lk flow eth [--root DIR] [--contract NAME] [--depth N] [--limit N] [--detail] [--include-tests] [--json]",
        "Example: lk flow eth --contract Vault --depth 5",
        "",
        "COMMAND VARIATIONS",
        "------------------",
        "  lk flow eth",
        "      Scan the current project/workspace and summarize native ETH movement.",
        "      Example: lk flow eth",
        "  lk flow eth --contract <NAME>",
        "      Start from public/external entry functions in one contract, while still following declared cross-contract calls.",
        "      Example: lk flow eth --contract Vault",
        "  lk flow eth --root <DIR>",
        "      Scan another project or monorepo root.",
        "      Example: lk flow eth --root ../gmx-v1",
        "",
        "OPTIONS / MODES",
        "---------------",
        "  --root <DIR>",
        "      Project/workspace root. Defaults to the current directory.",
        "      Example: lk flow eth --root ../protocol",
        "  --contract <NAME>",
        "      Restrict starting functions to this contract; reachable declared targets in other contracts remain in scope.",
        "      Example: lk flow eth --contract PositionManager",
        "  --depth <N>",
        "      Maximum source-call hops to follow (1-10; default 5).",
        "      Example: lk flow eth --depth 8",
        "  --limit <N>",
        "      Maximum source routes to explore and display (1-100; default: 100). Ingress, exit-site, accounting and unresolved-edge inventories remain complete.",
        "      Example: lk flow eth --limit 20",
        "  --detail",
        "      Show the expanded forensic evidence layout and additional review annotations.",
        "      Example: lk flow eth --detail",
        "  --include-tests",
        "      Include test, mock, fixture and harness contracts normally excluded from the default audit view.",
        "      Example: lk flow eth --include-tests",
        "  --json",
        "      Emit structured source edges and path records for downstream analysis.",
        "      Example: lk flow eth --json",
        "  --h, --help, -h, help",
        "      Show this help page. Help is read-only.",
        "      Example: lk flow eth --h",
        "",
        "HOW TO READ THE RESULT",
        "----------------------",
        "  PAYABLE/CAPABILITY means a function can accept ETH; it does not prove a caller supplied value.",
        "  TRANSFER ATTEMPT means source syntax tries to send ETH; it does not prove the call succeeded.",
        "  EXTERNAL_CALL paths may identify a declared interface/contract function, not the implementation at the runtime address.",
        "  A deposit and a later withdrawal are separate transactions unless an actual source call path connects them.",
        "  Forced ETH, complex assembly, dynamic dispatch and proxy implementation selection may remain unresolved.",
        "",
        "RELATED COMMANDS",
        "----------------",
        "  lk fn --flow in --asset eth",
        "  lk fn --flow out --asset eth",
        "  lk link <Contract>",
        "  lk trace source <Contract.function>",
        "  lk trace <TX>",
        "",
        "HELP TIP",
        "  Static source recon is read-only and does not compile, deploy, or send transactions.",
        "  Accepted help forms: --h, --help, -h, help.",
    ])


def _node_label(node: dict[str, Any]) -> str:
    return str(
        node.get("qualified_name")
        or node.get("signature")
        or node.get("name")
        or node.get("id")
        or "unknown"
    )


def _location(value: dict[str, Any]) -> str:
    source = value.get("source") or {}
    return f"{source.get('file', value.get('file', '?'))}:{source.get('line', value.get('line', '?'))}"


def _is_function(node: dict[str, Any]) -> bool:
    return node.get("kind") in {"function", "modifier"}


def _is_direct_flow_edge(edge: dict[str, Any]) -> bool:
    return (
        edge.get("kind") == "ASSET_FLOW"
        and edge.get("evidence") not in {
            "CALL_GRAPH_PROPAGATION",
            "MODIFIER_EXECUTION_PROPAGATION",
        }
        and not str(edge.get("id", "")).startswith("INFERRED:")
    )


def _is_eth_exit(edge: dict[str, Any]) -> bool:
    # A value-bearing self-call is an intra-account call, not a net ETH exit.
    if edge.get("status") == "SELF_VALUE_CALL_ATTEMPT":
        return False
    if edge.get("asset") == "eth":
        return edge.get("direction") in {"out", "unresolved"}
    return edge.get("asset") == "unknown" and edge.get("status") == "ASSEMBLY_UNRESOLVED"


def _contract_kind(node: dict[str, Any]) -> str:
    return str(node.get("contract_kind") or "contract").lower()


def _is_external_entry(node: dict[str, Any]) -> bool:
    """Only callable ABI entry points can receive a transaction's msg.value."""
    if _contract_kind(node) in {"interface", "library"}:
        return False
    visibility = str(node.get("visibility") or "").lower()
    name = str(node.get("name") or "").lower()
    return visibility in {"public", "external"} or name in {"constructor", "receive", "fallback"}


def _is_support_node(node: dict[str, Any]) -> bool:
    """Recognize conventional test/support locations without guessing from symbol contents."""
    path = str(node.get("file") or "").replace("\\", "/").lower()
    parts = {part for part in path.split("/") if part}
    contract = str(node.get("contract") or node.get("name") or "").lower()
    return bool(
        parts.intersection({"test", "tests", "mock", "mocks", "fixture", "fixtures", "harness", "harnesses"})
        or contract.startswith("mock")
        or contract.endswith(("test", "tests"))
    )


def _compact_function_label(node: dict[str, Any]) -> str:
    """Keep terminal routes scannable while retaining overload arity."""
    contract = str(node.get("contract") or "?")
    name = str(node.get("name") or "unknown")
    parameters = node.get("parameters") or []
    count = len(parameters)
    if count == 0:
        return f"{contract}.{name}()"
    return f"{contract}.{name} ({count} args)"


def _matches_contract(node: dict[str, Any], selected: set[str] | None) -> bool:
    return selected is None or str(node.get("contract") or "").lower() in selected


def _entry_roots(
    functions: dict[str, dict[str, Any]],
    selected_contracts: set[str] | None,
    *,
    include_tests: bool = False,
) -> list[dict[str, Any]]:
    roots = []
    for node in functions.values():
        if not _matches_contract(node, selected_contracts):
            continue
        if not include_tests and _is_support_node(node):
            continue
        if _contract_kind(node) in {"interface", "library"}:
            continue
        visibility = str(node.get("visibility") or "").lower()
        name = str(node.get("name") or "").lower()
        if visibility in {"public", "external"} or name in {"constructor", "receive", "fallback"}:
            roots.append(node)
    return sorted(roots, key=lambda node: (
        str(node.get("file") or ""),
        int(node.get("line") or 0),
        _node_label(node),
    ))


def _call_edges_by_source(
    edges: list[dict[str, Any]],
    functions: dict[str, dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    adjacency: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unresolved: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        if edge.get("kind") not in CALL_KINDS:
            continue
        source_id = str(edge.get("from") or "")
        target_id = str(edge.get("to") or "")
        if source_id not in functions:
            continue
        if edge.get("resolution") in RESOLVED and target_id in functions:
            adjacency[source_id].append(edge)
        else:
            unresolved[source_id].append(edge)
    for values in adjacency.values():
        values.sort(key=lambda edge: (
            (edge.get("source") or {}).get("file", ""),
            (edge.get("source") or {}).get("line", 0),
            edge.get("kind", ""),
            edge.get("to", ""),
        ))
    return adjacency, unresolved


def _path_records(
    root: dict[str, Any],
    functions: dict[str, dict[str, Any]],
    adjacency: dict[str, list[dict[str, Any]]],
    unresolved_by_source: dict[str, list[dict[str, Any]]],
    exits_by_source: dict[str, list[dict[str, Any]]],
    *,
    depth: int,
    limit: int,
) -> tuple[list[dict[str, Any]], set[str], list[dict[str, Any]], bool]:
    root_id = str(root["id"])
    queue = deque([(root_id, tuple(), frozenset({root_id}))])
    best_depth: dict[str, int] = {root_id: 0}
    records: list[dict[str, Any]] = []
    reachable: set[str] = set()
    unresolved: list[dict[str, Any]] = []
    truncated = False

    while queue:
        current_id, hops, path_nodes = queue.popleft()
        reachable.add(current_id)

        for edge in unresolved_by_source.get(current_id, []):
            unresolved.append({"from": functions[current_id], "edge": edge})

        for exit_edge in exits_by_source.get(current_id, []):
            path_function_ids = [root_id, *(str(hop.get("to") or "") for hop in hops)]
            path_functions = [functions[item] for item in path_function_ids if item in functions]
            records.append({
                "entry": root,
                "hops": list(hops),
                "functions": path_functions,
                "exit_function": functions[current_id],
                "exit": exit_edge,
                "cross_contract_hops": sum(
                    1 for hop in hops
                    if hop.get("kind") == "EXTERNAL_CALL"
                    and functions.get(str(hop.get("from") or ""), {}).get("contract")
                    != functions.get(str(hop.get("to") or ""), {}).get("contract")
                ),
            })
            if len(records) >= limit:
                if queue or adjacency.get(current_id):
                    truncated = True
                return records, reachable, unresolved, truncated

        if len(hops) >= depth:
            if adjacency.get(current_id):
                truncated = True
            continue

        for edge in adjacency.get(current_id, []):
            target_id = str(edge.get("to") or "")
            if target_id in path_nodes:
                continue
            next_depth = len(hops) + 1
            previous_depth = best_depth.get(target_id)
            if previous_depth is not None and previous_depth <= next_depth:
                continue
            best_depth[target_id] = next_depth
            queue.append((target_id, (*hops, edge), path_nodes | {target_id}))

    return records, reachable, unresolved, truncated


def _accounting_for_functions(
    function_ids: set[str],
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return every accounting edge attached to the functions in the inspected flow."""
    result = []
    for edge in edges:
        if edge.get("kind") not in ACCOUNTING_KINDS or edge.get("from") not in function_ids:
            continue
        target = nodes.get(str(edge.get("to") or ""), {})
        if target.get("kind") not in {"mapping", "state_variable", "function_pointer"}:
            continue
        result.append({"function": nodes.get(str(edge.get("from") or ""), {}), "variable": target, "edge": edge})
    result.sort(key=lambda item: (
        str(item["function"].get("file") or ""),
        int((item["edge"].get("source") or {}).get("line") or 0),
        str(item["variable"].get("name") or ""),
    ))
    return result

def build_eth_report(
    index: dict[str, Any],
    *,
    contract: str | None = None,
    depth: int = 5,
    limit: int = 8,
    include_tests: bool = False,
) -> dict[str, Any]:
    """Build a bounded graph report from static source edges; never claims runtime execution."""
    nodes = {
        str(item.get("id")): item
        for item in index.get("nodes") or []
        if isinstance(item, dict) and item.get("id")
    }
    functions = {key: item for key, item in nodes.items() if _is_function(item)}
    contracts = [item for item in nodes.values() if item.get("kind") == "contract"]

    selected_contracts: set[str] | None = None
    if contract:
        selected_contracts = {
            str(item.get("name") or "").lower()
            for item in contracts
            if str(item.get("name") or "").lower() == contract.lower()
        }
        if not selected_contracts:
            raise ValueError(f"No contract named '{contract}' exists in the indexed Solidity source.")

    all_edges = [item for item in index.get("edges") or [] if isinstance(item, dict)]
    direct_flows = [item for item in all_edges if _is_direct_flow_edge(item)]
    entry_signals = [
        edge for edge in direct_flows
        if edge.get("asset") == "eth"
        and edge.get("direction") == "in"
        and edge.get("status") in {"CAPABILITY", "VALUE_USAGE"}
    ]
    entries_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in entry_signals:
        function = functions.get(str(edge.get("from") or ""))
        if function and _is_external_entry(function):
            if include_tests or not _is_support_node(function):
                entries_by_function[str(edge["from"])].append(edge)

    exits = [
        edge for edge in direct_flows
        if _is_eth_exit(edge)
        and edge.get("from") in functions
        and (include_tests or not _is_support_node(functions[str(edge.get("from"))]))
    ]
    exits_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in exits:
        exits_by_source[str(edge["from"])].append(edge)

    adjacency, unresolved_by_source = _call_edges_by_source(all_edges, functions)
    roots = _entry_roots(functions, selected_contracts, include_tests=include_tests)
    paths: list[dict[str, Any]] = []
    reachable_functions: set[str] = set()
    unresolved: list[dict[str, Any]] = []
    truncated_roots: list[str] = []
    for root in roots:
        remaining = limit - len(paths)
        if remaining <= 0:
            truncated_roots.append(_node_label(root))
            break
        records, reachable, pending, truncated = _path_records(
            root, functions, adjacency, unresolved_by_source, exits_by_source,
            depth=depth, limit=remaining,
        )
        paths.extend(records)
        reachable_functions.update(reachable)
        unresolved.extend(pending)
        if truncated:
            truncated_roots.append(_node_label(root))

    visible_exits = exits
    if selected_contracts is not None:
        visible_exits = [edge for edge in exits if edge.get("from") in reachable_functions]

    unique_unresolved: dict[str, dict[str, Any]] = {}
    for item in unresolved:
        edge = item["edge"]
        unique_unresolved.setdefault(str(edge.get("id") or id(edge)), item)
    unresolved = list(unique_unresolved.values())
    eth_effect_functions = {
        str(edge.get("from") or "")
        for edge in all_edges
        if edge.get("kind") == "ASSET_FLOW"
        and (edge.get("asset") in {"eth", "unknown"})
    }
    unresolved = [
        item for item in unresolved
        if str(item.get("from", {}).get("id") or "") in eth_effect_functions
    ]

    entries = []
    for function_id, signals in entries_by_function.items():
        node = functions[function_id]
        if selected_contracts is not None and not _matches_contract(node, selected_contracts):
            continue
        if not include_tests and _is_support_node(node):
            continue
        entries.append({"function": node, "signals": signals})
    entries.sort(key=lambda item: (
        str(item["function"].get("file") or ""),
        int(item["function"].get("line") or 0),
    ))

    accounting_function_ids = {str(item["function"]["id"]) for item in entries}
    for record in paths:
        accounting_function_ids.update(str(item.get("id")) for item in record.get("functions") or [])
    accounting = _accounting_for_functions(accounting_function_ids, all_edges, nodes)

    inventory = index.get("inventory") or {}
    coverage_complete = bool(inventory.get("complete", True))
    return {
        "schema_version": 1,
        "kind": "static-eth-flow-recon",
        "root": index.get("root"),
        "contract_filter": contract,
        "parser": index.get("parser", "unknown"),
        "ast": index.get("ast") or {},
        "coverage": {
            "complete": coverage_complete,
            "uninspected": inventory.get("uninspected") or [],
        },
        "summary": {
            "contracts": len(contracts),
            "functions": len(functions),
            "entry_points": len(entries),
            "exit_sites": len(visible_exits),
            "paths_to_exit": len(paths),
            "cross_contract_hops": sum(int(item.get("cross_contract_hops") or 0) for item in paths),
            "unresolved_boundaries": len(unresolved),
            "truncated_roots": len(truncated_roots),
        },
        "entries": entries,
        "exits": [
            {"function": functions.get(str(edge.get("from") or ""), {}), "edge": edge}
            for edge in visible_exits
        ],
        "paths": paths,
        "accounting": accounting,
        "unresolved": unresolved,
        "truncated": truncated_roots,
        "nodes": nodes,
    }


def _exit_action(edge: dict[str, Any]) -> str:
    status = str(edge.get("status") or "UNKNOWN").replace("_", " ").lower()
    recipient = str(edge.get("recipient") or "").strip()
    method = str(edge.get("method") or "").strip()
    if status == "assembly unresolved":
        action = "assembly value movement (unresolved)"
    elif recipient and method:
        action = f"{recipient}.{method}()"
    elif recipient:
        action = f"send to {recipient}"
    elif method:
        action = f"{method}()"
    else:
        action = status
    amount = edge.get("amount")
    if amount:
        action += f" (amount={amount})"
    return action


def _route_label(record: dict[str, Any]) -> str:
    functions = record.get("functions") or []
    labels = [_compact_function_label(item) for item in functions]
    edge = record.get("exit") or {}
    action = _exit_action(edge)
    if labels:
        return " → ".join([*labels, action])
    return action


def _exit_mechanisms(report: dict[str, Any]) -> list[dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for item in report.get("exits") or []:
        edge = item.get("edge") or {}
        label = _exit_action(edge)
        group = groups.setdefault(label, {"label": label, "count": 0, "locations": []})
        group["count"] += 1
        group["locations"].append(_location(edge))
    return sorted(groups.values(), key=lambda item: (-item["count"], item["label"]))


def _state_touchpoints(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Group every state/accounting edge while retaining all functions and source sites."""
    groups: dict[str, dict[str, Any]] = {}
    for item in report.get("accounting") or []:
        variable = item.get("variable") or {}
        edge = item.get("edge") or {}
        key = str(variable.get("id") or variable.get("name") or "?")
        group = groups.setdefault(key, {
            "name": variable.get("name") or "?",
            "kinds": set(),
            "functions": set(),
            "accesses": set(),
            "locations": set(),
        })
        group["kinds"].add(str(edge.get("kind") or "TOUCH"))
        group["functions"].add(_node_label(item.get("function") or {}))
        if edge.get("access_path"):
            group["accesses"].add(str(edge["access_path"]))
        group["locations"].add(_location(edge))
    values = list(groups.values())
    values.sort(key=lambda item: (
        not bool(item["kinds"].intersection({"WRITES", "DELETES", "MUTATES"})),
        str(item["name"]).lower(),
    ))
    return values


def _print_inventory_warning(report: dict[str, Any], *, limit: int) -> None:
    if report["coverage"]["complete"]:
        return
    failures = report["coverage"]["uninspected"]
    print(f"WARNING  SOURCE COVERAGE INCOMPLETE ({len(failures)} uninspected item(s))")
    for item in failures[:limit]:
        print(
            f"  {item.get('path', '?')} [{item.get('phase', 'unknown')}]: "
            f"{item.get('error', 'not inspected')}"
        )
    if len(failures) > limit:
        print(f"  ... {len(failures) - limit} more")


def _render(report: dict[str, Any], *, limit: int) -> None:
    """Render the complete audit evidence in a structured, navigable terminal layout."""
    summary = report["summary"]
    parser = str(report.get("parser") or "unknown").lower()
    coverage = "COMPLETE" if report["coverage"]["complete"] else "INCOMPLETE"
    paths = report.get("paths") or []
    entries = report.get("entries") or []
    exits = report.get("exits") or []
    unresolved = report.get("unresolved") or []
    truncated = report.get("truncated") or []

    routed_entry_ids = {
        str((record.get("entry") or {}).get("id") or "")
        for record in paths
    }

    def divider() -> None:
        print("─" * 76)

    def section(number: str, label: str, count: int | None = None) -> None:
        print()
        divider()
        suffix = f"  ({count})" if count is not None else ""
        print(f"{number}  {label}{suffix}")
        divider()

    print("LOWKEY / ETH FLOW")
    print("═" * 76)
    print(f"PROJECT     {report.get('root') or '.'}")
    print(f"SOURCE      {parser} parser · {coverage} inventory")
    if report.get("contract_filter"):
        print(f"SCOPE       {report['contract_filter']} entry points + reachable declared calls")
    print(
        f"INDEX       {summary['contracts']} contracts · {summary['functions']} functions"
    )

    route_count = len(paths)
    route_count_label = f"{route_count}+" if truncated and route_count else str(route_count)
    print()
    print("FLOW SNAPSHOT")
    print(
        f"  INGRESS   {summary['entry_points']} ABI entry points"
        f"     EXITS   {summary['exit_sites']} native-ETH exit sites"
    )
    print(
        f"  ROUTES    {route_count_label} source paths to exit sites"
        f"     HOPS    {summary['cross_contract_hops']} declared cross-contract hops"
    )
    print(
        f"  REVIEW    {summary['unresolved_boundaries']} unresolved call boundaries"
        f"     BOUNDS  {len(truncated)} traversal-limited roots"
    )

    # Keep every ingress candidate visible. A route marker tells the auditor
    # whether this entry point was connected to an exit within the current scan.
    section("01", "ETH INGRESS POINTS", len(entries))
    if not entries:
        print("  No payable/value-reading ABI entry points were identified.")
    else:
        grouped_entries: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in entries:
            function = item.get("function") or {}
            grouped_entries[str(function.get("contract") or "Unknown contract")].append(item)
        for contract_name in sorted(grouped_entries):
            contract_entries = grouped_entries[contract_name]
            print(f"  {contract_name}  ·  {len(contract_entries)}")
            for index, item in enumerate(contract_entries):
                function = item.get("function") or {}
                statuses = {str(edge.get("status")) for edge in item.get("signals") or []}
                labels = []
                if "CAPABILITY" in statuses:
                    labels.append("PAYABLE")
                if "VALUE_USAGE" in statuses:
                    labels.append("READS msg.value")
                function_id = str(function.get("id") or "")
                labels.append("ROUTE FOUND" if function_id in routed_entry_ids else "NO ROUTE MAPPED")
                connector = "└─" if index == len(contract_entries) - 1 else "├─"
                print(f"    {connector} [{' · '.join(labels)}] {_node_label(function)}")
                print(f"       {_location(function)}")

    # Print each path as a small call tree, including the source location of
    # every call edge and the final ETH-effect site.
    section("02", "SOURCE ROUTES TO ETH EXITS", len(paths))
    if not paths:
        print("  No resolved public/external source path to a native-ETH exit was found.")
    for number, record in enumerate(paths, start=1):
        root = record.get("entry") or {}
        hops = record.get("hops") or []
        print(f"  [{number:02}] {_node_label(root)}")
        print(f"       ENTRY  {_location(root)}")
        for hop_index, hop in enumerate(hops):
            target = report["nodes"].get(str(hop.get("to") or ""), {})
            relation = str(hop.get("kind") or "CALLS").replace("_", " ")
            resolution = str(hop.get("resolution") or "UNRESOLVED")
            branch = "└─" if hop_index == len(hops) - 1 else "├─"
            print(
                f"       {branch} {relation} [{resolution}]  {_node_label(target)}"
            )
            print(f"          at {_location(hop)}")
            if hop.get("kind") == "EXTERNAL_CALL":
                print("          runtime implementation/address is not proven by this source edge")
        edge = record.get("exit") or {}
        print(f"       └─ ETH EXIT ATTEMPT  {_exit_action(edge)}")
        print(f"          at {_location(edge)}")
        if record.get("cross_contract_hops"):
            print("          verify the declared external target against the runtime address")
        if number != len(paths):
            print()

    # Group by mechanism for readability, but retain the exact function and
    # source site for every occurrence rather than hiding repeated sites.
    mechanism_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in exits:
        mechanism_groups[_exit_action(item.get("edge") or {})].append(item)
    section("03", "ETH EXIT SITES BY MECHANISM", len(exits))
    if not mechanism_groups:
        print("  No recognized native-ETH exit mechanism in this scope.")
    for mechanism in sorted(mechanism_groups, key=lambda key: (-len(mechanism_groups[key]), key)):
        sites = sorted(
            mechanism_groups[mechanism],
            key=lambda item: (
                str((item.get("function") or {}).get("file") or ""),
                int(((item.get("edge") or {}).get("source") or {}).get("line") or 0),
            ),
        )
        print(f"  {mechanism}  ·  {len(sites)} site(s)")
        for index, item in enumerate(sites):
            function = item.get("function") or {}
            edge = item.get("edge") or {}
            connector = "└─" if index == len(sites) - 1 else "├─"
            status = str(edge.get("status") or "UNKNOWN").replace("_", " ").lower()
            direction = str(edge.get("direction") or "unresolved").upper()
            print(f"    {connector} {direction} / {status}  {_node_label(function)}")
            print(f"       {_location(edge)}")

    touchpoints = _state_touchpoints(report)
    section("04", "STATE / ACCOUNTING TOUCHPOINTS", len(touchpoints))
    if not touchpoints:
        print("  No indexed mapping/state-variable accounting touchpoints in the inspected functions.")
    for index, item in enumerate(touchpoints):
        connector = "└─" if index == len(touchpoints) - 1 else "├─"
        operations = "/".join(sorted(item["kinds"]))
        print(f"  {connector} {operations:<22} {item['name']}")
        if item["accesses"]:
            print(f"     ACCESS  {', '.join(sorted(item['accesses']))}")
        print(f"     USED BY {', '.join(sorted(item['functions']))}")
        for location in sorted(item["locations"]):
            print(f"     SOURCE  {location}")

    section("05", "UNRESOLVED CALL BOUNDARIES", len(unresolved))
    if not unresolved:
        print("  No unresolved call edges were retained on the inspected ETH-related paths.")
    for index, item in enumerate(unresolved):
        edge = item.get("edge") or {}
        source_function = item.get("from") or {}
        receiver = edge.get("receiver") or edge.get("to") or "dynamic target"
        candidates = edge.get("candidates") or []
        suffix = f" · {len(candidates)} candidate(s)" if candidates else ""
        connector = "└─" if index == len(unresolved) - 1 else "├─"
        print(
            f"  {connector} {_node_label(source_function)} → {receiver}"
            f"  [{edge.get('resolution', 'UNRESOLVED')}]{suffix}"
        )
        print(f"     {_location(edge)}")
        if candidates:
            candidate_names = [
                str(candidate.get("qualified_name") or candidate.get("name") or candidate)
                if isinstance(candidate, dict) else str(candidate)
                for candidate in candidates
            ]
            print(f"     CANDIDATES  {', '.join(candidate_names)}")

    section("06", "REVIEW / COVERAGE")
    if unresolved:
        print(f"  • {len(unresolved)} call boundary/boundaries need manual target resolution.")
    if truncated:
        print(f"  • Traversal was bounded for {len(truncated)} root(s) by --depth or --limit.")
        for root_label in truncated:
            print(f"      {root_label}")
        print(f"    Current route budget: {limit}; maximum source-call depth: configured --depth.")
    if not report["coverage"]["complete"]:
        print("  • Source inventory is incomplete; uninspected files are listed below.")
        _print_inventory_warning(report, limit=max(limit, 100))
    if not unresolved and not truncated and report["coverage"]["complete"]:
        print("  No traversal or source-inventory warnings were recorded.")
    print("  PAYABLE is ingress capability, not proof that value was supplied.")
    print("  An ETH exit is a source-level attempt, not proof that the call succeeded.")
    print("  Forced ETH, dynamic dispatch, proxy implementation selection and complex assembly may remain unresolved.")

    print()
    divider()
    print("NEXT")
    print("  lk trace source '<Contract.function(...)>' --detail all")
    print("  lk link <Contract>                  Inspect the wider source relationship graph")
    print("  lk flow eth --detail                Expanded forensic annotations")
    print()
    print("STATIC SOURCE EVIDENCE ONLY  ·  No runtime execution is claimed.")



def _render_detail(report: dict[str, Any], *, limit: int) -> None:
    """Expanded forensic view. Kept separate so the default stays easy to scan."""
    summary = report["summary"]
    nodes = report["nodes"]
    print("LOWKEY / ETH FLOW RECON  ·  DETAIL")
    print(f"PROJECT   {report.get('root') or '.'}")
    coverage = "complete inventory" if report["coverage"]["complete"] else "incomplete inventory"
    print(f"SOURCE    {report.get('parser', 'unknown')}  ·  {coverage}")
    if report.get("contract_filter"):
        print(f"FILTER    contract={report['contract_filter']}")
    print(
        "SUMMARY   "
        f"contracts={summary['contracts']}  functions={summary['functions']}  "
        f"ETH entries={summary['entry_points']}  ETH exit sites={summary['exit_sites']}  "
        f"paths={summary['paths_to_exit']}"
    )
    print("EVIDENCE  Static source relationships; no transaction execution is claimed.")
    print()

    print("ETH ENTRY POINTS")
    for item in report["entries"][:limit]:
        function = item["function"]
        statuses = {str(edge.get("status")) for edge in item["signals"]}
        label = "payable" if "CAPABILITY" in statuses else "reads msg.value"
        if "VALUE_USAGE" in statuses and "CAPABILITY" in statuses:
            label += " · reads msg.value"
        print(f"  {label:<24} {_node_label(function)}")
        print(f"    {_location(function)}")
    if len(report["entries"]) > limit:
        print(f"  ... {len(report['entries']) - limit} more")

    print()
    print("ETH EXIT SITES")
    for item in report["exits"][:limit]:
        function, edge = item["function"], item["edge"]
        status = str(edge.get("status") or "UNKNOWN").replace("_", " ").lower()
        direction = str(edge.get("direction") or "unresolved").upper()
        details = []
        if edge.get("recipient"):
            details.append(f"to={edge['recipient']}")
        if edge.get("amount"):
            details.append(f"amount={edge['amount']}")
        if edge.get("method"):
            details.append(f"method={edge['method']}")
        suffix = "  " + "  ".join(details) if details else ""
        print(f"  {direction:<10} {status:<27} {_node_label(function)}{suffix}")
        print(f"    {_location(edge)}")
    if len(report["exits"]) > limit:
        print(f"  ... {len(report['exits']) - limit} more")

    print()
    print("CALL PATHS TO ETH EXITS")
    for number, item in enumerate(report["paths"][:limit], start=1):
        root = item["entry"]
        print(f"  [{number}] {_node_label(root)}")
        for hop in item["hops"]:
            target = nodes.get(str(hop.get("to") or ""), {})
            relation = str(hop.get("kind") or "CALLS").replace("_", " ").lower()
            note = str(hop.get("resolution") or "UNRESOLVED").lower()
            if hop.get("kind") == "EXTERNAL_CALL":
                note = "declared target; runtime implementation/address unresolved"
            print(f"      └─ {relation} → {_node_label(target)} [{note}]  {_location(hop)}")
        edge = item["exit"]
        print(f"      └─ ETH EXIT ATTEMPT: {_exit_action(edge)}  [{_location(edge)}]")
    if len(report["paths"]) > limit:
        print(f"  ... {len(report['paths']) - limit} more")

    touchpoints = _state_touchpoints(report, limit=limit)
    if touchpoints:
        print()
        print("ACCOUNTING TOUCHPOINTS")
        for item in touchpoints:
            kinds = "/".join(sorted(item["kinds"]))
            functions = ", ".join(sorted(item["functions"])[:4])
            accesses = ", ".join(sorted(item["accesses"])[:3])
            access_label = f" [{accesses}]" if accesses else ""
            print(f"  {kinds:<20} {item['name']}{access_label}  [{functions}]")
            print(f"    {item['location']}")

    if report["unresolved"]:
        print()
        print(f"UNRESOLVED CALL BOUNDARIES ({len(report['unresolved'])})")
        for item in report["unresolved"][:limit]:
            edge = item["edge"]
            candidates = edge.get("candidates") or []
            suffix = f" candidates={len(candidates)}" if candidates else ""
            print(
                f"  {_node_label(item['from'])} → "
                f"{edge.get('receiver') or edge.get('to') or 'dynamic target'}"
                f" [{edge.get('resolution', 'UNRESOLVED')}]{suffix}"
            )
            print(f"    {_location(edge)}")
        if len(report["unresolved"]) > limit:
            print(f"  ... {len(report['unresolved']) - limit} more")

    if report["truncated"]:
        print()
        print(f"DEPTH / OUTPUT LIMIT  Additional paths were not expanded for {len(report['truncated'])} root(s).")
        for label in report["truncated"][:limit]:
            print(f"  {label}")

    _print_inventory_warning(report, limit=limit)
    print()
    print("REVIEW NOTES")
    print("  Payable means ETH can enter; it does not prove a nonzero msg.value was supplied.")
    print("  Exit sites are attempts; inspect return handling, reverts, recipient control and balance changes.")
    print("  Deposits and later withdrawals are separate transactions unless a source call path connects them.")
    print("  Forced ETH, proxy implementation selection, dynamic calls and complex assembly may not be fully resolved.")


def main(argv: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if argv is None else argv)
    if any(str(value).lower() in HELP_FLAGS for value in values):
        print(_help())
        return 0

    parser = argparse.ArgumentParser(
        prog="lk flow eth",
        description="Read-only static reconnaissance of native ETH ingress, call paths and exit sites.",
        add_help=False,
    )
    parser.add_argument("--root", default=".", metavar="DIR", help="project/workspace root (default: current directory)")
    parser.add_argument("--contract", metavar="NAME", help="restrict starting functions to one contract")
    parser.add_argument("--depth", type=int, default=5, choices=range(1, 11), metavar="N", help="maximum source-call hops (default: 5)")
    parser.add_argument("--limit", type=int, default=100, metavar="N", help="maximum source routes to explore (1-100; default: 100)")
    parser.add_argument("--detail", action="store_true", help="show the expanded forensic evidence layout")
    parser.add_argument("--include-tests", action="store_true", help="include test, mock, fixture and harness contracts")
    parser.add_argument("--json", action="store_true", help="emit structured JSON")
    try:
        args = parser.parse_args(values)
    except SystemExit as error:
        return int(error.code)

    if args.limit < 1 or args.limit > 100:
        print("ERROR: --limit must be between 1 and 100.", file=sys.stderr)
        return 2

    try:
        index = build_source_index(args.root)
        report = build_eth_report(
            index, contract=args.contract, depth=args.depth, limit=args.limit,
            include_tests=args.include_tests,
        )
    except (SourceIndexError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2

    if args.json:
        output = {key: value for key, value in report.items() if key != "nodes"}
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        (_render_detail if args.detail else _render)(report, limit=args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
