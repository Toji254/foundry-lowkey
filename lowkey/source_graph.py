#!/usr/bin/env python3
"""Readable terminal and offline HTML views over Lowkey's static source graph.

The graph is a presentation of source_index evidence. It never upgrades static
relationships into claims about runtime execution.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any


EDGE_FILTERS: dict[str, set[str]] = {
    "calls": {"CALLS", "LIBRARY_CALL", "EXTERNAL_CALL", "APPLIES_MODIFIER", "OVERRIDES"},
    "storage": {
        "READS", "READS_CONSTANT", "READS_IMMUTABLE", "WRITES", "DELETES",
        "MUTATES", "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
        "INITIALIZES", "ALIASES_STORAGE", "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION",
        "USES_TYPE",
    },
    "reads": {"READS", "READS_CONSTANT", "READS_IMMUTABLE", "TRANSIENT_READS"},
    "writes": {
        "WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES",
        "TRANSIENT_DELETES", "INITIALIZES", "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION",
    },
    "imports": {"IMPORTS", "INHERITS", "USES_LIBRARY", "USES_TYPE"},
    "assets": {"ASSET_FLOW", "EXTERNAL_CALL"},
    "all": {
        "CALLS", "LIBRARY_CALL", "EXTERNAL_CALL", "APPLIES_MODIFIER", "OVERRIDES", "EMITS",
        "REVERTS", "READS", "READS_CONSTANT", "READS_IMMUTABLE", "WRITES",
        "DELETES", "MUTATES", "TRANSIENT_READS", "TRANSIENT_WRITES",
        "TRANSIENT_DELETES", "INITIALIZES", "ALIASES_STORAGE", "UNRESOLVED_STORAGE",
        "UNRESOLVED_MUTATION", "USES_TYPE", "IMPORTS", "INHERITS",
        "USES_LIBRARY", "ASSET_FLOW",
    },
}

DEFAULT_KINDS = EDGE_FILTERS["all"] - {
    "READS", "READS_CONSTANT", "READS_IMMUTABLE", "WRITES", "DELETES",
    "MUTATES", "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
    "INITIALIZES", "ALIASES_STORAGE", "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION",
    "ASSET_FLOW", "EMITS", "REVERTS", "IMPORTS",
}

KIND_LABELS = {
    "LIBRARY_CALL": "LIBRARY CALL",
    "CALLS": "CALLS",
    "EXTERNAL_CALL": "EXTERNAL CALL",
    "APPLIES_MODIFIER": "MODIFIER",
    "OVERRIDES": "OVERRIDES",
    "EMITS": "EMITS",
    "REVERTS": "REVERTS",
    "READS": "READS",
    "READS_CONSTANT": "READS CONSTANT",
    "READS_IMMUTABLE": "READS IMMUTABLE",
    "WRITES": "WRITES",
    "DELETES": "DELETES",
    "MUTATES": "MUTATES",
    "TRANSIENT_READS": "TRANSIENT READS",
    "TRANSIENT_WRITES": "TRANSIENT WRITES",
    "TRANSIENT_DELETES": "TRANSIENT DELETES",
    "INITIALIZES": "INITIALIZES",
    "ALIASES_STORAGE": "STORAGE ALIAS",
    "UNRESOLVED_STORAGE": "UNRESOLVED STORAGE",
    "UNRESOLVED_MUTATION": "UNRESOLVED MUTATION",
    "USES_TYPE": "USES TYPE",
    "IMPORTS": "IMPORTS",
    "INHERITS": "INHERITS",
    "USES_LIBRARY": "USES LIBRARY",
    "ASSET_FLOW": "ASSET FLOW",
}


def _is_third_party(node: dict[str, Any]) -> bool:
    if str(node.get("provenance") or "").casefold() == "third-party":
        return True
    path = str(node.get("file") or node.get("name") or "").replace("\\", "/").casefold()
    return any(part in {"node_modules", "vendor", "vendors", "third_party", "third-party"} for part in path.split("/"))


def _directory(path: str) -> str:
    parent = Path(path).parent.as_posix()
    return "." if parent in {"", "."} else parent


def _node_location(node: dict[str, Any]) -> str:
    path = str(node.get("file") or node.get("name") or "?")
    line = node.get("line")
    return f"{path}:{line}" if line is not None else path


def _node_label(node: dict[str, Any]) -> str:
    kind = str(node.get("kind") or "")
    if kind == "contract":
        return str(node.get("name") or "?")
    if kind in {"function", "modifier"}:
        return str(node.get("qualified_name") or node.get("signature") or node.get("name") or "?")
    contract = str(node.get("contract") or "")
    name = str(node.get("name") or "?")
    return f"{contract}.{name}" if contract else name


def _graph_node(
    node_id: str,
    *,
    label: str,
    kind: str,
    file: str = "",
    line: int | None = None,
    group: str = "",
    origin: str = "unknown",
    declaration_kind: str = "",
    contract: str = "",
    qualified_name: str = "",
    source_kind: str = "",
) -> dict[str, Any]:
    return {
        "id": node_id,
        "label": label,
        "type": kind,
        "file": file,
        "line": line,
        "location": f"{file}:{line}" if line is not None else file,
        "group": group or kind,
        "origin": origin,
        "declaration_kind": declaration_kind,
        "contract": contract,
        "qualified_name": qualified_name,
        "source_kind": source_kind,
    }


def build_protocol_graph(
    index: dict[str, Any],
    *,
    only: str | None = None,
    focus: str | None = None,
    depth: int = 1,
    include_third_party: bool = False,
) -> dict[str, Any]:
    """Collapse source relationships into a contract-level protocol graph."""
    if only is not None and only not in EDGE_FILTERS:
        raise ValueError(f"Unknown graph filter: {only}")

    raw_nodes = {
        str(item.get("id")): item
        for item in (index.get("nodes") or [])
        if isinstance(item, dict) and item.get("id")
    }
    contracts = {
        node_id: node for node_id, node in raw_nodes.items()
        if node.get("kind") == "contract"
        and (include_third_party or not _is_third_party(node))
    }
    contracts_by_name_file: dict[tuple[str, str], str] = {}
    contracts_by_name: dict[str, list[str]] = defaultdict(list)
    files_to_contracts: dict[str, list[str]] = defaultdict(list)
    for node_id, node in contracts.items():
        name = str(node.get("name") or "")
        file = str(node.get("file") or "")
        contracts_by_name_file[(name, file)] = node_id
        contracts_by_name[name].append(node_id)
        if file:
            files_to_contracts[file].append(node_id)

    def owner_contract(node_id: str | None) -> str | None:
        if not node_id:
            return None
        node = raw_nodes.get(str(node_id))
        if not node:
            return None
        if node.get("kind") == "contract":
            return str(node_id) if str(node_id) in contracts else None
        owner_name = str(node.get("contract") or "")
        owner_file = str(node.get("file") or "")
        exact = contracts_by_name_file.get((owner_name, owner_file))
        if exact:
            return exact
        matches = contracts_by_name.get(owner_name, [])
        return matches[0] if len(matches) == 1 else None

    mode = only or "architecture"
    selected_kinds = DEFAULT_KINDS if only is None else EDGE_FILTERS[only]
    graph_nodes: dict[str, dict[str, Any]] = {}
    aggregate: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    internal_counts: Counter[str] = Counter()
    edge_source_count = 0

    def add_contract_node(node_id: str) -> None:
        if node_id in graph_nodes:
            return
        node = contracts[node_id]
        file = str(node.get("file") or "")
        graph_nodes[node_id] = _graph_node(
            node_id,
            label=str(node.get("name") or "?"),
            kind="contract",
            file=file,
            line=node.get("line"),
            group=_directory(file),
            origin=str(node.get("provenance") or "unknown"),
            declaration_kind=str(node.get("declaration_kind") or "contract"),
            contract=str(node.get("name") or ""),
            source_kind="contract",
        )

    for node_id in contracts:
        add_contract_node(node_id)

    def add_special_node(node_id: str, label: str, kind: str, *, group: str = "external", file: str = "") -> None:
        if node_id not in graph_nodes:
            graph_nodes[node_id] = _graph_node(
                node_id, label=label, kind=kind, file=file,
                group=group, origin="external" if kind in {"external", "asset"} else "unknown",
                source_kind=kind,
            )

    def add_edge(
        source_id: str,
        target_id: str,
        kind: str,
        edge: dict[str, Any],
        *,
        label: str | None = None,
    ) -> None:
        nonlocal edge_source_count
        if source_id not in graph_nodes or target_id not in graph_nodes:
            return
        resolution = str(edge.get("resolution") or "DIRECT")
        edge_key = (source_id, target_id, kind, resolution)
        entry = aggregate.get(edge_key)
        if entry is None:
            entry = {
                "id": f"edge:{len(aggregate) + 1}",
                "source": source_id,
                "target": target_id,
                "kind": kind,
                "label": label or KIND_LABELS.get(kind, kind.replace("_", " ")),
                "count": 0,
                "resolution": resolution,
                "locations": [],
                "details": [],
            }
            aggregate[edge_key] = entry
        entry["count"] += 1
        edge_source_count += 1
        source = edge.get("source") or {}
        location = {
            "file": str(source.get("file") or edge.get("file") or ""),
            "line": source.get("line"),
            "detail": str(edge.get("access_path") or edge.get("detail") or ""),
        }
        if len(entry["locations"]) < 5 and location not in entry["locations"]:
            entry["locations"].append(location)
        detail = edge.get("method") or edge.get("operation") or edge.get("status")
        if detail and str(detail) not in entry["details"] and len(entry["details"]) < 8:
            entry["details"].append(str(detail))

    # Import relationships are file-to-file in the source index. Project them
    # onto the contracts declared in each file without manufacturing ABI calls.
    if "IMPORTS" in selected_kinds:
        for edge in index.get("edges") or []:
            if edge.get("kind") != "IMPORTS":
                continue
            source_file = raw_nodes.get(str(edge.get("from") or ""), {})
            target_file = raw_nodes.get(str(edge.get("to") or ""), {})
            source_path = str(source_file.get("name") or source_file.get("file") or "")
            target_path = str(target_file.get("name") or target_file.get("file") or edge.get("to") or "")
            source_ids = files_to_contracts.get(source_path, [])
            target_ids = files_to_contracts.get(target_path, [])
            if not source_ids:
                continue
            if target_ids:
                for source_id in source_ids:
                    for target_id in target_ids:
                        if source_id != target_id:
                            add_edge(source_id, target_id, "IMPORTS", edge)
            elif target_path and edge.get("resolution") == "UNRESOLVED":
                external_id = f"external-import:{target_path}"
                add_special_node(external_id, Path(target_path).name or target_path, "external", group=_directory(target_path), file=target_path)
                for source_id in source_ids:
                    add_edge(source_id, external_id, "IMPORTS", edge)

    storage_kinds = {
        "READS", "READS_CONSTANT", "READS_IMMUTABLE", "WRITES", "DELETES",
        "MUTATES", "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
        "INITIALIZES", "ALIASES_STORAGE", "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION",
    }
    for edge in index.get("edges") or []:
        kind = str(edge.get("kind") or "")
        if kind not in selected_kinds or kind == "IMPORTS":
            continue
        source_raw = raw_nodes.get(str(edge.get("from") or ""))
        target_raw = raw_nodes.get(str(edge.get("to") or ""))
        source_contract = owner_contract(str(edge.get("from") or ""))
        target_contract = owner_contract(str(edge.get("to") or ""))

        if kind in storage_kinds and only in {"storage", "reads", "writes", "all"}:
            if source_contract:
                add_contract_node(source_contract)
                variable = target_raw or {}
                target_id = str(edge.get("to") or "")
                target_label = str(variable.get("name") or edge.get("variable") or edge.get("access_path") or "unresolved slot")
                add_special_node(target_id, target_label, "storage", group=str(source_raw.get("contract") or "storage"), file=str(variable.get("file") or ""))
                add_edge(source_contract, target_id, kind, edge)
            continue

        if kind == "ASSET_FLOW" and only in {"assets", "all"}:
            if source_contract:
                add_contract_node(source_contract)
                asset = str(edge.get("asset") or "unknown").upper()
                direction = str(edge.get("direction") or "unresolved").upper()
                asset_id = f"asset:{asset.lower()}"
                add_special_node(asset_id, asset, "asset", group="assets")
                add_edge(source_contract, asset_id, kind, edge, label=f"{asset} {direction}")
            continue

        if kind == "EXTERNAL_CALL":
            if source_contract:
                add_contract_node(source_contract)
                if target_contract:
                    add_contract_node(target_contract)
                    if source_contract == target_contract:
                        internal_counts[source_contract] += 1
                    else:
                        add_edge(source_contract, target_contract, kind, edge)
                else:
                    # The index deliberately keeps the declared receiver/method
                    # rather than guessing an on-chain address or implementation.
                    receiver = str(edge.get("receiver") or edge.get("operation") or "unknown")
                    external_id = f"external-call:{receiver}"
                    add_special_node(external_id, f"{receiver} (external)", "external")
                    add_edge(source_contract, external_id, kind, edge)
            continue

        if kind in {"CALLS", "APPLIES_MODIFIER", "OVERRIDES"}:
            if source_contract and target_contract:
                add_contract_node(source_contract)
                add_contract_node(target_contract)
                if source_contract == target_contract:
                    internal_counts[source_contract] += 1
                else:
                    display_kind = kind
                    target_declaration = str(contracts[target_contract].get("declaration_kind") or "").casefold()
                    if kind == "CALLS" and target_declaration == "library":
                        display_kind = "LIBRARY_CALL"
                    add_edge(source_contract, target_contract, display_kind, edge)
            continue

        if kind in {"INHERITS", "USES_LIBRARY", "USES_TYPE"}:
            if source_contract and target_contract:
                add_contract_node(source_contract)
                add_contract_node(target_contract)
                if source_contract != target_contract:
                    add_edge(source_contract, target_contract, kind, edge)
            continue

        if kind in {"EMITS", "REVERTS"} and only == "all" and source_contract:
            add_contract_node(source_contract)
            target_id = str(edge.get("to") or "")
            label = str(target_raw.get("name") or edge.get("to") or kind.lower())
            add_special_node(target_id, label, "event" if kind == "EMITS" else "error")
            add_edge(source_contract, target_id, kind, edge)

    # Annotate each node with aggregated degree and internal-only relationships.
    for node in graph_nodes.values():
        node["internal_relationships"] = internal_counts.get(node["id"], 0)
        node["incoming"] = 0
        node["outgoing"] = 0
    for edge in aggregate.values():
        if edge["source"] in graph_nodes:
            graph_nodes[edge["source"]]["outgoing"] += edge["count"]
        if edge["target"] in graph_nodes:
            graph_nodes[edge["target"]]["incoming"] += edge["count"]

    graph_edges = sorted(
        aggregate.values(),
        key=lambda item: (item["kind"], item["source"], item["target"], item["resolution"]),
    )

    # Focus is a graph operation, not a textual filter: retain the selected
    # node(s) and connected neighbours up to the requested hop depth.
    focus_error = None
    if focus:
        needle = focus.strip().casefold()
        matches = [
            node_id for node_id, node in graph_nodes.items()
            if node["label"].casefold() == needle
            or node_id.casefold() == needle
            or node.get("qualified_name", "").casefold() == needle
            or node.get("contract", "").casefold() == needle
        ]
        if not matches and "." in focus:
            contract_part = focus.split(".", 1)[0].casefold()
            matches = [
                node_id for node_id, node in graph_nodes.items()
                if node.get("contract", "").casefold() == contract_part
                or node["label"].casefold() == contract_part
            ]
        if not matches:
            focus_error = f"No graph node matched '{focus}'."
        else:
            adjacency: dict[str, set[str]] = defaultdict(set)
            for edge in graph_edges:
                adjacency[edge["source"]].add(edge["target"])
                adjacency[edge["target"]].add(edge["source"])
            visited = set(matches)
            queue = deque((item, 0) for item in matches)
            while queue:
                current, level = queue.popleft()
                if level >= max(0, depth):
                    continue
                for neighbour in adjacency.get(current, set()):
                    if neighbour not in visited:
                        visited.add(neighbour)
                        queue.append((neighbour, level + 1))
            graph_nodes = {key: value for key, value in graph_nodes.items() if key in visited}
            graph_edges = [
                item for item in graph_edges
                if item["source"] in visited and item["target"] in visited
            ]

    summary = index.get("summary") or {}
    return {
        "schema_version": 1,
        "view": mode,
        "focus": focus,
        "focus_error": focus_error,
        "evidence": "STATIC_SOURCE",
        "nodes": sorted(graph_nodes.values(), key=lambda item: (item["group"], item["label"].casefold(), item["id"])),
        "edges": graph_edges,
        "summary": {
            "files": summary.get("files", 0),
            "declarations": len(contracts),
            "functions": summary.get("functions", 0),
            "source_relationships": summary.get("relationships", len(index.get("edges") or [])),
            "displayed_nodes": len(graph_nodes),
            "displayed_edges": len(graph_edges),
            "aggregated_source_edges": edge_source_count,
            "connected_nodes": sum(1 for node in graph_nodes.values() if node["incoming"] or node["outgoing"]),
            "isolated_nodes": sum(1 for node in graph_nodes.values() if not node["incoming"] and not node["outgoing"]),
            "internal_relationships": sum(internal_counts.values()),
        },
        "inventory": index.get("inventory") or {},
        "limitations": [
            "Static source relationships are not proof that a path executed or succeeded.",
            "Cross-contract links are collapsed from function/declaration edges for readability.",
            "Unresolved external calls identify source-level receivers, not deployed addresses or implementations.",
            "Storage and asset relationships are potential source effects and require runtime evidence.",
            "Third-party dependencies are hidden by default; use --include-third-party to include them.",
        ],
    }


def render_protocol_graph_terminal(graph: dict[str, Any], *, limit: int = 24) -> int:
    if graph.get("focus_error"):
        print(f"GRAPH FOCUS: {graph['focus_error']}")
        return 2

    summary = graph.get("summary") or {}
    nodes = {item["id"]: item for item in graph.get("nodes") or []}
    edges = graph.get("edges") or []
    print("LOWKEY // PROTOCOL GRAPH")
    print(
        f"{summary.get('files', 0)} Solidity files · "
        f"{summary.get('declarations', 0)} declarations · "
        f"{summary.get('functions', 0)} functions"
    )
    print(
        f"NODES  {summary.get('displayed_nodes', 0)} · "
        f"connected {summary.get('connected_nodes', 0)} · "
        f"isolated {summary.get('isolated_nodes', 0)}"
    )
    print(
        f"EDGES  {summary.get('displayed_edges', 0)} relationship groups · "
        f"{summary.get('aggregated_source_edges', 0)} source edges aggregated"
    )
    if graph.get("focus"):
        print(f"FOCUS  {graph['focus']} · depth-limited neighbourhood")
    if graph.get("view") != "architecture":
        print(f"VIEW   {str(graph.get('view')).upper()}")

    if not edges:
        print()
        print("NO CONNECTIONS FOUND")
        print("Try: lk link --only calls | lk link --only imports | lk link --include-third-party")
    else:
        print()
        print("CONTRACT CONNECTIONS")
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for edge in edges:
            grouped[edge["source"]].append(edge)
        ordered_sources = sorted(
            grouped,
            key=lambda key: (
                nodes.get(key, {}).get("group", ""),
                -sum(item["count"] for item in grouped[key]),
                nodes.get(key, {}).get("label", key).casefold(),
            ),
        )
        emitted = 0
        current_group = None
        for source_id in ordered_sources:
            source = nodes.get(source_id, {})
            group = str(source.get("group") or "other")
            if group != current_group:
                current_group = group
                print(f"{group}/")
            print(f"  [{source.get('label', source_id)}]")
            outgoing = sorted(
                grouped[source_id],
                key=lambda item: (-item["count"], item["kind"], nodes.get(item["target"], {}).get("label", "")),
            )
            for edge in outgoing:
                if emitted >= limit:
                    break
                target = nodes.get(edge["target"], {})
                label = edge["label"]
                resolution = edge["resolution"]
                count = f" ×{edge['count']}" if edge["count"] > 1 else ""
                qualifier = "" if resolution == "DIRECT" else f" [{resolution}]"
                print(f"    └── --{label}{count}--> [{target.get('label', edge['target'])}]{qualifier}")
                if edge.get("details"):
                    print(f"        via {', '.join(edge['details'][:3])}")
                if edge.get("locations"):
                    location = edge["locations"][0]
                    if location.get("file"):
                        suffix = f":{location['line']}" if location.get("line") else ""
                        print(f"        {location['file']}{suffix}")
                emitted += 1
            if emitted >= limit:
                break
        if len(edges) > emitted:
            print(f"  ... {len(edges) - emitted} additional relationship group(s); use --limit to expand")

    print()
    print("EXPLORE")
    print("  CONTRACT  lk link ContractName")
    print("  CALLS     lk link --only calls")
    print("  STORAGE   lk link ContractName --only storage")
    print("  IMPORTS   lk link --only imports")
    print("  VISUAL    lk link --format html")
    print("  INVENTORY lk link --list")
    print()
    print("EVIDENCE  Static source relationships; not runtime execution.")
    inventory = graph.get("inventory") or {}
    failures = inventory.get("uninspected") or []
    if not inventory.get("complete", True):
        print(f"WARNING  SOURCE COVERAGE INCOMPLETE ({len(failures)} uninspected item(s))")
        for item in failures[:5]:
            print(f"  {item.get('path', '?')} [{item.get('phase', 'unknown')}]: {item.get('error', 'not inspected')}")
        if len(failures) > 5:
            print(f"  ... {len(failures) - 5} more uninspected item(s)")
    return 0


def render_protocol_graph_json(graph: dict[str, Any]) -> int:
    if graph.get("focus_error"):
        print(json.dumps({"error": graph["focus_error"], "graph": graph}, indent=2, sort_keys=True))
        return 2
    print(json.dumps(graph, indent=2, sort_keys=True))
    return 0


HTML_TEMPLATE = r"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lowkey · Relationship Explorer</title>
<style>
:root{color-scheme:dark;--bg:#0a1020;--panel:#111b2f;--panel2:#15223a;--line:#2a3b57;--muted:#9aa9bf;--text:#e8eef8;--accent:#78c9ed;--green:#71c5a0;--amber:#e4b96c;--red:#df927d}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 ui-sans-serif,system-ui,sans-serif}
button,input,select{font:inherit}
button{cursor:pointer}
header{display:flex;align-items:center;gap:18px;padding:13px 18px;border-bottom:1px solid var(--line);background:#0d172a}
.brand{font-weight:850;letter-spacing:.075em}
.sub{color:var(--muted);font-size:12px;margin-top:2px}
.header-actions{display:flex;gap:8px;align-items:center;margin-left:auto}
.btn,input,select{border:1px solid #3a4d6b;border-radius:7px;background:#111d32;color:var(--text);padding:8px 10px}
.btn{font-weight:650}
.btn:hover,.contract-button:hover,.follow:hover,.relation-select:hover{border-color:var(--accent)}
.btn.primary{background:#17344a;border-color:#367b9c}
.btn:disabled{opacity:.35;cursor:not-allowed}
#kind{min-width:155px}
#warning{padding:8px 18px;background:#211c12;border-bottom:1px solid #554520;color:#f2cb76;font-size:12px}
main{display:grid;grid-template-columns:270px minmax(420px,1fr) 310px;height:calc(100vh - 105px);min-height:560px}
.panel{min-height:0;overflow:auto;background:var(--panel)}
#catalog{border-right:1px solid var(--line);padding:15px 12px}
#inspector{border-left:1px solid var(--line);padding:16px}
.panel-heading{font-size:11px;font-weight:800;letter-spacing:.12em;color:var(--muted);margin:0 0 10px}
#search{width:100%;margin-bottom:9px}
.catalog-meta{font-size:11px;color:var(--muted);margin:0 0 9px}
.folder-label{padding:12px 7px 5px;color:#8194ae;font-size:10px;font-weight:800;letter-spacing:.1em;text-transform:uppercase}
.contract-button{display:flex;align-items:center;justify-content:space-between;width:100%;gap:8px;padding:9px 8px;margin:2px 0;border:1px solid transparent;border-radius:7px;background:transparent;color:var(--text);text-align:left}
.contract-button.active{background:#1a3046;border-color:#3c7894}
.contract-name{font-weight:650;overflow-wrap:anywhere}
.contract-meta{display:block;color:var(--muted);font-size:10px;margin-top:2px}
.count{flex:0 0 auto;color:#a9bdd4;font-size:11px;font-variant-numeric:tabular-nums}
#workspace{min-width:0;min-height:0;overflow:auto;padding:20px 22px}
.crumbs{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:17px;color:var(--muted);font-size:12px}
.crumb{border:0;padding:3px 5px;background:transparent;color:var(--accent);border-radius:4px}
.crumb.current{color:var(--text);font-weight:700}
h1{font-size:23px;line-height:1.2;margin:0 0 7px;overflow-wrap:anywhere}
.lead{margin:0;color:var(--muted)}
.summary-strip{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0 20px}
.summary-chip{border:1px solid var(--line);background:#101c30;border-radius:7px;padding:7px 10px;font-size:12px;color:#c9d6e8}
.summary-chip b{color:#fff;font-size:14px;margin-right:4px}
.section-title{display:flex;align-items:center;justify-content:space-between;margin:22px 0 9px;font-size:11px;font-weight:850;letter-spacing:.11em;color:#b4c3d8;text-transform:uppercase}
.direction-group{margin:18px 0 24px}
.direction-heading{display:flex;align-items:center;gap:8px;margin-bottom:8px;font-size:12px;font-weight:850;letter-spacing:.09em}
.direction-heading.out{color:var(--green)}
.direction-heading.in{color:var(--amber)}
.direction-heading .line{height:1px;background:var(--line);flex:1}
.relation-list{display:grid;gap:7px}
.relation-card{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px;align-items:center;border:1px solid var(--line);background:#101b2e;border-radius:9px;padding:10px 11px}
.relation-card:hover{border-color:#496684}
.relation-select{display:block;min-width:0;border:0;background:transparent;color:var(--text);padding:0;text-align:left}
.relation-top{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.kind-pill,.status-pill{display:inline-block;border:1px solid #405674;border-radius:5px;padding:2px 6px;font-size:10px;font-weight:750;letter-spacing:.035em;color:#c7d7e9}
.kind-pill{background:#182940}
.status-pill.direct{color:#92d8b7;border-color:#366a55}
.status-pill.inferred{color:#f0c875;border-color:#78613b}
.status-pill.unresolved{color:#ef9c8b;border-color:#784a42}
.peer-name{font-weight:750;font-size:14px;overflow-wrap:anywhere}
.relation-detail{display:block;margin-top:5px;color:var(--muted);font-size:11px;overflow-wrap:anywhere}
.relation-count{color:#b6c5d8;font-size:11px;font-variant-numeric:tabular-nums}
.follow{border:1px solid #3a5872;border-radius:6px;background:#172b42;color:#ccecff;padding:7px 9px;font-size:11px;font-weight:750;white-space:nowrap}
.empty{border:1px dashed #40516b;border-radius:8px;padding:15px;color:var(--muted);font-size:13px}
#inspector h2{font-size:12px;letter-spacing:.1em;margin:17px 0 7px;color:#b3c3d8}
#inspector h2:first-child{margin-top:0}
#inspect-title{font-size:18px;font-weight:800;overflow-wrap:anywhere}
#inspect-sub{color:var(--muted);font-size:12px;margin-top:3px}
.inspect-row{margin:9px 0;color:#c4d2e4;font-size:12px;overflow-wrap:anywhere}
.inspect-row b{color:#f0f4fb}
.location{display:block;color:#a9d8ee;background:#0c1728;border:1px solid #263e58;border-radius:6px;padding:7px 8px;margin:6px 0;font:11px/1.45 ui-monospace,monospace;overflow-wrap:anywhere}
#suggestions{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:9px;margin-top:14px}
.suggestion{display:block;text-align:left;padding:12px;border:1px solid var(--line);border-radius:9px;background:#101c30;color:var(--text)}
.suggestion:hover{border-color:var(--accent)}
.suggestion strong{display:block;font-size:14px}
.suggestion span{display:block;margin-top:4px;color:var(--muted);font-size:11px}
.steps{margin:12px 0 0;padding-left:18px;color:var(--muted);font-size:12px}
.steps li{margin:6px 0}
.limit-note{font-size:11px;color:var(--muted);line-height:1.5}
@media(max-width:1100px){main{grid-template-columns:235px minmax(360px,1fr)}#inspector{grid-column:1/-1;border-left:0;border-top:1px solid var(--line);min-height:200px}#workspace{grid-column:2;grid-row:1}#catalog{grid-column:1;grid-row:1}}
@media(max-width:760px){header{align-items:flex-start;flex-wrap:wrap}.header-actions{width:100%;margin-left:0}main{display:flex;flex-direction:column;height:auto;min-height:0}#catalog{max-height:270px;border-right:0;border-bottom:1px solid var(--line)}#workspace{overflow:visible;padding:17px}#inspector{border-left:0;border-top:1px solid var(--line)}}
</style>
</head>
<body>
<header>
  <div>
    <div class="brand">LOWKEY // RELATIONSHIP EXPLORER</div>
    <div class="sub" id="subtitle">Follow source relationships contract by contract</div>
  </div>
  <div class="header-actions">
    <select id="kind" aria-label="Filter relationship type"><option value="">All relationship types</option></select>
    <button class="btn" id="back" disabled>← Back</button>
    <button class="btn" id="overview">Project overview</button>
  </div>
</header>
<div id="warning">STATIC SOURCE EVIDENCE — these links are found in source code; they do not prove a path executed or succeeded on-chain.</div>
<main>
  <aside class="panel" id="catalog">
    <div class="panel-heading">CONTRACTS</div>
    <input id="search" placeholder="Search contracts…" aria-label="Search contracts">
    <div class="catalog-meta" id="catalog-meta"></div>
    <div id="contract-list"></div>
  </aside>
  <section id="workspace">
    <div class="crumbs" id="crumbs"></div>
    <h1 id="focus-title">Choose a contract to begin</h1>
    <p class="lead" id="focus-lead">Start with one contract. Lowkey will show only its direct incoming and outgoing relationships.</p>
    <div class="summary-strip" id="summary-strip"></div>
    <div id="connections"></div>
  </section>
  <aside class="panel" id="inspector">
    <div id="inspect-title">How to follow the graph</div>
    <div id="inspect-sub">A focused investigation, not a wall of lines.</div>
    <ol class="steps">
      <li>Choose a contract from the left.</li>
      <li>Read its outgoing and incoming links separately.</li>
      <li>Check the source file and line for each link.</li>
      <li>Use Follow to move to the connected contract.</li>
      <li>Use Back to retrace your steps.</li>
    </ol>
    <h2>Evidence boundary</h2>
    <p class="limit-note">A source relationship is a lead for investigation. It does not prove runtime reachability, execution, successful transfer, or deployed implementation identity.</p>
    <div id="limits"></div>
  </aside>
</main>
<script id="graph-data" type="application/json">__GRAPH_DATA__</script>
<script>
(function(){
"use strict";
const DATA=JSON.parse(document.getElementById("graph-data").textContent);
const nodes=DATA.nodes||[],edges=DATA.edges||[];
const byId=new Map(nodes.map(function(n){return [n.id,n]}));
const contracts=nodes.filter(function(n){return n.type==="contract"}).sort(function(a,b){
  return (a.group||"").localeCompare(b.group||"") || a.label.localeCompare(b.label);
});
const rankedContracts=contracts.slice().sort(function(a,b){
  return ((b.incoming||0)+(b.outgoing||0))-((a.incoming||0)+(a.outgoing||0)) || a.label.localeCompare(b.label);
});
const kind=document.getElementById("kind"),search=document.getElementById("search");
const list=document.getElementById("contract-list"),connections=document.getElementById("connections");
let activeId=null,history=[],activeEdge=null;

function make(tag,className,text){
  const item=document.createElement(tag);
  if(className)item.className=className;
  if(text!==undefined&&text!==null)item.textContent=String(text);
  return item;
}
function add(parent,tag,className,text){
  const item=make(tag,className,text);parent.appendChild(item);return item;
}
function degree(n){return (n.incoming||0)+(n.outgoing||0)}
function visibleEdges(){return edges.filter(function(e){return !kind.value||e.kind===kind.value})}
function peerFor(edge,direction){return byId.get(direction==="out"?edge.target:edge.source)}
function statusClass(value){return String(value||"").toLowerCase()}
function locationText(loc){
  if(!loc||!loc.file)return "";
  return loc.file+(loc.line?":"+loc.line:"")+(loc.detail?" · "+loc.detail:"");
}
function clear(parent){parent.replaceChildren()}
function renderKindOptions(){
  Array.from(new Set(edges.map(function(e){return e.kind}))).sort().forEach(function(k){
    const option=make("option","",k.replaceAll("_"," "));
    option.value=k;kind.appendChild(option);
  });
}
function renderCatalog(){
  clear(list);
  const query=search.value.trim().toLowerCase();
  const matched=contracts.filter(function(n){
    return !query||n.label.toLowerCase().includes(query)||(n.file||"").toLowerCase().includes(query);
  });
  document.getElementById("catalog-meta").textContent=matched.length+" of "+contracts.length+" contracts · sorted by connected relationships";
  let folder="";
  matched.forEach(function(n){
    const nextFolder=n.group||"Other";
    if(nextFolder!==folder){folder=nextFolder;add(list,"div","folder-label",folder)}
    const button=make("button","contract-button"+(activeId===n.id?" active":""));
    button.type="button";
    const main=add(button,"span","");
    add(main,"span","contract-name",n.label);
    add(main,"span","contract-meta",n.file||"Source location unavailable");
    add(button,"span","count",degree(n)+" links");
    button.addEventListener("click",function(){openNode(n.id,true)});
    list.appendChild(button);
  });
  if(!matched.length)add(list,"div","empty","No contracts match that search.");
}
function renderCrumbs(){
  const root=document.getElementById("crumbs");clear(root);
  const home=make("button","crumb","Project");
  home.type="button";home.addEventListener("click",showOverview);root.appendChild(home);
  history.forEach(function(id,index){
    const node=byId.get(id);if(!node)return;
    add(root,"span","","›");
    const button=make("button","crumb"+(index===history.length-1?" current":""),node.label);
    button.type="button";
    button.addEventListener("click",function(){history=history.slice(0,index+1);activeId=id;activeEdge=null;render()});
    root.appendChild(button);
  });
  document.getElementById("back").disabled=history.length<2;
}
function renderOverview(){
  const heading=document.getElementById("focus-title");
  heading.textContent="Choose a contract to begin";
  document.getElementById("focus-lead").textContent="This project has "+contracts.length+" contract nodes and "+edges.length+" relationship groups. Pick one contract; Lowkey will expose its direct connections without drawing the entire protocol at once.";
  const strip=document.getElementById("summary-strip");clear(strip);
  [["Contracts",contracts.length],["Relationship groups",edges.length],["Source files",(DATA.summary||{}).files||0]].forEach(function(item){
    const chip=add(strip,"div","summary-chip","");
    add(chip,"b","",item[1]);chip.appendChild(document.createTextNode(item[0]));
  });
  clear(connections);
  add(connections,"div","section-title","GOOD STARTING POINTS");
  add(connections,"p","lead","These contracts have the most indexed relationships. They are starting points, not audit-priority rankings.");
  const suggestions=add(connections,"div","");
  suggestions.id="suggestions";
  rankedContracts.slice(0,8).forEach(function(n){
    const button=make("button","suggestion");
    button.type="button";
    add(button,"strong","",n.label);
    add(button,"span","",degree(n)+" indexed links · "+(n.file||""));
    button.addEventListener("click",function(){openNode(n.id,true)});
    suggestions.appendChild(button);
  });
  if(!contracts.length)add(connections,"div","empty","No contract declarations were available in this graph.");
  showNodeInspector(null);
}
function relationCard(edge,direction){
  const peer=peerFor(edge,direction);
  const card=make("div","relation-card");
  const inspect=make("button","relation-select");
  inspect.type="button";
  const top=add(inspect,"span","relation-top");
  add(top,"span","kind-pill",edge.label||edge.kind);
  add(top,"span","status-pill "+statusClass(edge.resolution),edge.resolution||"UNKNOWN");
  const peerLabel=peer?peer.label:(direction==="out"?edge.target:edge.source);
  add(inspect,"span","peer-name",peerLabel);
  const loc=(edge.locations||[])[0];
  add(inspect,"span","relation-detail",(edge.count>1?edge.count+" source relationships · ":"")+(locationText(loc)||"Source location unavailable"));
  inspect.addEventListener("click",function(){activeEdge={edge:edge,direction:direction};showEdgeInspector(edge,direction)});
  card.appendChild(inspect);
  const canFollow=!!peer&&degree(peer)>0;
  if(canFollow){
    const follow=make("button","follow","Follow →");
    follow.type="button";
    follow.title="Open "+peer.label+" and inspect its direct relationships";
    follow.addEventListener("click",function(){openNode(peer.id,true)});
    card.appendChild(follow);
  }else{
    const marker=make("span","relation-count",edge.count>1?"×"+edge.count:"");
    card.appendChild(marker);
  }
  return card;
}
function renderDirection(title,direction,rows){
  const group=add(connections,"section","direction-group");
  const heading=add(group,"div","direction-heading "+(direction==="out"?"out":"in"));
  add(heading,"span","",title);
  add(heading,"span","line","");
  const list=add(group,"div","relation-list");
  if(!rows.length){add(list,"div","empty","No "+direction+" relationships in this view.");return}
  rows.forEach(function(edge){list.appendChild(relationCard(edge,direction))});
}
function renderFocus(){
  const node=byId.get(activeId);
  if(!node){renderOverview();return}
  document.getElementById("focus-title").textContent=node.label;
  document.getElementById("focus-lead").textContent=(node.declaration_kind||node.type||"node").toUpperCase()+" · "+(node.file||node.group||"Source relationship endpoint");
  const all=visibleEdges();
  const outgoing=all.filter(function(e){return e.source===activeId}).sort(function(a,b){return b.count-a.count||a.label.localeCompare(b.label)});
  const incoming=all.filter(function(e){return e.target===activeId}).sort(function(a,b){return b.count-a.count||a.label.localeCompare(b.label)});
  const strip=document.getElementById("summary-strip");clear(strip);
  [["Outgoing",outgoing.length],["Incoming",incoming.length],["Source links",outgoing.concat(incoming).reduce(function(sum,e){return sum+(e.count||1)},0)]].forEach(function(item){
    const chip=add(strip,"div","summary-chip","");
    add(chip,"b","",item[1]);chip.appendChild(document.createTextNode(item[0]));
  });
  clear(connections);
  add(connections,"div","section-title","DIRECT RELATIONSHIPS");
  add(connections,"p","lead","Select a relationship to inspect its evidence. Use Follow to move one step through the protocol.");
  renderDirection("OUTGOING · RELATIONSHIPS FROM THIS CONTRACT", "out",outgoing);
  renderDirection("INCOMING · RELATIONSHIPS TO THIS CONTRACT", "in",incoming);
  showNodeInspector(node);
}
function showNodeInspector(node){
  clear(document.getElementById("inspect-title"));
  clear(document.getElementById("inspect-sub"));
  clear(document.getElementById("limits"));
  document.getElementById("inspect-title").textContent=node?node.label:"How to follow the graph";
  document.getElementById("inspect-sub").textContent=node?(node.declaration_kind||node.type||"node").toUpperCase()+" · "+(node.origin||"origin not classified"):"A focused investigation, not a wall of lines.";
  const limits=document.getElementById("limits");
  if(node){
    [["Source",node.location],["Directory",node.group],["Incoming indexed links",node.incoming],["Outgoing indexed links",node.outgoing],["Internal relationships",node.internal_relationships]].forEach(function(pair){
      if(pair[1]===undefined||pair[1]===null||pair[1]==="")return;
      const row=add(limits,"p","inspect-row","");
      const b=add(row,"b","",pair[0]+": ");
      row.appendChild(document.createTextNode(String(pair[1])));
    });
    add(limits,"h2","","FUNCTION-LEVEL TRACE");
    add(limits,"p","limit-note","This view aggregates relationships at contract level. For the actual function call tree, use: lk trace source ContractName.functionName");
  }else{
    (DATA.limitations||[]).forEach(function(t){add(limits,"p","limit-note",t)});
  }
}
function showEdgeInspector(edge,direction){
  const peer=peerFor(edge,direction);
  document.getElementById("inspect-title").textContent=edge.label||edge.kind;
  document.getElementById("inspect-sub").textContent=(direction==="out"?"OUTGOING FROM ":"INCOMING TO ")+(byId.get(activeId)||{}).label;
  const limits=document.getElementById("limits");clear(limits);
  [["Direction",direction==="out"?"Selected contract → connected node":"Connected node → selected contract"],["Connected node",peer?peer.label:(direction==="out"?edge.target:edge.source)],["Relationship",edge.kind],["Aggregated source matches",edge.count],["Resolution",edge.resolution]].forEach(function(pair){
    const row=add(limits,"p","inspect-row","");
    add(row,"b","",""+pair[0]+": ");
    row.appendChild(document.createTextNode(String(pair[1]===undefined?"unknown":pair[1])));
  });
  add(limits,"h2","","SOURCE LOCATIONS");
  const locations=edge.locations||[];
  if(!locations.length)add(limits,"p","limit-note","No source location was retained for this relationship.");
  locations.forEach(function(loc){
    add(limits,"code","location",locationText(loc)||"Source location unavailable");
  });
  if(edge.details&&edge.details.length){
    add(limits,"h2","","DETAILS");
    edge.details.forEach(function(detail){add(limits,"p","inspect-row",detail)});
  }
}
function render(){
  renderCatalog();renderCrumbs();
  if(activeId)renderFocus();else renderOverview();
  if(activeEdge&&activeId){
    const found=visibleEdges().find(function(e){return e.id===activeEdge.edge.id});
    if(found)showEdgeInspector(found,activeEdge.direction);
    else activeEdge=null;
  }
}
function openNode(id,push){
  if(!byId.has(id))return;
  if(push&&(history.length===0||history[history.length-1]!==id))history.push(id);
  activeId=id;activeEdge=null;render();
}
function showOverview(){history=[];activeId=null;activeEdge=null;render()}
document.getElementById("back").addEventListener("click",function(){
  if(history.length>1){history.pop();activeId=history[history.length-1];activeEdge=null;render()}
});
document.getElementById("overview").addEventListener("click",showOverview);
search.addEventListener("input",renderCatalog);
kind.addEventListener("change",function(){activeEdge=null;render()});
renderKindOptions();
(document.getElementById("subtitle")).textContent=contracts.length+" contracts · "+edges.length+" relationship groups · choose a contract to follow";
(DATA.limitations||[]).forEach(function(t){add(document.getElementById("limits"),"p","limit-note",t)});
if(DATA.focus){
  const wanted=String(DATA.focus).split(".")[0].toLowerCase();
  const found=contracts.find(function(n){return n.label.toLowerCase()===String(DATA.focus).toLowerCase()||n.label.toLowerCase()===wanted});
  if(found)history.push(found.id),activeId=found.id;
}
render();
})();
</script>
</body>
</html>

"""


def render_protocol_graph_html(graph: dict[str, Any], output_path: str | Path) -> Path:
    if graph.get("focus_error"):
        raise ValueError(str(graph["focus_error"]))
    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(graph, ensure_ascii=False, separators=(",", ":"))
    # Prevent a source-derived label from terminating the embedded JSON script.
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    document = HTML_TEMPLATE.replace("__GRAPH_DATA__", payload)
    fd, temporary = tempfile.mkstemp(prefix=".lk-graph-", suffix=".html", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(document)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass
    return destination


def render_project_graph(
    index: dict[str, Any],
    *,
    root: str | Path = ".",
    only: str | None = None,
    focus: str | None = None,
    depth: int = 1,
    limit: int = 24,
    include_third_party: bool = False,
    output: str | Path | None = None,
    output_format: str = "terminal",
) -> int:
    """Render the primary project graph in terminal, JSON, or offline HTML."""
    try:
        graph = build_protocol_graph(
            index, only=only, focus=focus, depth=depth,
            include_third_party=include_third_party,
        )
        if graph.get("focus_error"):
            print(f"GRAPH FOCUS: {graph['focus_error']}")
            return 2
        if output_format == "json":
            return render_protocol_graph_json(graph)
        if output_format == "html":
            if output:
                destination = Path(output).expanduser()
                if not destination.is_absolute():
                    destination = Path(root) / destination
            else:
                destination = Path(root) / ".lowkey" / "link-graph.html"
            saved = render_protocol_graph_html(graph, destination)
            print("LOWKEY // PROTOCOL GRAPH")
            print(f"GRAPH SAVED  {saved}")
            print(f"NODES        {len(graph['nodes'])}")
            print(f"CONNECTIONS  {len(graph['edges'])}")
            print("OPEN         xdg-open " + str(saved))
            print("EVIDENCE     Static source relationships; not runtime execution.")
            return 0
        return render_protocol_graph_terminal(graph, limit=limit)
    except (OSError, ValueError, TypeError) as error:
        print(f"GRAPH ERROR: {error}")
        return 2
