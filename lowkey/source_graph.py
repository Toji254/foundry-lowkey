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
    "calls": {"CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER", "OVERRIDES"},
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
        "CALLS", "EXTERNAL_CALL", "APPLIES_MODIFIER", "OVERRIDES", "EMITS",
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
    "ASSET_FLOW", "EMITS", "REVERTS",
}

KIND_LABELS = {
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

        if kind == "ASSET_FLOW" and only == "assets":
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
                    add_edge(source_contract, target_contract, kind, edge)
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


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Lowkey · Protocol Graph</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#111a2e;--line:#26344e;--muted:#91a0b9;--text:#e8eef8;--accent:#7dd3fc}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,sans-serif}
header{display:flex;gap:14px;align-items:center;flex-wrap:wrap;padding:14px 18px;border-bottom:1px solid var(--line);background:#0d1527}
.brand{font-weight:800;letter-spacing:.08em}.sub{color:var(--muted);font-size:12px}
.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-left:auto}
input,select,button{background:#101b30;border:1px solid #33425f;color:var(--text);border-radius:7px;padding:8px 10px;font:inherit}
input{min-width:210px}button{cursor:pointer}button:hover{border-color:var(--accent)}
main{display:grid;grid-template-columns:minmax(0,1fr) 310px;height:calc(100vh - 102px);min-height:520px}
#canvas{position:relative;overflow:hidden;background-image:radial-gradient(#26344e 1px,transparent 1px);background-size:24px 24px}
svg{width:100%;height:100%;display:block;touch-action:none}
aside{overflow:auto;border-left:1px solid var(--line);background:var(--panel);padding:16px}
h1{font-size:17px;margin:0 0 4px}h2{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:18px 0 8px}
p{margin:7px 0}.muted{color:var(--muted)}.metric{display:inline-block;margin:10px 12px 0 0}.metric b{font-size:18px;display:block}
#warning{padding:9px 18px;color:#fbbf24;border-bottom:1px solid #58451c;background:#211b12;font-size:12px}
.edge{stroke-width:1.8;opacity:.72;fill:none}.edge.dim{opacity:.08}.edge.selected{opacity:1;stroke-width:3.2}
.node rect{stroke-width:1.5;rx:8;fill:#14223a;stroke:#50627f}.node text{font-size:12px;fill:var(--text);pointer-events:none}
.node.contract rect{fill:#142c40;stroke:#3b9ac4}.node.external rect{fill:#302719;stroke:#bb8b40}.node.asset rect{fill:#2e2137;stroke:#b184c8}
.node.storage rect{fill:#172b22;stroke:#65a681}.node.module rect{fill:#202943;stroke:#8192b5}
.node.selected rect{stroke:#f5d36a;stroke-width:3}.node.dim{opacity:.2}.node{cursor:pointer}
.legend{display:flex;gap:10px;flex-wrap:wrap;color:var(--muted);font-size:11px;margin-top:10px}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:4px}
.pill{display:inline-block;padding:2px 6px;border:1px solid #40516f;border-radius:5px;color:#b8c7df;font-size:11px;margin:2px}
a{color:var(--accent)}code{color:#b6e3ff;overflow-wrap:anywhere}
@media(max-width:850px){main{grid-template-columns:1fr;height:auto;min-height:calc(100vh - 120px)}#canvas{height:65vh;min-height:420px}aside{border-left:0;border-top:1px solid var(--line)}header{align-items:flex-start}.toolbar{margin-left:0;width:100%}}
</style>
</head>
<body>
<header>
  <div><div class="brand">LOWKEY // PROTOCOL GRAPH</div><div class="sub" id="subtitle">Static source relationships · offline interactive map</div></div>
  <div class="toolbar">
    <input id="search" placeholder="Find a contract or dependency…" aria-label="Search graph">
    <select id="kind" aria-label="Relationship type"><option value="">All relationships</option></select>
    <button id="fit">Fit graph</button>
    <button id="reset">Reset</button>
  </div>
</header>
<div id="warning">STATIC SOURCE EVIDENCE — a relationship in this graph does not prove runtime execution, successful calls, or deployed implementation identity.</div>
<main>
  <section id="canvas"><svg id="graph" role="img" aria-label="Interactive contract relationship graph"><defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#91a0b9"/></marker></defs><g id="viewport"><g id="edges"></g><g id="nodes"></g></g></svg></section>
  <aside>
    <h1 id="detail-title">Protocol overview</h1>
    <p class="muted" id="detail-sub">Select a node to inspect its connections.</p>
    <div id="metrics"></div>
    <div class="legend"><span><i class="dot" style="background:#3b9ac4"></i>Contract</span><span><i class="dot" style="background:#65a681"></i>Storage</span><span><i class="dot" style="background:#bb8b40"></i>External</span><span><i class="dot" style="background:#b184c8"></i>Asset</span></div>
    <h2>Selected node</h2><div id="details" class="muted">No node selected.</div>
    <h2>Connections</h2><div id="connections" class="muted">Choose a node to see its incoming and outgoing relationships.</div>
    <h2>Analysis limits</h2><div id="limits" class="muted"></div>
  </aside>
</main>
<script id="graph-data" type="application/json">__GRAPH_DATA__</script>
<script>
(function(){
"use strict";
const DATA=JSON.parse(document.getElementById("graph-data").textContent);
const svg=document.getElementById("graph"),viewport=document.getElementById("viewport"),edgeLayer=document.getElementById("edges"),nodeLayer=document.getElementById("nodes");
const NS="http://www.w3.org/2000/svg",nodes=DATA.nodes||[],edges=DATA.edges||[],byId=new Map(nodes.map(n=>[n.id,n]));
const kinds=[...new Set(edges.map(e=>e.kind))].sort(),kindSelect=document.getElementById("kind");
kinds.forEach(k=>{const o=document.createElement("option");o.value=k;o.textContent=k.replaceAll("_"," ");kindSelect.appendChild(o)});
document.getElementById("subtitle").textContent=(DATA.summary.displayed_nodes||0)+" nodes · "+(DATA.summary.displayed_edges||0)+" relationship groups · "+(DATA.summary.files||0)+" source files";
document.getElementById("metrics").innerHTML="";
["displayed_nodes","displayed_edges","connected_nodes"].forEach((k,i)=>{const d=document.createElement("span");d.className="metric";const b=document.createElement("b");b.textContent=DATA.summary[k]||0;const s=document.createElement("span");s.className="muted";s.textContent=["Nodes","Links","Connected"][i];d.append(b,s);document.getElementById("metrics").appendChild(d)});
(DATA.limitations||[]).forEach(t=>{const p=document.createElement("p");p.textContent="• "+t;document.getElementById("limits").appendChild(p)});
const positions=new Map();let selected=null,scale=1,tx=0,ty=0,drag=null,pan=null;
const width=1600,height=1050;
function initialLayout(){
 const groups=[...new Set(nodes.map(n=>n.group||n.type))].sort(),buckets=new Map(groups.map(g=>[g,[]]));
 nodes.forEach(n=>buckets.get(n.group||n.type).push(n));
 groups.forEach((g,gi)=>{
   const centerAngle=(gi/Math.max(groups.length,1))*Math.PI*2-Math.PI/2;
   const radius=groups.length<2?0:Math.min(350,180+groups.length*13);
   const cx=width/2+Math.cos(centerAngle)*radius,cy=height/2+Math.sin(centerAngle)*radius;
   const bucket=buckets.get(g),ring=Math.max(110,bucket.length*17);
   bucket.forEach((n,i)=>{const a=(i/Math.max(bucket.length,1))*Math.PI*2;positions.set(n.id,{x:cx+Math.cos(a)*ring,y:cy+Math.sin(a)*ring})});
 });
 // A small deterministic force pass separates overlaps and pulls connected nodes together.
 for(let step=0;step<90;step++){
   const delta=new Map(nodes.map(n=>[n.id,{x:0,y:0}]));
   for(let i=0;i<nodes.length;i++)for(let j=i+1;j<nodes.length;j++){
     const a=positions.get(nodes[i].id),b=positions.get(nodes[j].id),dx=a.x-b.x,dy=a.y-b.y,d2=dx*dx+dy*dy+20;
     const f=4200/d2,fx=dx*f,fy=dy*f;delta.get(nodes[i].id).x+=fx;delta.get(nodes[i].id).y+=fy;delta.get(nodes[j].id).x-=fx;delta.get(nodes[j].id).y-=fy;
   }
   edges.forEach(e=>{const a=positions.get(e.source),b=positions.get(e.target);if(!a||!b)return;const dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1,f=(d-180)*.006;delta.get(e.source).x+=dx*f;delta.get(e.source).y+=dy*f;delta.get(e.target).x-=dx*f;delta.get(e.target).y-=dy*f});
   nodes.forEach(n=>{const p=positions.get(n.id),d=delta.get(n.id);p.x=Math.max(70,Math.min(width-70,p.x+d.x*.025));p.y=Math.max(70,Math.min(height-70,p.y+d.y*.025))});
 }
}
function el(tag,attrs){const e=document.createElementNS(NS,tag);Object.entries(attrs||{}).forEach(([k,v])=>e.setAttribute(k,v));return e}
function sizeFor(n){return {w:Math.max(116,Math.min(230,(n.label||"").length*7.2+28)),h:38}}
function render(){
 edgeLayer.replaceChildren();nodeLayer.replaceChildren();
 const chosenKind=kindSelect.value,query=document.getElementById("search").value.trim().toLowerCase();
 const visibleEdges=edges.filter(e=>(!chosenKind||e.kind===chosenKind));
 const neighbour=new Set();if(selected){neighbour.add(selected);visibleEdges.forEach(e=>{if(e.source===selected)neighbour.add(e.target);if(e.target===selected)neighbour.add(e.source)})}
 visibleEdges.forEach(e=>{
   const a=positions.get(e.source),b=positions.get(e.target);if(!a||!b)return;
   const line=el("line",{x1:a.x,y1:a.y,x2:b.x,y2:b.y,class:"edge"+(selected&&e.source!==selected&&e.target!==selected?" dim":"")+(selected&&(e.source===selected||e.target===selected)?" selected":""),stroke:edgeColor(e.kind),"marker-end":"url(#arrow)"});
   const title=el("title");title.textContent=e.label+" ×"+e.count+" · "+e.resolution;line.appendChild(title);edgeLayer.appendChild(line);
 });
 nodes.forEach(n=>{
   const p=positions.get(n.id),s=sizeFor(n),match=!query||n.label.toLowerCase().includes(query)||n.file.toLowerCase().includes(query);
   const active=!selected||neighbour.has(n.id),g=el("g",{class:"node "+n.type+(selected===n.id?" selected":"")+(active&&match?"":" dim"),transform:"translate("+(p.x-s.w/2)+","+(p.y-s.h/2)+")"});
   const rect=el("rect",{width:s.w,height:s.h});const text=el("text",{x:12,y:23});text.textContent=n.label.length>29?n.label.slice(0,26)+"…":n.label;
   const title=el("title");title.textContent=n.label+" · "+(n.location||n.type);g.append(rect,text,title);
   g.addEventListener("click",ev=>{ev.stopPropagation();selected=n.id;showDetails(n);render()});
   g.addEventListener("pointerdown",ev=>{ev.stopPropagation();drag={id:n.id,startX:ev.clientX,startY:ev.clientY,origin:{...p}};g.setPointerCapture(ev.pointerId)});
   g.addEventListener("pointermove",ev=>{if(!drag||drag.id!==n.id)return;const rectSvg=svg.getBoundingClientRect();const dx=(ev.clientX-drag.startX)*(width/rectSvg.width)/scale,dy=(ev.clientY-drag.startY)*(height/rectSvg.height)/scale;positions.set(n.id,{x:drag.origin.x+dx,y:drag.origin.y+dy});render()});
   g.addEventListener("pointerup",()=>{drag=null});nodeLayer.appendChild(g);
 });
}
function showDetails(n){
 document.getElementById("detail-title").textContent=n.label;
 document.getElementById("detail-sub").textContent=(n.type||"node").toUpperCase()+" · "+(n.origin||"unknown");
 const d=document.getElementById("details");d.replaceChildren();
 [["Location",n.location],["Directory",n.group],["Declaration",n.declaration_kind],["Internal relationships",n.internal_relationships],["Incoming",n.incoming],["Outgoing",n.outgoing]].forEach(([k,v])=>{if(v===undefined||v===null||v==="")return;const p=document.createElement("p"),b=document.createElement("b");b.textContent=k+": ";p.append(b,document.createTextNode(String(v)));d.appendChild(p)});
 const c=document.getElementById("connections");c.replaceChildren();
 const rows=edges.filter(e=>e.source===n.id||e.target===n.id);
 rows.slice(0,80).forEach(e=>{const p=document.createElement("p"),other=byId.get(e.source===n.id?e.target:e.source);p.textContent=(e.source===n.id?"→ ":"← ")+(other?other.label:e.target)+" · "+e.label+" ×"+e.count+" ["+e.resolution+"]";c.appendChild(p)});
 if(!rows.length)c.textContent="No displayed relationships for this node.";
}
function applyTransform(){viewport.setAttribute("transform","translate("+tx+" "+ty+") scale("+scale+")")}
function fit(){if(!nodes.length)return;const xs=nodes.map(n=>positions.get(n.id).x),ys=nodes.map(n=>positions.get(n.id).y),minX=Math.min(...xs)-160,maxX=Math.max(...xs)+160,minY=Math.min(...ys)-120,maxY=Math.max(...ys)+120;const box=svg.getBoundingClientRect(),sx=box.width/(maxX-minX),sy=box.height/(maxY-minY);scale=Math.max(.25,Math.min(1.6,Math.min(sx,sy)));tx=(box.width/scale-(minX+maxX))/2;ty=(box.height/scale-(minY+maxY))/2;applyTransform()}
function edgeColor(kind){return ({INHERITS:"#e6ba65",USES_LIBRARY:"#9b8bd5",USES_TYPE:"#7ba5d8",IMPORTS:"#8497b5",CALLS:"#63b6a0",EXTERNAL_CALL:"#d58b5c",APPLIES_MODIFIER:"#83a8d4",ASSET_FLOW:"#bd88d2",READS:"#6ea6a1",WRITES:"#e18b72"})[kind]||"#8292aa"}
svg.addEventListener("wheel",ev=>{ev.preventDefault();const factor=ev.deltaY<0?1.12:.89;scale=Math.max(.18,Math.min(3,scale*factor));applyTransform()},{passive:false});
svg.addEventListener("pointerdown",ev=>{if(ev.target!==svg&&ev.target.tagName!=="g")return;pan={x:ev.clientX,y:ev.clientY,tx,ty}});
svg.addEventListener("pointermove",ev=>{if(!pan)return;const r=svg.getBoundingClientRect();tx=pan.tx+(ev.clientX-pan.x)*(width/r.width)/scale;ty=pan.ty+(ev.clientY-pan.y)*(height/r.height)/scale;applyTransform()});
svg.addEventListener("pointerup",()=>{pan=null});svg.addEventListener("click",()=>{selected=null;document.getElementById("detail-title").textContent="Protocol overview";document.getElementById("detail-sub").textContent="Select a node to inspect its connections.";document.getElementById("details").textContent="No node selected.";document.getElementById("connections").textContent="Choose a node to see its incoming and outgoing relationships.";render()});
document.getElementById("search").addEventListener("input",render);kindSelect.addEventListener("change",render);document.getElementById("fit").addEventListener("click",fit);document.getElementById("reset").addEventListener("click",()=>{selected=null;scale=1;tx=0;ty=0;applyTransform();render()});
initialLayout();render();requestAnimationFrame(fit);
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
            destination = Path(output) if output else Path(root) / ".lowkey" / "link-graph.html"
            if not destination.is_absolute():
                destination = Path(root) / destination
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
