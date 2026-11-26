#!/usr/bin/env python3
"""Graph-first protocol explorer and safe local source-ingestion workspace.

The graph preserves Lowkey source-index evidence. The browser presents focused
projections of one model and never upgrades static edges into runtime claims.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import webbrowser
import zipfile
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from source_index import SourceIndexError, build_source_index
except ImportError:  # pragma: no cover
    from lowkey.source_index import SourceIndexError, build_source_index


EDGE_LABELS = {
    "CALLS": "CALLS", "LIBRARY_CALL": "LIBRARY CALL", "EXTERNAL_CALL": "EXTERNAL CALL",
    "APPLIES_MODIFIER": "MODIFIER", "OVERRIDES": "OVERRIDES",
    "READS": "READS", "READS_CONSTANT": "READS CONSTANT",
    "READS_IMMUTABLE": "READS IMMUTABLE", "WRITES": "WRITES",
    "DELETES": "DELETES", "MUTATES": "MUTATES",
    "TRANSIENT_READS": "TRANSIENT READS", "TRANSIENT_WRITES": "TRANSIENT WRITES",
    "TRANSIENT_DELETES": "TRANSIENT DELETES", "INITIALIZES": "INITIALIZES",
    "ALIASES_STORAGE": "STORAGE ALIAS", "UNRESOLVED_STORAGE": "UNRESOLVED STORAGE",
    "UNRESOLVED_MUTATION": "UNRESOLVED MUTATION", "USES_TYPE": "USES TYPE",
    "IMPORTS": "IMPORTS", "INHERITS": "INHERITS", "USES_LIBRARY": "USES LIBRARY",
    "ASSET_FLOW": "ASSET FLOW", "EMITS": "EMITS", "REVERTS": "REVERTS",
    "DECLARES": "CONTAINS",
}
CALL_KINDS = {"CALLS", "LIBRARY_CALL", "EXTERNAL_CALL", "APPLIES_MODIFIER", "OVERRIDES"}
STATE_KINDS = {
    "READS", "READS_CONSTANT", "READS_IMMUTABLE", "WRITES", "DELETES",
    "MUTATES", "TRANSIENT_READS", "TRANSIENT_WRITES", "TRANSIENT_DELETES",
    "INITIALIZES", "ALIASES_STORAGE", "UNRESOLVED_STORAGE", "UNRESOLVED_MUTATION",
}
ROOT_CONFIGS = {"foundry.toml", "remappings.txt", "soldeer.lock", ".gitmodules", ".gitignore"}
IGNORED_PARTS = {
    ".git", ".hg", ".svn", "node_modules", "out", "cache", "broadcast",
    "artifacts", "build", "dist", "__pycache__", ".venv", "venv",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}
MAX_UPLOAD_FILES = 1500
MAX_UPLOAD_BYTES = 128 * 1024 * 1024
MAX_UPLOAD_FILE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 3000


def _folder(path: str) -> str:
    parent = Path(path).parent.as_posix()
    return "." if parent in {"", "."} else parent


def _vendor_for(path: str, provenance: str) -> str:
    value = "/" + str(path or "").replace("\\", "/").casefold() + "/"
    for token, label in (
        ("openzeppelin", "OpenZeppelin"), ("chainlink", "Chainlink"),
        ("uniswap", "Uniswap"), ("solmate", "Solmate"), ("solady", "Solady"),
        ("compound", "Compound"), ("aave", "Aave"), ("safe-global", "Safe"),
        ("gnosis", "Safe"),
    ):
        if token in value:
            return label
    if str(provenance).casefold() == "third-party":
        parts = [part for part in value.split("/") if part]
        for part in parts:
            if part.startswith("@"):
                return part.lstrip("@").split("-")[0].title()
        for marker in ("lib", "libs", "vendor", "vendors", "dependencies"):
            if marker in parts and parts.index(marker) + 1 < len(parts):
                return parts[parts.index(marker) + 1].replace("_", " ").replace("-", " ").title()
        return "Other third-party"
    return "First-party"


def _node_type(raw: dict[str, Any]) -> str:
    kind = str(raw.get("kind") or "")
    if kind == "contract":
        return "declaration"
    if kind in {"function", "modifier"}:
        return kind
    if kind in {"mapping", "state_variable", "function_pointer", "struct_field"}:
        return "state"
    if kind in {"struct", "enum", "enum_value", "event", "custom_error", "file", "type"}:
        return kind
    return "other"


def _node_label(raw: dict[str, Any]) -> str:
    kind = str(raw.get("kind") or "")
    if kind == "contract":
        return str(raw.get("name") or "Unnamed declaration")
    if kind in {"function", "modifier"}:
        return str(raw.get("signature") or raw.get("qualified_name") or raw.get("name") or kind)
    if kind == "file":
        return str(raw.get("name") or raw.get("file") or "Source file")
    return str(raw.get("qualified_name") or raw.get("name") or kind or "Unknown")


def _source_excerpt(root: Path, file_name: str, line: Any, radius: int = 3) -> str:
    if not file_name or not isinstance(line, int) or line < 1:
        return ""
    candidate = Path(file_name)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
        if resolved.stat().st_size > MAX_UPLOAD_FILE_BYTES:
            return ""
        lines = resolved.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except (OSError, RuntimeError, ValueError):
        return ""
    start, end = max(1, line - radius), min(len(lines), line + radius)
    return "\n".join(
        f"{'>' if number == line else ' '} {number:>5}  {lines[number - 1]}"
        for number in range(start, end + 1)
    )[:1800]


def _owner_contract_id(
    raw: dict[str, Any],
    by_name_file: dict[tuple[str, str], str],
    by_name: dict[str, list[str]],
) -> str | None:
    name, file_name = str(raw.get("contract") or ""), str(raw.get("file") or "")
    exact = by_name_file.get((name, file_name))
    if exact:
        return exact
    matches = by_name.get(name, [])
    return matches[0] if len(matches) == 1 else None


def _make_review_leads(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        outgoing[edge["source"]].append(edge)
    leads = []
    for item in nodes:
        if item["type"] != "function":
            continue
        related = outgoing.get(item["id"], [])
        kinds = {edge["kind"] for edge in related}
        writes = any(edge["kind"] in {"WRITES", "DELETES", "MUTATES", "TRANSIENT_WRITES", "TRANSIENT_DELETES"} for edge in related)
        external = "EXTERNAL_CALL" in kinds
        incoming = any(edge["kind"] == "ASSET_FLOW" and edge.get("direction") in {"in", "both"} for edge in related)
        outgoing_asset = any(edge["kind"] == "ASSET_FLOW" and edge.get("direction") in {"out", "both", "unresolved"} for edge in related)
        unresolved = any(edge.get("resolution") in {"UNRESOLVED", "AMBIGUOUS"} for edge in related)
        text = " ".join((item.get("label", ""), item.get("contract", ""), item.get("file", ""))).casefold()
        signals, score = [], 0
        if external and writes:
            signals.append(("External interaction + state effects", "Check call ordering, callback exposure, reentrancy protection and state invariants."))
            score += 3
        if incoming or item.get("mutability") == "payable":
            signals.append(("Value-bearing entry point", "Trace supplied value, accounting updates, refund paths and custody assumptions."))
            score += 2
        if outgoing_asset:
            signals.append(("Asset transfer path", "Verify recipient and amount control, return-value handling and balance deltas."))
            score += 2
        if unresolved:
            signals.append(("Unresolved or ambiguous target", "Resolve the receiver and runtime implementation before making execution claims."))
            score += 1
        dependency_text = " ".join(
            str(edge.get("details", {}).get("target_label") or edge.get("receiver") or edge.get("method") or "")
            for edge in related
        ).casefold()
        if any(word in text + " " + dependency_text for word in ("oracle", "price", "feed", "twap", "indexprice", "getminprice", "getmaxprice")):
            signals.append(("Price / oracle dependency", "Check freshness, manipulation resistance, decimals, bounds and failure behaviour."))
            score += 2
        targets = [str(edge.get("details", {}).get("target_label") or "") for edge in related if edge["kind"] == "APPLIES_MODIFIER"]
        if any(any(word in target.casefold() for word in ("owner", "admin", "gov", "role", "auth")) for target in targets):
            signals.append(("Privileged execution path", "Verify role assignment, privilege boundaries and complete coverage of guarded functions."))
            score += 1
        if not signals:
            continue
        entrypoint = item.get("visibility") in {"external", "public"}
        leads.append({
            "id": "lead:" + item["id"], "function": item["id"], "contract": item.get("contract"),
            "label": item["label"], "file": item.get("file"), "line": item.get("line"),
            "entrypoint": entrypoint, "score": min(score + (1 if entrypoint else 0), 10),
            "tier": "HIGH REVIEW PRIORITY" if score >= 6 else "REVIEW LEAD",
            "signals": [{"label": label, "question": question} for label, question in signals],
            "edge_ids": [edge["id"] for edge in related if edge["kind"] in CALL_KINDS | STATE_KINDS | {"ASSET_FLOW"}],
            "evidence": item.get("evidence", "STATIC_SOURCE"),
            "source_excerpt": item.get("source_excerpt", ""),
        })
    leads.sort(key=lambda row: (-row["score"], not row["entrypoint"], row.get("file") or "", row["label"]))
    return leads


def build_explorer_model(index: dict[str, Any], root: str | Path = ".") -> dict[str, Any]:
    """Preserve source-index declarations and edges in one UI-ready evidence graph."""
    root_path = Path(root).expanduser().resolve()
    raw_nodes = {
        str(item.get("id")): item for item in (index.get("nodes") or [])
        if isinstance(item, dict) and item.get("id")
    }
    declarations = {key: raw for key, raw in raw_nodes.items() if raw.get("kind") == "contract"}
    by_name_file: dict[tuple[str, str], str] = {}
    by_name: dict[str, list[str]] = defaultdict(list)
    for node_id, raw in declarations.items():
        name, file_name = str(raw.get("name") or ""), str(raw.get("file") or "")
        by_name_file[(name, file_name)] = node_id
        by_name[name].append(node_id)

    nodes_by_id: dict[str, dict[str, Any]] = {}
    for node_id, raw in raw_nodes.items():
        kind = str(raw.get("kind") or "")
        file_name = str(raw.get("file") or raw.get("name") or "")
        provenance = str(raw.get("provenance") or "unclassified")
        owner_id = None if kind == "contract" else _owner_contract_id(raw, by_name_file, by_name)
        owner_raw = declarations.get(owner_id or "", {})
        declaration_kind = raw.get("declaration_kind") or raw.get("contract_kind") or owner_raw.get("declaration_kind") or ""
        label = _node_label(raw)
        node = {
            "id": node_id, "type": _node_type(raw), "kind": kind, "label": label,
            "qualified_name": str(raw.get("qualified_name") or label),
            "name": str(raw.get("name") or label), "contract": str(raw.get("contract") or ""),
            "contract_id": owner_id or (node_id if kind == "contract" else None),
            "declaration_kind": str(declaration_kind),
            "file": str(raw.get("file") or ""), "line": raw.get("line"),
            "location": f"{raw.get('file')}:{raw.get('line')}" if raw.get("line") else str(raw.get("file") or ""),
            "folder": _folder(file_name) if file_name else ".",
            "origin": provenance, "vendor": _vendor_for(file_name, provenance),
            "scope": "support" if any(part.casefold() in {"test", "tests", "mock", "mocks", "script", "scripts", "fixture", "fixtures"} for part in Path(file_name).parts[:-1]) else "application",
            "evidence": str(raw.get("evidence") or "STATIC_SOURCE"),
            "visibility": raw.get("visibility"), "mutability": raw.get("mutability"),
            "signature": raw.get("signature"), "parameters": raw.get("parameters") or [],
            "storage_class": raw.get("storage_class") or raw.get("persistence"),
            "type_text": raw.get("type") or "", "mapping_keys": raw.get("mapping_keys") or [],
            "mapping_value_type": raw.get("mapping_value_type") or "",
            "initializer": raw.get("initializer"), "bases": raw.get("bases") or [],
            "ancestors": raw.get("ancestors") or [], "using_libraries": raw.get("using_libraries") or [],
            "incoming": 0, "outgoing": 0,
        }
        node["source_excerpt"] = _source_excerpt(root_path, node["file"], node["line"])
        nodes_by_id[node_id] = node

    def add_external(target_id: str, edge: dict[str, Any]) -> None:
        if target_id in nodes_by_id:
            return
        kind = str(edge.get("kind") or "")
        if kind == "ASSET_FLOW" or target_id.startswith("asset:"):
            ui_type = "asset"
            label = target_id.split("asset:erc20:", 1)[1].upper() if target_id.startswith("asset:erc20:") else str(edge.get("asset") or target_id.split(":")[-1]).upper()
        elif kind in STATE_KINDS or target_id.startswith("storage-slot:"):
            ui_type = "unresolved_state"
            label = str(edge.get("variable") or edge.get("access_path") or target_id)
        elif kind == "IMPORTS" and ("/" in target_id or target_id.endswith(".sol")):
            ui_type, label = "file", Path(target_id).name
        else:
            ui_type = "external"
            label = str(edge.get("receiver") or edge.get("method") or edge.get("operation") or target_id)
        nodes_by_id[target_id] = {
            "id": target_id, "type": ui_type, "kind": ui_type, "label": label,
            "qualified_name": label, "name": label, "contract": "", "contract_id": None,
            "declaration_kind": "", "file": "", "line": None, "location": "",
            "folder": "external", "origin": "unresolved" if edge.get("resolution") == "UNRESOLVED" else "external",
            "vendor": "Unresolved", "scope": "external", "evidence": edge.get("evidence") or "STATIC_SOURCE",
            "visibility": None, "mutability": None, "signature": None, "parameters": [],
            "storage_class": None, "type_text": "", "mapping_keys": [], "mapping_value_type": "",
            "initializer": None, "bases": [], "ancestors": [], "using_libraries": [],
            "incoming": 0, "outgoing": 0, "source_excerpt": "",
        }

    edges = []
    edge_ids: set[str] = set()
    for raw in index.get("edges") or []:
        if not isinstance(raw, dict):
            continue
        source_id, target_id = str(raw.get("from") or ""), str(raw.get("to") or "")
        if not source_id or not target_id or source_id not in nodes_by_id:
            continue
        add_external(target_id, raw)
        edge_id = str(raw.get("id") or f"edge:{len(edges)+1}")
        if edge_id in edge_ids:
            edge_id += ":" + str(len(edges) + 1)
        edge_ids.add(edge_id)
        source = raw.get("source") or {}
        file_name, line = str(source.get("file") or raw.get("file") or ""), source.get("line")
        details = dict(raw)
        details["source_excerpt"] = _source_excerpt(root_path, file_name, line)
        details["target_label"] = nodes_by_id[target_id]["label"]
        raw_kind = str(raw.get("kind") or "UNKNOWN")
        target_raw = raw_nodes.get(target_id, {})
        target_owner = _owner_contract_id(target_raw, by_name_file, by_name) if target_raw else None
        target_declaration = declarations.get(target_owner or "", {})
        is_library_call = (
            raw_kind == "CALLS"
            and str(raw.get("resolution") or "DIRECT") != "UNRESOLVED"
            and (
                str(raw.get("call_kind") or "").casefold() in {"library", "using-for extension"}
                or str(target_raw.get("contract_kind") or target_declaration.get("declaration_kind") or "").casefold() == "library"
            )
        )
        display_kind = "LIBRARY_CALL" if is_library_call else raw_kind
        edge = {
            "id": edge_id, "source": source_id, "target": target_id,
            "kind": display_kind, "source_kind": raw_kind,
            "label": EDGE_LABELS.get(display_kind, display_kind.replace("_", " ")),
            "resolution": str(raw.get("resolution") or "DIRECT"),
            "evidence": str(raw.get("evidence") or "STATIC_SOURCE"),
            "file": file_name, "line": line, "detail": str(raw.get("detail") or ""),
            "via": raw.get("via") or [], "access_path": raw.get("access_path") or "",
            "status": raw.get("status") or "", "asset": raw.get("asset") or "",
            "direction": raw.get("direction") or "", "recipient": raw.get("recipient") or "",
            "amount": raw.get("amount") or "", "method": raw.get("method") or "",
            "receiver": raw.get("receiver") or "",
            "implementation_resolution": raw.get("implementation_resolution") or "",
            "call_kind": raw.get("call_kind") or "", "source_excerpt": details["source_excerpt"],
            "details": details,
        }
        edges.append(edge)
        nodes_by_id[source_id]["outgoing"] += 1
        nodes_by_id[target_id]["incoming"] += 1

    # Ownership is a navigational relationship, distinct from an executable call.
    existing = {(edge["source"], edge["target"], edge["kind"]) for edge in edges}
    for node in list(nodes_by_id.values()):
        parent = node.get("contract_id")
        key = (parent, node["id"], "CONTAINS")
        if parent and parent != node["id"] and parent in nodes_by_id and key not in existing:
            edges.append({
                "id": "contains:" + parent + ":" + node["id"], "source": parent, "target": node["id"],
                "kind": "CONTAINS", "label": "CONTAINS", "resolution": "DIRECT",
                "evidence": "DECLARATION_OWNERSHIP", "file": node.get("file"), "line": node.get("line"),
                "detail": "Declaration ownership derived from source-index metadata.", "via": [],
                "access_path": "", "status": "", "asset": "", "direction": "",
                "recipient": "", "amount": "", "method": "", "receiver": "",
                "implementation_resolution": "", "call_kind": "",
                "source_excerpt": node.get("source_excerpt", ""), "details": {},
            })
            nodes_by_id[parent]["outgoing"] += 1
            node["incoming"] += 1

    nodes = list(nodes_by_id.values())
    groups: dict[str, dict[str, Any]] = {}
    for node in nodes:
        if node["type"] != "declaration":
            continue
        group_id = "group:" + node["folder"]
        group = groups.setdefault(group_id, {
            "id": group_id, "folder": node["folder"], "label": node["folder"],
            "count": 0, "functions": 0, "storage": 0, "vendors": set(),
            "first_party": 0, "third_party": 0, "declarations": [],
        })
        group["count"] += 1
        group["declarations"].append(node["id"])
        group["vendors"].add(node["vendor"])
        group["third_party" if node["origin"] == "third-party" else "first_party"] += 1
    for node in nodes:
        owner = nodes_by_id.get(node.get("contract_id") or "")
        if not owner or owner["type"] != "declaration":
            continue
        group = groups.get("group:" + owner["folder"])
        if group:
            if node["type"] in {"function", "modifier"}:
                group["functions"] += 1
            if node["type"] == "state":
                group["storage"] += 1
    for group in groups.values():
        group["vendors"] = sorted(group["vendors"])
        group["declarations"].sort(key=lambda item: nodes_by_id[item]["label"].casefold())

    # Subsystem overview edges are aggregates; original function/state edges remain untouched.
    overview: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edge in edges:
        source_node, target_node = nodes_by_id.get(edge["source"], {}), nodes_by_id.get(edge["target"], {})
        if edge["kind"] == "CONTAINS" or edge["kind"] in STATE_KINDS:
            continue
        if edge["kind"] == "IMPORTS":
            source_group, target_group = "group:" + source_node.get("folder", "."), "group:" + target_node.get("folder", "external")
        else:
            source_owner, target_owner = source_node.get("contract_id"), target_node.get("contract_id")
            if not source_owner:
                continue
            source_group = "group:" + nodes_by_id.get(source_owner, {}).get("folder", ".")
            target_group = "group:" + nodes_by_id.get(target_owner, {}).get("folder", "external") if target_owner else (
                "asset-boundary" if edge["kind"] == "ASSET_FLOW" else "external-dependencies"
            )
        if source_group == target_group:
            continue
        key = (source_group, target_group, edge["kind"], edge["resolution"])
        row = overview.setdefault(key, {
            "id": "overview:" + str(len(overview) + 1), "source": source_group,
            "target": target_group, "kind": edge["kind"], "label": edge["label"],
            "count": 0, "resolution": edge["resolution"], "examples": [],
        })
        row["count"] += 1
        if len(row["examples"]) < 5:
            row["examples"].append({
                "source_contract": source_node.get("contract") or source_node.get("label"),
                "target_contract": target_node.get("contract") or target_node.get("label"),
                "source_file": edge.get("file"), "line": edge.get("line"),
            })
    if any(item["target"] == "asset-boundary" for item in overview.values()):
        groups["asset-boundary"] = {"id": "asset-boundary", "folder": "Asset flows", "label": "Asset flows", "count": 0, "functions": 0, "storage": 0, "vendors": [], "first_party": 0, "third_party": 0, "declarations": []}
    if any(item["target"] == "external-dependencies" for item in overview.values()):
        groups["external-dependencies"] = {"id": "external-dependencies", "folder": "External boundaries", "label": "External boundaries", "count": 0, "functions": 0, "storage": 0, "vendors": [], "first_party": 0, "third_party": 0, "declarations": []}

    summary, inventory = index.get("summary") or {}, index.get("inventory") or {}
    leads = _make_review_leads(nodes, edges)
    return {
        "schema_version": 2, "product": "LOWKEY_PROTOCOL_EXPLORER", "evidence_model": "STATIC_SOURCE",
        "parser": index.get("parser", "LEXICAL"), "ast": index.get("ast") or {},
        "effect_propagation": index.get("effect_propagation") or {},
        "nodes": sorted(nodes, key=lambda item: (item["folder"], item["type"], item["label"].casefold(), item["id"])),
        "edges": edges, "overview_edges": list(overview.values()),
        "groups": sorted(groups.values(), key=lambda item: item["folder"].casefold()),
        "review_leads": leads,
        "vendors": sorted({item["vendor"] for item in nodes if item["origin"] == "third-party"}),
        "inventory": {
            "complete": bool(inventory.get("complete", False)),
            "files_inspected": inventory.get("files_inspected", 0),
            "files_discovered": inventory.get("files_discovered", 0),
            "uninspected": inventory.get("uninspected") or [],
            "excluded_directories": inventory.get("excluded_directories") or [],
        },
        "summary": {
            "files": summary.get("files", 0), "declarations": len(declarations),
            "functions": sum(1 for item in nodes if item["type"] == "function"),
            "modifiers": sum(1 for item in nodes if item["type"] == "modifier"),
            "storage": sum(1 for item in nodes if item["type"] == "state"),
            "mappings": sum(1 for item in nodes if item["kind"] == "mapping"),
            "relationships": len(edges), "source_relationships": summary.get("relationships", 0),
            "groups": len(groups), "third_party_declarations": sum(1 for item in nodes if item["type"] == "declaration" and item["origin"] == "third-party"),
            "review_leads": len(leads), "unresolved": summary.get("unresolved", 0),
            "ambiguous": summary.get("ambiguous", 0), "coverage_complete": bool(inventory.get("complete", False)),
        },
        "limitations": [
            "Static source relationships are not proof of runtime execution or success.",
            "Inferred helper effects need branch and execution-context review.",
            "Interface declarations do not prove the deployed implementation selected at a runtime address.",
            "Asset-flow edges are source candidates; verify call success and balance changes with traces.",
            "Review leads are triage signals, not vulnerability findings.",
        ],
    }


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark">
<title>Lowkey · Protocol Graph</title>
<style>
:root{color-scheme:dark;--bg:#08101d;--panel:#0e1929;--line:#263a55;--muted:#91a4bc;--text:#e8f0fa;--cyan:#50c9ef;--green:#57c69c;--amber:#e8b85d;--violet:#a88af0}
*{box-sizing:border-box}html,body{height:100%;margin:0}body{background:var(--bg);color:var(--text);font:13px/1.45 Inter,ui-sans-serif,system-ui,sans-serif;overflow:hidden}
button,input,select{font:inherit}button{color:inherit;cursor:pointer}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.topbar{height:62px;display:flex;align-items:center;gap:14px;padding:0 16px;border-bottom:1px solid var(--line);background:#0b1626;position:relative;z-index:5}
.brand{display:flex;align-items:center;gap:9px;white-space:nowrap}.brand-mark{width:29px;height:29px;border:2px solid var(--cyan);border-radius:9px;display:grid;place-items:center;color:var(--cyan);font-weight:900;box-shadow:0 0 20px #50c9ef33}.brand-name{font-weight:850;letter-spacing:.07em}.brand-name span{font-weight:450;color:#a5b6cd}.project-pill{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;border:1px solid var(--line);background:#111f33;color:#cbd8e8;border-radius:8px;padding:7px 9px}
.modes{display:flex;gap:3px}.mode-tab{border:1px solid transparent;background:transparent;color:#9caec4;border-radius:8px;padding:8px 9px;font-size:11px;font-weight:750;white-space:nowrap}.mode-tab.active{color:#dff8ff;background:#11344a;border-color:#225d7a;box-shadow:inset 0 -2px var(--cyan)}
.global-search{margin-left:auto;display:flex;align-items:center;gap:8px;min-width:180px;max-width:310px;flex:1;border:1px solid var(--line);border-radius:9px;background:#0d1a2c;padding:0 9px;color:#8ea5bf}.global-search input{width:100%;min-width:0;background:transparent;border:0;outline:0;color:var(--text);padding:9px 0}.top-actions{display:flex;gap:6px;align-items:center}.tool-button,.icon-button{border:1px solid var(--line);background:#111f33;color:#cbd8e8;border-radius:8px;padding:7px 9px;font-weight:650;white-space:nowrap}.tool-button:hover,.icon-button:hover{border-color:#4d83aa;background:#162942}.tool-button.primary{background:#126087;border-color:#268cb8;color:white}
.search-results{position:absolute;top:55px;right:185px;width:min(430px,calc(100vw - 30px));max-height:62vh;overflow:auto;background:#101e32;border:1px solid #395675;border-radius:10px;box-shadow:0 18px 55px #000b;padding:6px;z-index:15}.search-result{width:100%;display:block;text-align:left;border:1px solid transparent;border-radius:7px;background:transparent;padding:8px;color:var(--text)}.search-result:hover{background:#182e48;border-color:#3b789a}.search-result strong{display:block;font-size:11px}.search-result small{display:block;color:#90a7c2;font-size:10px;margin-top:3px;overflow-wrap:anywhere}.search-empty{padding:11px;color:var(--muted);font-size:11px}
.app{height:calc(100% - 62px);display:grid;grid-template-columns:270px minmax(420px,1fr) 320px;min-width:900px}.left,.right{background:var(--panel);min-height:0;overflow:auto}.left{border-right:1px solid var(--line);padding:13px 11px}.right{border-left:1px solid var(--line);padding:14px}
.panel-head{display:flex;align-items:center;justify-content:space-between;color:#b8c8dc;font-size:10px;font-weight:850;letter-spacing:.13em;margin:2px 2px 10px}.count-label{font-variant-numeric:tabular-nums;color:#8fa6c0;font-size:10px}
.project-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:6px;margin-bottom:12px}.stat{background:#122138;border:1px solid #273d5b;border-radius:8px;padding:8px 6px}.stat b{font-size:16px;display:block;color:#f1f7ff;font-variant-numeric:tabular-nums}.stat span{font-size:9px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em}
.search-box{display:flex;align-items:center;gap:7px;border:1px solid #304764;background:#0a1525;border-radius:8px;padding:0 9px;margin-bottom:9px}.search-box input{width:100%;min-width:0;border:0;outline:0;background:transparent;color:var(--text);padding:9px 0}
.tree{display:grid;gap:2px;margin-bottom:14px}.folder-row{display:flex;align-items:center;gap:6px;padding:7px 5px;color:#9fb1c8;font-weight:800;font-size:10px;letter-spacing:.07em;text-transform:uppercase;border-radius:6px}.folder-row:hover{background:#172941}.folder-row button{all:unset;cursor:pointer;flex:1}.folder-row span{color:#718ba7}
.declaration-row{width:100%;display:flex;align-items:center;gap:7px;text-align:left;padding:7px 7px;border:1px solid transparent;background:transparent;border-radius:7px;color:#dce7f4}.declaration-row:hover{background:#14263e;border-color:#2a4565}.declaration-row.active{background:#15334c;border-color:#2c83a7;box-shadow:inset 2px 0 var(--cyan)}.node-icon{width:19px;height:19px;display:grid;place-items:center;border-radius:5px;background:#173652;color:#70d3f7;font-size:11px;font-weight:850;flex:0 0 auto}.node-icon.interface{background:#2b2145;color:#c2a5ff}.node-icon.library{background:#173c32;color:#70ddb5}.declaration-main{min-width:0;flex:1}.declaration-name{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-weight:650}.declaration-meta{display:block;font-size:10px;color:#8198b4;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.declaration-count{font-size:10px;color:#8ca6c1;font-variant-numeric:tabular-nums}
.filters{border-top:1px solid var(--line);padding-top:12px}.filter-section{margin-bottom:13px}.filter-title{display:flex;justify-content:space-between;font-size:10px;font-weight:850;color:#9eb1c9;letter-spacing:.11em;text-transform:uppercase;margin-bottom:7px}.filter-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}.checkline{display:flex;align-items:center;gap:6px;color:#c2d0e2;font-size:10px;min-width:0}.checkline input{accent-color:#38bde9}.vendor-list{display:grid;gap:6px}.vendor-list .checkline{justify-content:space-between}
.center{min-width:0;min-height:0;display:grid;grid-template-rows:52px minmax(250px,1fr) 105px;position:relative;background:radial-gradient(ellipse at 50% 40%,#142945 0%,#0a1423 68%)}
.graph-toolbar{display:flex;align-items:center;gap:6px;padding:7px 11px;border-bottom:1px solid #1d314b;background:#0b1728cc}.toolbar-label{font-size:10px;color:#849bb5;font-weight:800;letter-spacing:.1em}.toolbar-spacer{flex:1}.rel-filter{border:1px solid var(--line);background:#0f1d31;color:#b9c9dc;border-radius:7px;padding:7px 8px;max-width:160px}
.graph-stage{position:relative;min-height:0;overflow:hidden;background-image:radial-gradient(#24405f66 1px,transparent 1px);background-size:22px 22px}#graph{width:100%;height:100%;display:block;touch-action:none;cursor:grab}#graph.dragging{cursor:grabbing}
.edge{fill:none;stroke:#607f9f;stroke-width:2;opacity:.76;marker-end:url(#arrow);transition:opacity .18s,stroke-width .18s}.edge.CALLS{stroke:#54c6a0}.edge.LIBRARY_CALL,.edge.USES_LIBRARY{stroke:#64c69d}.edge.EXTERNAL_CALL{stroke:#e6a66a;stroke-dasharray:3 4}.edge.APPLIES_MODIFIER{stroke:#9d9fea}.edge.OVERRIDES,.edge.INHERITS,.edge.USES_TYPE{stroke:#a68ef0}.edge.READS,.edge.WRITES,.edge.DELETES{stroke:#64bbd9}.edge.ASSET_FLOW{stroke:#d68ae3;stroke-width:2.5}.edge.IMPORTS{stroke:#6a829d;stroke-dasharray:5 6}.edge.CONTAINS{stroke:#314a63;stroke-width:1.1;stroke-dasharray:3 5;marker-end:none;opacity:.45}.edge.hot{opacity:1;stroke-width:3.5}.edge-label{font-size:10px;fill:#aebed1;paint-order:stroke;stroke:#091321;stroke-width:4px;pointer-events:none}
.graph-node{cursor:pointer}.graph-node rect{fill:#14243b;stroke:#55708e;stroke-width:1.5;rx:10;filter:drop-shadow(0 7px 12px #0005)}.graph-node.declaration rect{fill:#112e48;stroke:#399bd0}.graph-node.interface rect{fill:#281f45;stroke:#a88af0}.graph-node.library rect{fill:#143c33;stroke:#57c69c}.graph-node.function rect,.graph-node.modifier rect{fill:#192944;stroke:#7fa6d3}.graph-node.state rect{fill:#19372e;stroke:#64b68e}.graph-node.asset rect{fill:#35213d;stroke:#c58ada}.graph-node.external rect,.graph-node.unresolved_state rect{fill:#38291f;stroke:#d6a55e}.graph-node.group rect{fill:#142b43;stroke:#3e86ae;stroke-width:2}.graph-node.selected rect{stroke:#59ddff;stroke-width:3;filter:drop-shadow(0 0 13px #42c9f888)}.graph-node:hover rect{stroke:#9deaff;stroke-width:2.5}.graph-node text{pointer-events:none}.node-title{font-size:14px;font-weight:800;fill:#eff7ff}.node-subtitle{font-size:10px;fill:#9eb3cc}
.graph-empty{position:absolute;inset:0;display:grid;place-items:center;pointer-events:none}.graph-empty span{max-width:420px;text-align:center;color:#9cb0c9;background:#0d1c30e8;border:1px solid #284563;border-radius:12px;padding:16px}
#minimap{position:absolute;right:12px;bottom:12px;width:154px;height:95px;border:1px solid #36516e;border-radius:8px;background:#091626dd;pointer-events:auto;cursor:crosshair;touch-action:manipulation}.graph-hint{position:absolute;left:13px;bottom:13px;color:#7f96b2;font-size:10px;background:#081523cc;border:1px solid #253e5c;border-radius:6px;padding:5px 8px;pointer-events:none}
.flow-panel{border-top:1px solid var(--line);background:#0b1728;padding:9px 13px;overflow:hidden}.flow-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:7px}.flow-title{font-size:10px;font-weight:850;letter-spacing:.12em;color:#9eb3cc}.flow-track{display:flex;align-items:center;gap:7px;overflow-x:auto;padding:2px 0 8px}.flow-step{display:flex;align-items:center;gap:6px;white-space:nowrap;border:1px solid #2a4868;background:#12243b;color:#dceafa;border-radius:8px;padding:7px 9px;font-size:11px;font-weight:650;cursor:pointer}.flow-step:hover{border-color:var(--cyan);background:#18334d}.flow-arrow{color:#5dbde0;font-size:16px;flex:0 0 auto}.flow-note{font-size:10px;color:#8198b3}
.right-title{display:flex;align-items:flex-start;gap:9px;margin-bottom:12px}.entity-icon{width:37px;height:37px;display:grid;place-items:center;background:#12334c;border:1px solid #2a7195;border-radius:10px;color:#79d8fc;font-size:18px;font-weight:900}.entity-main{min-width:0;flex:1}.entity-name{font-size:17px;font-weight:850;line-height:1.2;overflow-wrap:anywhere}.entity-meta{font-size:10px;color:#8ea5bf;margin-top:4px;overflow-wrap:anywhere}.entity-badge{border:1px solid #2a7f68;color:#75dbb6;background:#11372c;border-radius:99px;padding:3px 7px;font-size:9px;font-weight:850}
.inspector-tabs{display:flex;gap:2px;border-bottom:1px solid var(--line);margin-bottom:11px;overflow-x:auto}.inspector-tab{border:0;border-bottom:2px solid transparent;background:transparent;padding:8px 8px 7px;color:#8da3bd;font-size:10px;font-weight:800;white-space:nowrap}.inspector-tab.active{color:#8ee6ff;border-color:var(--cyan)}
.inspector-section{margin-bottom:14px}.section-head{display:flex;align-items:center;justify-content:space-between;color:#9eb3cc;font-size:10px;font-weight:850;letter-spacing:.1em;margin:10px 0 7px}.item-list{display:grid;gap:5px}.inspect-item{width:100%;text-align:left;border:1px solid #273e5a;background:#101e32;border-radius:7px;padding:8px 9px;color:#dbe7f5}.inspect-item:hover{border-color:#4b91b8;background:#152943}.inspect-item strong{display:block;font-size:11px;overflow-wrap:anywhere}.inspect-item small{display:block;color:#8ba2bc;font-size:9px;margin-top:3px;overflow-wrap:anywhere}.signal{border:1px solid #56462d;background:#261f15;border-radius:8px;padding:9px;margin-bottom:7px}.signal strong{font-size:10px;color:#f2c777;display:block}.signal p{font-size:10px;color:#b6c1cf;margin:5px 0 0}.source-card{border:1px solid #2b435e;background:#091726;border-radius:8px;padding:8px;max-height:230px;overflow:auto}.source-card pre{margin:0;color:#b8d6ed;font:10px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre;tab-size:4}
.coverage{border:1px solid #29445f;background:#102037;border-radius:8px;padding:9px;margin:12px 0}.coverage.ok{border-color:#275e4b;background:#102a25}.coverage.warn{border-color:#775e32;background:#2b2417}.coverage strong{font-size:11px}.coverage p{margin:4px 0 0;font-size:10px;color:#9fb2c9}.muted{color:var(--muted)}
.modal-shade{position:fixed;inset:0;z-index:20;background:#020813bf;display:none;place-items:center;padding:18px}.modal-shade.open{display:grid}.modal{width:min(560px,100%);border:1px solid #35516f;border-radius:14px;background:#101d30;box-shadow:0 25px 80px #000b;padding:18px}.modal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}.modal-head strong{font-size:15px}.modal-close{border:0;background:transparent;color:#9bb0c7;font-size:20px}.modal p{color:#9fb3cb;font-size:12px}.modal-row{display:flex;gap:7px;margin:9px 0}.modal-row input{flex:1;min-width:0;border:1px solid #36506e;background:#0b1829;color:var(--text);padding:9px;border-radius:8px}.modal-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:14px}.upload-drop{border:1px dashed #48708f;border-radius:10px;background:#0b1a2b;padding:17px;text-align:center;color:#afc2d9}.statusline{font-size:11px;color:#7ed8fa;min-height:17px;margin-top:8px}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%) translateY(12px);opacity:0;pointer-events:none;background:#17364b;border:1px solid #367a9c;color:#e4f8ff;border-radius:8px;padding:9px 13px;z-index:40;box-shadow:0 12px 32px #0009;transition:.2s}#toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
@media(max-width:1180px){.app{grid-template-columns:235px minmax(380px,1fr) 290px}.brand-name{font-size:12px}.mode-tab{padding:8px}.global-search{max-width:220px}}
@media(max-width:980px){body{overflow:auto}.app{height:auto;min-width:0;grid-template-columns:220px minmax(0,1fr)}.right{grid-column:1/-1;border-left:0;border-top:1px solid var(--line);min-height:300px}.center{height:760px}.topbar{flex-wrap:wrap;height:auto;min-height:62px;padding:9px 12px}.global-search{order:4;max-width:none;flex-basis:100%}.app{height:auto}.left{max-height:1000px}}
</style>
</head>
<body>
<header class="topbar">
  <div class="brand"><div class="brand-mark">L</div><div class="brand-name">LOWKEY <span>// PROTOCOL GRAPH</span></div></div>
  <div class="project-pill" id="project-name">Protocol workspace</div>
  <nav class="modes">
    <button class="mode-tab active" data-mode="architecture">Architecture</button>
    <button class="mode-tab" data-mode="functions">Function flow</button>
    <button class="mode-tab" data-mode="storage">Storage</button>
    <button class="mode-tab" data-mode="assets">Asset flow</button>
    <button class="mode-tab" data-mode="security">Review leads</button>
  </nav>
  <label class="global-search"><span>⌕</span><input id="global-search" placeholder="Search contracts, functions, state…"><span>/</span></label>
  <div class="search-results" id="search-results" hidden></div>
  <div class="top-actions"><button class="tool-button" id="import-open">＋ Import</button><button class="tool-button" id="export-json">Export graph</button></div>
</header>
<div class="app">
  <aside class="left">
    <div class="panel-head"><span>PROJECT EXPLORER</span><span class="count-label" id="coverage-short">INDEX</span></div>
    <div class="project-stats" id="project-stats"></div>
    <div class="search-box"><span>⌕</span><input id="sidebar-search" placeholder="Find any declaration…"></div>
    <div class="tree" id="declaration-tree"></div>
    <div class="filters">
      <div class="filter-section"><div class="filter-title"><span>Declaration types</span><button class="muted" id="reset-filters" style="border:0;background:transparent">Reset</button></div>
        <div class="filter-grid">
          <label class="checkline"><input type="checkbox" data-filter="contract" checked> Contracts</label>
          <label class="checkline"><input type="checkbox" data-filter="abstract" checked> Abstract</label>
          <label class="checkline"><input type="checkbox" data-filter="interface" checked> Interfaces</label>
          <label class="checkline"><input type="checkbox" data-filter="library" checked> Libraries</label>
        </div>
      </div>
      <div class="filter-section"><div class="filter-title">Source scope</div>
        <div class="filter-grid">
          <label class="checkline"><input type="checkbox" data-filter="first-party" checked> First-party</label>
          <label class="checkline"><input type="checkbox" data-filter="third-party"> Third-party</label>
          <label class="checkline"><input type="checkbox" data-filter="support"> Tests / mocks</label>
          <label class="checkline"><input type="checkbox" data-filter="unresolved" checked> Unresolved</label>
        </div>
      </div>
      <div class="filter-section"><div class="filter-title">Hide vendor dependencies</div><div class="vendor-list" id="vendor-filters"></div></div>
      <div class="filter-section"><div class="filter-title">Relationship layers</div>
        <div class="filter-grid">
          <label class="checkline"><input type="checkbox" data-edge="CALLS" checked> Internal calls</label>
          <label class="checkline"><input type="checkbox" data-edge="EXTERNAL_CALL" checked> Interfaces</label>
          <label class="checkline"><input type="checkbox" data-edge="APPLIES_MODIFIER" checked> Modifiers</label>
          <label class="checkline"><input type="checkbox" data-edge="INHERITS" checked> Inheritance</label>
          <label class="checkline"><input type="checkbox" data-edge="READS" checked> Reads</label>
          <label class="checkline"><input type="checkbox" data-edge="WRITES" checked> Writes</label>
          <label class="checkline"><input type="checkbox" data-edge="DELETES" checked> Deletes</label>
          <label class="checkline"><input type="checkbox" data-edge="ASSET_FLOW" checked> Assets</label>
          <label class="checkline"><input type="checkbox" data-edge="USES_LIBRARY" checked> Libraries</label>
          <label class="checkline"><input type="checkbox" data-edge="IMPORTS"> Imports</label>
        </div>
      </div>
    </div>
  </aside>
  <section class="center">
    <div class="graph-toolbar">
      <span class="toolbar-label" id="view-label">SYSTEM MAP</span>
      <button class="icon-button" id="zoom-out">−</button><button class="icon-button" id="zoom-in">＋</button>
      <button class="tool-button" id="back-graph" disabled>← Back</button><button class="tool-button" id="fit-graph">Fit</button><button class="tool-button" id="clear-focus">Overview</button>
      <span class="toolbar-spacer"></span>
      <select class="rel-filter" id="edge-select"><option value="">All visible relationships</option></select>
    </div>
    <div class="graph-stage" id="graph-stage">
      <svg id="graph" viewBox="0 0 1500 920" role="img" aria-label="Interactive protocol relationship graph">
        <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0 L10 5 L0 10z" fill="#8199b5"/></marker></defs>
        <g id="viewport"><g id="graph-edges"></g><g id="graph-nodes"></g></g>
      </svg>
      <div class="graph-empty" id="graph-empty" style="display:none"><span>No visible relationships match these filters. Re-enable a layer or select another node.</span></div>
      <div class="graph-hint">DRAG TO PAN · WHEEL TO ZOOM · CLICK A NODE TO EXPAND</div>
      <svg id="minimap" viewBox="0 0 154 95"></svg>
    </div>
    <div class="flow-panel">
      <div class="flow-head"><span class="flow-title" id="flow-title">SELECTED WORKFLOW</span><span class="flow-note" id="flow-note">Choose a function to follow its call and effect path</span></div>
      <div class="flow-track" id="flow-track"></div>
    </div>
  </section>
  <aside class="right"><div id="inspector"></div></aside>
</div>
<div class="modal-shade" id="import-modal"><div class="modal">
  <div class="modal-head"><strong>Import a source workspace</strong><button class="modal-close" id="import-close">×</button></div>
  <p>Choose a local Solidity folder, individual source files, a ZIP archive, or a GitHub repository. Lowkey runs its real source index locally and returns the same evidence-rich graph model.</p>
  <div class="upload-drop">Drop a Solidity project here or choose a source below.
    <div class="modal-actions"><button class="tool-button primary" id="choose-files">Choose files</button><button class="tool-button" id="choose-folder">Choose folder</button><button class="tool-button" id="choose-zip">Choose ZIP</button></div>
  </div>
  <input id="files-input" type="file" multiple accept=".sol,.toml,.txt,.lock" hidden>
  <input id="folder-input" type="file" webkitdirectory directory multiple hidden>
  <input id="zip-input" type="file" accept=".zip,application/zip" hidden>
  <div class="section-head" style="margin-top:16px">IMPORT FROM GITHUB</div>
  <div class="modal-row"><input id="github-url" placeholder="https://github.com/owner/repository"></div>
  <div class="modal-row"><input id="github-ref" placeholder="Branch or tag (optional)"></div>
  <div class="modal-actions"><button class="tool-button primary" id="github-import">Clone and build graph</button></div>
  <div class="statusline" id="import-status"></div>
  <p class="muted" id="import-mode-note"></p>
</div></div><div id="toast"></div>
<script id="graph-data" type="application/json">__GRAPH_DATA__</script>
<script>
(function(){
"use strict";
let MODEL=JSON.parse(document.getElementById("graph-data").textContent);
const SERVER_MODE=__SERVER_MODE__;
const byId=new Map(),positions=new Map();
let mode="architecture",selectedId=null,selectedTab="overview",selectedEdge=null,history=[];
let scale=1,tx=0,ty=0,drag=null,pan=null,renderNodes=[],renderEdges=[];
const svg=document.getElementById("graph"),viewport=document.getElementById("viewport");
const edgeLayer=document.getElementById("graph-edges"),nodeLayer=document.getElementById("graph-nodes");
const search=document.getElementById("global-search"),sidebarSearch=document.getElementById("sidebar-search");
function clear(parent){parent.replaceChildren()}
function el(tag,attrs){const item=document.createElementNS("http://www.w3.org/2000/svg",tag);Object.entries(attrs||{}).forEach(function(pair){item.setAttribute(pair[0],pair[1])});return item}
function h(tag,cls,value){const item=document.createElement(tag);if(cls)item.className=cls;if(value!==undefined&&value!==null)item.textContent=String(value);return item}
function add(parent,tag,cls,value){const item=h(tag,cls,value);parent.appendChild(item);return item}
function mapModel(){byId.clear();MODEL.nodes.forEach(function(n){byId.set(n.id,n)});(MODEL.groups||[]).forEach(function(g){byId.set(g.id,{...g,id:g.id,type:"group",kind:"group",label:g.label,folder:g.folder,description:g.count+" declarations",vendor:(g.vendors||[]).join(", "),origin:"mixed",scope:"application",incoming:0,outgoing:0})})}
function node(id){return byId.get(id)}
function toast(message){const item=document.getElementById("toast");item.textContent=message;item.classList.add("show");clearTimeout(toast.handle);toast.handle=setTimeout(function(){item.classList.remove("show")},2600)}
function filters(){const result={};document.querySelectorAll("[data-filter]").forEach(function(x){result[x.dataset.filter]=x.checked});return result}
function visibleNode(n){
  if(!n)return false;
  const f=filters();
  if(n.type==="group"){
    if(Array.isArray(n.declarations)&&n.declarations.length)return n.declarations.some(function(id){return visibleNode(node(id))});
    return true;
  }
  const declaration=n.type==="declaration"?n:node(n.contract_id);
  if(declaration&&declaration.type==="declaration"){
    const dk=(declaration.declaration_kind||"contract").toLowerCase();
    const key=dk.includes("interface")?"interface":dk.includes("library")?"library":dk.includes("abstract")?"abstract":"contract";
    if(!f[key])return false;
  }
  if(n.origin==="third-party"&&!f["third-party"])return false;
  if(n.origin!=="third-party"&&!f["first-party"]&&n.scope!=="external")return false;
  if(n.scope==="support"&&!f.support)return false;
  if(n.origin==="unresolved"&&!f.unresolved)return false;
  const vendorInput=Array.from(document.querySelectorAll("[data-vendor]")).find(function(x){return x.dataset.vendor===n.vendor});
  if(vendorInput&&vendorInput.checked)return false;
  return true;
}
function visibleEdge(e){
  const edgeFilters={};document.querySelectorAll("[data-edge]").forEach(function(x){edgeFilters[x.dataset.edge]=x.checked});
  let family=e.kind;
  if(e.kind==="LIBRARY_CALL"||e.kind==="USES_LIBRARY")family="USES_LIBRARY";
  else if(["READS_CONSTANT","READS_IMMUTABLE","TRANSIENT_READS"].includes(e.kind))family="READS";
  else if(["WRITES","DELETES","MUTATES","TRANSIENT_WRITES","TRANSIENT_DELETES","INITIALIZES","UNRESOLVED_STORAGE","UNRESOLVED_MUTATION"].includes(e.kind))family="WRITES";
  if(edgeFilters[family]===false)return false;
  const choice=document.getElementById("edge-select").value;
  if(choice&&choice!==e.kind)return false;
  if((e.resolution==="UNRESOLVED"||e.resolution==="AMBIGUOUS")&&!filters().unresolved)return false;
  return visibleNode(node(e.source))&&visibleNode(node(e.target));
}
function declarationNodes(){return MODEL.nodes.filter(function(n){return n.type==="declaration"&&visibleNode(n)})}
function groupNodes(){return MODEL.groups.map(function(g){return node(g.id)}).filter(visibleNode)}
function folderProjection(folder){
  const group=MODEL.groups.find(function(g){return g.folder===folder});if(!group)return {nodes:[],edges:[]};
  const ids=new Set((group.declarations||[]).filter(function(id){return visibleNode(node(id))}));
  const rows=new Map();
  MODEL.edges.forEach(function(e){
    if(e.kind==="CONTAINS"||["READS","READS_CONSTANT","READS_IMMUTABLE","WRITES","DELETES","MUTATES","TRANSIENT_READS","TRANSIENT_WRITES","TRANSIENT_DELETES","INITIALIZES","ALIASES_STORAGE","UNRESOLVED_STORAGE","UNRESOLVED_MUTATION"].includes(e.kind))return;
    const a=node(e.source),b=node(e.target);if(!a||!b||!visibleEdge(e))return;
    const aOwner=a.type==="declaration"?a.id:a.contract_id;
    const bOwner=b.type==="declaration"?b.id:b.contract_id;
    const aLocal=!!aOwner&&ids.has(aOwner);
    const bLocal=!!bOwner&&ids.has(bOwner);
    if(!aLocal&&!bLocal)return;
    // Keep concrete functions/endpoints and their owning declarations so the
    // folder map exposes external calls and asset boundaries, not just peers.
    ids.add(e.source);ids.add(e.target);
    if(aOwner)ids.add(aOwner);
    if(bOwner)ids.add(bOwner);
    const sourceAnchor=aOwner||e.source;
    const targetAnchor=bOwner||e.target;
    if(sourceAnchor===targetAnchor)return;
    const key=sourceAnchor+"|"+targetAnchor+"|"+e.kind+"|"+e.resolution;
    const row=rows.get(key)||{
      id:key,source:sourceAnchor,target:targetAnchor,kind:e.kind,
      label:e.label,count:0,resolution:e.resolution,file:e.file,line:e.line
    };
    row.count++;rows.set(key,row);
  });
  const nodes=Array.from(ids).map(node).filter(function(n){return n&&visibleNode(n)});
  const kept=new Set(nodes.map(function(n){return n.id}));
  const edges=MODEL.edges.filter(function(e){
    if(e.kind==="CONTAINS")return kept.has(e.source)&&kept.has(e.target)&&visibleEdge(e);
    const a=node(e.source),b=node(e.target);
    const aOwner=a&&(a.type==="declaration"?a.id:a.contract_id);
    const bOwner=b&&(b.type==="declaration"?b.id:b.contract_id);
    return kept.has(e.source)&&kept.has(e.target)&&visibleEdge(e)&&
      ((aOwner&&ids.has(aOwner))||(bOwner&&ids.has(bOwner)));
  });
  // Use the source edge set for exact node-to-node relationships. The aggregate
  // rows are available as topology summaries to the inspector when needed.
  return {nodes:nodes,edges:edges,aggregates:Array.from(rows.values())};
}
function selectedContractProjection(contractId){
  const focus=node(contractId);if(!focus)return {nodes:[],edges:[]};
  const owned=MODEL.nodes.filter(function(n){return n.contract_id===contractId});
  const functions=owned.filter(function(n){return n.type==="function"||n.type==="modifier"});
  const ownFunctionIds=new Set(functions.map(function(fn){return fn.id}));
  const relevant=MODEL.edges.filter(function(e){
    if(e.kind==="CONTAINS")return false;
    const inbound=ownFunctionIds.has(e.target)&&["CALLS","LIBRARY_CALL","EXTERNAL_CALL"].includes(e.kind);
    const outbound=ownFunctionIds.has(e.source);
    const contractDependency=e.source===contractId&&["INHERITS","USES_LIBRARY","USES_TYPE","IMPORTS"].includes(e.kind);
    return (inbound||outbound||contractDependency)&&visibleEdge(e);
  });
  const ids=new Set([contractId]);
  relevant.forEach(function(e){
    ids.add(e.source);ids.add(e.target);
    const a=node(e.source),b=node(e.target);
    if(a&&a.contract_id)ids.add(a.contract_id);
    if(b&&b.contract_id)ids.add(b.contract_id);
  });
  // Retain all externally callable entry points, including functions with no indexed edges.
  functions.filter(function(fn){return fn.visibility==="external"||fn.visibility==="public"}).forEach(function(fn){
    if(visibleNode(fn))ids.add(fn.id);
  });
  const includedContracts=new Set(Array.from(ids).map(function(id){
    const n=node(id);return n&&(n.type==="declaration"?n.id:n.contract_id);
  }).filter(Boolean));
  const ownership=MODEL.edges.filter(function(e){
    return e.kind==="CONTAINS"&&includedContracts.has(e.source)&&ids.has(e.target)&&visibleEdge(e);
  });
  ownership.forEach(function(e){ids.add(e.source);ids.add(e.target)});
  const nodes=Array.from(ids).map(node).filter(function(n){return n&&visibleNode(n)});
  const kept=new Set(nodes.map(function(n){return n.id}));
  const edges=MODEL.edges.filter(function(e){
    if(e.kind==="CONTAINS")return includedContracts.has(e.source)&&kept.has(e.target)&&visibleEdge(e);
    return kept.has(e.source)&&kept.has(e.target)&&visibleEdge(e);
  });
  return {nodes:nodes,edges:edges};
}
function functionProjection(contractId,focusFunction){
  const functions=MODEL.nodes.filter(function(n){return ["function","modifier"].includes(n.type)&&n.contract_id===contractId&&visibleNode(n)});
  const root=focusFunction?node(focusFunction):functions.find(function(n){return n.visibility==="external"||n.visibility==="public"})||functions[0];
  if(!root)return {nodes:[],edges:[],root:null};
  const distance=new Map([[root.id,0]]),queue=[root.id],callEdges=[];
  while(queue.length){
    const current=queue.shift();
    MODEL.edges.forEach(function(e){
      if(e.source!==current||!["CALLS","LIBRARY_CALL","EXTERNAL_CALL","APPLIES_MODIFIER","OVERRIDES"].includes(e.kind)||!visibleEdge(e))return;
      callEdges.push(e);
      const target=node(e.target);
      if(target&&["function","modifier"].includes(target.type)&&!distance.has(target.id)){
        distance.set(target.id,distance.get(current)+1);
        queue.push(target.id);
      }
    });
  }
  const distanceMap=distance;
  const functionIds=new Set(distanceMap.keys());
  const ids=new Set(functionIds);
  const edges=callEdges.filter(function(e){return functionIds.has(e.source)});
  edges.forEach(function(e){ids.add(e.source);ids.add(e.target)});
  MODEL.edges.forEach(function(e){
    if(!functionIds.has(e.source)||!["READS","READS_CONSTANT","READS_IMMUTABLE","WRITES","DELETES","MUTATES","TRANSIENT_READS","TRANSIENT_WRITES","TRANSIENT_DELETES","INITIALIZES","ALIASES_STORAGE","UNRESOLVED_STORAGE","UNRESOLVED_MUTATION","ASSET_FLOW"].includes(e.kind))return;
    if(visibleEdge(e)){edges.push(e);ids.add(e.target)}
  });
  const ownerIds=new Set(Array.from(functionIds).map(function(id){return (node(id)||{}).contract_id}).filter(Boolean));
  ownerIds.forEach(function(id){if(visibleNode(node(id)))ids.add(id)});
  const ownership=MODEL.edges.filter(function(e){
    return e.kind==="CONTAINS"&&ownerIds.has(e.source)&&functionIds.has(e.target)&&visibleEdge(e);
  });
  ownership.forEach(function(e){edges.push(e)});
  const kept=new Set(ids);
  const filteredEdges=Array.from(new Map(edges.filter(function(e){return kept.has(e.source)&&kept.has(e.target)}).map(function(e){return [e.id,e]})).values());
  return {nodes:Array.from(ids).map(node).filter(Boolean),edges:filteredEdges,root:root,distance:distanceMap};
}
function storageProjection(contractId){
  if(!contractId||!node(contractId))return {nodes:[],edges:[]};
  const functions=MODEL.nodes.filter(function(n){return ["function","modifier"].includes(n.type)&&n.contract_id===contractId&&visibleNode(n)});
  const ids=new Set([contractId]),functionIds=new Set(functions.map(function(n){return n.id})),edges=[];
  functionIds.forEach(function(id){ids.add(id)});
  MODEL.edges.forEach(function(e){
    if(!functionIds.has(e.source)||!["READS","READS_CONSTANT","READS_IMMUTABLE","WRITES","DELETES","MUTATES","TRANSIENT_READS","TRANSIENT_WRITES","TRANSIENT_DELETES","INITIALIZES","ALIASES_STORAGE","UNRESOLVED_STORAGE","UNRESOLVED_MUTATION"].includes(e.kind)||!visibleEdge(e))return;
    edges.push(e);ids.add(e.target);
  });
  MODEL.edges.forEach(function(e){
    if(e.kind==="CONTAINS"&&e.source===contractId&&functionIds.has(e.target)&&visibleEdge(e))edges.push(e);
  });
  return {nodes:Array.from(ids).map(node).filter(Boolean),edges:edges};
}
function assetProjection(contractId){
  if(!contractId||!node(contractId))return {nodes:[],edges:[]};
  const functions=MODEL.nodes.filter(function(n){return ["function","modifier"].includes(n.type)&&n.contract_id===contractId&&visibleNode(n)});
  const functionIds=new Set(functions.map(function(n){return n.id})),ids=new Set([contractId]),edges=[];
  functionIds.forEach(function(id){ids.add(id)});
  MODEL.edges.forEach(function(e){
    if(functionIds.has(e.source)&&e.kind==="ASSET_FLOW"&&visibleEdge(e)){edges.push(e);ids.add(e.target)}
  });
  MODEL.edges.forEach(function(e){
    if(e.kind==="CONTAINS"&&e.source===contractId&&functionIds.has(e.target)&&visibleEdge(e))edges.push(e);
  });
  return {nodes:Array.from(ids).map(node).filter(Boolean),edges:edges};
}
function securityProjection(contractId){
  const leads=MODEL.review_leads.filter(function(lead){return !contractId||lead.contract===(node(contractId)||{}).name||lead.contract===(node(contractId)||{}).contract});
  const ids=new Set(),edges=[],owners=new Set();
  leads.forEach(function(lead){
    ids.add(lead.function);
    const fn=node(lead.function);if(fn&&fn.contract_id)owners.add(fn.contract_id);
    lead.edge_ids.forEach(function(id){
      const e=MODEL.edges.find(function(item){return item.id===id});
      if(e&&visibleEdge(e)){edges.push(e);ids.add(e.source);ids.add(e.target)}
    });
  });
  owners.forEach(function(id){if(visibleNode(node(id)))ids.add(id)});
  MODEL.edges.forEach(function(e){
    if(e.kind==="CONTAINS"&&owners.has(e.source)&&ids.has(e.target)&&visibleEdge(e))edges.push(e);
  });
  return {nodes:Array.from(ids).map(node).filter(Boolean),edges:Array.from(new Map(edges.map(function(e){return [e.id,e]})).values()),leads:leads};
}
function overviewProjection(){
  const groupMap=new Map(groupNodes().map(function(g){return [g.id,g]}));
  const rows=new Map();
  MODEL.edges.forEach(function(e){
    if(e.kind==="CONTAINS"||["READS","READS_CONSTANT","READS_IMMUTABLE","WRITES","DELETES","MUTATES","TRANSIENT_READS","TRANSIENT_WRITES","TRANSIENT_DELETES","INITIALIZES","ALIASES_STORAGE","UNRESOLVED_STORAGE","UNRESOLVED_MUTATION"].includes(e.kind))return;
    if(!visibleEdge(e))return;
    const a=node(e.source),b=node(e.target);if(!a||!b)return;
    let sourceGroup=null,targetGroup=null;
    if(e.kind==="IMPORTS"){
      sourceGroup="group:"+a.folder;
      targetGroup=b.type==="file"?"group:"+b.folder:"external-dependencies";
    }else{
      const sourceOwner=a.type==="declaration"?a.id:a.contract_id;
      const targetOwner=b.type==="declaration"?b.id:b.contract_id;
      if(!sourceOwner)return;
      sourceGroup="group:"+(node(sourceOwner)||{}).folder;
      targetGroup=targetOwner?"group:"+(node(targetOwner)||{}).folder:(e.kind==="ASSET_FLOW"?"asset-boundary":"external-dependencies");
    }
    if(!sourceGroup||!targetGroup||sourceGroup===targetGroup)return;
    if(!groupMap.has(sourceGroup)){
      const group=MODEL.groups.find(function(item){return item.id===sourceGroup});
      if(group&&visibleNode(node(sourceGroup)))groupMap.set(sourceGroup,node(sourceGroup));
    }
    if(!groupMap.has(targetGroup)){
      const group=MODEL.groups.find(function(item){return item.id===targetGroup});
      if(group&&visibleNode(node(targetGroup)))groupMap.set(targetGroup,node(targetGroup));
      else if(targetGroup==="asset-boundary"||targetGroup==="external-dependencies"){
        groupMap.set(targetGroup,{
          id:targetGroup,type:"group",kind:"group",
          label:targetGroup==="asset-boundary"?"Asset flows":"External boundaries",
          folder:targetGroup,count:0,declarations:[],origin:"external",scope:"external"
        });
      }
    }
    if(!groupMap.has(sourceGroup)||!groupMap.has(targetGroup))return;
    const key=sourceGroup+"|"+targetGroup+"|"+e.kind+"|"+e.resolution;
    const row=rows.get(key)||{
      id:"overview:"+key,source:sourceGroup,target:targetGroup,
      kind:e.kind,label:e.label,count:0,resolution:e.resolution,examples:[]
    };
    row.count++;
    if(row.examples.length<5)row.examples.push({
      source_contract:a.contract||a.label,target_contract:b.contract||b.label,
      source_file:e.file,line:e.line
    });
    rows.set(key,row);
  });
  return {nodes:Array.from(groupMap.values()),edges:Array.from(rows.values())};
}
function currentProjection(){
  const selected=node(selectedId);
  if(mode==="architecture"){
    if(!selected)return overviewProjection();
    if(selected.type==="group")return folderProjection(selected.folder);
    if(selected.type==="declaration")return selectedContractProjection(selectedId);
    return overviewProjection();
  }
  const owner=selected?(selected.type==="declaration"?selected.id:selected.contract_id):null;
  if(mode==="functions"){
    if(!selected)return {nodes:[],edges:[],root:null};
    return functionProjection(owner,selected&&["function","modifier"].includes(selected.type)?selected.id:null);
  }
  if(mode==="storage")return storageProjection(owner);
  if(mode==="assets")return assetProjection(owner);
  if(mode==="security")return securityProjection(owner);
  return overviewProjection();
}
function layoutProjection(projection,rootId){
  const nodes=projection.nodes||[],edges=projection.edges||[],pos=new Map();
  if(!nodes.length)return pos;
  if(rootId&&nodes.some(function(n){return n.id===rootId})){
    const levels=new Map([[rootId,0]]),queue=[rootId];
    while(queue.length){
      const current=queue.shift(),level=levels.get(current);
      edges.forEach(function(e){
        if(e.source===current&&["CALLS","LIBRARY_CALL","EXTERNAL_CALL","APPLIES_MODIFIER","OVERRIDES","INHERITS","USES_LIBRARY","USES_TYPE","CONTAINS"].includes(e.kind)&&!levels.has(e.target)&&node(e.target)){
          levels.set(e.target,level+1);queue.push(e.target);
        }else if(e.kind==="CONTAINS"&&e.target===current&&!levels.has(e.source)&&node(e.source)){
          levels.set(e.source,level+1);queue.push(e.source);
        }
      });
    }
    const columns=new Map();
    nodes.forEach(function(n){const level=levels.has(n.id)?levels.get(n.id):6;if(!columns.has(level))columns.set(level,[]);columns.get(level).push(n)});
    Array.from(columns.keys()).sort(function(a,b){return a-b}).forEach(function(col){
      columns.get(col).sort(function(a,b){return a.label.localeCompare(b.label)}).forEach(function(n,i){
        pos.set(n.id,{x:150+col*320,y:100+i*Math.max(88,Math.min(130,720/Math.max(columns.get(col).length,1)))});
      });
    });
    let bottom=0;
    nodes.filter(function(n){return ["state","asset","unresolved_state"].includes(n.type)}).forEach(function(n){pos.set(n.id,{x:200+(bottom%4)*300,y:790+Math.floor(bottom/4)*86});bottom++});
    return pos;
  }
  const declarations=nodes.filter(function(n){return n.type==="declaration"||n.type==="group"});
  const functions=nodes.filter(function(n){return n.type==="function"||n.type==="modifier"});
  const states=nodes.filter(function(n){return n.type==="state"||n.type==="unresolved_state"});
  const assets=nodes.filter(function(n){return n.type==="asset"});
  const externals=nodes.filter(function(n){return n.type==="external"||n.type==="interface"});
  declarations.forEach(function(n,i){pos.set(n.id,{x:250+(i%3)*460,y:160+Math.floor(i/3)*300})});
  functions.forEach(function(n,i){if(!pos.has(n.id))pos.set(n.id,{x:240+(i%4)*280,y:495+Math.floor(i/4)*85})});
  states.forEach(function(n,i){pos.set(n.id,{x:220+(i%4)*300,y:790+Math.floor(i/4)*82})});
  assets.forEach(function(n,i){pos.set(n.id,{x:1080+(i%2)*220,y:735+Math.floor(i/2)*85})});
  externals.forEach(function(n,i){if(!pos.has(n.id))pos.set(n.id,{x:1120,y:145+i*115})});
  nodes.forEach(function(n,i){if(!pos.has(n.id))pos.set(n.id,{x:170+(i%5)*260,y:285+Math.floor(i/5)*110})});
  return pos;
}
function dimensions(n){return {w:Math.max(150,Math.min(270,(n.label||n.id).length*7.2+45)),h:n.type==="group"?76:58}}
function curve(a,b,index){const dx=b.x-a.x,bend=Math.max(55,Math.min(180,Math.abs(dx)*.28))+((index%3)-1)*22;return "M"+a.x+" "+a.y+" C"+(a.x+Math.sign(dx||1)*bend)+" "+a.y+" "+(b.x-Math.sign(dx||1)*bend)+" "+b.y+" "+b.x+" "+b.y}
function subtitle(n){
  if(n.type==="declaration")return (n.declaration_kind||"contract")+" · "+(n.folder||"");
  if(n.type==="function"||n.type==="modifier")return (n.visibility||"visibility unknown")+" · "+(n.mutability||"nonpayable");
  if(n.type==="state")return (n.storage_class||"storage")+" · "+(n.type_text||"state");
  if(n.type==="asset")return "asset movement candidate";
  if(n.type==="group")return n.description||n.count+" declarations";
  return n.file||n.type;
}
function renderGraph(){
  const p=currentProjection();renderNodes=p.nodes||[];renderEdges=(p.edges||[]).filter(visibleEdge);
  positions.clear();
  const root=mode==="functions"&&node(selectedId)&&["function","modifier"].includes(node(selectedId).type)?selectedId:selectedId;
  layoutProjection({nodes:renderNodes,edges:renderEdges},root).forEach(function(value,key){positions.set(key,value)});
  clear(edgeLayer);clear(nodeLayer);
  const coords=new Map(renderNodes.map(function(n){return [n.id,positions.get(n.id)]}));
  renderEdges.forEach(function(e,i){
    const a=coords.get(e.source),b=coords.get(e.target);if(!a||!b)return;
    const da=dimensions(node(e.source)||{}),db=dimensions(node(e.target)||{});
    const start={x:a.x+da.w/2,y:a.y+da.h/2},end={x:b.x-db.w/2,y:b.y+db.h/2};
    const path=el("path",{d:curve(start,end,i),class:"edge "+String(e.kind).replace(/[^A-Za-z0-9_-]/g,"_")+(selectedEdge===e.id?" hot":""),"data-edge-id":e.id});
    const title=el("title");title.textContent=(e.label||e.kind)+" · "+e.resolution+(e.file?" · "+e.file+":"+e.line:"");path.appendChild(title);
    path.addEventListener("click",function(event){event.stopPropagation();showEdgeDetails(e)});
    edgeLayer.appendChild(path);
    if(renderEdges.length<=180&&e.kind!=="CONTAINS"){
      const text=el("text",{x:(start.x+end.x)/2,y:(start.y+end.y)/2-6,class:"edge-label"});
      text.textContent=(e.label||e.kind)+(e.count>1?" ×"+e.count:"");edgeLayer.appendChild(text);
    }
  });
  renderNodes.forEach(function(n){
    const pnt=coords.get(n.id);if(!pnt)return;
    const d=dimensions(n),kind=n.type==="declaration"?(n.declaration_kind||"contract").toLowerCase().includes("interface")?"interface":(n.declaration_kind||"").toLowerCase().includes("library")?"library":"declaration":n.type;
    const group=el("g",{class:"graph-node "+kind+(selectedId===n.id?" selected":""),transform:"translate("+(pnt.x-d.w/2)+","+(pnt.y-d.h/2)+")","data-node-id":n.id});
    group.appendChild(el("rect",{width:d.w,height:d.h}));
    const title=el("text",{x:13,y:24,class:"node-title"});title.textContent=n.label.length>34?n.label.slice(0,31)+"…":n.label;
    const sub=el("text",{x:13,y:43,class:"node-subtitle"});sub.textContent=(subtitle(n)||"").slice(0,43);
    group.append(title,sub);
    const tip=el("title");tip.textContent=n.label+" · "+(n.location||n.file||n.type);group.appendChild(tip);
    group.addEventListener("click",function(event){event.stopPropagation();openNode(n.id,true)});
    group.addEventListener("pointerdown",function(event){event.stopPropagation();drag={id:n.id,startX:event.clientX,startY:event.clientY,origin:{x:pnt.x,y:pnt.y}};group.setPointerCapture(event.pointerId)});
    group.addEventListener("pointermove",function(event){
      if(!drag||drag.id!==n.id)return;
      const bounds=svg.getBoundingClientRect();positions.set(n.id,{x:drag.origin.x+(event.clientX-drag.startX)*(1500/bounds.width)/scale,y:drag.origin.y+(event.clientY-drag.startY)*(920/bounds.height)/scale});renderPositionsOnly();
    });
    group.addEventListener("pointerup",function(){drag=null});group.addEventListener("pointercancel",function(){drag=null});
    nodeLayer.appendChild(group);
  });
  document.getElementById("graph-empty").style.display=renderNodes.length?"none":"grid";
  document.getElementById("view-label").textContent=mode.toUpperCase().replace("FUNCTIONS","FUNCTION FLOW").replace("SECURITY","SECURITY REVIEW");
  const empty=document.getElementById("graph-empty");
  if(!renderNodes.length){
    const message=mode==="functions"&&!selectedId?"Select a contract or function to inspect its call tree.":mode==="storage"&&!selectedId?"Select a contract to inspect function-to-storage relationships.":mode==="assets"&&!selectedId?"Select a contract to inspect its asset-flow paths.":"No visible relationships match these filters. Re-enable a layer or select another node.";
    empty.querySelector("span").textContent=message;
  }
  updateMinimap();applyTransform();
}
function renderPositionsOnly(){
  Array.from(nodeLayer.children).forEach(function(group){
    const id=group.getAttribute("data-node-id"),p=positions.get(id),n=node(id);if(!p||!n)return;
    const d=dimensions(n);group.setAttribute("transform","translate("+(p.x-d.w/2)+","+(p.y-d.h/2)+")");
  });
  Array.from(edgeLayer.children).forEach(function(path){
    const edge=renderEdges.find(function(e){return e.id===path.getAttribute("data-edge-id")});if(!edge)return;
    const a=positions.get(edge.source),b=positions.get(edge.target);if(!a||!b)return;
    const da=dimensions(node(edge.source)||{}),db=dimensions(node(edge.target)||{});
    path.setAttribute("d",curve({x:a.x+da.w/2,y:a.y+da.h/2},{x:b.x-db.w/2,y:b.y+db.h/2},0));
  });
  updateMinimap();
}
let minimapBounds=null;
function updateMinimap(){
  const mini=document.getElementById("minimap");clear(mini);
  if(!positions.size){minimapBounds=null;return}
  const values=Array.from(positions.values()),xs=values.map(function(p){return p.x}),ys=values.map(function(p){return p.y});
  const minX=Math.min(...xs)-100,maxX=Math.max(...xs)+100,minY=Math.min(...ys)-70,maxY=Math.max(...ys)+70,sx=132/Math.max(1,maxX-minX),sy=73/Math.max(1,maxY-minY);
  minimapBounds={minX:minX,minY:minY,sx:sx,sy:sy};
  renderEdges.forEach(function(e){const a=positions.get(e.source),b=positions.get(e.target);if(a&&b)mini.appendChild(el("line",{x1:10+(a.x-minX)*sx,y1:10+(a.y-minY)*sy,x2:10+(b.x-minX)*sx,y2:10+(b.y-minY)*sy,stroke:"#547493","stroke-width":.6}))});
  renderNodes.forEach(function(n){const p=positions.get(n.id);if(p)mini.appendChild(el("circle",{cx:10+(p.x-minX)*sx,cy:10+(p.y-minY)*sy,r:n.type==="declaration"||n.type==="group"?2.8:1.6,fill:n.type==="asset"?"#c58ada":n.type==="state"?"#64b68e":"#59bde7"}))});
}
function applyTransform(){viewport.setAttribute("transform","translate("+tx+" "+ty+") scale("+scale+")")}
document.getElementById("minimap").addEventListener("click",function(event){
  if(!minimapBounds||!renderNodes.length)return;
  const bounds=this.getBoundingClientRect();
  const x=(event.clientX-bounds.left)*154/bounds.width;
  const y=(event.clientY-bounds.top)*95/bounds.height;
  let nearest=null,nearestDistance=Infinity;
  renderNodes.forEach(function(n){
    const p=positions.get(n.id);if(!p)return;
    const px=10+(p.x-minimapBounds.minX)*minimapBounds.sx;
    const py=10+(p.y-minimapBounds.minY)*minimapBounds.sy;
    const distance=(px-x)*(px-x)+(py-y)*(py-y);
    if(distance<nearestDistance){nearestDistance=distance;nearest=n}
  });
  if(nearest){openNode(nearest.id,true)}
});
function fitGraph(){
  if(!positions.size)return;
  const values=Array.from(positions.values()),xs=values.map(function(p){return p.x}),ys=values.map(function(p){return p.y});
  const minX=Math.min(...xs)-190,maxX=Math.max(...xs)+190,minY=Math.min(...ys)-130,maxY=Math.max(...ys)+130,bounds=svg.getBoundingClientRect();
  scale=Math.max(.23,Math.min(1.35,Math.min((bounds.width||1000)/(maxX-minX),(bounds.height||700)/(maxY-minY))));
  tx=(1500/scale-(minX+maxX))/2;ty=(920/scale-(minY+maxY))/2;applyTransform();
}
function showEdgeDetails(e){
  selectedEdge=e.id;clear(document.getElementById("inspector"));const root=document.getElementById("inspector");
  add(root,"div","section-head","RELATIONSHIP EVIDENCE");add(root,"div","entity-name",e.label||e.kind);
  add(root,"p","entity-meta",(node(e.source)?.label||e.source)+" → "+(node(e.target)?.label||e.target));
  const badge=add(root,"div","coverage "+(e.resolution==="DIRECT"?"ok":"warn"),e.resolution+" · "+e.evidence);
  if(e.file)add(root,"code","location",e.file+(e.line?":"+e.line:""));
  if(e.receiver)add(root,"p","muted","Receiver: "+e.receiver);
  if(e.method)add(root,"p","muted","Declared method: "+e.method);
  if(e.implementation_resolution){
    const implementation=add(root,"div","coverage "+(e.implementation_resolution==="DIRECT"?"ok":"warn"),"Implementation resolution: "+e.implementation_resolution);
    add(implementation,"p","",e.implementation_resolution==="UNRESOLVED"?"The declared interface method is known, but the deployed implementation is not established by this source edge.":"Implementation is statically identified at this source site.");
  }
  if(e.asset||e.direction||e.recipient||e.amount){
    add(root,"div","section-head","ASSET DETAILS");
    [["Asset",e.asset],["Direction",e.direction],["Recipient",e.recipient],["Amount expression",e.amount],["Transfer status",e.status]].forEach(function(pair){
      if(pair[1]===undefined||pair[1]===null||pair[1]==="")return;
      add(root,"p","muted",pair[0]+": "+pair[1]);
    });
  }
  if(e.access_path)add(root,"p","muted","Storage access: "+e.access_path);
  if(e.detail)add(root,"p","muted",e.detail);
  if(e.via&&e.via.length)add(root,"p","muted","Reachability chain: "+e.via.map(function(id){return node(id)?.label||id}).join(" → "));
  if(e.source_excerpt){const code=add(root,"div","source-card");add(code,"pre","",e.source_excerpt)}
  if(e.file){
    const copy=add(root,"button","tool-button","Copy source location");
    copy.addEventListener("click",function(){
      const value=e.file+(e.line?":"+e.line:"");
      if(navigator.clipboard&&navigator.clipboard.writeText){
        navigator.clipboard.writeText(value).then(function(){toast("Source location copied")}).catch(function(){toast(value)});
      }else toast(value);
    });
  }
  const button=add(root,"button","tool-button primary","Open source function");button.addEventListener("click",function(){openNode(e.source,true)});
  renderGraph();
}
function renderStats(){
  const root=document.getElementById("project-stats");clear(root);
  [["FILES",MODEL.summary.files],["DECLARATIONS",MODEL.summary.declarations],["FUNCTIONS",MODEL.summary.functions]].forEach(function(pair){
    const box=add(root,"div","stat");add(box,"b","",pair[1]);add(box,"span","",pair[0]);
  });
  document.getElementById("coverage-short").textContent=MODEL.inventory.complete?"COMPLETE":"CHECK COVERAGE";
}
function renderVendorFilters(){
  const root=document.getElementById("vendor-filters");clear(root);
  (MODEL.vendors||[]).forEach(function(vendor){
    const label=add(root,"label","checkline",""),input=document.createElement("input");input.type="checkbox";input.checked=false;input.dataset.vendor=vendor;
    input.addEventListener("change",function(){renderSidebar();renderGraph()});label.append(input);add(label,"span","", "Hide "+vendor);
    const count=MODEL.nodes.filter(function(n){return n.origin==="third-party"&&n.vendor===vendor&&n.type==="declaration"}).length;
    add(label,"span","count-label",count);
  });
}
function renderSidebar(){
  const root=document.getElementById("declaration-tree");clear(root);
  const query=sidebarSearch.value.trim().toLowerCase(),groups=new Map();
  declarationNodes().forEach(function(n){
    if(query&&!n.label.toLowerCase().includes(query)&&!n.file.toLowerCase().includes(query))return;
    if(!groups.has(n.folder))groups.set(n.folder,[]);groups.get(n.folder).push(n);
  });
  Array.from(groups.keys()).sort().forEach(function(folder){
    const box=add(root,"div","folder-group"),row=add(box,"div","folder-row"),toggle=add(row,"button","","▾  "+folder+"/"),items=groups.get(folder).sort(function(a,b){return a.label.localeCompare(b.label)});
    add(row,"span","",items.length);
    const children=add(box,"div","folder-children");toggle.addEventListener("click",function(){children.hidden=!children.hidden;toggle.textContent=(children.hidden?"▸  ":"▾  ")+folder+"/"});
    items.forEach(function(n){
      const button=add(children,"button","declaration-row"+(selectedId===n.id?" active":""),"");
      const dk=(n.declaration_kind||"").toLowerCase(),ico=add(button,"span","node-icon"+(dk.includes("interface")?" interface":dk.includes("library")?" library":""),dk.includes("interface")?"I":dk.includes("library")?"L":"◇");
      const main=add(button,"span","declaration-main");add(main,"span","declaration-name",n.label);add(main,"span","declaration-meta",(n.declaration_kind||"contract")+" · "+n.file);
      const fnCount=MODEL.nodes.filter(function(x){return x.contract_id===n.id&&(x.type==="function"||x.type==="modifier")}).length;
      add(button,"span","declaration-count",fnCount+"ƒ");button.addEventListener("click",function(){openNode(n.id,true)});
    });
  });
  if(!root.children.length)add(root,"p","muted","No declarations match. Reset filters to restore the full inventory.");
  renderVendorFilters();
}
function inspectorItem(parent,n,secondary){
  const button=add(parent,"button","inspect-item","");add(button,"strong","",n.label);add(button,"small","",secondary||n.location||n.kind);
  button.addEventListener("click",function(){openNode(n.id,true)});return button;
}
function renderSection(parent,title,items,empty){
  const box=add(parent,"div","inspector-section");add(box,"div","section-head",title+" · "+items.length);const list=add(box,"div","item-list");
  if(!items.length)add(list,"p","muted",empty||"No indexed items.");
  items.forEach(function(item){inspectorItem(list,item,item.location||item.kind)});return box;
}
function renderInspector(){
  const root=document.getElementById("inspector");clear(root);
  const selected=node(selectedId);
  if(!selected){
    add(root,"div","entity-name","Protocol overview");add(root,"p","entity-meta","Select any subsystem or declaration to explore the source graph.");
    const coverage=add(root,"div","coverage "+(MODEL.inventory.complete?"ok":"warn"));
    add(coverage,"strong","",MODEL.inventory.complete?"Source inventory complete":"Source inventory needs attention");
    add(coverage,"p","",MODEL.inventory.files_inspected+" indexed · "+MODEL.inventory.files_discovered+" discovered · "+MODEL.inventory.uninspected.length+" inspection issues");
    if(MODEL.inventory.excluded_directories.length){
      const excluded=add(root,"div","inspector-section");add(excluded,"div","section-head","EXCLUDED SOURCE DIRECTORIES · "+MODEL.inventory.excluded_directories.length);
      MODEL.inventory.excluded_directories.forEach(function(item){add(excluded,"p","muted",item.path+" · "+item.reason)});
    }
    const leadSection=add(root,"div","inspector-section");add(leadSection,"div","section-head","AUDIT REVIEW LEADS · "+MODEL.review_leads.length);
    MODEL.review_leads.forEach(function(lead){const b=add(leadSection,"button","inspect-item","");add(b,"strong","",lead.label);add(b,"small","",lead.tier+" · "+lead.score+"/10");b.addEventListener("click",function(){openNode(lead.function,true)})});
    if(MODEL.inventory.uninspected.length){
      const failures=add(root,"div","inspector-section");add(failures,"div","section-head","UNINSPECTED SOURCES");
      MODEL.inventory.uninspected.forEach(function(item){add(failures,"p","muted",item.path+" · "+item.phase+" · "+item.error)});
    }
    return;
  }
  const header=add(root,"div","right-title");add(header,"div","entity-icon",selected.type==="declaration"?"◇":selected.type==="function"?"ƒ":selected.type==="state"?"▤":selected.type==="asset"?"◉":"↗");
  const main=add(header,"div","entity-main");add(main,"div","entity-name",selected.label);add(main,"div","entity-meta",selected.location||selected.file||selected.type);
  add(header,"span","entity-badge",selected.declaration_kind||selected.type);
  const tabs=add(root,"nav","inspector-tabs");
  ["overview","functions","state","calls","assets","review"].forEach(function(tab){const button=add(tabs,"button","inspector-tab"+(selectedTab===tab?" active":""),tab.toUpperCase());button.addEventListener("click",function(){selectedTab=tab;renderInspector()})});
  const body=add(root,"div","inspector-body"),owner=selected.type==="declaration"?selected.id:selected.contract_id;
  const owned=MODEL.nodes.filter(function(n){return n.contract_id===owner});
  const functions=owned.filter(function(n){return n.type==="function"||n.type==="modifier"}).sort(function(a,b){return Number(b.visibility==="external"||b.visibility==="public")-Number(a.visibility==="external"||a.visibility==="public")||a.label.localeCompare(b.label)});
  const state=owned.filter(function(n){return n.type==="state"}).sort(function(a,b){return a.label.localeCompare(b.label)});
  if(selectedTab==="overview"){
    add(body,"p","muted",(selected.origin||"source")+" · "+selected.evidence+(selected.vendor!=="First-party"?" · "+selected.vendor:""));
    if(selected.type==="declaration"){
      add(body,"div","section-head","DECLARATION SUMMARY");add(body,"p","inspect-item",functions.length+" functions / modifiers · "+state.length+" state declarations");
      renderSection(body,"KEY ENTRY POINTS",functions.filter(function(n){return n.visibility==="external"||n.visibility==="public"}),"No public or external functions indexed.");
      renderSection(body,"STATE SURFACE",state,"No state declarations indexed.");
    }else if(selected.type==="function"||selected.type==="modifier"){
      add(body,"div","section-head","FUNCTION PROFILE");
      [["Visibility",selected.visibility],["Mutability",selected.mutability],["Parameters",(selected.parameters||[]).join(", ")||"none recorded"],["Contract",selected.contract]].forEach(function(pair){add(body,"p","inspect-item",pair[0]+": "+(pair[1]||"unknown"))});
    }else add(body,"p","muted",selected.type_text||"Indexed source declaration or relationship endpoint.");
  }else if(selectedTab==="functions")renderSection(body,"FUNCTIONS / MODIFIERS",functions,"No functions indexed.");
  else if(selectedTab==="state"){
    renderSection(body,"STATE DECLARATIONS",state,"No state variables indexed.");
    const edges=MODEL.edges.filter(function(e){return functions.some(function(fn){return fn.id===e.source})&&["READS","WRITES","DELETES","MUTATES","INITIALIZES"].includes(e.kind)});
    add(body,"div","section-head","FUNCTION / STATE ACCESS · "+edges.length);
    edges.forEach(function(e){const b=add(body,"button","inspect-item",e.kind+" · "+(node(e.target)?.label||e.target));b.addEventListener("click",function(){openNode(e.target,true)})});
  }else if(selectedTab==="calls"){
    const edges=MODEL.edges.filter(function(e){return functions.some(function(fn){return fn.id===e.source})&&["CALLS","LIBRARY_CALL","EXTERNAL_CALL","APPLIES_MODIFIER","USES_LIBRARY","INHERITS"].includes(e.kind)});
    add(body,"div","section-head","CALL / INTERFACE BOUNDARIES · "+edges.length);
    edges.forEach(function(e){const b=add(body,"button","inspect-item",e.label+" → "+(node(e.target)?.label||e.target));add(b,"small","",e.resolution+" · "+e.file+":"+e.line);b.addEventListener("click",function(){if(node(e.target))openNode(e.target,true)})});
  }else if(selectedTab==="assets"){
    const edges=MODEL.edges.filter(function(e){return functions.some(function(fn){return fn.id===e.source})&&e.kind==="ASSET_FLOW"});
    add(body,"div","section-head","ASSET FLOW CANDIDATES · "+edges.length);
    edges.forEach(function(e){const b=add(body,"button","inspect-item",e.asset+" "+e.direction+" · "+(node(e.target)?.label||e.target));add(b,"small","",e.status+" · "+e.file+":"+e.line);b.addEventListener("click",function(){if(node(e.target))openNode(e.target,true)})});
  }else{
    const leads=MODEL.review_leads.filter(function(lead){return lead.function===selected.id||lead.contract===selected.name||lead.contract===selected.contract});
    if(!leads.length)add(body,"p","muted","No heuristic review leads are attached. Absence of a signal does not establish safety.");
    leads.forEach(function(lead){
      const box=add(body,"div","signal");add(box,"strong","",lead.tier+" · "+lead.score+"/10");add(box,"div","",lead.label);
      lead.signals.forEach(function(signal){add(box,"p","",signal.label+": "+signal.question)});
      const b=add(box,"button","tool-button","Follow function");b.addEventListener("click",function(){openNode(lead.function,true)});
    });
  }
  if(selected.file){
    const section=add(body,"div","inspector-section");add(section,"div","section-head","SOURCE LOCATION");add(section,"code","location",selected.file+(selected.line?":"+selected.line:""));
    if(selected.source_excerpt){const code=add(section,"div","source-card");add(code,"pre","",selected.source_excerpt)}
  }
}
function renderFlow(){
  const track=document.getElementById("flow-track");clear(track);const selected=node(selectedId);
  if(!selected){document.getElementById("flow-title").textContent="SELECTED WORKFLOW";document.getElementById("flow-note").textContent="Choose a function to trace its call and effect path";return}
  const functionId=["function","modifier"].includes(selected.type)?selected.id:null;
  document.getElementById("flow-title").textContent="CALL / EFFECT PATH";
  if(!functionId){document.getElementById("flow-note").textContent="Select an individual function to follow reachable helpers and effects";return}
  const path=[functionId],seen=new Set(path);let current=functionId;
  for(let i=0;i<MODEL.edges.length+1;i++){
    const next=MODEL.edges.find(function(e){return e.source===current&&["CALLS","LIBRARY_CALL","EXTERNAL_CALL","APPLIES_MODIFIER"].includes(e.kind)&&node(e.target)&&!seen.has(e.target)&&visibleEdge(e)});
    if(!next)break;current=next.target;seen.add(current);path.push(current);
  }
  path.forEach(function(id,i){const n=node(id);if(!n)return;if(i)add(track,"span","flow-arrow","→");const b=add(track,"button","flow-step",String(i+1)+" · "+n.label);b.addEventListener("click",function(){openNode(id,true)})});
  const effects=MODEL.edges.filter(function(e){return e.source===functionId&&["READS","READS_CONSTANT","READS_IMMUTABLE","WRITES","DELETES","MUTATES","TRANSIENT_READS","TRANSIENT_WRITES","TRANSIENT_DELETES","INITIALIZES","ALIASES_STORAGE","UNRESOLVED_STORAGE","UNRESOLVED_MUTATION","ASSET_FLOW"].includes(e.kind)});
  if(effects.length)add(track,"span","flow-arrow","→"),add(track,"span","flow-step","STATE / ASSET EFFECTS · "+effects.length);
  document.getElementById("flow-note").textContent="Static path candidate · verify branch conditions and runtime execution";
}
function renderSearchResults(){
  const root=document.getElementById("search-results"),query=search.value.trim().toLowerCase();
  clear(root);if(!query){root.hidden=true;return}
  const priority={declaration:0,function:1,modifier:2,state:3,asset:4};
  const matches=MODEL.nodes.filter(function(n){
    if(n.type==="file"||!visibleNode(n))return false;
    return [n.label,n.qualified_name,n.file,n.contract,n.type_text].some(function(value){return String(value||"").toLowerCase().includes(query)});
  }).sort(function(a,b){
    const ap=a.label.toLowerCase().startsWith(query)?0:1,bp=b.label.toLowerCase().startsWith(query)?0:1;
    return ap-bp||(priority[a.type]||5)-(priority[b.type]||5)||a.label.localeCompare(b.label);
  }).slice(0,24);
  if(!matches.length){add(root,"div","search-empty","No visible declarations, functions or state items match.");root.hidden=false;return}
  if(matches.length===24)add(root,"div","search-empty","Showing the first 24 matches · refine your search to narrow the results.");
  matches.forEach(function(n){
    const button=add(root,"button","search-result","");
    add(button,"strong","",n.label);
    add(button,"small","",(n.declaration_kind||n.type)+" · "+(n.file||n.contract||""));
    button.addEventListener("click",function(){search.value="";sidebarSearch.value="";root.hidden=true;renderSidebar();openNode(n.id,true)});
  });
  root.hidden=false;
}
function renderAll(){
  renderStats();renderSidebar();renderGraph();renderInspector();renderFlow();
  const back=document.getElementById("back-graph");if(back)back.disabled=history.length===0;
}
function openNode(id,push){
  const n=node(id);if(!n)return;
  if(push&&selectedId&&selectedId!==id)history.push(selectedId);
  selectedId=id;selectedEdge=null;
  if(n.type==="function"||n.type==="modifier")mode="functions";
  else if(n.type==="state"||n.type==="unresolved_state")mode="storage";
  else if(n.type==="asset")mode="assets";
  else mode="architecture";
  document.querySelectorAll(".mode-tab").forEach(function(b){b.classList.toggle("active",b.dataset.mode===mode)});
  renderAll();requestAnimationFrame(fitGraph);
}
function clearFocus(){selectedId=null;history=[];selectedEdge=null;selectedTab="overview";mode="architecture";document.querySelectorAll(".mode-tab").forEach(function(b){b.classList.toggle("active",b.dataset.mode===mode)});renderAll();fitGraph()}
function setMode(next){mode=next;selectedEdge=null;document.querySelectorAll(".mode-tab").forEach(function(b){b.classList.toggle("active",b.dataset.mode===mode)});renderGraph();renderInspector();renderFlow();requestAnimationFrame(fitGraph)}
function setServerStatus(text){document.getElementById("import-status").textContent=text}
function refreshModel(next){
  if(!next||next.schema_version!==2||!Array.isArray(next.nodes)||!Array.isArray(next.edges))throw new Error("The selected file is not a Lowkey graph model.");
  MODEL=next;mapModel();selectedId=null;history=[];mode="architecture";selectedTab="overview";selectedEdge=null;
  document.getElementById("project-name").textContent=MODEL.project_name||"Imported source workspace";
  renderAll();fitGraph();toast("Graph workspace loaded");
}
async function importFiles(fileList){
  if(!SERVER_MODE){toast("Source import needs the local workspace. Run lk link --serve");return}
  const files=Array.from(fileList||[]).filter(function(file){
    const path=file.webkitRelativePath||file.name,parts=path.replace(/\\/g,"/").split("/");
    if(parts.some(function(part){return [".git",".hg",".svn","node_modules","out","cache","broadcast","artifacts","build","dist","__pycache__",".venv","venv"].includes(part)}))return false;
    const ext=file.name.toLowerCase().split(".").pop();
    return ext==="sol"||["foundry.toml","remappings.txt","soldeer.lock",".gitmodules",".gitignore"].includes(file.name.toLowerCase());
  });
  if(!files.some(function(file){return file.name.toLowerCase().endsWith(".sol")})){toast("No Solidity source files selected.");return}
  setServerStatus("Reading "+files.length+" selected files…");
  try{
    const payload=[];for(const file of files)payload.push({path:file.webkitRelativePath||file.name,content:await file.text()});
    const response=await fetch("/api/import",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({files:payload,name:"Uploaded Solidity workspace"})});
    const result=await response.json();if(!response.ok)throw new Error(result.error||"Import failed");
    refreshModel(result.graph);setServerStatus("Indexed "+result.graph.summary.files+" Solidity files.");document.getElementById("import-modal").classList.remove("open");
  }catch(error){setServerStatus(String(error.message||error))}
}
async function importZip(file){
  if(!SERVER_MODE){toast("ZIP import needs the local workspace. Run lk link --serve");return}
  setServerStatus("Uploading and indexing archive…");
  try{
    const response=await fetch("/api/archive",{method:"POST",headers:{"Content-Type":"application/zip","X-Archive-Name":encodeURIComponent(file.name)},body:file});
    const result=await response.json();if(!response.ok)throw new Error(result.error||"Archive import failed");
    refreshModel(result.graph);setServerStatus("Archive indexed · "+result.graph.summary.files+" Solidity files.");document.getElementById("import-modal").classList.remove("open");
  }catch(error){setServerStatus(String(error.message||error))}
}
async function importGithub(){
  if(!SERVER_MODE){toast("GitHub import needs the local workspace. Run lk link --serve");return}
  const url=document.getElementById("github-url").value.trim(),ref=document.getElementById("github-ref").value.trim();
  if(!url){setServerStatus("Enter a GitHub repository URL.");return}
  setServerStatus("Cloning and indexing repository…");
  try{
    const response=await fetch("/api/github",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:url,ref:ref})});
    const result=await response.json();if(!response.ok)throw new Error(result.error||"GitHub import failed");
    refreshModel(result.graph);setServerStatus("GitHub source indexed · "+result.graph.summary.files+" files.");document.getElementById("import-modal").classList.remove("open");
  }catch(error){setServerStatus(String(error.message||error))}
}
function downloadGraph(){
  const blob=new Blob([JSON.stringify(MODEL,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");
  a.href=url;a.download="lowkey-protocol-graph.json";a.click();URL.revokeObjectURL(url);
}
function openGraphFile(file){
  const reader=new FileReader();reader.onload=function(){try{refreshModel(JSON.parse(String(reader.result)))}catch(error){toast(error.message)}};reader.readAsText(file);
}
function setupImport(){
  const modal=document.getElementById("import-modal");
  document.getElementById("import-open").addEventListener("click",function(){modal.classList.add("open");document.getElementById("import-mode-note").textContent=SERVER_MODE?"Workspace server active · source analysis runs locally.":"Standalone export is offline. For source folder, ZIP or GitHub ingestion run lk link --serve."});
  document.getElementById("import-close").addEventListener("click",function(){modal.classList.remove("open")});
  modal.addEventListener("click",function(event){if(event.target===modal)modal.classList.remove("open")});
  document.getElementById("choose-files").addEventListener("click",function(){document.getElementById("files-input").click()});
  document.getElementById("choose-folder").addEventListener("click",function(){document.getElementById("folder-input").click()});
  document.getElementById("choose-zip").addEventListener("click",function(){document.getElementById("zip-input").click()});
  document.getElementById("files-input").addEventListener("change",function(event){importFiles(event.target.files);event.target.value=""});
  document.getElementById("folder-input").addEventListener("change",function(event){importFiles(event.target.files);event.target.value=""});
  document.getElementById("zip-input").addEventListener("change",function(event){if(event.target.files[0])importZip(event.target.files[0]);event.target.value=""});
  document.getElementById("github-import").addEventListener("click",importGithub);
}
function resetFilters(){
  document.querySelectorAll("[data-filter]").forEach(function(x){x.checked=x.dataset.filter==="first-party"||x.dataset.filter==="unresolved"||["contract","abstract","interface","library"].includes(x.dataset.filter)});
  document.querySelectorAll("[data-edge]").forEach(function(x){x.checked=x.dataset.edge!=="IMPORTS"});
  document.querySelectorAll("[data-vendor]").forEach(function(x){x.checked=false});renderAll();
}
function setupInteractions(){
  document.querySelectorAll(".mode-tab").forEach(function(button){button.addEventListener("click",function(){setMode(button.dataset.mode)})});
  document.querySelectorAll("[data-filter],[data-edge]").forEach(function(input){input.addEventListener("change",function(){renderSidebar();renderGraph();renderInspector()})});
  document.getElementById("reset-filters").addEventListener("click",resetFilters);
  document.getElementById("edge-select").addEventListener("change",renderGraph);
  sidebarSearch.addEventListener("input",renderSidebar);
  search.addEventListener("input",function(){sidebarSearch.value=search.value;renderSidebar();renderSearchResults()});
  search.addEventListener("focus",renderSearchResults);
  document.addEventListener("click",function(event){if(!event.target.closest(".global-search")&&!event.target.closest("#search-results"))document.getElementById("search-results").hidden=true});
  document.getElementById("zoom-in").addEventListener("click",function(){scale=Math.min(2.8,scale*1.2);applyTransform()});
  document.getElementById("zoom-out").addEventListener("click",function(){scale=Math.max(.2,scale/1.2);applyTransform()});
  document.getElementById("fit-graph").addEventListener("click",fitGraph);
  document.getElementById("clear-focus").addEventListener("click",clearFocus);
  document.getElementById("back-graph").addEventListener("click",function(){
    if(!history.length)return;
    const previous=history.pop();openNode(previous,false);
  });
  document.getElementById("export-json").addEventListener("click",downloadGraph);
  const open=add(document.querySelector(".top-actions"),"button","tool-button","Open graph JSON");
  open.addEventListener("click",function(){const input=document.createElement("input");input.type="file";input.accept=".json,application/json";input.addEventListener("change",function(){if(input.files[0])openGraphFile(input.files[0])});input.click()});
  svg.addEventListener("wheel",function(event){event.preventDefault();scale=Math.max(.2,Math.min(2.8,scale*(event.deltaY<0?1.12:.89)));applyTransform()},{passive:false});
  svg.addEventListener("pointerdown",function(event){if(event.target.closest&&event.target.closest(".graph-node"))return;pan={x:event.clientX,y:event.clientY,tx:tx,ty:ty};svg.classList.add("dragging")});
  svg.addEventListener("pointermove",function(event){if(!pan)return;const bounds=svg.getBoundingClientRect();tx=pan.tx+(event.clientX-pan.x)*(1500/bounds.width)/scale;ty=pan.ty+(event.clientY-pan.y)*(920/bounds.height)/scale;applyTransform()});
  svg.addEventListener("pointerup",function(){pan=null;svg.classList.remove("dragging")});svg.addEventListener("pointercancel",function(){pan=null;svg.classList.remove("dragging")});
  svg.addEventListener("dblclick",fitGraph);
  document.addEventListener("keydown",function(event){
    if(event.key==="/"&&!["INPUT","TEXTAREA"].includes(document.activeElement.tagName)){event.preventDefault();search.focus()}
    if(event.key==="Escape"){document.getElementById("import-modal").classList.remove("open");search.blur()}
    if(event.key==="Backspace"&&!["INPUT","TEXTAREA"].includes(document.activeElement.tagName)&&history.length){const previous=history.pop();openNode(previous,false)}
  });
  const stage=document.getElementById("graph-stage");
  stage.addEventListener("dragover",function(event){event.preventDefault();stage.style.outline="2px dashed var(--cyan)"});
  stage.addEventListener("dragleave",function(){stage.style.outline=""});
  stage.addEventListener("drop",function(event){event.preventDefault();stage.style.outline="";const files=Array.from(event.dataTransfer.files||[]);if(files.length===1&&files[0].name.toLowerCase().endsWith(".zip"))importZip(files[0]);else importFiles(files)});
}
function initialise(){
  mapModel();document.getElementById("project-name").textContent=MODEL.project_name||"Local protocol workspace";
  const select=document.getElementById("edge-select");
  Array.from(new Set(MODEL.edges.map(function(e){return e.kind}))).sort().forEach(function(kind){const option=document.createElement("option");option.value=kind;option.textContent=kind.replaceAll("_"," ");select.appendChild(option)});
  if(MODEL.show_third_party){const thirdParty=document.querySelector('[data-filter="third-party"]');if(thirdParty)thirdParty.checked=true}
  if(MODEL.initial_only){
    const modeMap={storage:"storage",reads:"storage",writes:"storage",assets:"assets"};
    if(modeMap[MODEL.initial_only])mode=modeMap[MODEL.initial_only];
    if(MODEL.initial_only==="imports")document.querySelectorAll("[data-edge]").forEach(function(input){input.checked=input.dataset.edge==="IMPORTS"});
    if(MODEL.initial_only==="all")document.querySelector('[data-edge="IMPORTS"]').checked=true;
    if(MODEL.initial_only==="reads")document.querySelector('[data-edge="WRITES"]').checked=false;
    if(MODEL.initial_only==="writes")document.querySelector('[data-edge="READS"]').checked=false;
    if(MODEL.initial_only==="calls"){
      document.querySelectorAll("[data-edge]").forEach(function(input){input.checked=["CALLS","EXTERNAL_CALL","APPLIES_MODIFIER","USES_LIBRARY"].includes(input.dataset.edge)});
    }
    document.querySelectorAll(".mode-tab").forEach(function(button){button.classList.toggle("active",button.dataset.mode===mode)});
  }
  setupImport();setupInteractions();
  const wanted=String(MODEL.initial_selection||"").toLowerCase();
  const initial=MODEL.nodes.find(function(n){return n.id===MODEL.initial_selection||n.label.toLowerCase()===wanted||String(n.qualified_name||"").toLowerCase()===wanted});
  if(initial){openNode(initial.id,false);requestAnimationFrame(fitGraph)}else{renderAll();requestAnimationFrame(fitGraph)}
}
initialise();
})();
</script>
</body>
</html>
"""


def render_explorer_document(model: dict[str, Any], *, server_mode: bool = False) -> str:
    payload = json.dumps(model, ensure_ascii=False, separators=(",", ":"))
    payload = payload.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    return HTML_TEMPLATE.replace("__GRAPH_DATA__", payload).replace("__SERVER_MODE__", "true" if server_mode else "false")


def render_explorer_html(
    index: dict[str, Any],
    root: str | Path = ".",
    *,
    output: str | Path | None = None,
    focus: str | None = None,
    include_third_party: bool = False,
    only: str | None = None,
) -> Path:
    root_path = Path(root).expanduser().resolve()
    if root_path.is_file():
        root_path = root_path.parent
    model = build_explorer_model(index, root=root_path)
    model["project_name"] = root_path.name or "Protocol workspace"
    model["initial_selection"] = focus
    model["show_third_party"] = bool(include_third_party)
    model["initial_only"] = only
    if output:
        destination = Path(output).expanduser()
        if not destination.is_absolute():
            destination = Path.cwd() / destination
    else:
        destination = root_path / ".lowkey" / "link-graph.html"
    destination.parent.mkdir(parents=True, exist_ok=True)
    document = render_explorer_document(model)
    fd, temporary = tempfile.mkstemp(prefix=".lk-explorer-", suffix=".html", dir=str(destination.parent))
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


def _normalise_paths(paths: list[PurePosixPath]) -> list[PurePosixPath]:
    if paths and all(len(item.parts) > 1 for item in paths):
        first = {item.parts[0] for item in paths}
        if len(first) == 1:
            return [PurePosixPath(*item.parts[1:]) for item in paths]
    return paths


def _safe_upload_path(value: str, *, ignore_unsupported: bool = False) -> PurePosixPath | None:
    normalised = str(value or "").replace("\\", "/")
    candidate = PurePosixPath(normalised)
    if not normalised or candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise ValueError(f"Unsafe source path: {value!r}")
    if re.match(r"^[A-Za-z]:", normalised):
        raise ValueError(f"Drive-qualified source path is not allowed: {value!r}")
    if any(part in IGNORED_PARTS for part in candidate.parts):
        if ignore_unsupported:
            return None
        raise ValueError(f"Build or VCS directory cannot be imported: {value!r}")
    suffix = Path(candidate.name).suffix.lower()
    if suffix != ".sol" and candidate.name.lower() not in ROOT_CONFIGS:
        if ignore_unsupported:
            return None
        raise ValueError(f"Unsupported file type: {value!r}. Use Solidity files and recognised project configuration files.")
    return candidate


def write_uploaded_files(files: list[dict[str, Any]], destination: str | Path) -> Path:
    if not isinstance(files, list) or not files or len(files) > MAX_UPLOAD_FILES:
        raise ValueError(f"Select between 1 and {MAX_UPLOAD_FILES} supported files.")
    if any(not isinstance(item, dict) for item in files):
        raise ValueError("Each uploaded file must contain a path and text content.")
    validated = [(_safe_upload_path(str(item.get("path") or "")), item) for item in files]
    if any(path is None for path, _ in validated):
        raise ValueError("The selected upload contains an unsupported file type.")
    typed = [(path, item) for path, item in validated if path is not None]
    paths = _normalise_paths([path for path, _ in typed])
    if len(set(paths)) != len(paths):
        raise ValueError("The upload contains duplicate paths after folder-root normalisation.")
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    total = sol_count = 0
    for relative, (_, item) in zip(paths, typed):
        content = item.get("content")
        if not isinstance(content, str):
            raise ValueError(f"Text content is missing for {relative}.")
        encoded = content.encode("utf-8")
        if len(encoded) > MAX_UPLOAD_FILE_BYTES:
            raise ValueError(f"{relative} exceeds the 2 MiB per-file source limit.")
        total += len(encoded)
        if total > MAX_UPLOAD_BYTES:
            raise ValueError("The uploaded workspace exceeds the 128 MiB source budget.")
        if relative.suffix.lower() == ".sol":
            sol_count += 1
        target = (root / Path(*relative.parts)).resolve()
        target.relative_to(root)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(encoded)
    if sol_count == 0:
        raise ValueError("The selected workspace contains no .sol source files.")
    return root


def extract_source_archive(archive_path: str | Path, destination: str | Path) -> Path:
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    total = sol_count = 0
    with zipfile.ZipFile(archive_path) as bundle:
        members = [item for item in bundle.infolist() if not item.is_dir()]
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(f"Archive exceeds the {MAX_ARCHIVE_ENTRIES}-file safety limit.")
        validated = []
        for info in members:
            relative = _safe_upload_path(info.filename, ignore_unsupported=True)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError(f"Symbolic links are not allowed: {info.filename}")
            total += info.file_size
            if total > MAX_UPLOAD_BYTES:
                raise ValueError("Archive exceeds the 128 MiB uncompressed source budget.")
            if info.file_size > MAX_UPLOAD_FILE_BYTES:
                if relative is not None:
                    raise ValueError(f"{info.filename} exceeds the 2 MiB per-file source limit.")
                continue
            if relative is not None:
                validated.append((info, relative))
        paths = _normalise_paths([item[1] for item in validated])
        if len(set(paths)) != len(paths):
            raise ValueError("Archive contains duplicate source paths after root-folder normalisation.")
        for (info, _), relative in zip(validated, paths):
            if relative.suffix.lower() == ".sol":
                sol_count += 1
            target = (root / Path(*relative.parts)).resolve()
            target.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
    if sol_count == 0:
        raise ValueError("Archive contains no Solidity source files.")
    return root


def validate_github_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(str(value or "").strip())
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise ValueError("Only HTTPS repository URLs on github.com are supported.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Credentials, query strings and fragments are not accepted in repository URLs.")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2:
        raise ValueError("Use a repository URL like https://github.com/owner/repository.")
    owner, name = parts
    name = name.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
        raise ValueError("Repository owner or name contains unsupported characters.")
    return f"https://github.com/{owner}/{name}.git"


def clone_github_repository(url: str, destination: str | Path, ref: str | None = None) -> Path:
    repo_url = validate_github_url(url)
    if ref and (ref.startswith("-") or any(ord(char) < 32 for char in ref) or ".." in ref.split("/")):
        raise ValueError("Invalid Git ref.")
    root = Path(destination).resolve()
    root.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone", "--depth", "1", "--no-tags", "--single-branch", "--filter=blob:none"]
    if ref:
        command.extend(["--branch", ref])
    command.extend([repo_url, str(root)])
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=180, check=False)
    except FileNotFoundError as error:
        raise ValueError("Git is required to import a GitHub repository.") from error
    except subprocess.TimeoutExpired as error:
        raise ValueError("GitHub clone timed out after 180 seconds.") from error
    if result.returncode:
        message = (result.stderr or result.stdout or "git clone failed").strip()
        raise ValueError("Could not import GitHub repository: " + message[-1200:])
    if not any(root.rglob("*.sol")):
        raise ValueError("The selected repository contains no Solidity source files.")
    return root


def _build_imported_graph(source_root: Path, name: str) -> dict[str, Any]:
    index = build_source_index(source_root, use_cache=False)
    graph = build_explorer_model(index, root=source_root)
    graph["project_name"] = name
    return graph


def create_explorer_server(
    index: dict[str, Any],
    root: str | Path = ".",
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    include_third_party: bool = False,
    only: str | None = None,
) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("The source workspace server may only bind to loopback.")
    root_path = Path(root).expanduser().resolve()
    if root_path.is_file():
        root_path = root_path.parent
    model = build_explorer_model(index, root=root_path)
    model["project_name"] = root_path.name or "Local project"
    model["show_third_party"] = bool(include_third_party)
    model["initial_only"] = only

    class Handler(BaseHTTPRequestHandler):
        server_version = "LowkeyExplorer/1"
        def log_message(self, fmt: str, *args: Any) -> None:
            return
        def send_bytes(self, status: int, payload: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def send_json(self, status: int, value: dict[str, Any]) -> None:
            self.send_bytes(status, json.dumps(value, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")
        def read_body(self, limit: int = MAX_UPLOAD_BYTES + 20 * 1024 * 1024) -> bytes:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError as error:
                raise ValueError("Invalid Content-Length.") from error
            if length < 1 or length > limit:
                raise ValueError("Upload is empty or exceeds the local source budget.")
            payload = self.rfile.read(length)
            if len(payload) != length:
                raise ValueError("Upload body was incomplete.")
            return payload
        def check_origin(self) -> None:
            port_number = int(self.server.server_address[1])
            allowed_hosts = {
                f"127.0.0.1:{port_number}", f"localhost:{port_number}",
                f"[::1]:{port_number}", f"::1:{port_number}",
            }
            host_header = self.headers.get("Host", "").casefold()
            if host_header not in allowed_hosts:
                raise ValueError("The local workspace only accepts loopback Host headers.")
            origin = self.headers.get("Origin")
            if origin:
                parsed = urllib.parse.urlsplit(origin)
                if parsed.scheme != "http" or parsed.netloc.casefold() not in allowed_hosts:
                    raise ValueError("Cross-origin requests are not accepted by the local workspace.")
        def do_GET(self) -> None:
            try:
                self.check_origin()
            except ValueError as error:
                self.send_json(421, {"error": str(error)})
                return
            if self.path in {"/", "/index.html"}:
                self.send_bytes(200, render_explorer_document(model, server_mode=True).encode("utf-8"), "text/html; charset=utf-8")
            elif self.path == "/health":
                self.send_json(200, {"ok": True, "service": "lowkey-local-source-workspace"})
            else:
                self.send_json(404, {"error": "Not found."})
        def do_POST(self) -> None:
            try:
                self.check_origin()
                if self.path == "/api/import":
                    payload = json.loads(self.read_body().decode("utf-8"))
                    files = payload.get("files") if isinstance(payload, dict) else None
                    with tempfile.TemporaryDirectory(prefix="lowkey-upload-") as temporary:
                        source_root = write_uploaded_files(files, temporary)
                        graph = _build_imported_graph(source_root, str(payload.get("name") or "Uploaded Solidity workspace"))
                    self.send_json(200, {"graph": graph}); return
                if self.path == "/api/archive":
                    data = self.read_body()
                    name = urllib.parse.unquote(self.headers.get("X-Archive-Name", "source.zip"))
                    if not name.lower().endswith(".zip"):
                        raise ValueError("Upload a .zip archive.")
                    with tempfile.TemporaryDirectory(prefix="lowkey-archive-") as temporary:
                        archive = Path(temporary) / "upload.zip"; archive.write_bytes(data)
                        source_root = Path(temporary) / "source"
                        extract_source_archive(archive, source_root)
                        graph = _build_imported_graph(source_root, Path(name).name)
                    self.send_json(200, {"graph": graph}); return
                if self.path == "/api/github":
                    payload = json.loads(self.read_body(64 * 1024).decode("utf-8"))
                    url = validate_github_url(payload.get("url", ""))
                    ref = str(payload.get("ref") or "").strip() or None
                    repo_name = Path(urllib.parse.urlsplit(url).path).stem
                    with tempfile.TemporaryDirectory(prefix="lowkey-github-") as temporary:
                        checkout = Path(temporary) / "checkout"
                        clone_github_repository(url, checkout, ref=ref)
                        graph = _build_imported_graph(checkout, repo_name)
                    self.send_json(200, {"graph": graph}); return
                self.send_json(404, {"error": "Not found."})
            except (ValueError, OSError, UnicodeError, json.JSONDecodeError, zipfile.BadZipFile, SourceIndexError, subprocess.SubprocessError) as error:
                self.send_json(400, {"error": str(error)[:1800]})

    return ThreadingHTTPServer((host, port), Handler)


def serve_explorer(
    index: dict[str, Any],
    root: str | Path = ".",
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
    include_third_party: bool = False,
    only: str | None = None,
) -> int:
    server = create_explorer_server(
        index, root=root, host=host, port=port,
        include_third_party=include_third_party, only=only,
    )
    address, actual_port = server.server_address[:2]
    url = f"http://{address}:{actual_port}/"
    print("LOWKEY // LOCAL PROTOCOL WORKSPACE")
    print("OPEN       " + url)
    print("IMPORT     Solidity files · folders · ZIP archives · GitHub repositories")
    print("PRIVACY    Loopback-only server; uploaded source is processed locally.")
    print("STOP       Press Ctrl+C in this terminal.")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nLOWKEY workspace stopped.")
    finally:
        server.server_close()
    return 0
