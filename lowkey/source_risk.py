#!/usr/bin/env python3
"""Source-only risk triage when no live target has been configured."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import audit_context
import project_tools
import project_detection
import foundry_build

PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("tx.origin", "Authorization / identity context", re.compile(r"\btx\s*\.\s*origin\b")),
    ("delegatecall", "Delegate execution", re.compile(r"\.\s*delegatecall\s*(?:\{|\()")),
    ("low-level call", "External call / callback boundary", re.compile(r"\.\s*call\s*(?:\{|\()")),
    ("staticcall", "External read boundary", re.compile(r"\.\s*staticcall\s*(?:\{|\()")),
    ("selfdestruct", "Contract destruction primitive", re.compile(r"\bselfdestruct\s*\(")),
    ("block timestamp", "Time-dependent logic", re.compile(r"\bblock\s*\.\s*timestamp\b")),
    ("block number", "Block-height-dependent logic", re.compile(r"\bblock\s*\.\s*number\b")),
    ("signature recovery", "Signature verification", re.compile(r"\b(?:ecrecover|ECDSA\.recover)\b")),
    ("assembly", "Inline assembly", re.compile(r"\bassembly\b")),
    ("unchecked", "Unchecked arithmetic", re.compile(r"\bunchecked\s*\{")),
)


def _fallback_to_native(argv: list[str]) -> int:
    script = Path(__file__).resolve().with_name("lk.py")
    if not script.is_file():
        print("Lowkey risk: native risk router is unavailable.", file=sys.stderr)
        return 2
    return subprocess.run(
        [sys.executable, str(script), "risk", *argv],
        cwd=Path.cwd(), check=False,
    ).returncode


def _select_source_root(requested: Path) -> tuple[Path | None, str | None]:
    project, error = foundry_build._resolve_project_root(requested)
    if error:
        return None, error
    if project is not None:
        return project, None
    try:
        return project_tools.project_root(requested), None
    except Exception as exc:
        return None, str(exc)


def _source_matches(root: Path, graph: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for node in graph.get("nodes", []):
        if not project_tools._protocol_node(node):
            continue
        rel = str(node.get("file") or "")
        path = (root / rel).resolve()
        try:
            path.relative_to(root.resolve())
            source = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
        stripped = project_tools._strip_source_comments(source, "solidity", mask_strings=True)
        original_lines = source.splitlines()
        for line_number, line in enumerate(stripped.splitlines(), 1):
            for pattern_id, category, pattern in PATTERNS:
                match = pattern.search(line)
                if not match:
                    continue
                original = original_lines[line_number - 1].strip() if line_number <= len(original_lines) else line.strip()
                findings.append({
                    "pattern": pattern_id,
                    "category": category,
                    "file": rel,
                    "line": line_number,
                    "snippet": original[:300],
                    "evidence_status": "syntax-match",
                    "verdict": "not a vulnerability verdict; control flow, caller policy and impact remain unreviewed",
                })
                if len(findings) >= 120:
                    return findings
    return findings


def _render(root: Path, project: dict[str, Any], graph: dict[str, Any], matches: list[dict[str, Any]]) -> str:
    summary = graph.get("summary", {})
    nodes = [node for node in graph.get("nodes", []) if project_tools._protocol_node(node)]
    declarations = [
        (str(node.get("file") or ""), declaration)
        for node in nodes
        for declaration in node.get("declarations", [])
    ]
    contracts = [item for item in declarations if item[1].get("kind") == "contract"]
    interfaces = [item for item in declarations if item[1].get("kind") == "interface"]
    libraries = [item for item in declarations if item[1].get("kind") == "library"]
    unresolved = [
        edge for edge in graph.get("edges", [])
        if edge.get("kind") == "import" and not edge.get("resolved")
    ]
    calls = [
        (str(node.get("file") or ""), call)
        for node in nodes for call in node.get("calls", [])
    ]
    lines = [
        "LOWKEY SOURCE-ONLY RISK TRIAGE",
        "=" * 72,
        f"Project       : {root}",
        f"Backend       : {project.get('backend') or 'unknown'}",
        f"Scope         : {project.get('scope_type') or 'package source'}",
        f"Source files  : {len(nodes)} protocol/source node(s)",
        f"Declarations  : {len(contracts)} contract(s), {len(interfaces)} interface(s), {len(libraries)} library/libraries",
        f"Imports       : {summary.get('local_imports', 0)} same-package, {summary.get('workspace_imports', 0)} first-party workspace, {summary.get('external_imports', 0)} third-party, {len(unresolved)} unresolved",
        f"Call sites    : {len(calls)} source-level call site(s)",
        "",
        "This mode needs no deployed address, RPC, actor, compilation or transaction.",
        "It reads the selected source package and reports syntax/context leads only.",
        "No pattern match below is a confirmed vulnerability.",
        "",
    ]
    if unresolved:
        lines.append("UNRESOLVED IMPORTS")
        for edge in unresolved[:12]:
            lines.append(f"  {edge.get('from')}:{edge.get('line')} -> {edge.get('raw')}")
        lines.append("")
    if calls:
        lines.append("EXTERNAL / LOW-LEVEL CALL SURFACE")
        for file, call in calls[:20]:
            lines.append(
                f"  {file}:{call.get('line')} {call.get('kind')} "
                f"{call.get('target') or call.get('expression') or ''}".rstrip()
            )
        if len(calls) > 20:
            lines.append(f"  ... {len(calls) - 20} additional call site(s) remain in the source graph")
        lines.append("")
    lines.append("SOURCE PATTERN MATCHES (SYNTAX ONLY)")
    if not matches:
        lines.append("  No matches from the small source-surface inventory.")
    else:
        for item in matches[:40]:
            lines.append(
                f"  {item['pattern']}  {item['file']}:{item['line']}  {item['snippet']}"
            )
        if len(matches) > 40:
            lines.append(f"  ... {len(matches) - 40} additional matches were capped from display")
    lines += [
        "",
        "NEXT NATIVE STEPS",
        "  lk findings       inspect existing detector signals",
        "  lk focus <ID>     focus one native signal",
        "  lk context        inspect the shared project/audit context",
        "  lk project        inspect the source and dependency map",
        "",
        "Live runtime risk is separate. It requires a configured target contract, RPC and actor.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(
        prog="lk risk",
        description="Review source risk before deployment, or explicitly request live runtime risk.",
    )
    parser.add_argument("--root", help="package or workspace root")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--source", action="store_true", help="force source-only triage")
    mode.add_argument("--runtime", action="store_true", help="require the existing live target/RPC/actor")
    parser.add_argument("--json", action="store_true", help="print source triage as JSON")
    args, remaining = parser.parse_known_args(raw)

    requested = Path(args.root).expanduser().resolve() if args.root else Path.cwd().resolve()
    project, error = _select_source_root(requested)
    if error:
        print(f"Lowkey risk: {error}", file=sys.stderr)
        return 2
    if project is None:
        return _fallback_to_native(raw)
    context = audit_context.load(project)
    target = context.get("target") if isinstance(context.get("target"), dict) else {}
    has_target = bool(target.get("address") or target.get("contract"))

    if args.runtime:
        if not has_target:
            print(
                "Live runtime risk needs an explicitly configured target contract, RPC URL and actor. "
                "No address, RPC, actor or chain state was invented. Configure the target/lab first, then rerun lk risk --runtime.",
                file=sys.stderr,
            )
            return 2
        return _fallback_to_native(raw)
    if has_target and not args.source:
        return _fallback_to_native(raw)
    if remaining:
        if not args.source:
            return _fallback_to_native(raw)
        print("Lowkey risk: source-only mode does not accept live/runtime-specific options.", file=sys.stderr)
        return 2

    project_info = project_tools.detect_project(project)
    graph = project_tools.build_dependency_graph(project)
    matches = _source_matches(project, graph)
    data = {
        "project_root": str(project),
        "target_configured": has_target,
        "source_only": True,
        "project": project_info,
        "graph_summary": graph.get("summary", {}),
        "syntax_matches": matches,
        "verified": False,
        "execution": {
            "compiled": False,
            "tests_run": False,
            "deployed": False,
            "transactions_sent": False,
            "provider_calls": False,
        },
    }
    if args.json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(_render(project, project_info, graph, matches))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
