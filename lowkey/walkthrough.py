#!/usr/bin/env python3
"""
System-aware Lowkey protocol walkthrough.

This module is intentionally self-contained so it can replace an existing
lowkey/walkthrough.py without requiring changes to lk.py.

Design:
  source -> ABI -> static dependency graph -> live address graph
        -> role/state discovery -> semantic argument synthesis
        -> eth_call preflight -> live send (optional)
        -> failure diagnosis + evidence
        -> deterministic fuzz/probe mode

The engine does not claim that a successful random probe is a vulnerability.
It records observed behavior and makes every generated input replayable.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import secrets
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib import request

try:
    import system_model
except ImportError:
    system_model = None

ZERO = "0x" + "0" * 40
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
HEX_RE = re.compile(r"0x[0-9a-fA-F]+$")


def _color_enabled() -> bool:
    forced = os.environ.get("LOWKEY_COLOR", "").strip().lower()
    if forced in {"0", "false", "no", "off"} or "NO_COLOR" in os.environ:
        return False
    if forced in {"1", "true", "yes", "on"}:
        return True
    return bool(getattr(sys.stdout, "isatty", lambda: False)())


_COLORS = {
    "reset": "\x1b[0m",
    "bold": "\x1b[1m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "magenta": "\x1b[35m",
    "cyan": "\x1b[36m",
    "dim": "\x1b[2m",
}


def _paint(text: str, color: str) -> str:
    if not _color_enabled():
        return text
    return f"{_COLORS.get(color, '')}{text}{_COLORS['reset']}"


def _section(title: str, color: str = "cyan") -> str:
    return _paint(title, color)


def _status_icon(status: str) -> str:
    value = str(status or "").upper()
    if value in {"SUCCESS", "DONE", "PASS"}:
        return _paint("✓", "green")
    if value == "READY":
        return _paint("→", "cyan")
    if value in {"BLOCKED", "FAILED", "ERROR"}:
        return _paint("✗", "red")
    if value in {"WARN", "WARNING"}:
        return _paint("!", "yellow")
    return _paint("•", "cyan")


def _cmd(args: list[str], cwd: Path | None = None, timeout: int = 30) -> tuple[int, str, str]:
    """Run a local command and return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            [str(arg) for arg in args],
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return 124, str(stdout), str(stderr) or f"command timed out after {timeout}s"
    except OSError as exc:
        return 127, "", str(exc)


@dataclass
class FunctionInfo:
    contract: str
    name: str
    inputs: list[dict[str, Any]]
    outputs: list[dict[str, Any]]
    mutability: str
    signature: str
    source: str | None = None
    line: int | None = None
    body: str = ""
    modifiers: list[str] | None = None
    calls: list[dict[str, Any]] | None = None
    visibility: str = "unknown"
    reads: list[str] | None = None
    writes: list[str] | None = None
    array_ops: list[str] | None = None

    def __post_init__(self) -> None:
        self.modifiers = self.modifiers or []
        self.calls = self.calls or []
        self.reads = self.reads or []
        self.writes = self.writes or []
        self.array_ops = self.array_ops or []


@dataclass
class ContractInfo:
    name: str
    source: str | None
    line: int | None
    kind: str = "contract"
    imports: list[str] | None = None
    functions: list[FunctionInfo] | None = None
    errors: list[dict[str, Any]] | None = None
    address_vars: list[str] | None = None
    state_vars: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        self.imports = self.imports or []
        self.functions = self.functions or []
        self.errors = self.errors or []
        self.address_vars = self.address_vars or []
        self.state_vars = self.state_vars or []


@dataclass
class LiveNode:
    address: str
    name: str
    code_size: int
    artifact_contract: str | None = None
    discovered_from: str | None = None
    getter: str | None = None


def _is_address(value: Any) -> bool:
    return isinstance(value, str) and bool(ADDRESS_RE.fullmatch(value))


def _short_address(value: Any) -> str:
    if _is_address(value):
        return value[:10] + "…" + value[-8:]
    return str(value)


def _clean_name(value: str) -> str:
    name = re.sub(r"^I", "", str(value or ""))
    name = name.replace("IBattleChain", "").replace("Upgradeable", "")
    return name


def _contract_purpose(name: str, functions: list[FunctionInfo] | None = None) -> str:
    low = name.lower()
    fn_names = {f.name.lower() for f in (functions or [])}
    if "factory" in low or "createpool" in fn_names:
        return "creates/configures protocol instances"
    if "pool" in low and "factory" not in low:
        return "holds participant state, stakes and settlement funds"
    if "agreement" in low:
        return "defines who/what is approved and in scope"
    if "token" in low or "erc20" in low:
        return "asset used by the protocol for value/staking"
    if "safeharbor" in low or "registry" in low:
        return "external source of protocol validity/state"
    if "moderator" in low:
        return "controls or reports outcome decisions"
    if "proxy" in low:
        return "forwards calls to an implementation contract"
    if any(x in fn_names for x in ("owner", "transferownership", "pause", "unpause")):
        return "administrative/control component"
    return "protocol component"


def _friendly_connection_phrase(edge: dict[str, str]) -> str:
    kind = str(edge.get("kind") or "")
    fn = str(edge.get("function") or "")
    low = fn.lower()
    if "createpool" in low and "owner" in low:
        return "checks who owns the agreement"
    if "createpool" in low and "initialize" in low:
        return "creates/initializes a new pool"
    if "initialize" in low and "isagreementvalid" in low:
        return "checks that the agreement is valid"
    if "getagreementstate" in low:
        return "reads agreement/security state"
    if "iscontractinscope" in low:
        return "checks whether a contract is in scope"
    if "flag" in low:
        return "reports an outcome to the target component"
    if kind.startswith("runtime:"):
        return "reads a live dependency from the contract"
    if kind == "member-call":
        return "calls a configured dependency"
    return "uses"


def _connection_destination(edge: dict[str, str], nodes: list[LiveNode]) -> str:
    raw = str(edge.get("to") or "")
    clean = _clean_name(raw)
    normalized = re.sub(r"[^a-z0-9]", "", clean.lower())
    candidates = []
    for node in nodes:
        name = node.artifact_contract or node.name
        n = re.sub(r"[^a-z0-9]", "", _clean_name(name).lower())
        candidates.append((n, name))
    for n, name in candidates:
        if normalized and (normalized == n or normalized in n or n in normalized):
            return name
    return clean or raw


def _web_connection_label(edge: dict[str, str]) -> str:
    """Return a compact human-readable relationship label."""
    kind = str(edge.get("kind") or "")
    fn = str(edge.get("function") or "")
    low = fn.lower()
    if "createpool" in low and "owner" in low:
        return "checks ownership"
    if "createpool" in low and "initialize" in low:
        return "creates / initializes"
    if "isagreementvalid" in low:
        return "validates agreement"
    if "getagreementstate" in low:
        return "reads security state"
    if "iscontractinscope" in low:
        return "checks scope"
    if "flagoutcome" in low:
        return "reports outcome"
    if kind.startswith("runtime:"):
        getter = kind.split(":", 1)[1]
        return f"reads dependency via {getter}()"
    if kind == "member-call":
        return "uses configured dependency"
    if kind == "external-call":
        return "calls external interface"
    if kind == "internal-call":
        return "enters internal logic"
    return "connects to"

def _web_node_name(value: str) -> str:
    return _clean_name(value).strip() or "Unknown"

def _render_connection_web(
    nodes: list[LiveNode],
    edges: list[dict[str, str]],
    actions: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Render a compact relationship topology with hidden-count summaries."""
    meaningful: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for edge in edges:
        if edge.get("kind") == "import":
            continue
        source = _web_node_name(str(edge.get("from") or ""))
        destination = _web_node_name(str(edge.get("to") or ""))
        if source == destination:
            continue
        label = _web_connection_label(edge)
        key = (source, destination, label, str(edge.get("function") or ""))
        if key in seen:
            continue
        seen.add(key)
        meaningful.append({
            "from": source,
            "to": destination,
            "label": label,
            "function": str(edge.get("function") or ""),
        })

    if not meaningful:
        return [f"  {_paint('└─ no proven contract-to-contract connections yet', 'yellow')}"]

    names: list[str] = []
    for edge in meaningful:
        for name in (edge["from"], edge["to"]):
            if name not in names:
                names.append(name)
    degree = {name: 0 for name in names}
    for edge in meaningful:
        degree[edge["from"]] += 1
        degree[edge["to"]] += 1
    center = max(names, key=lambda name: (degree[name], -names.index(name)))
    inbound = [e for e in meaningful if e["to"] == center]
    outbound = [e for e in meaningful if e["from"] == center]
    cross = [e for e in meaningful if e not in inbound and e not in outbound]

    def compact(name: str, width: int = 22) -> str:
        return name if len(name) <= width else name[:width - 1] + "…"

    def edge_lines(edge: dict[str, str], direction: str) -> list[str]:
        label = _paint(f"[{edge['label']}]", "cyan")
        if direction == "in":
            result = [
                f"       {compact(edge['from']):<22} ╲",
                f"                         ╲─{label}──▶  [{center}]",
            ]
        elif direction == "out":
            result = [
                f"       [{center}]  ──{label}──╲",
                f"                              ╲──▶  {compact(edge['to'])}",
            ]
        else:
            result = [
                f"       {compact(edge['from']):<22} ╲",
                f"                         ╰─{label}─▶  {compact(edge['to'])}",
            ]
        if edge["function"]:
            result.append(f"                              {_paint(edge['function'], 'dim')}")
        return result

    out = [
        f"  ╭─ WEB / {_paint(center, 'bold')} ─────────────────────────────────────────────╮",
        f"  │ {compact(center, 48)}  • {degree[center]} proven relationship(s)",
        "  ╰──────────────────────────────────────────────────────────────╯",
    ]

    for title, values, direction, limit in (
        ("  FROM / who can affect or feed the hub", inbound, "in", 5),
        ("  TO / what the hub relies on or controls", outbound, "out", 5),
        ("  CROSS-LINKS / supporting components", cross, "cross", 6),
    ):
        if not values:
            continue
        out += ["", title]
        for edge in values[:limit]:
            out.extend(edge_lines(edge, direction))
        if len(values) > limit:
            out.append(f"       {_paint(f'… +{len(values) - limit} more connection(s) in evidence', 'dim')}")

    actor_links: list[tuple[str, str, str]] = []
    for action in actions or []:
        actor = str(action.get("actor_name") or "")
        node = action.get("node")
        fn_obj = action.get("function")
        if not actor or not isinstance(node, LiveNode) or not isinstance(fn_obj, FunctionInfo):
            continue
        target = _web_node_name(node.artifact_contract or node.name)
        link = (actor, target, fn_obj.name)
        if link not in actor_links:
            actor_links.append(link)
    if actor_links:
        out += ["", "  ACTORS / where the human side enters the web"]
        for actor, target, fn_name in actor_links[:6]:
            out.append(
                f"       {_paint(compact(actor), 'magenta'):<22} "
                f"──{_paint(f'[calls {fn_name}()]', 'magenta')}──▶  {compact(target)}"
            )
        if len(actor_links) > 6:
            out.append(f"       {_paint(f'… +{len(actor_links) - 6} more actor paths', 'dim')}")

    return out


def _function_access_label(
    fn: FunctionInfo,
    functions: list[FunctionInfo],
) -> str:
    modifiers = [str(x) for x in fn.modifiers or []]
    owner_gate = next((x for x in modifiers if x.lower() == "onlyowner"), None)
    role_gate = next((x for x in modifiers if x.lower().startswith("onlyrole")), None)
    gate = owner_gate or role_gate
    if fn.visibility in {"external", "public"}:
        return (
            f"{gate} only" if gate
            else "any external caller"
        )
    callers = sorted({
        candidate.name
        for candidate in functions
        if any(
            call.get("kind") == "internal-call"
            and str(call.get("function")) == fn.name
            for call in candidate.calls or []
        )
    })
    reach = ", ".join(callers[:5]) if callers else "no caller proven by source scan"
    return f"{fn.visibility} only; reached from {reach}"


def _render_contract_surface(
    contract: ContractInfo,
    functions: list[FunctionInfo],
) -> list[str]:
    lines: list[str] = []
    states = contract.state_vars or []
    lines.append(_section("STORAGE / WHAT THIS CONTRACT REMEMBERS", "blue"))
    if not states:
        lines.append("  No source-level state declarations were recovered.")
    else:
        for state in states[:8]:
            name = str(state.get("name") or "?")
            typ = str(state.get("type") or "unknown")
            vis = str(state.get("visibility") or "internal")
            low_type = typ.lower()
            kind = (
                "MAPPING" if low_type.startswith("mapping")
                else "ARRAY" if "[" in typ
                else "VALUE"
            )
            writers = [fn for fn in functions if name in (fn.writes or [])]
            readers = [fn for fn in functions if name in (fn.reads or []) and fn not in writers]
            head = f"  {_paint(kind, 'blue')}  {_paint(name, 'blue')} : {typ}  ({vis})"
            if state.get("constant"):
                head += " [constant]"
            elif state.get("immutable"):
                head += " [immutable]"
            lines.append(head)

            if writers:
                writer_bits = []
                for fn in writers[:5]:
                    writer_bits.append(f"{fn.name} [{_function_access_label(fn, functions)}]")
                lines.append(f"      {_paint('WRITES', 'red')}  {', '.join(writer_bits)}")
            else:
                lines.append(f"      {_paint('WRITES', 'dim')}  no source writer found")

            if readers:
                lines.append(f"      {_paint('READS', 'cyan')}   {', '.join(fn.name for fn in readers[:5])}")

            ops = []
            for fn in functions:
                if name in (fn.reads or []) or name in (fn.writes or []):
                    ops.extend(fn.array_ops or [])
            if ops:
                lines.append(f"      {_paint('DATA FLOW', 'blue')} {', '.join(sorted(set(ops))[:5])}")

    lines.append("")
    lines.append(_section("ACCESS / WHO CAN DO WHAT", "magenta"))
    entry_points = [
        fn for fn in functions
        if fn.visibility in {"external", "public"}
        and (
            fn.writes
            or fn.calls
            or fn.modifiers
            or fn.mutability not in {"view", "pure"}
        )
    ]
    entry_points.sort(key=lambda fn: (-len(fn.writes), -len(fn.calls), fn.name))
    if not entry_points:
        lines.append("  No state-changing public/external entry points recovered.")
    else:
        for fn in entry_points[:8]:
            lines.append(
                f"  {_paint(fn.visibility.upper(), 'magenta'):<10} {fn.name}()"
            )
            lines.append(f"      WHO    {_function_access_label(fn, functions)}")
            does = []
            if fn.writes:
                does.append("writes " + ", ".join(fn.writes[:4]))
            if fn.calls:
                does.append("calls " + ", ".join(str(x.get("function")) for x in fn.calls[:4]))
            lines.append(f"      DOES   {'; '.join(does) if does else 'changes protocol state'}")

    internals = [
        fn for fn in functions
        if fn.visibility in {"private", "internal"} and (fn.writes or fn.calls)
    ]
    if internals:
        lines.append("")
        lines.append(_section("INTERNAL / PRIVATE LOGIC", "yellow"))
        for fn in sorted(internals, key=lambda x: (-len(x.writes), -len(x.calls), x.name))[:6]:
            lines.append(f"  {_paint(fn.visibility.upper(), 'yellow'):<10} {fn.name}()")
            lines.append(f"      WHO    {_function_access_label(fn, functions)}")
            if fn.writes:
                lines.append(f"      TOUCH  {', '.join(fn.writes[:5])}")
            if fn.calls:
                lines.append(f"      CALLS  {', '.join(str(x.get('function')) for x in fn.calls[:5])}")
    return lines


def _render_state_diagnosis(actions: list[dict[str, Any]]) -> list[str]:
    blocked = [a for a in actions if str(a.get("status")) == "BLOCKED"]
    if not blocked:
        return []
    reasons: list[tuple[str, int, str]] = []
    seen: dict[str, int] = {}
    recs: dict[str, str] = {}
    for action in blocked:
        result = action.get("result") or {}
        msg, recommendation = _friendly_error(
            result.get("decoded_error"),
            result.get("raw", ""),
        )
        key = msg.lower()
        seen[key] = seen.get(key, 0) + 1
        recs[key] = recommendation
    for key, count in seen.items():
        reasons.append((key, count, recs[key]))
    out = [_section("WHY ACTIONS ARE BLOCKED", "red")]
    for msg, count, recommendation in sorted(reasons, key=lambda x: (-x[1], x[0]))[:5]:
        suffix = f" ×{count}" if count > 1 else ""
        out.append(f"  {_paint('✗', 'red')} {msg}{suffix}")
        out.append(f"      {_paint('NEXT', 'yellow')} {recommendation}")
    return out


def _render_action_card(
    root: Path,
    action: dict[str, Any],
    index: int,
    total: int,
    links: bool,
) -> str:
    node: LiveNode = action["node"]
    fn: FunctionInfo = action["function"]
    status = str(action.get("status") or "NEXT").upper()
    actor = str(action.get("actor_name") or "Unknown")
    status_word = _step_status_word(action)
    label = f"{node.artifact_contract or node.name}.{fn.name}"
    if links and fn.source and fn.line:
        label = _source_link(root, fn.source, fn.line, label)

    lines = [
        f"{_section(f'STEP {index + 1:02d} / {total:02d}', 'cyan')}  "
        f"{_status_icon(status)} {_paint(status_word, 'green' if status_word == 'DONE' else 'cyan' if status_word == 'READY' else 'red' if status_word in {'BLOCKED','FAILED'} else 'yellow')}",
        f"  {_paint(action.get('phase', 'STEP'), 'yellow')}  {_paint(actor, 'magenta')} → {label}",
        f"  WHAT   {action.get('what') or _action_what(fn, node)}",
        f"  WHY    {action.get('why') or _action_why(fn, node)}",
    ]
    result = action.get("result") or {}
    if result.get("ok"):
        lines.append(f"  RESULT {_status_icon('PASS')} Chain accepted the simulation.")
    elif result:
        friendly, recommendation = _friendly_error(
            result.get("decoded_error"),
            result.get("raw", ""),
        )
        lines.append(f"  RESULT {_status_icon('BLOCKED')} {friendly}")
        lines.append(f"  NEXT   {_paint(recommendation, 'yellow')}")
        for item in action.get("diagnosis", [])[:2]:
            lines.append(f"         evidence: {item}")
    return "\n".join(lines)


def _format_state_value(value: Any) -> str:
    if isinstance(value, bool):
        return "ON / true" if value else "OFF / false"
    if isinstance(value, list):
        if not value:
            return "empty []"
        if len(value) > 4:
            return "[" + ", ".join(_short_address(x) if _is_address(x) else str(x) for x in value[:4]) + f", … +{len(value)-4}]"
        return "[" + ", ".join(_short_address(x) if _is_address(x) else str(x) for x in value) + "]"
    if _is_address(value):
        return _short_address(value)
    return str(value)


def _render_live_state(
    target: LiveNode,
    functions: list[FunctionInfo],
    getter_values: dict[str, Any],
) -> list[str]:
    lines = [_section("LIVE STATE / WHAT THE CHAIN CURRENTLY SAYS", "blue")]
    if not getter_values:
        lines.append("  No simple zero-argument readable state was recovered.")
        return lines

    interesting = []
    for name, value in getter_values.items():
        lower = name.lower()
        score = 10
        if any(token in lower for token in ("owner", "admin", "moderator", "state", "status", "paused", "allowed", "open", "active", "expiry", "deadline", "stake", "balance", "count")):
            score += 20
        if isinstance(value, (list, dict)):
            score += 5
        interesting.append((score, name, value))
    interesting.sort(key=lambda x: (-x[0], x[1]))

    for _, name, value in interesting[:10]:
        lines.append(f"  {_paint(name, 'blue')} = {_format_state_value(value)}")
    lines.append("  These are observed values from read-only calls; they are state evidence, not guesses.")
    return lines


def _render_story(
    root: Path,
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    contracts: dict[str, ContractInfo],
    actions: list[dict[str, Any]],
    actors: dict[str, str],
    current: int | None = None,
    links: bool = True,
    meta: dict[str, Any] | None = None,
) -> str:
    """Render the audit story as a compact, layered human-readable console view."""
    meta = meta if isinstance(meta, dict) else {}
    live_nodes = [node for node in nodes if node.code_size > 0]
    target = str(meta.get("target") or "")
    target_node = next(
        (node for node in live_nodes if node.address.lower() == target.lower()),
        None,
    )
    target_name = (
        target_node.artifact_contract or target_node.name
        if target_node else "Not resolved"
    )

    lines: list[str] = []
    lines.append(_paint("╭────────────────────────────────────────────────────────────╮", "cyan"))
    lines.append(_paint("│ LOWKEY  /  PROTOCOL WALKTHROUGH                            │", "bold"))
    lines.append(_paint("╰────────────────────────────────────────────────────────────╯", "cyan"))
    lines.append(
        f"  Environment  Local RPC • {len(live_nodes)} live contract(s) • {len(_canonical_actor_names(actors))} actor(s)"
    )
    lines.append(f"  Focus        {target_name} • {_short_address(target) if target else 'no target'}")
    source = str(meta.get("target_source") or "")
    if "mismatch" in source:
        lines.append(f"  Identity     {_paint('✗ mismatch / stale evidence detected', 'red')}")
    elif "exact" in source:
        lines.append(f"  Identity     {_paint('✓ bytecode matches local artifact', 'green')}")
    elif "current broadcast" in source:
        lines.append(f"  Identity     {_paint('✓ current local deployment', 'green')}")
    else:
        lines.append(f"  Identity     {_paint('• not fully proven', 'yellow')}")

    if meta.get("auto_bootstrap"):
        boot = meta["auto_bootstrap"]
        if boot.get("status") == "success":
            lines.append(f"  Bootstrap    {_paint('✓ local setup ready', 'green')} ({boot.get('reason', 'completed')})")
        else:
            lines.append(f"  Bootstrap    {_paint('! setup not completed', 'yellow')} ({boot.get('reason', 'not needed')})")

    if actors:
        names = _canonical_actor_names(actors)
        if names:
            lines.append(f"  Actors       {_paint(' / '.join(names), 'magenta')}")

    lines.append("")
    lines.append(_section("SYSTEM CONNECTION WEB", "cyan"))
    lines.extend(_render_connection_web(nodes, _system_edges(nodes, functions_by_contract, contracts), actions))

    if target_node:
        cname = target_node.artifact_contract or target_node.name
        contract = contracts.get(cname)
        functions = functions_by_contract.get(cname, [])
        if contract:
            lines.append("")
            lines.append(_paint(f"FOCUS CONTRACT / {cname}", "bold"))
            lines.append(f"  {_contract_purpose(cname, functions)}")
            lines.append("")
            lines.extend(_render_live_state(
                target_node,
                functions,
                (meta.get("runtime_getters") or {}).get(target.lower(), {}),
            ))
            lines.append("")
            lines.extend(_render_contract_surface(contract, functions))

    if actions:
        diagnosis = _render_state_diagnosis(actions)
        if diagnosis:
            lines.append("")
            lines.extend(diagnosis)
        lines.append("")
        lines.append(_section("CURRENT WALKTHROUGH STEP", "cyan"))
        if current is not None and 0 <= current < len(actions):
            lines.append(_render_action_card(root, actions[current], current, len(actions), links))
            if current + 1 < len(actions):
                nxt = actions[current + 1]
                lines.append("")
                lines.append(
                    f"  { _paint('NEXT', 'yellow') }  "
                    f"{current + 2:02d}/{len(actions):02d}  "
                    f"{nxt.get('phase', 'STEP')}  →  "
                    f"{nxt['node'].artifact_contract or nxt['node'].name}.{nxt['function'].name}"
                )
        else:
            lines.append(f"  Walkthrough examined {len(actions)} candidate(s).")
            done = sum(_step_status_word(a) == "DONE" for a in actions)
            blocked = sum(_step_status_word(a) == "BLOCKED" for a in actions)
            failed = sum(_step_status_word(a) == "FAILED" for a in actions)
            lines.append(f"  {_paint('✓', 'green')} passed/ready: {done}")
            lines.append(f"  {_paint('✗', 'red')} blocked: {blocked}")
            lines.append(f"  {_paint('!', 'yellow')} send failures: {failed}")
    else:
        lines.append("")
        lines.append(_section("CURRENT WALKTHROUGH STEP", "cyan"))
        lines.append("  No coherent state-changing action was found from the current state.")

    lines.append("")
    lines.append(_paint("BLUE", "blue") + " storage   " +
                  _paint("CYAN", "cyan") + " relationship   " +
                  _paint("GREEN", "green") + " success   " +
                  _paint("RED", "red") + " blocked   " +
                  _paint("YELLOW", "yellow") + " warning/next   " +
                  _paint("MAGENTA", "magenta") + " actor")
    return "\n".join(lines)


def _is_local_rpc(rpc: str) -> bool:
    low = rpc.lower()
    return any(host in low for host in ("127.0.0.1", "localhost", "::1"))


def _mutations(value: Any, typ: str, actors: dict[str, str], rng: random.Random) -> list[Any]:
    t = typ
    out: list[Any] = []
    if t.startswith("uint"):
        # Keep both tiny transition values and width-aware upper boundaries.
        vals = [0, 1, 2, 2**8 - 1, 2**16 - 1, 2**32 - 1]
        for v in vals:
            if v != value:
                out.append(v)
        out.append(rng.randrange(0, 10**9))
    elif t.startswith("int"):
        out.extend([0, -1, 1, -2**127, 2**127 - 1])
    elif t == "bool":
        out.append(not bool(value))
    elif t == "address":
        for name in ("Alice", "Bob", "Attacker"):
            addr = actors.get(name)
            if addr and addr.lower() != str(value).lower():
                out.append(addr)
        out.append(ZERO)
        out.append("0x" + secrets.token_hex(20))
    elif t == "address[]":
        base = list(value or [])
        if base:
            out.append([])
            if len(base) > 1:
                out.append(base[1:] + base[:1])
                out.append(base + [base[0]])
            out.append([ZERO] * len(base))
        else:
            out.append(list(actors.values())[:2])
    elif t == "bytes32":
        out.extend(["0x" + "00" * 32, "0x" + "ff" * 32])
    elif t == "bytes":
        out.extend(["0x", "0x00", "0x" + rng.randbytes(8).hex()])
    return [x for x in out if x != value]


def _parse_flags(argv: list[str]) -> dict[str, Any]:
    mode = "walk"
    rest = list(argv)
    if rest and rest[0] == "test":
        mode = "test"
        rest = rest[1:]
    flags: dict[str, Any] = {
        "mode": mode,
        "auto": False,
        "steps": 12,
        "cases": 20,
        "seed": None,
        "send": False,
        "bootstrap": False,
        "links": True,
        "non_interactive": False,
    }
    i = 0
    while i < len(rest):
        item = rest[i]
        if item == "--auto":
            flags["auto"] = True
        elif item in {"--send", "--live"}:
            flags["send"] = True
        elif item == "--bootstrap":
            flags["bootstrap"] = True
        elif item == "--no-links":
            flags["links"] = False
        elif item == "--non-interactive":
            flags["non_interactive"] = True
        elif item == "--steps" and i + 1 < len(rest):
            i += 1
            flags["steps"] = max(1, int(rest[i]))
        elif item == "--cases" and i + 1 < len(rest):
            i += 1
            flags["cases"] = max(1, int(rest[i]))
        elif item == "--seed" and i + 1 < len(rest):
            i += 1
            flags["seed"] = int(rest[i])
        elif item in {"--help", "-h"}:
            flags["help"] = True
        i += 1
    return flags


def _help() -> None:
    print(
        """LOWKEY WALKTHROUGH

  lk walkthrough --auto --steps 12
      System-aware walkthrough. On a local RPC, safely dry-runs a discovered
      setup/deploy script when runtime state is missing, then rebuilds the
      live + static contract model before planning interactions.

  lk walkthrough test --cases 50 --seed 1337
      Deterministic active probing. Randomizes values by ABI type and semantic
      role. Uses eth_call by default; add --send only on a local Anvil chain.

  Options:
    --send             Actually send mutating probes/interactions
    --bootstrap        Show deployment/test entry-point discovery
    --steps N          Number of walkthrough actions
    --cases N          Number of mutation cases per probe
    --seed N           Replayable random seed
    --no-links         Disable Ctrl+Click OSC-8 source links
    --non-interactive  Never wait for Enter
    Colors are enabled automatically on a terminal; set LOWKEY_COLOR=1 to force
    them or NO_COLOR=1 to disable them.
"""
    )


def _build_model(
    root: Path,
    config: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, list[FunctionInfo]],
    list[LiveNode],
    dict[str, dict[str, Any]],
    dict[str, ContractInfo],
    dict[str, str],
    dict[str, str],
]:
    rpc = _rpc_url(config)
    try:
        _rpc(rpc, "eth_chainId", [])
    except Exception as exc:
        raise RuntimeError(f"RPC unavailable at {rpc}: {exc}") from exc

    manifest = _load_system_manifest(root, rpc, config)
    bootstrap = _bootstrap_from_manifest(manifest, rpc) or _discover_bootstrap(root, rpc)

    target, target_source = _resolve_walkthrough_target(
        root, config, rpc, bootstrap
    )

    artifacts, artifact_files = _load_artifacts(root)
    label = _target_label(config, target)
    configured = (config.get("abi_paths") or {}).get(target)
    if configured:
        try:
            data = json.loads(Path(configured).expanduser().read_text(encoding="utf-8"))
            abi = data.get("abi") if isinstance(data, dict) else None
            cname = str(data.get("contractName") or Path(configured).stem) if isinstance(data, dict) else Path(configured).stem
            if isinstance(abi, list):
                artifacts[cname] = abi
                artifact_files[cname] = Path(configured).expanduser()
            if label == "Target":
                label = cname
        except (OSError, json.JSONDecodeError):
            pass
    contracts = _parse_solidity_sources(root)
    functions_by_contract = _merge_artifact_functions(
        contracts,
        artifacts,
        artifact_files,
        root,
    )

    if not target:
        actors = _actor_context(config, rpc)
        meta = {
            "rpc": rpc,
            "target": None,
            "target_source": target_source,
            "chain_timestamp": _latest_timestamp(rpc),
            "contract_count": len(contracts),
            "artifact_count": len(artifacts),
            "live_nodes": [],
            "known_roles": {},
            "runtime_getters": {},
            "bootstrap": bootstrap,
            "system_manifest": manifest,
            "static_system": _static_system_context(bootstrap, contracts),
        }
        return (
            meta,
            functions_by_contract,
            [],
            {},
            contracts,
            actors,
            {},
        )

    label = _target_label(config, target)
    configured = (config.get("abi_paths") or {}).get(target)
    if configured:
        try:
            data = json.loads(
                Path(configured).expanduser().read_text(encoding="utf-8")
            )
            abi = data.get("abi") if isinstance(data, dict) else None
            cname = (
                str(data.get("contractName") or Path(configured).stem)
                if isinstance(data, dict)
                else Path(configured).stem
            )
            if isinstance(abi, list):
                artifacts[cname] = abi
                artifact_files[cname] = Path(configured).expanduser()
            if label == "Target":
                label = cname
        except (OSError, json.JSONDecodeError):
            pass

    nodes, getter_data, _ = _build_live_graph(
        root,
        rpc,
        target,
        label,
        functions_by_contract,
        artifact_files,
    )
    extra_roots: list[tuple[str, str]] = []
    for key, value in (config.get("targets") or {}).items():
        if _is_address(value) and value.lower() != target.lower():
            extra_roots.append((value, str(key)))
    for path in sorted((root / "broadcast").glob("**/run-latest.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for tx in payload.get("transactions", []) or []:
            addr = tx.get("contractAddress") or tx.get("contract_address")
            cname = tx.get("contractName") or tx.get("contract_name") or "Deployment"
            if _is_address(addr):
                extra_roots.append((addr, str(cname)))
    known_live = {n.address.lower() for n in nodes}
    for addr, name in extra_roots[:30]:
        if addr.lower() in known_live or _code_size(rpc, addr) == 0:
            continue
        more_nodes, more_getters, _ = _build_live_graph(
            root, rpc, addr, name, functions_by_contract, artifact_files
        )
        for child in more_nodes:
            if child.address.lower() not in known_live:
                nodes.append(child)
                known_live.add(child.address.lower())
        getter_data.update(more_getters)
    actors = _actor_context(config, rpc)
    known = _known_contracts(nodes, functions_by_contract)
    # Refresh the "agreement" role using runtime getter names, because many
    # contracts expose dependencies without naming their artifact contract.
    for node in nodes:
        vals = getter_data.get(node.address.lower(), {})
        for key, value in vals.items():
            if not _is_address(value):
                continue
            if "agreement" in key.lower() and _code_size(rpc, value) > 0:
                known.setdefault("agreement", value)
            if "token" in key.lower() and _code_size(rpc, value) > 0:
                known.setdefault("erc20", value)
            if "registry" in key.lower() and _code_size(rpc, value) > 0:
                known.setdefault("safeharbor", value)

    meta = {
        "rpc": rpc,
        "target": target,
        "target_source": target_source,
        "chain_timestamp": _latest_timestamp(rpc),
        "contract_count": len(contracts),
        "artifact_count": len(artifacts),
        "live_nodes": [asdict(x) for x in nodes],
        "known_roles": known,
        "runtime_getters": getter_data,
        "bootstrap": bootstrap,
        "system_manifest": manifest,
        "static_system": _static_system_context(bootstrap, contracts),
    }
    return meta, functions_by_contract, nodes, getter_data, contracts, actors, known


def _walkthrough_phase_priority(fn: FunctionInfo) -> tuple[int, str]:
    phase = _action_phase(fn)
    return {
        "CREATE": 500,
        "PARTICIPATE": 400,
        "OUTCOME": 300,
        "SETTLE": 200,
        "INTERACTION": 100,
        "SETUP": -100,
        "ADMIN": -200,
    }.get(phase, 0), phase


def _walkthrough_is_setup_action(fn: FunctionInfo, meta: dict[str, Any]) -> bool:
    name = fn.name.lower()
    if name.startswith("initialize"):
        return True
    if name in {"setstaketokenallowed", "pause", "unpause", "upgrade"}:
        return True
    return False


def _plan_actions(
    root: Path,
    meta: dict[str, Any],
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
    actors: dict[str, str],
    known: dict[str, str],
    all_errors: list[dict[str, Any]],
    steps: int,
) -> list[dict[str, Any]]:
    rpc = str(meta["rpc"])
    now = int(meta["chain_timestamp"])
    actions: list[dict[str, Any]] = []
    candidates: list[tuple[int, int, LiveNode, FunctionInfo]] = []
    for node in nodes:
        if node.code_size == 0:
            continue
        funcs = functions_by_contract.get(node.artifact_contract or node.name, [])
        for fn in funcs:
            score = _rank_function(fn)
            if score <= 0:
                continue
            name = fn.name.lower()
            if _walkthrough_is_setup_action(fn, meta):
                continue
            phase_priority, _ = _walkthrough_phase_priority(fn)
            if phase_priority <= 0:
                continue
            candidates.append((phase_priority, score, node, fn))
    candidates.sort(key=lambda x: (-x[0], -x[1], x[2].name, x[3].name, x[3].signature))

    seen: set[tuple[str, str]] = set()
    for _, _, node, fn in candidates:
        key = (node.address.lower(), fn.name.lower())
        if key in seen:
            continue
        seen.add(key)
        args, reason = _semantic_args(
            node,
            fn,
            functions_by_contract,
            nodes,
            actors,
            known,
            now,
            root,
            rpc,
        )
        if args is None:
            continue
        caller, actor_name = _choose_caller(
            root,
            rpc,
            node,
            fn,
            actors,
            nodes,
            functions_by_contract,
        )

        # Factory-style creation often gates the caller against the owner of
        # the referenced protocol contract. Resolve that owner from the exact
        # semantic argument instead of assuming Alice is the caller.
        if ".owner()" in (fn.body or "") and "msg.sender" in (fn.body or ""):
            agreement_pos = next(
                (
                    i for i, p in enumerate(fn.inputs)
                    if str(p.get("name") or "").lower() == "agreement"
                ),
                None,
            )
            if agreement_pos is not None and _is_address(args[agreement_pos]):
                code, out, _ = _query_by_signature(
                    root,
                    rpc,
                    args[agreement_pos],
                    "owner()(address)",
                    [],
                )
                if code == 0:
                    owner = re.search(r"0x[0-9a-fA-F]{40}", out)
                    if owner:
                        caller, actor_name = owner.group(0), "Agreement Owner"

        if not caller:
            continue
        precheck = _preflight_failure(
            root,
            rpc,
            node,
            fn,
            args,
            caller,
            all_errors,
        )
        diagnosis = []
        if not precheck["ok"]:
            diagnosis = _known_preconditions(
                root,
                rpc,
                node,
                fn,
                args,
                caller,
                functions_by_contract,
                nodes,
                known,
                actors,
            )
        action = {
            "node": node,
            "function": fn,
            "args": args,
            "caller": caller,
            "actor_name": actor_name,
            "status": "READY" if precheck["ok"] else "BLOCKED",
            "phase": _action_phase(fn),
            "what": _action_what(fn, node),
            "why": _action_why(fn, node),
            "semantic_reason": (
                "ABI + source role synthesis"
                if not reason
                else reason
            ),
            "result": precheck,
            "diagnosis": diagnosis,
        }
        actions.append(action)
        if len(actions) >= steps:
            break
    return actions


def _run_walkthrough(
    root: Path,
    config: dict[str, Any],
    flags: dict[str, Any],
) -> int:
    meta, fns, nodes, getter_data, contracts, actors, known = _build_model(
        root, config
    )

    if flags.get("auto") and _is_local_rpc(str(meta["rpc"])):
        live_nodes = meta.get("live_nodes") or []
        if not any(
            isinstance(node, dict) and int(node.get("code_size") or 0) > 0
            for node in live_nodes
        ):
            bootstrap_ok, bootstrap_reason = _auto_bootstrap_local(
                root,
                config,
                meta.get("bootstrap") or {},
            )
            meta["auto_bootstrap"] = {
                "status": "success" if bootstrap_ok else "not_executed",
                "reason": bootstrap_reason,
            }
            if bootstrap_ok:
                meta, fns, nodes, getter_data, contracts, actors, known = _build_model(
                    root, config
                )
                meta["auto_bootstrap"] = {
                    "status": "success",
                    "reason": bootstrap_reason,
                }

    errors = _all_errors(_load_artifacts(root)[0])
    if flags.get("bootstrap") or not meta.get("target"):
        _print_bootstrap_discovery(meta)
    actions = _plan_actions(
        root,
        meta,
        fns,
        nodes,
        actors,
        known,
        errors,
        int(flags["steps"]),
    )

    payload = {
        "mode": "walkthrough",
        "started_at": time.time(),
        "model": meta,
        "actions": [],
    }
    current = 0
    if not actions:
        print(_render_story(root, nodes, fns, contracts, [], actors, None, flags.get("links", True), meta))
        target = meta.get("target")
        live_nodes = meta.get("live_nodes") or []
        if target and not any(
            isinstance(node, dict) and int(node.get("code_size") or 0) > 0
            for node in live_nodes
        ):
            print("\nNo semantically executable actions were discovered.")
            print("Target state is static-only: the persisted target has no live bytecode on the selected RPC.")
        else:
            print("\nNo semantically executable actions were discovered.")
            print("That is intentional: Lowkey will not substitute EOAs for contract roles.")
        _persist(root, payload)
        return 0

    print(_render_story(
        root,
        nodes,
        fns,
        contracts,
        [],
        actors,
        None,
        flags.get("links", True),
        meta,
    ))
    print("")
    for index, action in enumerate(actions):
        current = index
        print(_render_action_card(
            root,
            action,
            index,
            len(actions),
            flags.get("links", True),
        ))
        if not flags["non_interactive"]:
            try:
                command = input("\n  ⏎ next   q = stop   ").strip().lower()
            except EOFError:
                command = ""
            if command == "q":
                print("\nStopped.")
                _persist(root, payload)
                return 130

        # Re-check just before execution because another action may have changed state.
        node: LiveNode = action["node"]
        fn: FunctionInfo = action["function"]
        pre = _preflight_failure(
            root,
            str(meta["rpc"]),
            node,
            fn,
            action["args"],
            action["caller"],
            errors,
        )
        action["result"] = pre
        action["diagnosis"] = (
            []
            if pre["ok"]
            else _known_preconditions(
                root,
                str(meta["rpc"]),
                node,
                fn,
                action["args"],
                action["caller"],
                fns,
                nodes,
                known,
                actors,
            )
        )
        action["status"] = "READY" if pre["ok"] else "BLOCKED"

        live_send = bool(flags.get("send"))
        if live_send and pre["ok"]:
            if not _is_local_rpc(str(meta["rpc"])):
                action["send_skipped"] = "refusing remote mutating send without explicit local RPC"
            else:
                code, out, err = _cast_send(
                    root,
                    str(meta["rpc"]),
                    node.address,
                    fn,
                    _arg_values_to_strings(action["args"]),
                    action["caller"],
                )
                action["send"] = {
                    "exit_code": code,
                    "stdout": out,
                    "stderr": err,
                }
                action["status"] = "SUCCESS" if code == 0 else "FAILED"
        else:
            action["status"] = (
                "READY" if pre["ok"] else "BLOCKED"
            )

        payload["actions"].append(
            {
                **{k: v for k, v in action.items() if k not in {"node", "function"}},
                "node": asdict(node),
                "function": asdict(fn),
            }
        )

    print("")
    print(_render_story(root, nodes, fns, contracts, actions, actors, None, flags.get("links", True), meta))
    print("\nEvidence: .audit/evidence/walkthrough.json")
    _persist(root, payload)
    return 0


def _run_probe(
    root: Path,
    config: dict[str, Any],
    flags: dict[str, Any],
) -> int:
    meta, fns, nodes, getter_data, contracts, actors, known = _build_model(
        root, config
    )
    if flags.get("bootstrap") or not meta.get("target"):
        _print_bootstrap_discovery(meta)
    artifacts, _ = _load_artifacts(root)
    errors = _all_errors(artifacts)
    rng_seed = int(flags["seed"]) if flags["seed"] is not None else random.randrange(1, 2**63)
    rng = random.Random(rng_seed)

    candidates: list[tuple[LiveNode, FunctionInfo]] = []
    for node in nodes:
        fs = fns.get(node.artifact_contract or node.name, [])
        for fn in fs:
            if fn.mutability in {"view", "pure"}:
                continue
            args, reason = _semantic_args(
                node,
                fn,
                fns,
                nodes,
                actors,
                known,
                int(meta["chain_timestamp"]),
                root,
                str(meta["rpc"]),
            )
            if args is not None:
                candidates.append((node, fn))

    records: list[dict[str, Any]] = []
    case_budget = int(flags["cases"])
    print("LOWKEY // ACTIVE PROTOCOL PROBING")
    print(f"Seed: {rng_seed}")
    print(
        "Mode:",
        "LIVE SEND" if flags.get("send") else "eth_call simulation",
    )
    print("Note: probe success is observed behavior, not a vulnerability verdict.")
    print("")

    for node, fn in candidates[: int(flags["steps"])]:
        caller, actor_name = _choose_caller(
            root,
            str(meta["rpc"]),
            node,
            fn,
            actors,
            nodes,
            fns,
        )
        if not caller:
            continue
        base, reason = _semantic_args(
            node,
            fn,
            fns,
            nodes,
            actors,
            known,
            int(meta["chain_timestamp"]),
            root,
            str(meta["rpc"]),
        )
        if base is None:
            continue

        variants: list[list[Any]] = [list(base)]
        for idx, param in enumerate(fn.inputs):
            typ = _canonical_abi_type(param)
            for mutation in _mutations(base[idx], typ, actors, rng):
                candidate = list(base)
                candidate[idx] = mutation
                variants.append(candidate)
                if len(variants) >= case_budget + 1:
                    break
            if len(variants) >= case_budget + 1:
                break

        for case_index, args in enumerate(variants[: case_budget + 1]):
            result = _preflight_failure(
                root,
                str(meta["rpc"]),
                node,
                fn,
                args,
                caller,
                errors,
            )
            record = {
                "node": asdict(node),
                "function": asdict(fn),
                "caller": caller,
                "actor": actor_name,
                "case": case_index,
                "args": args,
                "result": result,
                "classification": (
                    "PASS" if result["ok"] else "REVERT"
                ),
            }
            if flags.get("send") and result["ok"]:
                if _is_local_rpc(str(meta["rpc"])):
                    code, out, err = _cast_send(
                        root,
                        str(meta["rpc"]),
                        node.address,
                        fn,
                        _arg_values_to_strings(args),
                        caller,
                    )
                    record["send"] = {
                        "exit_code": code,
                        "stdout": out,
                        "stderr": err,
                    }
                    record["classification"] = (
                        "SENT" if code == 0 else "SEND_FAILED"
                    )
                else:
                    record["classification"] = "PASS_SIM_ONLY"
            records.append(record)
            print(
                f"{record['classification']:<12} "
                f"{node.artifact_contract or node.name}.{fn.signature} "
                f"case={case_index} "
                f"args={_render_value(args)}"
            )
            if result["decoded_error"]:
                print(f"  ↳ {_pretty_error(result)}")
            if len(records) >= int(flags["steps"]) * case_budget:
                break
        if len(records) >= int(flags["steps"]) * case_budget:
            break

    payload = {
        "mode": "test",
        "seed": rng_seed,
        "started_at": time.time(),
        "model": meta,
        "records": records,
    }
    _persist(root, payload)
    print("\nEvidence: .audit/evidence/walkthrough.json")
    return 0


def run(config: dict[str, Any], args: list[str], host: Any = None) -> int:
    """Drop-in entry point expected by Lowkey's existing lk.py dispatcher."""
    flags = _parse_flags(args)
    if flags.get("help"):
        _help()
        return 0

    root = Path.cwd().resolve()
    try:
        if flags["mode"] == "test":
            return _run_probe(root, config, flags)
        return _run_walkthrough(root, config, flags)
    except KeyboardInterrupt:
        print("\nStopped.")
        return 130
    except Exception as exc:
        print(f"LOWKEY WALKTHROUGH ERROR: {exc}", file=sys.stderr)
        return 1
