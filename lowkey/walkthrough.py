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


def _canonical_actor_names(actors: dict[str, str]) -> list[str]:
    return [name for name in ("Alice", "Bob", "Attacker", "Owner", "Agreement Owner", "Moderator") if actors.get(name)]


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
    return "connects to"

def _web_node_name(value: str) -> str:
    return _clean_name(value).strip() or "Unknown"

def _render_connection_web(
    nodes: list[LiveNode],
    edges: list[dict[str, str]],
    actions: list[dict[str, Any]] | None = None,
) -> list[str]:
    """Render a terminal-friendly relationship topology rather than a flat edge list."""
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
        return ["  └─ no proven contract-to-contract connections yet"]

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

    out = [
        f"  ╭─ WEB / {center} ─────────────────────────────────────────────╮",
        f"  │ {compact(center, 48)}  • {degree[center]} proven relationship(s)",
        "  ╰──────────────────────────────────────────────────────────────╯",
    ]

    if inbound:
        out += ["", "  FROM / who can affect or feed the hub"]
        for edge in inbound[:8]:
            source = compact(edge["from"])
            out.append(f"       {source:<22} ╲")
            out.append(f"                         ╲─[{edge['label']}]──▶  [{center}]")
            if edge["function"]:
                out.append(f"                              {edge['function']}")

    if outbound:
        out += ["", "  TO / what the hub relies on or controls"]
        for edge in outbound[:8]:
            destination = compact(edge["to"])
            out.append(f"       [{center}]  ──[{edge['label']}]──╲")
            out.append(f"                              ╲──▶  {destination}")
            if edge["function"]:
                out.append(f"                                   {edge['function']}")

    if cross:
        out += ["", "  CROSS-LINKS / the web outside the hub"]
        for edge in cross[:10]:
            out.append(f"       {compact(edge['from']):<22} ╲")
            out.append(f"                         ╰─[{edge['label']}]─▶  {compact(edge['to'])}")
            if edge["function"]:
                out.append(f"                              {edge['function']}")

    actor_links: list[tuple[str, str, str]] = []
    for action in actions or []:
        actor = str(action.get("actor_name") or "")
        node = action.get("node")
        fn = action.get("function")
        if not actor or not isinstance(node, LiveNode) or not isinstance(fn, FunctionInfo):
            continue
        target = _web_node_name(node.artifact_contract or node.name)
        link = (actor, target, fn.name)
        if link not in actor_links:
            actor_links.append(link)
    if actor_links:
        out += ["", "  ACTORS / where the human side enters the web"]
        for actor, target, fn_name in actor_links[:8]:
            out.append(f"       {compact(actor):<22} ──[calls {fn_name}()]──▶  {compact(target)}")

    out += [
        "",
        "  READ THIS AS:",
        "    node       = component or actor",
        "    [label]    = what crosses the connection",
        "    function   = source/runtime evidence proving the relationship",
        "    hub        = the component with the most observed relationships",
    ]
    return out


def _action_phase(fn: FunctionInfo) -> str:
    n = fn.name.lower()
    if any(x in n for x in ("create", "initialize")):
        return "SETUP" if "initialize" in n else "CREATE"
    if any(x in n for x in ("stake", "deposit", "contribute")):
        return "PARTICIPATE"
    if any(x in n for x in ("flag", "resolve", "claim", "redeem", "release")):
        return "OUTCOME"
    if any(x in n for x in ("withdraw", "sweep")):
        return "SETTLE"
    if any(x in n for x in ("set", "pause", "unpause", "upgrade", "authorize")):
        return "ADMIN"
    return "INTERACTION"


def _action_what(fn: FunctionInfo, node: LiveNode) -> str:
    n = fn.name.lower()
    if "createpool" in n:
        return "Create a new pool using an approved agreement and stake token."
    if n == "stake":
        return "Put stake into the pool so this participant becomes part of the protocol state."
    if "contribute" in n:
        return "Add bonus/value to the pool for a later outcome or settlement."
    if "flagoutcome" in n:
        return "Report an outcome so the pool can move into an outcome-dependent state."
    if "withdraw" in n:
        return "Ask the pool to release this participant's withdrawable value."
    if "sweepunclaimed" in n:
        return "Move value that the protocol considers permanently unclaimed/corrupted."
    if "initialize" in n:
        return "Initialize one-time contract state; this is normally a deployment/setup action."
    if "setstaketokenallowed" in n:
        return "Tell the factory which stake token it is allowed to accept."
    if "set" in n:
        return "Change a piece of protocol configuration."
    return f"Call {node.artifact_contract or node.name}.{fn.name} and observe its state transition."


def _action_why(fn: FunctionInfo, node: LiveNode) -> str:
    n = fn.name.lower()
    if "createpool" in n:
        return "This is the main bridge from the factory into a newly created pool."
    if n == "stake":
        return "This is a core user action: it changes who has value at risk in the pool."
    if "withdraw" in n:
        return "Withdrawal is a security boundary because it moves value out of the protocol."
    if "contribute" in n:
        return "This changes pool value and can affect later settlement outcomes."
    if "flagoutcome" in n or "resolve" in n:
        return "Outcome decisions usually unlock or restrict later claims/withdrawals."
    if "setstaketokenallowed" in n or n.startswith("set"):
        return "Lowkey normally keeps deployment/configuration actions out of the user journey unless needed to repair the environment."
    if "initialize" in n:
        return "Initialization defines the trusted starting state; repeating it is usually expected to fail."
    return "Lowkey selected it because it can change protocol state or cross a security boundary."


def _friendly_error(decoded: str | None, raw: str) -> tuple[str, str]:
    text = str(decoded or raw or "").strip()
    low = text.lower()
    if "staketokennotalowed" in low:
        return (
            "The factory rejected the token because it is not currently approved for staking.",
            "Use the legitimate factory setup/owner flow to approve the token, then retry pool creation.",
        )
    if "stakingclosed" in low:
        return (
            "The pool is not accepting new stakes in its current state.",
            "Check the pool lifecycle and its setup/expiry state before treating staking as the next step.",
        )
    if "invalidinitialization" in low:
        return (
            "The contract says its one-time initialization has already been used.",
            "Treat this as deployment/setup state, not as the normal user flow; inspect the existing initialized values.",
        )
    if "outcomenotset" in low:
        return (
            "There is no outcome recorded yet, so this action has nothing to settle against.",
            "Find the outcome/flagging step first and then re-check this settlement path.",
        )
    if "outcomenoteligibleforsweep" in low:
        return (
            "The current outcome/state does not make these funds eligible for sweeping.",
            "Inspect the conditions that make an outcome sweepable instead of forcing the call.",
        )
    if text and ("execution reverted" in low or low.startswith("error:")):
        return (
            "The chain rejected the call, but did not provide a useful decoded reason.",
            "First verify the target contract identity and current state; then inspect the source check that guards this function.",
        )
    return (
        text or "The simulated call could not be executed.",
        "Inspect the current state and function preconditions before trying the action again.",
    )


def _step_status_word(action: dict[str, Any]) -> str:
    status = str(action.get("status") or "PLANNED").upper()
    if status == "SUCCESS":
        return "DONE"
    if status == "FAILED":
        return "FAILED"
    if status == "READY":
        return "READY"
    if status == "BLOCKED":
        return "BLOCKED"
    return "NEXT"


def _checksumish(value: str) -> str:
    if not _is_address(value):
        return value
    # Keep exact chain value but normalize its casing for display.
    return "0x" + value[2:].lower()


def _rpc_url(config: dict[str, Any]) -> str:
    return (
        str(config.get("rpc") or os.environ.get("ETH_RPC_URL") or "http://127.0.0.1:8545")
        .strip()
    )


def _rpc(url: str, method: str, params: list[Any]) -> Any:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode()
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=8) as response:
        payload = json.loads(response.read().decode())
    if "error" in payload:
        raise RuntimeError(str(payload["error"]))
    return payload.get("result")


def _code_size(url: str, address: str) -> int:
    try:
        code = _rpc(url, "eth_getCode", [address, "latest"])
        return max(0, (len(code or "0x") - 2) // 2)
    except Exception:
        return 0


def _eth_accounts(url: str) -> list[str]:
    """Return accounts exposed by the selected local JSON-RPC node."""
    try:
        result = _rpc(url, "eth_accounts", [])
    except Exception:
        return []
    if not isinstance(result, list):
        return []
    return [str(item) for item in result if _is_address(item)]


def _latest_timestamp(url: str) -> int:
    try:
        block = _rpc(url, "eth_getBlockByNumber", ["latest", False])
        return int(block["timestamp"], 16)
    except Exception:
        return int(time.time())


def _load_system_manifest(root: Path, rpc: str, config: dict[str, Any]) -> dict[str, Any] | None:
    if system_model is None:
        return None
    try:
        manifest, _ = system_model.refresh_manifest(
            root,
            rpc=rpc,
            config=config,
            reason="walkthrough:start",
        )
        return manifest
    except Exception:
        return system_model.load_manifest(root) if system_model else None


def _bootstrap_from_manifest(manifest: dict[str, Any] | None, rpc: str) -> dict[str, Any] | None:
    if not manifest:
        return None
    deployments = [
        x for x in (manifest.get("deployments") or [])
        if isinstance(x, dict)
        and not any(part.lower() == "dry-run" for part in str(x.get("broadcast") or x.get("path") or "").split("/"))
    ]
    audit_evidence = manifest.get("audit_evidence") or []
    return {
        "deployments": deployments,
        "live_deployments": [
            x for x in deployments
            if x.get("live") and x.get("code_size", x.get("live"))
        ],
        "scripts": [
            {
                "path": x.get("path"),
                "score": 0,
                "signals": [
                    a.get("kind")
                    for a in x.get("actions") or []
                    if isinstance(a, dict)
                ],
                "command": f"forge script {x.get('path')} --rpc-url {rpc} --broadcast",
            }
            for x in manifest.get("scripts") or []
        ],
        "tests": [
            {
                "path": x.get("path"),
                "signals": ["fixture/test"],
                "command": f"forge test --match-path {x.get('path')} -vvvv",
            }
            for x in manifest.get("tests") or []
        ],
        "adversarial": manifest.get("adversarial_evidence") or [],
        "audit_evidence": audit_evidence,
        "audit_targets": _extract_audit_targets(audit_evidence),
        "initialization": manifest.get("initialization") or [],
        "roles": manifest.get("roles") or [],
        "relationships": manifest.get("relationships") or [],
        "source": "system_bootstrap_manifest",
    }


def _extract_audit_targets(audit_evidence: list[Any]) -> list[dict[str, str]]:
    """Extract deterministic, live candidate targets from persisted audit evidence."""
    priority = {
        "audit_start.json": 0,
        "context.json": 1,
        "session_resume.json": 2,
        "risk.json": 3,
        "poc.json": 4,
        "walkthrough.json": 5,
    }
    candidates: list[tuple[int, str, str]] = []
    for item in audit_evidence:
        if not isinstance(item, dict):
            continue
        target = item.get("target")
        if not _is_address(target):
            continue
        file_name = Path(str(item.get("file") or "")).name
        candidates.append((priority.get(file_name, 50), file_name, str(target)))

    candidates.sort(key=lambda x: (x[0], x[1], x[2].lower()))
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for _, file_name, target in candidates:
        key = target.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append({"target": target, "file": file_name})
    return result


def _discover_bootstrap(root: Path, rpc: str) -> dict[str, Any]:
    """Discover generic Foundry entry points without executing project code."""
    deployments: list[dict[str, Any]] = []
    seen_deployments: set[tuple[str, str]] = set()

    for path in sorted((root / "broadcast").glob("**/run-latest.json")):
        rel_path = path.relative_to(root).as_posix()
        # Foundry writes simulated runs under a "dry-run" path. Those files
        # describe addresses that may never have been deployed and must not be
        # treated as live deployment evidence.
        if any(part.lower() == "dry-run" for part in path.relative_to(root).parts):
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for index, tx in enumerate(payload.get("transactions", []) or []):
            if not isinstance(tx, dict):
                continue
            addr = tx.get("contractAddress") or tx.get("contract_address")
            if not _is_address(addr):
                continue
            contract = str(
                tx.get("contractName")
                or tx.get("contract_name")
                or tx.get("contract")
                or "Deployment"
            )
            key = (addr.lower(), path.as_posix())
            if key in seen_deployments:
                continue
            seen_deployments.add(key)
            deployments.append(
                {
                    "address": addr,
                    "contract": contract,
                    "broadcast": path.relative_to(root).as_posix(),
                    "index": index,
                    "live": _code_size(rpc, addr) > 0,
                }
            )

    scripts: list[dict[str, Any]] = []
    for path in sorted((root / "script").glob("**/*.s.sol")):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        masked = _strip_solidity_comments(source)
        signals: list[str] = []
        if re.search(r"\bfunction\s+run\s*\(", masked):
            signals.append("run()")
        if re.search(r"\bvm\.startBroadcast\s*\(", masked):
            signals.append("broadcast")
        if re.search(r"\bnew\s+[A-Za-z_]\w*\s*\(", masked):
            signals.append("contract creation")
        if re.search(r"\bCREATE2?\b", masked):
            signals.append("create opcode")
        if not signals:
            continue
        rel = path.relative_to(root).as_posix()
        score = 0
        if "run()" in signals:
            score += 3
        if "broadcast" in signals:
            score += 3
        if "contract creation" in signals or "create opcode" in signals:
            score += 2
        scripts.append(
            {
                "path": rel,
                "score": score,
                "signals": signals,
                "command": (
                    f"forge script {shlex.quote(rel)} "
                    f"--rpc-url {shlex.quote(rpc)} --broadcast"
                ),
            }
        )

    tests: list[dict[str, Any]] = []
    seen_tests: set[Path] = set()
    for base in (root / "test", root / "tests"):
        for path in sorted(base.glob("**/*.t.sol")):
            if path in seen_tests:
                continue
            seen_tests.add(path)
            try:
                source = path.read_text(encoding="utf-8")
            except OSError:
                continue
            masked = _strip_solidity_comments(source)
            signals: list[str] = []
            if re.search(r"\bfunction\s+setUp\s*\(", masked):
                signals.append("setUp()")
            if re.search(r"\b(?:new|deploy)\b", masked):
                signals.append("deployment")
            if not signals:
                continue
            rel = path.relative_to(root).as_posix()
            tests.append(
                {
                    "path": rel,
                    "signals": signals,
                    "command": (
                        f"forge test --match-path {shlex.quote(rel)} -vvvv"
                    ),
                }
            )

    scripts.sort(key=lambda item: (-int(item["score"]), item["path"]))
    tests.sort(key=lambda item: item["path"])
    return {
        "deployments": deployments,
        "live_deployments": [item for item in deployments if item["live"]],
        "scripts": scripts,
        "tests": tests,
    }


def _resolve_walkthrough_target(
    root: Path,
    config: dict[str, Any],
    rpc: str,
    bootstrap: dict[str, Any],
) -> tuple[str | None, str]:
    """Resolve a target, preferring live runtime state over stale static state."""
    configured = str(config.get("target") or "").strip()
    configured_static: tuple[str, str] | None = None
    live_deployments = [
        x for x in (bootstrap.get("live_deployments") or [])
        if isinstance(x, dict)
        and not any(part.lower() == "dry-run" for part in str(x.get("broadcast") or "").split("/"))
    ]

    def current_broadcast_match(address: str, expected_name: str) -> dict[str, Any] | None:
        expected = re.sub(r"[^a-z0-9]", "", _clean_name(expected_name).lower())
        same_address = [
            x for x in live_deployments
            if str(x.get("address") or "").lower() == address.lower()
        ]
        for item in same_address:
            actual = re.sub(r"[^a-z0-9]", "", _clean_name(str(item.get("contract") or "")).lower())
            if expected and actual and (expected == actual or expected in actual or actual in expected):
                return item
        return same_address[0] if same_address else None

    configured = str(config.get("target") or "").strip()
    configured_static: tuple[str, str] | None = None
    if _is_address(configured):
        expected = str(config.get("target_contract") or _target_label(config, configured) or "")
        current = current_broadcast_match(configured, expected) if expected else None
        if current:
            return configured, "current broadcast target"
        # A live address that is identified by persisted evidence but does not
        # match the current deployment identity is stale-prone (especially on
        # a reset Anvil where CREATE addresses are reused). Prefer a current
        # deployment with the expected contract identity.
        if live_deployments and expected:
            expected_norm = re.sub(r"[^a-z0-9]", "", _clean_name(expected).lower())
            for item in live_deployments:
                actual_norm = re.sub(r"[^a-z0-9]", "", _clean_name(str(item.get("contract") or "")).lower())
                if expected_norm and actual_norm and (expected_norm == actual_norm or expected_norm in actual_norm or actual_norm in expected_norm):
                    return str(item["address"]), f"current broadcast deployment ({item.get('contract')})"
        if _code_size(rpc, configured) > 0:
            return configured, "configured target"
        configured_static = (configured, "configured target (no live bytecode)")

    saved_static: list[tuple[str, str]] = []
    saved_targets = config.get("targets") or {}
    if isinstance(saved_targets, dict):
        for name, value in saved_targets.items():
            if not _is_address(value):
                continue
            if _code_size(rpc, value) > 0:
                return value, f"saved target '{name}'"
            saved_static.append((value, f"saved target '{name}' (no live bytecode)"))

    audit_targets = bootstrap.get("audit_targets") or _extract_audit_targets(
        bootstrap.get("audit_evidence") or []
    )
    if not audit_targets:
        direct_evidence: list[dict[str, Any]] = []
        for path in sorted((root / ".audit" / "evidence").glob("*.json")):
            if path.name == "system_bootstrap.json":
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, dict) and _is_address(data.get("target")):
                direct_evidence.append({"target": data["target"], "file": path.name})
        audit_targets = _extract_audit_targets(direct_evidence)

    audit_static: list[tuple[str, str]] = []
    for item in audit_targets:
        if not isinstance(item, dict):
            continue
        target = item.get("target")
        if not _is_address(target):
            continue
        file_name = str(item.get("file") or "")
        source = f"audit evidence '{file_name}'" if file_name else "audit evidence"
        if _code_size(rpc, target) > 0:
            if not live_deployments:
                return target, source
            matched = current_broadcast_match(target, str(config.get("target_contract") or _target_label(config, target) or ""))
            if matched:
                return target, source
        audit_static.append((target, source + " (no live bytecode or stale identity)"))

    live = list(live_deployments)
    live.sort(
        key=lambda item: (
            str(item.get("broadcast") or ""),
            int(item.get("index") or 0),
        ),
        reverse=True,
    )
    if live:
        item = live[0]
        return str(item["address"]), f"broadcast {item['broadcast']}"

    if configured_static:
        return configured_static
    if audit_static:
        return audit_static[0]
    if saved_static:
        return saved_static[0]
    return None, "not discovered"


def _bootstrap_script_score(item: dict[str, Any]) -> int:
    """Rank local setup candidates without assuming project naming conventions."""
    path = str(item.get("path") or "").lower()
    signals = {str(x).lower() for x in item.get("signals") or []}
    if not path or any(token in path for token in ("poc", "exploit", "attack", "malicious")):
        return -10_000

    score = 0
    if "run()" in signals:
        score += 5
    if "broadcast" in signals:
        score += 5
    if "contract creation" in signals or "create opcode" in signals:
        score += 4
    for token, bonus in (
        ("local", 8),
        ("setup", 7),
        ("bootstrap", 6),
        ("deploy", 5),
        ("fixture", 4),
        ("lab", 3),
    ):
        if token in path:
            score += bonus
    return score


def _script_has_remote_execution_hazards(root: Path, rel_path: str) -> tuple[bool, str]:
    """Reject auto-bootstrap scripts that explicitly manipulate remote forks."""
    try:
        source = (root / rel_path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return True, f"cannot read bootstrap script: {exc}"

    masked = _strip_solidity_comments(source).lower()
    for marker in ("vm.createselectfork", "vm.createfork", "vm.rpc", "vm.transact"):
        if marker in masked:
            return True, f"script contains remote/fork execution primitive {marker}"
    return False, ""


def _auto_bootstrap_local(
    root: Path,
    config: dict[str, Any],
    bootstrap: dict[str, Any],
) -> tuple[bool, str]:
    """Populate local Anvil from a conservative discovered setup script."""
    rpc = _rpc_url(config)
    if not _is_local_rpc(rpc):
        return False, "auto bootstrap requires a local RPC"

    scripts = [x for x in (bootstrap.get("scripts") or []) if isinstance(x, dict)]
    ranked = sorted(
        scripts,
        key=lambda item: (-_bootstrap_script_score(item), str(item.get("path") or "")),
    )
    accounts = _eth_accounts(rpc)
    sender = accounts[0] if accounts else None

    for item in ranked:
        path = str(item.get("path") or "").strip()
        if _bootstrap_script_score(item) < 0:
            continue
        if not re.search(r"\.s\.sol$", path):
            continue
        hazardous, _reason = _script_has_remote_execution_hazards(root, path)
        if hazardous:
            continue

        dry_command = ["forge", "script", path, "--rpc-url", rpc]
        broadcast_command = ["forge", "script", path, "--rpc-url", rpc, "--broadcast"]
        if sender:
            dry_command += ["--unlocked", "--sender", sender]
            broadcast_command += ["--unlocked", "--sender", sender]

        code, _out, _err = _cmd(dry_command, cwd=root, timeout=90)
        if code != 0:
            continue
        code, _out, _err = _cmd(broadcast_command, cwd=root, timeout=120)
        if code == 0:
            return True, f"executed {path}"

    return False, "no safe bootstrap script completed successfully"


def _print_bootstrap_discovery(meta: dict[str, Any]) -> None:
    """Show bootstrap evidence as a concise explanation, not a command dump."""
    bootstrap = meta.get("bootstrap") or {}
    live = bootstrap.get("live_deployments") or []
    deployments = bootstrap.get("deployments") or []
    scripts = bootstrap.get("scripts") or []
    tests = bootstrap.get("tests") or []
    audit_targets = bootstrap.get("audit_targets") or []
    auto = meta.get("auto_bootstrap") or {}

    print("BOOTSTRAP / ENVIRONMENT")
    if live:
        print(f"  ✓ Local runtime contains {len(live)} deployed contract(s).")
    elif deployments:
        print("  ! Deployment records exist, but none match live bytecode on this RPC.")
    else:
        print("  ! No current deployment records were found.")

    if auto.get("status") == "success":
        print(f"  ✓ Auto setup: {auto.get('reason', 'local setup executed')}")
    elif auto:
        print(f"  • Auto setup: {auto.get('reason', 'not executed')}")

    if scripts:
        safe = [x for x in scripts if _bootstrap_script_score(x) >= 0]
        print(f"  Setup entry points: {len(safe)} safe candidate(s) found.")
        for item in safe[:4]:
            signals = ", ".join(str(x) for x in item.get("signals") or [])
            print(f"    → {item.get('path')}  ({signals})")
    else:
        print("  Setup entry points: none detected.")

    if tests:
        print(f"  Test/fixture entry points: {len(tests)} found.")
    if audit_targets:
        print(f"  Persisted audit target(s): {len(audit_targets)} found.")



def _strip_solidity_comments(text: str) -> str:
    """Mask // and /* */ comments without changing source offsets or line numbers."""
    chars = list(text)
    i = 0
    n = len(chars)
    state = "code"
    quote = ""
    while i < n:
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < n else ""
        if state == "code":
            if ch == "/" and nxt == "/":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            if ch == "/" and nxt == "*":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            if ch in {'"', "'"}:
                quote = ch
                state = "string"
            i += 1
            continue
        if state == "line_comment":
            if ch == "\n":
                state = "code"
            elif ch != "\r":
                chars[i] = " "
            i += 1
            continue
        if state == "block_comment":
            if ch == "*" and nxt == "/":
                chars[i] = " "
                chars[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch not in "\r\n":
                chars[i] = " "
            i += 1
            continue
        # Solidity string literal: keep contents so call syntax inside strings
        # is not converted into phantom source edges.
        if state == "string":
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                state = "code"
            i += 1
    return "".join(chars)


def _split_params(text: str) -> list[str]:
    items: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escape = False
    for i, ch in enumerate(text):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            item = text[start:i].strip()
            if item:
                items.append(item)
            start = i + 1
    tail = text[start:].strip()
    if tail:
        items.append(tail)
    return items


def _parse_decl_type(item: str) -> tuple[str, str]:
    item = re.sub(r"\s+", " ", item.strip())
    if not item:
        return "bytes", ""
    item = re.sub(r"\b(?:memory|calldata|storage|indexed)\b", " ", item)
    item = re.sub(r"\s+", " ", item).strip()
    parts = item.split(" ")
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[-1]


def _canonical_abi_type(param: dict[str, Any]) -> str:
    typ = str(param.get("type") or "bytes")
    if typ.startswith("tuple"):
        suffix = typ[5:]
        components = param.get("components") or []
        inner = ",".join(_canonical_abi_type(x) for x in components)
        return f"({inner}){suffix}"
    return typ


def _function_signature_from_abi(item: dict[str, Any]) -> str:
    name = str(item.get("name") or "")
    types = [_canonical_abi_type(x) for x in item.get("inputs", [])]
    return f"{name}({','.join(types)})"


def _load_artifacts(root: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Path]]:
    by_contract: dict[str, list[dict[str, Any]]] = {}
    files: dict[str, Path] = {}
    for path in sorted(root.glob("out/**/*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        abi = data.get("abi")
        if not isinstance(abi, list):
            continue
        name = str(data.get("contractName") or path.stem)
        if name not in by_contract:
            by_contract[name] = abi
            files[name] = path
    return by_contract, files


def _parse_solidity_sources(root: Path) -> dict[str, ContractInfo]:
    contracts: dict[str, ContractInfo] = {}
    patterns = list(root.glob("src/**/*.sol")) + list(root.glob("contracts/**/*.sol"))
    seen: set[Path] = set()
    for path in patterns:
        if not path.is_file() or path in seen:
            continue
        seen.add(path)
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue

        rel = path.relative_to(root).as_posix()
        scan_text = _strip_solidity_comments(text)
        import_list = re.findall(r'\bimport\s+(?:[^;]*?from\s+)?["\']([^"\']+)["\']\s*;', scan_text)

        for match in re.finditer(
            r"\b(contract|interface|library)\s+([A-Za-z_]\w*)",
            scan_text,
        ):
            kind, name = match.groups()
            line = text.count("\n", 0, match.start()) + 1
            ci = ContractInfo(
                name=name,
                source=rel,
                line=line,
                kind=kind,
                imports=import_list,
            )
            block_start = match.start()
            next_decl = re.search(
                r"\b(?:contract|interface|library)\s+[A-Za-z_]\w*",
                scan_text[match.end():],
            )
            block_end = (
                match.end() + next_decl.start()
                if next_decl
                else len(text)
            )
            ci.address_vars = [
                x.group(1)
                for x in re.finditer(
                    r"\baddress(?:\s+[A-Za-z_]\w+)?\s+(?:public|private|internal|external)\s+([A-Za-z_]\w*)\s*(?:=|;)",
                    scan_text[block_start:block_end],
                )
            ]
            for fmatch in re.finditer(
                r"\bfunction\s+([A-Za-z_]\w*)\s*\((.*?)\)\s*([^{;]*)(?:\{|;)",
                scan_text[block_start:block_end],
                flags=re.S,
            ):
                fname, ptext, tail = fmatch.groups()
                pitems = _split_params(ptext)
                inputs: list[dict[str, Any]] = []
                for raw in pitems:
                    typ, pname = _parse_decl_type(raw)
                    inputs.append({"type": typ, "name": pname})
                floc = block_start + fmatch.start()
                fline = scan_text.count("\n", 0, floc) + 1
                absolute = block_start + fmatch.start()
                brace = text.find("{", absolute, block_start + fmatch.end() + 1)
                body = ""
                if brace >= 0:
                    depth = 0
                    end = brace
                    for j in range(brace, min(len(text), brace + 30000)):
                        if text[j] == "{":
                            depth += 1
                        elif text[j] == "}":
                            depth -= 1
                            if depth == 0:
                                end = j + 1
                                break
                    body = text[brace:end]
                modifiers = re.findall(
                    r"\b(only[A-Za-z_]\w*|when[A-Za-z_]\w*|nonReentrant|initializer|payable|view|pure)\b",
                    tail,
                )
                calls: list[dict[str, Any]] = []
                for c in re.finditer(
                    r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(",
                    body,
                ):
                    calls.append(
                        {
                            "kind": "member-call",
                            "receiver": c.group(1),
                            "function": c.group(2),
                        }
                    )
                for c in re.finditer(
                    r"\b([A-Z][A-Za-z0-9_]*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*([A-Za-z_]\w*)\s*\(",
                    body,
                ):
                    calls.append(
                        {
                            "kind": "typed-call",
                            "interface": c.group(1),
                            "receiver": c.group(2),
                            "function": c.group(3),
                        }
                    )
                sig = f"{fname}({','.join(x['type'] for x in inputs)})"
                ci.functions.append(
                    FunctionInfo(
                        contract=name,
                        name=fname,
                        inputs=inputs,
                        outputs=[],
                        mutability=(
                            "view" if re.search(r"\bview\b", tail)
                            else "pure" if re.search(r"\bpure\b", tail)
                            else "payable" if re.search(r"\bpayable\b", tail)
                            else "nonpayable"
                        ),
                        signature=sig,
                        source=rel,
                        line=fline,
                        body=body,
                        modifiers=modifiers,
                        calls=calls,
                    )
                )

            for em in re.finditer(
                r"\berror\s+([A-Za-z_]\w*)\s*\((.*?)\)\s*;",
                text[block_start:block_end],
                flags=re.S,
            ):
                err_name, err_args = em.groups()
                err_inputs = []
                for raw in _split_params(err_args):
                    typ, pname = _parse_decl_type(raw)
                    err_inputs.append({"type": typ, "name": pname})
                ci.errors.append(
                    {"name": err_name, "inputs": err_inputs}
                )
            contracts[name] = ci
    return contracts


def _merge_artifact_functions(
    contracts: dict[str, ContractInfo],
    artifacts: dict[str, list[dict[str, Any]]],
    artifact_files: dict[str, Path],
    root: Path,
) -> dict[str, list[FunctionInfo]]:
    by_contract: dict[str, list[FunctionInfo]] = {}
    for name, abi in artifacts.items():
        ci = contracts.get(name)
        source_map: dict[str, tuple[str | None, int | None]] = {}
        if ci:
            source_map = {
                f.signature: (f.source, f.line)
                for f in ci.functions
            }
        functions: list[FunctionInfo] = []
        for item in abi:
            if item.get("type") != "function":
                continue
            sig = _function_signature_from_abi(item)
            src, line = source_map.get(sig, (None, None))
            functions.append(
                FunctionInfo(
                    contract=name,
                    name=str(item.get("name") or ""),
                    inputs=item.get("inputs") or [],
                    outputs=item.get("outputs") or [],
                    mutability=str(item.get("stateMutability") or "nonpayable"),
                    signature=sig,
                    source=src,
                    line=line,
                    body=(
                        next(
                            (
                                f.body
                                for f in (ci.functions if ci else [])
                                if f.signature == sig
                            ),
                            "",
                        )
                    ),
                    modifiers=(
                        next(
                            (
                                f.modifiers
                                for f in (ci.functions if ci else [])
                                if f.signature == sig
                            ),
                            [],
                        )
                    ),
                    calls=(
                        next(
                            (
                                f.calls
                                for f in (ci.functions if ci else [])
                                if f.signature == sig
                            ),
                            [],
                        )
                    ),
                )
            )
        by_contract[name] = functions
    return by_contract


def _source_link(root: Path, source: str | None, line: int | None, text: str) -> str:
    if not source or not line:
        return text
    path = (root / source).resolve()
    if not path.exists():
        return text
    href = f"file://{path}:{line}"
    # OSC 8 hyperlink. Supported by modern GNOME Terminal, VS Code terminal,
    # iTerm2 and several other terminals; unsupported terminals simply render text.
    return f"\x1b]8;;{href}\x1b\\{text}\x1b]8;;\x1b\\"


def _run(
    command: list[str],
    root: Path | None = None,
    timeout: int = 30,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            command,
            cwd=str(root) if root else None,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except FileNotFoundError:
        return 127, "", f"{command[0]} not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out after {timeout}s"
    except OSError as exc:
        return 1, "", str(exc)


def _cast_call(
    root: Path,
    rpc: str,
    address: str,
    function: FunctionInfo,
    args: list[str],
    caller: str | None = None,
) -> tuple[int, str, str]:
    cmd = ["cast", "call", address, function.signature, *args, "--rpc-url", rpc]
    if caller and _is_address(caller):
        cmd.extend(["--from", caller])
    return _run(cmd, root, 30)


def _cast_send(
    root: Path,
    rpc: str,
    address: str,
    function: FunctionInfo,
    args: list[str],
    caller: str,
) -> tuple[int, str, str]:
    cmd = [
        "cast",
        "send",
        address,
        function.signature,
        *args,
        "--rpc-url",
        rpc,
        "--from",
        caller,
        "--unlocked",
    ]
    return _run(cmd, root, 60)


def _debug_trace_call(
    root: Path,
    rpc: str,
    address: str,
    function: FunctionInfo,
    args: list[Any],
    caller: str | None,
) -> dict[str, Any] | None:
    """Best-effort callTracer evidence for opaque empty reverts."""
    try:
        code, calldata, _ = _run(
            ["cast", "calldata", function.signature, *_arg_values_to_strings(args)],
            root,
            15,
        )
        if code != 0 or not calldata.strip():
            return None
        tx = {
            "from": caller if _is_address(caller) else ZERO,
            "to": address,
            "data": calldata.strip(),
        }
        payload = _rpc(
            rpc,
            "debug_traceCall",
            [tx, "latest", {"tracer": "callTracer"}],
        )
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _trace_revert_frames(trace: Any) -> list[str]:
    frames: list[str] = []

    def visit(node: Any) -> None:
        if not isinstance(node, dict):
            return
        target = node.get("to") or node.get("from") or "unknown"
        error = node.get("revertReason") or node.get("error")
        if error:
            frames.append(f"{target}: {error}")
        for child in node.get("calls") or []:
            visit(child)

    visit(trace)
    return frames


def _parse_revert_blob(text: str) -> str | None:
    candidates = re.findall(
        r"0x[0-9a-fA-F]{8,}",
        text.replace('\\"', '"'),
    )
    if not candidates:
        return None
    # Prefer a blob that includes at least a full 4-byte selector.
    for item in reversed(candidates):
        if len(item) >= 10:
            return item
    return None


def _keccak_selector(signature: str) -> str:
    try:
        from Crypto.Hash import keccak  # type: ignore
        k = keccak.new(digest_bits=256)
        k.update(signature.encode())
        return "0x" + k.hexdigest()[:8]
    except Exception:
        code, out, _ = _run(["cast", "sig", signature], None, 10)
        if code == 0:
            m = re.search(r"0x[0-9a-fA-F]{8}", out)
            if m:
                return m.group(0).lower()
    # Deliberately return an impossible sentinel; callers do not rely on it for control flow.
    return "0x00000000"


def _decode_word(typ: str, word: bytes) -> Any:
    t = typ.lower()
    if t.startswith("uint") or t.startswith("int"):
        return int.from_bytes(word, "big", signed=t.startswith("int"))
    if t == "bool":
        return bool(int.from_bytes(word, "big"))
    if t == "address":
        return "0x" + word[-20:].hex()
    if t.startswith("bytes") and len(t) > 5:
        n = int(t[5:])
        return "0x" + word[:n].hex()
    return "0x" + word.hex()


def _decode_error(
    blob: str | None,
    errors: Iterable[dict[str, Any]],
) -> str | None:
    if not blob or len(blob) < 10:
        return None
    raw = bytes.fromhex(blob[2:])
    selector = "0x" + raw[:4].hex()
    for err in errors:
        name = str(err.get("name") or "")
        inputs = err.get("inputs") or []
        sig = f"{name}({','.join(_canonical_abi_type(x) for x in inputs)})"
        if _keccak_selector(sig) != selector:
            continue
        payload = raw[4:]
        values: list[Any] = []
        for i, item in enumerate(inputs):
            typ = _canonical_abi_type(item)
            # Dynamic decoding is deliberately conservative; static errors are
            # by far the most common and are fully decoded here.
            if "[" in typ or typ in {"bytes", "string"} or typ.startswith("("):
                values.append("<dynamic>")
                continue
            off = i * 32
            if len(payload) < off + 32:
                values.append("<truncated>")
            else:
                values.append(_decode_word(typ, payload[off:off + 32]))
        if values:
            return f"{name}({', '.join(str(v) for v in values)})"
        return f"{name}()"
    return selector


def _all_errors(artifacts: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for abi in artifacts.values():
        for item in abi:
            if item.get("type") != "error":
                continue
            sig = _function_signature_from_abi(
                {**item, "name": item.get("name")}
            )
            key = sig
            if key in seen:
                continue
            seen.add(key)
            out.append(item)
    return out


def _parse_cast_value(raw: str, typ: str) -> Any:
    text = raw.strip()
    if typ.endswith("[]"):
        inner = text.strip("[] ")
        if not inner:
            return []
        return [
            _parse_cast_value(part.strip(), typ[:-2])
            for part in _split_params(inner)
        ]
    if _is_address(text):
        return text
    if text.lower() in {"true", "false"}:
        return text.lower() == "true"
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def _render_value(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(_render_value(x) for x in value) + "]"
    return str(value)


def _normalize_arg_for_cast(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ",".join(_normalize_arg_for_cast(x) for x in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _function_by_name(functions: Iterable[FunctionInfo], name: str) -> FunctionInfo | None:
    matches = [f for f in functions if f.name == name]
    return matches[0] if matches else None


def _read_simple_getter(
    root: Path,
    rpc: str,
    node: LiveNode,
    function: FunctionInfo,
    *,
    caller: str | None = None,
) -> tuple[Any, str]:
    code, out, err = _cast_call(root, rpc, node.address, function, [], caller)
    if code != 0:
        return None, err or out
    text = out.strip()
    if not text:
        return None, ""
    outputs = function.outputs
    if len(outputs) == 1 and str(outputs[0].get("type")) == "address":
        m = re.search(r"0x[0-9a-fA-F]{40}", text)
        return (m.group(0) if m else None), text
    if len(outputs) == 1 and str(outputs[0].get("type")) == "address[]":
        vals = re.findall(r"0x[0-9a-fA-F]{40}", text)
        return vals, text
    if len(outputs) == 1 and str(outputs[0].get("type")) == "bool":
        return text.lower().split()[0] == "true", text
    if len(outputs) == 1 and (
        str(outputs[0].get("type") or "").startswith(("uint", "int"))
    ):
        m = re.search(r"-?\d+", text)
        return (int(m.group(0)) if m else None), text
    return text, text


def _discover_getters(
    root: Path,
    rpc: str,
    node: LiveNode,
    functions: list[FunctionInfo],
) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for fn in functions:
        if fn.mutability not in {"view", "pure"}:
            continue
        if fn.inputs:
            continue
        if len(fn.outputs) != 1:
            continue
        typ = str(fn.outputs[0].get("type") or "")
        if typ not in {"address", "address[]", "bool"} and not typ.startswith(("uint", "int")):
            continue
        val, raw = _read_simple_getter(root, rpc, node, fn)
        if val is not None:
            values[fn.name] = val
    return values


def _looks_like_erc20(functions: list[FunctionInfo]) -> bool:
    names = {f.name for f in functions}
    return {"balanceOf", "transfer"}.issubset(names)


def _looks_like_agreement(functions: list[FunctionInfo]) -> bool:
    names = {f.name for f in functions}
    return "isContractInScope" in names and "owner" in names


def _build_live_graph(
    root: Path,
    rpc: str,
    target: str,
    label_hint: str | None,
    functions_by_contract: dict[str, list[FunctionInfo]],
    artifact_files: dict[str, Path],
) -> tuple[list[LiveNode], dict[str, dict[str, Any]], dict[str, str]]:
    nodes: list[LiveNode] = []
    getter_data: dict[str, dict[str, Any]] = {}
    address_names: dict[str, str] = {}
    queue: list[tuple[str, str, str | None, str | None]] = [
        (target, label_hint or "Target", None, None)
    ]
    seen: set[str] = set()

    while queue and len(nodes) < 40:
        address, label, parent, getter = queue.pop(0)
        if not _is_address(address):
            continue
        key = address.lower()
        if key in seen:
            continue
        seen.add(key)
        size = _code_size(rpc, address)
        # A target with zero code is intentionally retained so diagnostics can
        # say "there is no contract here" instead of inventing a revert reason.
        artifact_contract = None
        if label in functions_by_contract:
            artifact_contract = label
        else:
            for cname in functions_by_contract:
                if cname.lower() == label.lower():
                    artifact_contract = cname
                    break
        node = LiveNode(
            address=address,
            name=artifact_contract or label,
            code_size=size,
            artifact_contract=artifact_contract,
            discovered_from=parent,
            getter=getter,
        )
        nodes.append(node)
        if size == 0:
            continue

        funcs = functions_by_contract.get(artifact_contract or "", [])
        vals = _discover_getters(root, rpc, node, funcs)
        getter_data[address.lower()] = vals

        for gname, value in vals.items():
            if _is_address(value) and value.lower() != ZERO.lower():
                if _code_size(rpc, value) > 0:
                    child_label = gname
                    for cname, fs in functions_by_contract.items():
                        if gname in {f.name for f in fs}:
                            child_label = cname
                            break
                    queue.append((value, child_label, address, gname))
                    address_names[value.lower()] = gname
            elif isinstance(value, list):
                for item in value[:20]:
                    if _is_address(item) and _code_size(rpc, item) > 0:
                        queue.append((item, gname, address, gname))
                        address_names[item.lower()] = gname

    return nodes, getter_data, address_names


def _actor_context(config: dict[str, Any], rpc: str) -> dict[str, str]:
    accounts = _eth_accounts(rpc)
    actors: dict[str, str] = {}
    saved = config.get("aliases") or {}
    if isinstance(saved, dict):
        for name, addr in saved.items():
            if _is_address(addr):
                actors[str(name)] = addr

    defaults = ["Alice", "Bob", "Attacker"]
    for i, addr in enumerate(accounts[:3]):
        actors.setdefault(defaults[i], addr)

    # Common lower-case aliases, used for role matching.
    for canonical in list(actors):
        actors[canonical.lower()] = actors[canonical]
    return actors


def _known_contracts(nodes: list[LiveNode], functions_by_contract: dict[str, list[FunctionInfo]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for node in nodes:
        cname = node.artifact_contract or node.name
        result[cname.lower()] = node.address
        fs = functions_by_contract.get(cname, [])
        if _looks_like_erc20(fs):
            result.setdefault("erc20", node.address)
        if _looks_like_agreement(fs):
            result.setdefault("agreement", node.address)
        if "isAgreementValid" in {f.name for f in fs}:
            result.setdefault("safeharbor", node.address)
        if "getAgreementState" in {f.name for f in fs}:
            result.setdefault("attackregistry", node.address)
    return result


def _query_by_signature(
    root: Path,
    rpc: str,
    address: str,
    signature: str,
    args: list[str] | None = None,
    caller: str | None = None,
) -> tuple[int, str, str]:
    fn = FunctionInfo(
        contract="Runtime",
        name=signature.split("(", 1)[0],
        inputs=[],
        outputs=[],
        mutability="view",
        signature=signature,
    )
    return _cast_call(root, rpc, address, fn, args or [], caller)


def _scope_accounts(
    root: Path,
    rpc: str,
    agreement: str | None,
    agreement_functions: list[FunctionInfo] | None,
) -> list[str]:
    if not agreement or not agreement_functions:
        return []

    live_node = LiveNode(agreement, "Agreement", _code_size(rpc, agreement))

    # Prefer a bulk getter whose ABI says it returns address[] and whose name
    # indicates accounts/scope/members. This works across unrelated protocols.
    bulk_candidates = [
        fn
        for fn in agreement_functions
        if fn.mutability in {"view", "pure"}
        and any(
            _canonical_abi_type(o) == "address[]"
            for o in (fn.outputs or [])
        )
        and any(
            token in fn.name.lower()
            for token in ("account", "scope", "member", "participant")
        )
        and not fn.inputs
    ]
    for fn in bulk_candidates:
        val, _ = _read_simple_getter(root, rpc, live_node, fn)
        addresses = [x for x in (val or []) if _is_address(x)]
        if addresses:
            return addresses

    # Fallback: find an address -> bool membership query and test RPC accounts.
    membership_candidates = [
        fn
        for fn in agreement_functions
        if fn.mutability in {"view", "pure"}
        and len(fn.inputs) == 1
        and _canonical_abi_type(fn.inputs[0]) == "address"
        and len(fn.outputs) == 1
        and _canonical_abi_type(fn.outputs[0]) == "bool"
        and any(
            token in fn.name.lower()
            for token in ("scope", "account", "member", "participant", "in")
        )
    ]
    for fn in membership_candidates:
        discovered: list[str] = []
        for candidate in _eth_accounts(rpc):
            code, out, _ = _query_by_signature(
                root,
                rpc,
                agreement,
                _function_signature_from_abi({
                    "name": fn.name,
                    "inputs": fn.inputs,
                }),
                [_normalize_arg_for_cast(candidate)],
            )
            if code == 0 and out.strip().lower() in {"true", "1"}:
                discovered.append(candidate)
        if discovered:
            return discovered
    return []

def _find_node_by_predicate(
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    predicate: Any,
) -> LiveNode | None:
    for node in nodes:
        cname = node.artifact_contract or node.name
        if predicate(functions_by_contract.get(cname, [])):
            return node
    return None


def _semantic_address(
    param_name: str,
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    actors: dict[str, str],
    known: dict[str, str],
    *,
    prefer_contract: bool = False,
    root: Path | None = None,
    rpc: str | None = None,
) -> str | None:
    n = param_name.lower()
    if "agreement" in n:
        return known.get("agreement")
    if "stake" in n and "token" in n or n in {"token", "staketoken"}:
        return known.get("erc20")
    if any(x in n for x in ("recovery", "recipient", "owner", "admin", "caller", "sender")):
        return actors.get("alice") or actors.get("Alice")
    if "attacker" in n:
        return actors.get("attacker")
    if "moderator" in n or "manager" in n:
        for node in nodes:
            cname = node.artifact_contract or node.name
            if cname.lower() in {"confidencepool", "confidencepoolfactory"}:
                continue
            fs = functions_by_contract.get(cname, [])
            if any(f.name == "owner" for f in fs):
                owner_fn = _function_by_name(fs, "owner")
                if owner_fn:
                    val, _ = _read_simple_getter(
                        root or Path.cwd(),
                        rpc or _rpc_url({}),
                        node,
                        owner_fn,
                    )
                    if _is_address(val):
                        return val
        return actors.get("alice") or actors.get("Alice")
    if any(x in n for x in ("pool", "implementation", "registry", "oracle", "factory")):
        for key in (n, "poolimplementation", "safeharbor", "attackregistry"):
            if key in known:
                return known[key]
    if prefer_contract:
        for node in nodes:
            if node.code_size > 0:
                return node.address
    return actors.get("alice") or actors.get("Alice")


def _semantic_arg(
    param: dict[str, Any],
    node: LiveNode,
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
    actors: dict[str, str],
    known: dict[str, str],
    now: int,
    root: Path,
    rpc: str,
) -> Any:
    typ = str(param.get("type") or "bytes")
    name = str(param.get("name") or "").lower()

    if typ == "address":
        return _semantic_address(name, nodes, functions_by_contract, actors, known, root=root, rpc=rpc)

    if typ == "address[]":
        if "account" in name or "scope" in name:
            agreement = known.get("agreement")
            if agreement:
                afn = functions_by_contract.get(
                    next(
                        (
                            n.artifact_contract
                            for n in nodes
                            if n.address.lower() == agreement.lower()
                        ),
                        "Agreement",
                    ),
                    [],
                )
                scope = _scope_accounts(root, rpc, agreement, afn)
                if scope:
                    return scope
        return [actors[x] for x in ("Alice", "Bob") if x in actors]

    if typ.startswith("uint") or typ.startswith("int"):
        if any(x in name for x in ("expiry", "deadline", "timestamp", "end", "until")):
            return now + 31 * 24 * 60 * 60
        if "minstake" in name:
            return 1
        if "amount" in name:
            fs = functions_by_contract.get(node.artifact_contract or node.name, [])
            min_fn = _function_by_name(fs, "minStake")
            if min_fn:
                val, _ = _read_simple_getter(
                    root,
                    rpc,
                    node,
                    min_fn,
                )
                if isinstance(val, int) and val > 0:
                    return val
            return 1
        return 1

    if typ == "bool":
        if any(x in name for x in ("allowed", "enable", "enabled")):
            return True
        return False

    if typ == "bytes32":
        return "0x" + "00" * 32

    if typ == "bytes":
        return "0x"

    if typ == "string":
        return "lowkey"

    # Dynamic or tuple types require a richer schema than a human-readable
    # walkthrough should invent automatically. Leave them as unsupported.
    return None


def _semantic_args(
    node: LiveNode,
    fn: FunctionInfo,
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
    actors: dict[str, str],
    known: dict[str, str],
    now: int,
    root: Path,
    rpc: str,
) -> tuple[list[Any] | None, str | None]:
    args: list[Any] = []
    for item in fn.inputs:
        typ = _canonical_abi_type(item)
        if typ.startswith("(") or typ.endswith("]") and typ != "address[]":
            # Handle address[] above; tuples and nested arrays are intentionally
            # deferred to explicit/manual tests.
            if typ != "address[]":
                return None, f"complex ABI type {typ} is not auto-synthesized"
        value = _semantic_arg(
            item,
            node,
            functions_by_contract,
            nodes,
            actors,
            known,
            now,
            root,
            rpc,
        )
        if value is None:
            return None, f"no safe semantic value for {item.get('name') or typ}"
        args.append(value)

    return args, None


def _arg_values_to_strings(args: list[Any]) -> list[str]:
    return [_normalize_arg_for_cast(x) for x in args]


def _preflight_failure(
    root: Path,
    rpc: str,
    node: LiveNode,
    fn: FunctionInfo,
    args: list[Any],
    caller: str,
    all_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    code, out, err = _cast_call(
        root,
        rpc,
        node.address,
        fn,
        _arg_values_to_strings(args),
        caller,
    )
    combined = "\n".join(x for x in (err, out) if x)
    blob = _parse_revert_blob(combined)
    decoded = _decode_error(blob, all_errors)
    trace = None
    trace_revert_frames: list[str] = []
    if code != 0 and not decoded and (not blob or blob == "0x"):
        trace = _debug_trace_call(root, rpc, node.address, fn, args, caller)
        trace_revert_frames = _trace_revert_frames(trace)
    return {
        "ok": code == 0,
        "exit_code": code,
        "stdout": out,
        "stderr": err,
        "revert_data": blob,
        "decoded_error": decoded,
        "trace": trace,
        "trace_revert_frames": trace_revert_frames,
        "raw": combined[-2000:],
    }


def _known_preconditions(
    root: Path,
    rpc: str,
    node: LiveNode,
    fn: FunctionInfo,
    args: list[Any],
    caller: str,
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
    known: dict[str, str],
    actors: dict[str, str],
) -> list[str]:
    """Evaluate common source-shaped preconditions without hard-coding a project.

    This is deliberately a small generic evaluator. It reports evidence-backed
    checks instead of pretending it can symbolically solve arbitrary Solidity.
    """
    findings: list[str] = []
    fs = functions_by_contract.get(node.artifact_contract or node.name, [])
    by_name = {f.name: f for f in fs}
    values = {str(p.get("name") or f"arg{i}"): v for i, (p, v) in enumerate(zip(fn.inputs, args))}
    src = fn.body or ""

    # Live bytecode is a first-class precondition.
    if node.code_size == 0:
        findings.append(f"target {node.address} has no runtime bytecode")

    # Time-based expiry/deadline gates.
    # Instead of assuming the exact constant, compare the source-level shape and
    # use the current simulated timestamp.
    if "block.timestamp" in src and "expiry" in src and re.search(r"expiry[^;]*(?:block\.timestamp|\+|\-)", src):
        exp = values.get("expiry")
        if isinstance(exp, int):
            now = _latest_timestamp(rpc)
            if exp <= now:
                findings.append(f"expiry {exp} is not in the future")
            elif exp < now + 7 * 24 * 60 * 60:
                findings.append(f"expiry {exp} is less than 7 days from the live chain")

    # Owner-of-referenced-contract is a common authorization gate.
    if ".owner()" in src and "msg.sender" in src:
        agreement = values.get("agreement")
        if _is_address(agreement) and _code_size(rpc, agreement) > 0:
            code, out, err = _query_by_signature(
                root,
                rpc,
                agreement,
                "owner()(address)",
                [],
            )
            owner = re.search(r"0x[0-9a-fA-F]{40}", out)
            if code == 0 and owner and owner.group(0).lower() != caller.lower():
                findings.append(
                    f"agreement.owner() is {owner.group(0)}, but caller is {caller}"
                )


    return findings


def _rank_function(fn: FunctionInfo) -> int:
    if fn.mutability in {"view", "pure"}:
        return -100
    n = fn.name.lower()
    score = 20
    for token, bonus in (
        ("setstaketokenallowed", 34),
        ("create", 30),
        ("initialize", 20),
        ("stake", 25),
        ("deposit", 25),
        ("contribute", 22),
        ("borrow", 20),
        ("withdraw", 20),
        ("claim", 18),
        ("redeem", 18),
        ("release", 18),
        ("execute", 15),
        ("flag", 12),
        ("resolve", 12),
        ("sweep", 10),
    ):
        if token in n:
            score += bonus
    for token in ("set", "pause", "unpause", "upgrade", "authorize"):
        if n.startswith(token):
            score -= 20
    if n in {"constructor", "fallback", "receive"}:
        score = -100
    return score


def _choose_caller(
    root: Path,
    rpc: str,
    node: LiveNode,
    fn: FunctionInfo,
    actors: dict[str, str],
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
) -> tuple[str | None, str]:
    n = fn.name.lower()
    # Known protocol roles first.
    if "attacker" in n and actors.get("Attacker"):
        return actors["Attacker"], "Attacker"
    if n in {"claimattackerbounty"} and actors.get("Attacker"):
        return actors["Attacker"], "Attacker"

    fs = functions_by_contract.get(node.artifact_contract or node.name, [])
    owner_fn = _function_by_name(fs, "owner")
    if owner_fn and any(x in n for x in ("set", "pause", "unpause", "upgrade", "authorize")):
        val, _ = _read_simple_getter(root, rpc, node, owner_fn)
        if _is_address(val):
            return val, "Owner"

    if n in {"flagoutcome"}:
        mod_fn = _function_by_name(fs, "outcomeModerator")
        if mod_fn:
            val, _ = _read_simple_getter(root, rpc, node, mod_fn)
            if _is_address(val):
                return val, "Moderator"

    return (
        actors.get("Alice") or actors.get("alice"),
        "Alice",
    )


def _function_source(
    root: Path,
    contracts: dict[str, ContractInfo],
    fn: FunctionInfo,
) -> tuple[str | None, int | None]:
    if fn.source and fn.line:
        return fn.source, fn.line
    ci = contracts.get(fn.contract)
    if ci:
        return ci.source, ci.line
    return None, None


def _system_edges(
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    contracts: dict[str, ContractInfo],
) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []

    # Static source/import edges.
    for cname, ci in contracts.items():
        for imp in ci.imports:
            edges.append(
                {
                    "from": cname,
                    "to": imp,
                    "kind": "import",
                }
            )
        for fn in ci.functions:
            for call in fn.calls or []:
                if call["kind"] == "typed-call":
                    edges.append(
                        {
                            "from": cname,
                            "to": call["interface"],
                            "kind": "external-call",
                            "function": f"{fn.name} -> {call['function']}",
                        }
                    )
                else:
                    receiver = call["receiver"]
                    state_or_input = set(ci.address_vars)
                    state_or_input.update(
                        str(p.get("name") or "")
                        for p in fn.inputs
                        if isinstance(p, dict)
                    )
                    if receiver in state_or_input:
                        edges.append(
                            {
                                "from": cname,
                                "to": receiver,
                                "kind": "member-call",
                                "function": f"{fn.name} -> {call['function']}",
                            }
                        )

    # Runtime getter edges connect actual addresses.
    for node in nodes:
        for other in nodes:
            if node.address.lower() == other.address.lower():
                continue
            if other.discovered_from and other.discovered_from.lower() == node.address.lower():
                edges.append(
                    {
                        "from": node.artifact_contract or node.name,
                        "to": other.artifact_contract or other.name,
                        "kind": f"runtime:{other.getter or 'address-returning getter'}",
                    }
                )
    return edges


def _static_system_context(
    bootstrap: dict[str, Any] | None,
    contracts: dict[str, ContractInfo],
) -> dict[str, Any]:
    """Build a protocol-agnostic static system view from source/setup evidence."""
    bootstrap = bootstrap or {}
    initialization = [
        x for x in (bootstrap.get("initialization") or [])
        if isinstance(x, dict)
    ]

    deployed: list[str] = []
    for item in initialization:
        if item.get("kind") != "deploy":
            continue
        name = str(item.get("target") or "").strip()
        if name and name not in deployed:
            deployed.append(name)

    project_contracts: list[str] = []
    for name, info in contracts.items():
        source = str(info.source or "")
        if not source.startswith(("src/", "contracts/")):
            continue
        if info.kind not in {"contract", "abstract"}:
            continue
        project_contracts.append(name)
    project_contracts.sort()

    script_flow: dict[str, list[dict[str, Any]]] = {}
    for item in initialization:
        source = str(item.get("source") or "unknown")
        script_flow.setdefault(source, []).append(
            {
                "kind": str(item.get("kind") or "unknown"),
                "target": str(item.get("target") or ""),
                "line": item.get("line"),
                "evidence": str(item.get("evidence") or ""),
            }
        )

    return {
        "deployed_contracts": deployed,
        "project_contracts": project_contracts,
        "script_flow": script_flow,
        "initialization_steps": len(initialization),
    }


def _target_label(config: dict[str, Any], target: str | None) -> str:
    if not _is_address(target):
        return "Target"
    if str(config.get("target") or "").lower() == target.lower():
        labels = config.get("labels") or {}
        configured = labels.get(target) if isinstance(labels, dict) else None
        return str(config.get("target_contract") or configured or "Target")
    labels = config.get("labels") or {}
    if isinstance(labels, dict):
        for k, v in labels.items():
            if str(k).lower() == target.lower():
                return str(v)
    return "Target"


def _pretty_error(result: dict[str, Any]) -> str:
    decoded = result.get("decoded_error")
    if decoded:
        return decoded
    raw = str(result.get("raw") or "")
    blob = result.get("revert_data")
    if blob:
        return f"revert data {blob}"
    if raw:
        return raw.splitlines()[-1][:240]
    return "execution reverted without returndata"


def _persist(root: Path, payload: dict[str, Any]) -> None:
    path = root / ".audit" / "evidence" / "walkthrough.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, default=str) + "\n",
        encoding="utf-8",
    )


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
    """Render the walkthrough as a compact human-facing protocol story."""
    meta = meta if isinstance(meta, dict) else {}
    lines: list[str] = []
    live_nodes = [n for n in nodes if n.code_size > 0]
    target = meta.get("target")
    target_name = _target_label({}, target) if target else "Not resolved"
    if target:
        for n in nodes:
            if n.address.lower() == str(target).lower():
                target_name = n.artifact_contract or n.name
                break

    lines.append("╭────────────────────────────────────────────────────────────╮")
    lines.append("│ LOWKEY  /  SYSTEM WALKTHROUGH                              │")
    lines.append("╰────────────────────────────────────────────────────────────╯")
    lines.append(f"  Environment  Local RPC • {_short_address(str(target)) if target else 'no target'}")
    lines.append(f"  System       {len(live_nodes)} live contract(s) • {len(actors)} actor(s)")
    lines.append(f"  Focus        {target_name}")
    source = str(meta.get("target_source") or "")
    if "current broadcast" in source:
        lines.append("  Identity     ✓ matched to the current local deployment")
    elif "audit evidence" in source and "no live" not in source:
        lines.append("  Identity     • taken from persisted audit evidence")

    if meta.get("auto_bootstrap"):
        boot = meta["auto_bootstrap"]
        if boot.get("status") == "success":
            lines.append(f"  Bootstrap    ✓ Local setup loaded ({boot.get('reason', 'completed')})")
        else:
            lines.append(f"  Bootstrap    • {boot.get('reason', 'not needed')}")

    lines.append("")
    lines.append("SYSTEM IN PLAIN ENGLISH")
    if actors:
        actor_bits = [name for name in ("Alice", "Bob", "Attacker") if actors.get(name)]
        if actor_bits:
            lines.append("  " + " / ".join(actor_bits) + " are the people Lowkey can use as test actors.")

    role_nodes: dict[str, LiveNode] = {}
    for n in live_nodes:
        low = (n.artifact_contract or n.name).lower()
        for key, tokens in {
            "factory": ("factory",),
            "pool": ("pool",),
            "agreement": ("agreement",),
            "token": ("token", "erc20"),
            "registry": ("registry", "safeharbor"),
            "moderator": ("moderator",),
        }.items():
            if key not in role_nodes and any(token in low for token in tokens):
                role_nodes[key] = n

    if role_nodes:
        if role_nodes.get("factory"):
            n = role_nodes["factory"]
            lines.append(f"  {n.artifact_contract or n.name}  → {_contract_purpose(n.artifact_contract or n.name, functions_by_contract.get(n.artifact_contract or n.name))}")
            if role_nodes.get("agreement"):
                a = role_nodes["agreement"]
                lines.append(f"     ├─ checks → {a.artifact_contract or a.name}  (agreement/permissions)")
            if role_nodes.get("token"):
                t = role_nodes["token"]
                lines.append(f"     ├─ accepts → {t.artifact_contract or t.name}  (stake asset)")
            if role_nodes.get("pool"):
                p = role_nodes["pool"]
                lines.append(f"     └─ creates/initializes → {p.artifact_contract or p.name}")
        if role_nodes.get("pool"):
            p = role_nodes["pool"]
            lines.append(f"  {p.artifact_contract or p.name}  → {_contract_purpose(p.artifact_contract or p.name, functions_by_contract.get(p.artifact_contract or p.name))}")
            if role_nodes.get("registry"):
                r = role_nodes["registry"]
                lines.append(f"     └─ consults → {r.artifact_contract or r.name}  (external validity/state)")
    else:
        lines.append("  Lowkey found contracts, but could not confidently assign their protocol roles yet.")

    lines.append("")
    lines.append("WALKTHROUGH PHASES")
    lines.append("  CREATE       build the protocol instance and its starting configuration")
    lines.append("  PARTICIPATE  users add stake/value and enter the protocol state")
    lines.append("  OUTCOME      the system records or reacts to an outcome")
    lines.append("  SETTLE       the protocol releases, claims or sweeps value")
    lines.append("  ADMIN        deployment/configuration work; normally kept out of the user journey")

    lines.append("")
    lines.append("SYSTEM CONNECTION WEB")
    lines.extend(_render_connection_web(nodes, _system_edges(nodes, functions_by_contract, contracts), actions))

    lines.append("")
    lines.append("WHAT LOWKEY IS DOING")
    if not actions:
        lines.append("  No safe next action was found from the current state.")
    else:
        upto = len(actions) if current is None else min(len(actions), current + 1)
        for index, action in enumerate(actions[:upto]):
            fn: FunctionInfo = action["function"]
            node: LiveNode = action["node"]
            status = _step_status_word(action)
            actor = str(action.get("actor_name") or "Unknown")
            mark = "✓" if status == "DONE" else "!" if status in {"BLOCKED", "FAILED"} else "→"
            lines.append("")
            lines.append(f"  {mark} {index + 1:02d}  {action.get('phase', 'STEP')} / {status}")
            label = f"{node.artifact_contract or node.name}.{fn.name}"
            if links and fn.source and fn.line:
                label = _source_link(root, fn.source, fn.line, label)
            lines.append(f"      {actor} → {label}")
            lines.append(f"      WHAT   {action.get('what') or _action_what(fn, node)}")
            lines.append(f"      WHY    {action.get('why') or _action_why(fn, node)}")

            result = action.get("result") or {}
            if result.get("ok"):
                lines.append("      RESULT ✓ The chain accepts this action in simulation.")
            else:
                friendly, recommendation = _friendly_error(result.get("decoded_error"), result.get("raw", ""))
                lines.append(f"      RESULT ! {friendly}")
                lines.append(f"      NEXT   {recommendation}")
                for item in action.get("diagnosis", [])[:2]:
                    lines.append(f"             evidence: {item}")

            if current is None and index >= 5 and len(actions) > 6:
                lines.append(f"      … {len(actions) - index - 1} more candidate step(s) hidden")
                break

    lines.append("")
    lines.append("LEGEND")
    lines.append("  WHAT  = what the contract is being asked to do")
    lines.append("  WHY   = why this action belongs in the protocol story")
    lines.append("  RESULT = what the live chain actually said")
    lines.append("  NEXT  = the practical thing to inspect/fix before retrying")
    lines.append("")
    lines.append("TIP  Run without --bootstrap for this clean view; use --bootstrap only when you need raw evidence.")
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
        "bootstrap": bootstrap,
        "system_manifest": manifest,
        "static_system": _static_system_context(bootstrap, contracts),
    }
    return meta, functions_by_contract, nodes, getter_data, contracts, actors, known


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
    candidates: list[tuple[int, LiveNode, FunctionInfo]] = []
    for node in nodes:
        if node.code_size == 0:
            continue
        funcs = functions_by_contract.get(node.artifact_contract or node.name, [])
        for fn in funcs:
            score = _rank_function(fn)
            n = fn.name.lower()
            already_configured = any(
                str(item.get("target") or "").lower().find(n) >= 0
                for item in (meta.get("bootstrap") or {}).get("initialization") or []
                if isinstance(item, dict)
            )
            if already_configured and (n.startswith("initialize") or n.startswith("set") or n in {"pause", "unpause", "upgrade"}):
                continue
            if score > 0:
                candidates.append((score, node, fn))
    candidates.sort(key=lambda x: (-x[0], x[1].name, x[2].name))

    seen: set[tuple[str, str]] = set()
    for _, node, fn in candidates:
        key = (node.address.lower(), fn.signature)
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

    for index, action in enumerate(actions):
        current = index
        print("\033[2J\033[H", end="")
        print(
            _render_story(
                root,
                nodes,
                fns,
                contracts,
                actions,
                actors,
                current,
                flags.get("links", True),
                meta,
            )
        )
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

        live_send = bool(flags.get("send") or flags.get("auto"))
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

    print("\033[2J\033[H", end="")
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
