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
    "cyan": "\x1b[96m",
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
    if "::" in raw:
        return raw
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
    if kind in {"storage-write", "storage-readwrite"}:
        return "writes shared storage"
    if kind == "storage-read":
        return "reads shared storage"
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
    """Render a terminal-friendly relationship topology rather than a flat edge list."""
    meaningful: list[dict[str, str]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for edge in edges:
        if edge.get("kind") in {
            "import", "storage-write", "storage-read", "storage-readwrite"
        }:
            continue
        source = _web_node_name(str(edge.get("from") or ""))
        destination = _web_node_name(str(edge.get("to") or ""))
        if source == destination:
            continue
        label = _paint(_web_connection_label(edge), "cyan")
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
        for edge in inbound[:5]:
            source = compact(edge["from"])
            out.append(f"       {source:<22} ╲")
            out.append(f"                         ╲─[{edge['label']}]──▶  [{center}]")
            if edge["function"]:
                out.append(f"                              {edge['function']}")

    if outbound:
        out += ["", "  TO / what the hub relies on or controls"]
        for edge in outbound[:5]:
            destination = compact(edge["to"])
            out.append(f"       [{center}]  ──[{edge['label']}]──╲")
            out.append(f"                              ╲──▶  {destination}")
            if edge["function"]:
                out.append(f"                                   {edge['function']}")

    if cross:
        out += ["", "  CROSS-LINKS / the web outside the hub"]
        for edge in cross[:6]:
            out.append(f"       {compact(edge['from']):<22} ╲")
            out.append(f"                         ╰─[{edge['label']}]─▶  {compact(edge['to'])}")
            if edge["function"]:
                out.append(f"                              {edge['function']}")

    actor_paths: dict[tuple[str, str], list[str]] = {}
    for action in actions or []:
        actor = str(action.get("actor_name") or "")
        node = action.get("node")
        fn = action.get("function")
        if not actor or not isinstance(node, LiveNode) or not isinstance(fn, FunctionInfo):
            continue
        target = _web_node_name(node.artifact_contract or node.name)
        actor_paths.setdefault((actor, target), []).append(fn.name)

    if actor_paths:
        out += ["", "  ACTORS / where people enter the web"]
        for (actor, target), fn_names in list(actor_paths.items())[:5]:
            unique = list(dict.fromkeys(fn_names))
            label = ", ".join(f"{name}()" for name in unique[:3])
            if len(unique) > 3:
                label += f", … +{len(unique)-3}"
            out.append(
                f"       {_paint(compact(actor), 'magenta'):<22} "
                f"──[{_paint(label, 'magenta')}]──▶  {compact(target)}"
            )

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
    if any(x in n for x in ("set", "pause", "unpause", "upgrade", "authorize", "ownership", "renounce", "transfer")):
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
    error_name = text.split("(", 1)[0].strip().casefold()

    messages = {
        "staketokennotallowed": (
            "The factory rejected the token because it is not currently approved for staking.",
            "Use the legitimate factory setup/owner flow to approve the token, then retry pool creation.",
        ),
        "stakingclosed": (
            "The pool is not accepting new stakes in its current state.",
            "Check the pool lifecycle and setup/expiry state before treating staking as the next step.",
        ),
        "invalidinitialization": (
            "The contract says its one-time initialization has already been used.",
            "Treat this as deployment/setup state, not the normal user flow; inspect the existing initialized values.",
        ),
        "outcomenotset": (
            "There is no outcome recorded yet, so this action has nothing to settle against.",
            "Find the outcome/flagging step first and then re-check this settlement path.",
        ),
        "outcomenoteligibleforsweep": (
            "The current outcome/state does not make these funds eligible for sweeping.",
            "Inspect the conditions that make an outcome sweepable instead of forcing the call.",
        ),
    }
    if error_name in messages:
        return messages[error_name]

    lowered = text.casefold()
    if lowered.startswith(("executionreverted", "error")):
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
    artifact_files = _load_artifacts(root)[1]
    configured = str(config.get("target") or "").strip()
    configured_static: tuple[str, str] | None = None
    saved_static: list[tuple[str, str]] = []
    live = [
        x for x in (bootstrap.get("live_deployments") or [])
        if isinstance(x, dict) and "dry-run" not in str(x.get("broadcast") or "").lower()
    ]

    def names_match(actual: str, expected: str) -> bool:
        a = re.sub(r"[^a-z0-9]", "", _clean_name(actual).lower())
        b = re.sub(r"[^a-z0-9]", "", _clean_name(expected).lower())
        return bool(a and b and (a == b or a in b or b in a))

    def compatible(address: str, expected: str) -> bool:
        return _runtime_identity(root, rpc, address, expected, artifact_files) != "mismatch"

    if _is_address(configured):
        expected = str(config.get("target_contract") or _target_label(config, configured) or "")
        same = next(
            (
                item for item in live
                if str(item.get("address") or "").lower() == configured.lower()
                and (not expected or names_match(str(item.get("contract") or ""), expected))
            ),
            None,
        )
        if same and (not expected or compatible(configured, expected)):
            ident = _runtime_identity(root, rpc, configured, expected, artifact_files)
            return configured, f"current broadcast target ({ident})"

        if expected:
            for item in live:
                address = str(item.get("address") or "")
                if address and names_match(str(item.get("contract") or ""), expected) and compatible(address, expected):
                    ident = _runtime_identity(root, rpc, address, expected, artifact_files)
                    return address, f"current broadcast deployment ({item.get('contract')}, {ident})"

        code = _code_size(rpc, configured)
        if code > 0 and (not expected or compatible(configured, expected)):
            return configured, "configured target"
        configured_static = (
            configured,
            f"configured target ({'identity mismatch' if code > 0 else 'no live bytecode'})",
        )

    saved_targets = config.get("targets") or {}
    if isinstance(saved_targets, dict):
        for name, value in saved_targets.items():
            if not _is_address(value):
                continue
            if _code_size(rpc, value) > 0:
                saved_static.append((value, f"saved target '{name}'"))
            else:
                saved_static.append((value, f"saved target '{name}' (no live bytecode)"))

    audit_targets = bootstrap.get("audit_targets") or _extract_audit_targets(
        bootstrap.get("audit_evidence") or []
    )
    audit_static: list[tuple[str, str]] = []
    expected = str(config.get("target_contract") or "")
    for item in audit_targets:
        address = item.get("target") if isinstance(item, dict) else None
        if not _is_address(address):
            continue
        file_name = str(item.get("file") or "target")
        source = f"audit evidence '{file_name}'"
        code = _code_size(rpc, address)
        if code > 0 and (
            not live or not expected or compatible(address, expected)
        ):
            return address, source
        if code > 0:
            audit_static.append((address, source + " (identity mismatch)"))
        else:
            audit_static.append((address, source + " (no live bytecode)"))

    if live:
        live.sort(
            key=lambda x: (
                str(x.get("broadcast") or ""),
                int(x.get("index") or 0),
            ),
            reverse=True,
        )
        item = live[0]
        return str(item.get("address")), f"broadcast {item.get('broadcast') or 'deployment'}"

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


def _artifact_runtime_code(path: Path) -> str | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    deployed = payload.get("deployedBytecode")
    value = deployed.get("object") if isinstance(deployed, dict) else deployed
    if not isinstance(value, str) or not value.startswith("0x") or len(value) <= 2:
        return None
    return value.lower()


def _runtime_identity(
    root: Path,
    rpc: str,
    address: str,
    contract: str,
    artifact_files: dict[str, Path] | None = None,
) -> str:
    if not _is_address(address) or not contract:
        return "unknown"
    files = artifact_files or _load_artifacts(root)[1]
    path = files.get(contract) or next(
        (p for name, p in files.items() if name.lower() == contract.lower()),
        None,
    )
    expected = _artifact_runtime_code(path) if path else None
    if expected is None:
        return "unknown"
    try:
        actual = str(_rpc(rpc, "eth_getCode", [address, "latest"]) or "0x").lower()
    except Exception:
        return "unknown"
    if actual == expected:
        return "exact"
    if len(actual) == len(expected) and len(actual) > 100:
        if actual[:74] == expected[:74] and actual[-74:] == expected[-74:]:
            return "weak"
    return "mismatch"


def _identify_runtime_contract(
    root: Path,
    rpc: str,
    address: str,
    artifact_files: dict[str, Path],
) -> str | None:
    matches = [
        name for name in artifact_files
        if _runtime_identity(root, rpc, address, name, artifact_files) == "exact"
    ]
    return sorted(matches)[0] if matches else None


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



def _extract_state_vars(segment: str, base_offset: int, source_text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    depth = 0
    start: int | None = None
    quote: str | None = None
    escape = False
    for i, ch in enumerate(segment):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in {'"', "'"}:
            quote = ch
            continue
        if ch == "{":
            if depth == 0:
                depth = 1
                start = i + 1
            else:
                depth += 1
                if depth == 2:
                    start = None
            continue
        if ch == "}":
            depth = max(0, depth - 1)
            if depth == 0:
                start = None
            elif depth == 1:
                start = i + 1
            continue
        if ch != ";" or depth != 1 or start is None:
            continue
        statement = segment[start:i].strip()
        start = i + 1
        if not statement:
            continue
        if statement.lower().startswith(("function ","event ","error ","modifier ","using ","struct ","enum ","constructor","fallback","receive")):
            continue
        assignment = re.search(r"(?<![<>!=])=(?![=>])", statement)
        declaration = statement[:assignment.start()].strip() if assignment else statement.strip()
        match = re.search(r"\b([A-Za-z_]\w*)\b\s*$", declaration)
        if not match:
            continue
        name = match.group(1)
        prefix = declaration[:match.start()].strip()
        if not prefix:
            continue
        modifiers = re.findall(r"\b(public|private|internal|constant|immutable|override)\b", prefix)
        typ = re.sub(r"\b(public|private|internal|constant|immutable|override)\b", " ", prefix)
        typ = re.sub(r"\s+", " ", typ).strip()
        if not typ:
            continue
        out.append({
            "name": name,
            "type": typ,
            "visibility": next((x for x in modifiers if x in {"public","private","internal"}), "internal"),
            "constant": "constant" in modifiers,
            "immutable": "immutable" in modifiers,
            "line": source_text.count("\n", 0, base_offset + segment.find(statement)) + 1,
        })
    return out


def _analyze_function_source(
    body: str,
    state_vars: list[dict[str, Any]],
    function_names: set[str],
    current_name: str,
) -> tuple[list[str], list[str], list[str], list[dict[str, str]]]:
    reads: list[str] = []
    writes: list[str] = []
    array_ops: list[str] = []
    internal_calls: list[dict[str, str]] = []
    for state in state_vars:
        name = str(state.get("name") or "")
        if not name or not re.search(rf"\b{re.escape(name)}\b", body):
            continue
        reads.append(name)
        if re.search(rf"\b{re.escape(name)}\b(?:\s*\[[^\]]+\])?\s*(?:\+=|-=|\*=|/=|%=|=|\+\+|--)", body) or re.search(rf"\bdelete\s+{re.escape(name)}\b", body):
            writes.append(name)
        if re.search(rf"\b{re.escape(name)}\b[^;{{}}]{{0,160}}\.\s*(push|pop)\s*\(", body):
            writes.append(name)
            match = re.search(rf"\b{re.escape(name)}\b[^;{{}}]{{0,160}}\.\s*(push|pop)\s*\(", body)
            if match:
                array_ops.append(f"{match.group(1)}() on {name}")
        if re.search(rf"\b{re.escape(name)}\b\s*\[[^\]]+\]", body):
            array_ops.append(f"indexed access on {name}")
        if re.search(rf"\b{re.escape(name)}\b[^;{{}}]{{0,160}}\.\s*length\b", body):
            array_ops.append(f"reads {name}.length")
    for name in sorted(function_names):
        if name != current_name and re.search(rf"(?<![\w.]){re.escape(name)}\s*\(", body):
            internal_calls.append({"kind":"internal-call","function":name})
    return sorted(set(reads)), sorted(set(writes)), sorted(set(array_ops)), internal_calls


def _propagate_internal_storage(functions: list[FunctionInfo]) -> None:
    """Propagate storage effects through internal/private call paths.

    Example:
        external deposit() -> private _record() -> balances.write
    is represented as deposit() -> balances.write as well as the explicit
    deposit() -> _record() call edge.
    """
    by_name = {fn.name: fn for fn in functions}
    memo: dict[str, tuple[set[str], set[str], set[str]]] = {}
    visiting: set[str] = set()

    def visit(fn: FunctionInfo) -> tuple[set[str], set[str], set[str]]:
        if fn.name in memo:
            return memo[fn.name]
        if fn.name in visiting:
            return set(fn.reads), set(fn.writes), set(fn.array_ops)
        visiting.add(fn.name)

        reads = set(fn.reads or [])
        writes = set(fn.writes or [])
        array_ops = set(fn.array_ops or [])
        for call in fn.calls or []:
            if call.get("kind") != "internal-call":
                continue
            callee = by_name.get(str(call.get("function") or ""))
            if callee is None:
                continue
            callee_reads, callee_writes, callee_ops = visit(callee)
            reads.update(callee_reads)
            writes.update(callee_writes)
            array_ops.update(callee_ops)

        visiting.discard(fn.name)
        result = (reads, writes, array_ops)
        memo[fn.name] = result
        return result

    for fn in functions:
        reads, writes, array_ops = visit(fn)
        fn.reads = sorted(reads)
        fn.writes = sorted(writes)
        fn.array_ops = sorted(array_ops)


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
            segment = scan_text[block_start:block_end]
            ci.state_vars = _extract_state_vars(segment, block_start, text)
            ci.address_vars = [
                str(item.get("name"))
                for item in ci.state_vars
                if str(item.get("type") or "").strip().startswith("address")
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
                        visibility=next(
                            (x for x in ("external","public","internal","private") if re.search(rf"\b{x}\b", tail)),
                            "unknown",
                        ),
                    )
                )

            function_names = {f.name for f in ci.functions}
            for info in ci.functions:
                reads, writes, array_ops, internal_calls = _analyze_function_source(
                    info.body or "",
                    ci.state_vars or [],
                    function_names,
                    info.name,
                )
                info.reads = reads
                info.writes = writes
                info.array_ops = array_ops
                info.calls.extend(internal_calls)

            _propagate_internal_storage(ci.functions)

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
        source = {f.signature: f for f in (ci.functions if ci else [])}
        functions: list[FunctionInfo] = []
        for item in abi:
            if item.get("type") != "function":
                continue
            sig = _function_signature_from_abi(item)
            src = source.get(sig)
            functions.append(
                FunctionInfo(
                    contract=name,
                    name=str(item.get("name") or ""),
                    inputs=item.get("inputs") or [],
                    outputs=item.get("outputs") or [],
                    mutability=str(item.get("stateMutability") or "nonpayable"),
                    signature=sig,
                    source=src.source if src else None,
                    line=src.line if src else None,
                    body=src.body if src else "",
                    modifiers=list(src.modifiers or []) if src else [],
                    calls=list(src.calls or []) if src else [],
                    visibility=src.visibility if src else "unknown",
                    reads=list(src.reads or []) if src else [],
                    writes=list(src.writes or []) if src else [],
                    array_ops=list(src.array_ops or []) if src else [],
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



def _local_signer_addresses(rpc: str) -> list[str]:
    """Return JSON-RPC accounts that the local node can actually sign for."""
    return [addr.lower() for addr in _eth_accounts(rpc)]


def _sender_available_for_local_send(rpc: str, caller: str) -> bool:
    if not _is_local_rpc(rpc) or not _is_address(caller):
        return False
    return caller.lower() in set(_local_signer_addresses(rpc))

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
        if artifact_contract and size > 0:
            if _runtime_identity(root, rpc, address, artifact_contract, artifact_files) == "mismatch":
                identified = _identify_runtime_contract(root, rpc, address, artifact_files)
                if identified:
                    artifact_contract = identified
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
    if "implementation" in n:
        for candidate in nodes:
            cname = (candidate.artifact_contract or candidate.name).lower()
            if "pool" in cname and "factory" not in cname and candidate.code_size > 0:
                return candidate.address
        return known.get("poolimplementation") or known.get("implementation")
    if "moderator" in n:
        for candidate in nodes:
            cname = (candidate.artifact_contract or candidate.name).lower()
            if "moderator" in cname and candidate.code_size > 0:
                return candidate.address
        return known.get("moderator")
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
    include_trace: bool = False,
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
    # cast call stdout is return data on success. Revert decoding must only
    # inspect failed calls, otherwise values such as 0x00000000 get mistaken
    # for a four-byte custom-error selector.
    blob = _parse_revert_blob(combined) if code != 0 else None
    decoded = _decode_error(blob, all_errors) if code != 0 else None
    trace = None
    trace_revert_frames: list[str] = []
    if include_trace or (code != 0 and not decoded and (not blob or blob == "0x")):
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


def _extract_guard_signals(fn: FunctionInfo) -> list[str]:
    body = fn.body or ""
    signals: list[str] = []
    for match in re.finditer(r"\brequire\s*\((.{1,300})\)", body, flags=re.S):
        expr = " ".join(match.group(1).split())
        if expr:
            signals.append(f"require({expr})")
    for match in re.finditer(r"\bif\s*\((.{1,260})\)\s*\{(.{0,700})?\b(?:revert|return)\b", body, flags=re.S):
        expr = " ".join(match.group(1).split())
        if expr:
            signals.append(f"if({expr})")
    for match in re.finditer(r"\brevert\s+([A-Za-z_]\w*)\s*\(", body):
        signals.append(f"revert {match.group(1)}()")
    return list(dict.fromkeys(signals))


def _state_transition_candidates(
    fn: FunctionInfo,
    functions_by_contract: dict[str, list[FunctionInfo]],
) -> list[tuple[str, str]]:
    gate_states = [
        state for state in (fn.reads or [])
        if any(
            token in state.lower()
            for token in (
                "state", "status", "phase", "stage", "active", "open",
                "closed", "paused", "outcome", "expiry", "deadline",
                "end", "until", "final",
            )
        )
    ]
    transitions: list[tuple[str, str]] = []
    for state in gate_states:
        writers = [
            candidate.name
            for candidate in functions_by_contract.get(fn.contract, [])
            if candidate.name != fn.name and state in (candidate.writes or [])
        ]
        for writer in writers[:5]:
            item = (state, writer)
            if item not in transitions:
                transitions.append(item)
    return transitions


def _focus_node(
    meta: dict[str, Any],
    nodes: list[LiveNode],
    contracts: dict[str, ContractInfo],
) -> LiveNode | None:
    target = str(meta.get("target") or "")
    live_nodes = [node for node in nodes if node.code_size > 0]
    exact = next(
        (node for node in live_nodes if node.address.lower() == target.lower()),
        None,
    )
    if exact and (exact.artifact_contract or exact.name) in contracts:
        return exact

    expected = str(meta.get("target_contract") or "")
    if expected:
        match = next(
            (
                node for node in live_nodes
                if (node.artifact_contract or node.name).lower() == expected.lower()
                and (node.artifact_contract or node.name) in contracts
            ),
            None,
        )
        if match:
            return match

    pool = next(
        (
            node for node in live_nodes
            if "pool" in (node.artifact_contract or node.name).lower()
            and "factory" not in (node.artifact_contract or node.name).lower()
            and (node.artifact_contract or node.name) in contracts
        ),
        None,
    )
    return pool or exact


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

    for guard in _extract_guard_signals(fn)[:5]:
        relevant = [
            state for state in (fn.reads or [])
            if re.search(rf"\b{re.escape(state)}\b", guard)
        ]
        if relevant:
            findings.append(
                f"source gate reads {', '.join(relevant[:3])}: {guard[:220]}"
            )

    for state, writer in _state_transition_candidates(fn, functions_by_contract)[:4]:
        findings.append(
            f"state transition path: {writer}() writes {state}, which {fn.name}() reads"
        )

    return findings



def _is_token_utility_function(fn: FunctionInfo, functions: list[FunctionInfo]) -> bool:
    """Return true for standard asset-management helpers on detected ERC20-like components."""
    if not _looks_like_erc20(functions):
        return False
    return fn.name.lower() in {
        "approve",
        "increaseallowance",
        "decreaseallowance",
        "transfer",
        "transferfrom",
        "mint",
        "burn",
        "permit",
    }


def _is_protocol_entrypoint(fn: FunctionInfo, node: LiveNode, functions: list[FunctionInfo]) -> bool:
    """Prefer protocol behavior over generic asset plumbing in the walkthrough."""
    if _is_token_utility_function(fn, functions):
        return False
    purpose = _contract_purpose(node.artifact_contract or node.name, functions)
    if purpose in {
        "asset used by the protocol for value/staking",
    }:
        return False
    return fn.visibility in {"external", "public"} and fn.mutability not in {"view", "pure"}

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
    if n in {
        "approve", "increaseallowance", "decreaseallowance",
        "transfer", "transferfrom", "mint", "burn", "permit",
    }:
        score -= 45
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

    # Static source/import edges and function-to-contract relationships.
    for cname, ci in contracts.items():
        for imp in ci.imports:
            edges.append({
                "from": cname,
                "to": imp,
                "kind": "import",
            })

        functions = functions_by_contract.get(cname, [])
        function_names = {f.name for f in functions}
        for fn in functions:
            # Shared storage is represented as a real graph node. Every function
            # that reads/writes a state variable points at the same state node.
            for state in fn.writes or []:
                edges.append({
                    "from": f"{cname}.{fn.name}()",
                    "to": f"{cname}::{state}",
                    "kind": "storage-write",
                    "function": f"{fn.name}() -> {state}",
                })
            for state in fn.reads or []:
                if state in (fn.writes or []):
                    edges.append({
                        "from": f"{cname}.{fn.name}()",
                        "to": f"{cname}::{state}",
                        "kind": "storage-readwrite",
                        "function": f"{fn.name}() <-> {state}",
                    })
                else:
                    edges.append({
                        "from": f"{cname}.{fn.name}()",
                        "to": f"{cname}::{state}",
                        "kind": "storage-read",
                        "function": f"{fn.name}() -> {state}",
                    })

            for call in fn.calls or []:
                if call["kind"] == "typed-call":
                    edges.append({
                        "from": cname,
                        "to": call["interface"],
                        "kind": "external-call",
                        "function": f"{fn.name} -> {call['function']}",
                    })
                elif call["kind"] == "internal-call":
                    callee = str(call.get("function") or "")
                    if callee in function_names:
                        edges.append({
                            "from": f"{cname}.{fn.name}()",
                            "to": f"{cname}.{callee}()",
                            "kind": "internal-call",
                            "function": f"{fn.name} -> {callee}",
                        })
                else:
                    receiver = str(call.get("receiver") or "")
                    state_or_input = set(ci.address_vars)
                    state_or_input.update(
                        str(p.get("name") or "")
                        for p in fn.inputs
                        if isinstance(p, dict)
                    )
                    if receiver in state_or_input:
                        edges.append({
                            "from": cname,
                            "to": receiver,
                            "kind": "member-call",
                            "function": f"{fn.name} -> {call['function']}",
                        })

    # Runtime getter edges connect actual deployed components.
    for node in nodes:
        for other in nodes:
            if node.address.lower() == other.address.lower():
                continue
            if (
                other.discovered_from
                and other.discovered_from.lower() == node.address.lower()
            ):
                edges.append({
                    "from": node.artifact_contract or node.name,
                    "to": other.artifact_contract or other.name,
                    "kind": f"runtime:{other.getter or 'address-returning getter'}",
                })
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

def _deployment_contract_label(
    bootstrap: dict[str, Any] | None,
    target: str | None,
) -> str | None:
    if not _is_address(target):
        return None
    for item in (bootstrap or {}).get("live_deployments") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("address") or "").lower() == target.lower():
            contract = str(item.get("contract") or "").strip()
            if contract:
                return contract
    return None


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



def _function_access_label(fn: FunctionInfo, functions: list[FunctionInfo]) -> str:
    modifiers = [str(x) for x in fn.modifiers or []]
    gate = next((x for x in modifiers if x.lower() == "onlyowner"), None)
    gate = gate or next((x for x in modifiers if x.lower().startswith("onlyrole")), None)
    if fn.visibility in {"external", "public"}:
        if gate:
            return f"{gate} only"
        body = fn.body or ""
        msg_sender = re.findall(
            r"msg\.sender\s*==\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*==\s*msg\.sender",
            body,
        )
        refs = [a or b for a, b in msg_sender if a or b]
        if refs:
            return f"only the address stored in {refs[0]}"
        if "msg.sender" in body and any(
            token in body.lower()
            for token in ("require(", "revert ", "only", "authorized", "notauthorized")
        ):
            return "externally callable but source-gated"
        return "any external caller"
    callers = sorted({
        candidate.name
        for candidate in functions
        if any(
            call.get("kind") == "internal-call"
            and str(call.get("function")) == fn.name
            for call in candidate.calls or []
        )
    })
    return f"{fn.visibility} only; reached from {', '.join(callers[:5]) if callers else 'no caller proven by source scan'}"


def _format_state_value(value: Any) -> str:
    if isinstance(value, bool):
        return "ON / true" if value else "OFF / false"
    if isinstance(value, list):
        values = [_short_address(x) if _is_address(x) else str(x) for x in value[:4]]
        suffix = f", … +{len(value)-4}" if len(value) > 4 else ""
        return "[" + ", ".join(values) + suffix + "]"
    return _short_address(value) if _is_address(value) else str(value)


def _render_live_state(values: dict[str, Any]) -> list[str]:
    lines = [_section("LIVE STATE / WHAT THE CHAIN CURRENTLY SAYS", "blue")]
    if not values:
        lines.append("  No simple zero-argument state getters recovered.")
        return lines
    ranked = sorted(
        values.items(),
        key=lambda item: (
            0 if any(
                token in item[0].lower()
                for token in (
                    "owner","admin","moderator","state","status","paused",
                    "allowed","active","expiry","deadline","stake","balance","count"
                )
            ) else 1,
            item[0],
        ),
    )
    for name, value in ranked[:8]:
        lines.append(f"  {_paint(name, 'blue')} = {_format_state_value(value)}")
    lines.append("  " + _paint("read-only observation; not an inferred value", "dim"))
    return lines


def _render_contract_surface(contract: ContractInfo, functions: list[FunctionInfo]) -> list[str]:
    lines = [_section("STORAGE / WHAT THIS CONTRACT REMEMBERS", "blue")]
    states = contract.state_vars or []
    if not states:
        lines.append("  No source-level storage declarations recovered.")
    for state in states[:8]:
        name = str(state.get("name") or "?")
        typ = str(state.get("type") or "unknown")
        kind = "MAPPING" if typ.lower().startswith("mapping") else "ARRAY" if "[" in typ else "VALUE"
        writers = [fn for fn in functions if name in (fn.writes or [])]
        readers = [fn for fn in functions if name in (fn.reads or []) and fn not in writers]
        lines.append(
            f"  {_paint(kind, 'blue')}  {_paint(name, 'blue')} : {typ} "
            f"({state.get('visibility','internal')})"
        )
        if writers:
            writer_bits = [
                f"{fn.name} [{_function_access_label(fn, functions)}]"
                for fn in writers[:4]
            ]
            lines.append(f"      {_paint('WRITES', 'red')}  " + ", ".join(writer_bits))
        else:
            lines.append(f"      {_paint('WRITES', 'dim')}  no source writer found")
        if readers:
            lines.append(f"      {_paint('READS', 'cyan')}   " + ", ".join(fn.name for fn in readers[:4]))
        ops = []
        for fn in functions:
            if name not in (fn.reads or []) and name not in (fn.writes or []):
                continue
            for op in fn.array_ops or []:
                if re.search(rf"\bon\s+{re.escape(name)}\b", op):
                    ops.append(op)
        if ops:
            lines.append(
                f"      {_paint('DATA FLOW', 'blue')} "
                + ", ".join(sorted(set(ops))[:4])
            )

    lines.append("")
    lines.append(_section("ACCESS / WHO CAN DO WHAT", "magenta"))
    entries = [
        fn for fn in functions
        if fn.visibility in {"external", "public"}
        and (
            fn.writes
            or fn.calls
            or fn.modifiers
            or fn.mutability not in {"view", "pure"}
        )
    ]
    entries.sort(key=lambda fn: (-len(fn.writes), -len(fn.calls), fn.name))
    for fn in entries[:8]:
        lines.append(f"  {_paint(fn.visibility.upper(), 'magenta'):<10} {fn.name}()")
        lines.append(f"      WHO    {_function_access_label(fn, functions)}")
        touched = []
        if fn.writes:
            touched.append("writes " + ", ".join(fn.writes[:4]))
        if fn.calls:
            touched.append("calls " + ", ".join(str(call.get('function')) for call in fn.calls[:4]))
        lines.append(f"      DOES   {'; '.join(touched) if touched else 'changes protocol state'}")

    internal = [
        fn for fn in functions
        if fn.visibility in {"private", "internal"} and (fn.writes or fn.calls)
    ]
    if internal:
        lines.append("")
        lines.append(_section("INTERNAL / PRIVATE LOGIC", "yellow"))
        for fn in sorted(internal, key=lambda f: (-len(f.writes), -len(f.calls), f.name))[:6]:
            lines.append(f"  {_paint(fn.visibility.upper(), 'yellow'):<10} {fn.name}()")
            lines.append(f"      REACHED {_function_access_label(fn, functions)}")
            if fn.writes:
                lines.append(f"      TOUCH   {', '.join(fn.writes[:5])}")
            if fn.calls:
                lines.append(f"      CALLS   {', '.join(str(call.get('function')) for call in fn.calls[:5])}")
    return lines


def _render_shared_state_flow(
    functions_by_contract: dict[str, list[FunctionInfo]],
    contracts: dict[str, ContractInfo],
    nodes: list[LiveNode] | None = None,
) -> list[str]:
    lines = [_section("SHARED STATE FLOW / FUNCTIONS ↔ STORAGE", "blue")]
    emitted = 0

    live_contracts = {
        node.artifact_contract or node.name
        for node in (nodes or [])
        if node.code_size > 0
    }
    for cname, contract in contracts.items():
        if nodes is not None and cname not in live_contracts:
            continue
        functions = functions_by_contract.get(cname, [])
        states = contract.state_vars or []
        for state in states:
            name = str(state.get("name") or "")
            if not name:
                continue
            readers = [
                fn for fn in functions
                if name in (fn.reads or [])
            ]
            writers = [
                fn for fn in functions
                if name in (fn.writes or [])
            ]
            if not readers and not writers:
                continue

            kind = (
                "MAPPING" if str(state.get("type") or "").lower().startswith("mapping")
                else "ARRAY" if "[" in str(state.get("type") or "")
                else "STATE"
            )
            label = f"{cname}::{name}"
            lines.append(
                f"  {_paint(kind, 'blue')} {_paint(label, 'blue')} "
                f": {state.get('type') or 'unknown'}"
            )

            touched = []
            seen_functions: set[str] = set()
            for fn in writers:
                marker_label = "WRITE"
                touched.append((fn, marker_label))
                seen_functions.add(fn.signature)
            for fn in readers:
                if fn.signature in seen_functions:
                    continue
                touched.append((fn, "READ"))

            for fn, mode in touched[:8]:
                access = _function_access_label(fn, functions)
                lines.append(
                    f"      {_paint(fn.name + '()', 'bold')} "
                    f"──[{_paint(mode, 'red' if mode == 'WRITE' else 'cyan')}]──▶ "
                    f"{_paint(label, 'blue')}"
                    f"   {access}"
                )
            if len(touched) > 1:
                lines.append(
                    f"      {_paint('SHARED', 'blue')} "
                    f"{len(touched)} function path(s) converge on this same storage"
                )
            if len(touched) > 8:
                lines.append(f"      … +{len(touched)-8} function/storage edge(s)")
            emitted += 1

    if not emitted:
        lines.append("  No shared source-level storage relationships recovered.")
    return lines


def _render_component_surfaces(
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    contracts: dict[str, ContractInfo],
) -> list[str]:
    lines = [_section("COMPONENT SURFACES / WHO TOUCHES WHAT", "cyan")]
    shown = 0
    for node in nodes:
        if node.code_size <= 0:
            continue
        cname = node.artifact_contract or node.name
        contract = contracts.get(cname)
        funcs = functions_by_contract.get(cname, [])
        if not contract:
            continue

        mutating = [
            fn for fn in funcs
            if fn.visibility in {"external", "public"}
            and fn.mutability not in {"view", "pure"}
        ]
        mutating.sort(
            key=lambda fn: (
                -_walkthrough_phase_priority(fn)[0],
                -len(fn.writes),
                fn.name,
            )
        )
        states = contract.state_vars or []
        important_states = [
            str(item.get("name") or "?")
            for item in states
            if str(item.get("name") or "")
        ]

        lines.append(
            f"  {_paint(cname, 'bold')}  "
            f"{_contract_purpose(cname, funcs)}"
        )
        if important_states:
            lines.append(
                f"      {_paint('STATE', 'blue')} "
                + ", ".join(important_states[:5])
                + (f", … +{len(important_states)-5}" if len(important_states) > 5 else "")
            )
        if mutating:
            entries = []
            for fn in mutating[:5]:
                writes = (
                    f" → WRITE:{', '.join(fn.writes[:2])}"
                    if fn.writes else
                    f" → READ:{', '.join(fn.reads[:2])}"
                    if fn.reads else ""
                )
                call_chain = ""
                internal = [
                    str(call.get("function") or "")
                    for call in fn.calls or []
                    if call.get("kind") == "internal-call"
                ]
                if internal:
                    call_chain = f"  ⤷ {', '.join(dict.fromkeys(internal[:2]))}"
                entries.append(
                    f"{fn.name} [{_function_access_label(fn, funcs)}]{writes}{call_chain}"
                )
            lines.append(f"      {_paint('ENTRY', 'magenta')} " + "; ".join(entries))
        else:
            readables = [
                fn.name for fn in funcs
                if fn.visibility in {"external", "public"}
                and fn.mutability in {"view", "pure"}
            ]
            if readables:
                lines.append(
                    f"      {_paint('READ', 'cyan')} " + ", ".join(readables[:5])
                )
        shown += 1
        if shown >= 8:
            break
    if shown == 0:
        lines.append("  No source-backed live component surfaces were recovered.")
    return lines


def _render_lifecycle_summary(
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
) -> list[str]:
    phase_items: dict[str, list[str]] = {}
    for node in nodes:
        if node.code_size <= 0:
            continue
        cname = node.artifact_contract or node.name
        for fn in functions_by_contract.get(cname, []):
            if fn.mutability in {"view", "pure"} or fn.visibility not in {"external", "public"}:
                continue
            phase = _action_phase(fn)
            if phase in {"SETUP", "ADMIN"}:
                continue
            phase_items.setdefault(phase, []).append(f"{cname}.{fn.name}()")

    order = ["CREATE", "PARTICIPATE", "OUTCOME", "SETTLE", "INTERACTION"]
    lines = [_section("PROTOCOL FLOW / STATIC LIFECYCLE MAP", "yellow")]
    emitted = 0
    for phase in order:
        items = phase_items.get(phase) or []
        if not items:
            continue
        lines.append(
            f"  {phase:<11} "
            + " → ".join(items[:4])
            + (f" → … +{len(items)-4}" if len(items) > 4 else "")
        )
        emitted += 1
    if not emitted:
        lines.append("  No lifecycle-changing entry points recovered.")
    return lines


def _render_state_diagnosis(actions: list[dict[str, Any]]) -> list[str]:
    blocked = [action for action in actions if str(action.get("status")) == "BLOCKED"]
    if not blocked:
        return []
    counts: dict[str, int] = {}
    recommendations: dict[str, str] = {}
    for action in blocked:
        result = action.get("result") or {}
        msg, rec = _friendly_error(
            result.get("decoded_error"),
            result.get("raw", ""),
        )
        counts[msg] = counts.get(msg, 0) + 1
        recommendations[msg] = rec
    lines = [_section("WHY ACTIONS ARE BLOCKED", "red")]
    for msg, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:5]:
        suffix = f" ×{count}" if count > 1 else ""
        lines.append(f"  {_status_icon('BLOCKED')} {msg}{suffix}")
        lines.append(f"      {_paint('NEXT', 'yellow')} {recommendations[msg]}")
    return lines


def _render_action_card(
    root: Path,
    action: dict[str, Any],
    index: int,
    total: int,
    links: bool,
) -> str:
    node: LiveNode = action["node"]
    fn: FunctionInfo = action["function"]
    status = _step_status_word(action)
    label = f"{node.artifact_contract or node.name}.{fn.name}"
    if links and fn.source and fn.line:
        label = _source_link(root, fn.source, fn.line, label)
    status_color = (
        "green" if status == "DONE"
        else "cyan" if status == "READY"
        else "red" if status in {"BLOCKED","FAILED"}
        else "yellow"
    )
    lines = [
        f"{_section(f'STEP {index+1:02d} / {total:02d}', 'cyan')} "
        f"{_status_icon(status)} {_paint(status, status_color)}",
        f"  {_paint(str(action.get('phase','STEP')), 'yellow')}  "
        f"{_paint(str(action.get('actor_name') or 'Unknown'), 'magenta')} → {label}",
        f"  WHAT   {action.get('what') or _action_what(fn, node)}",
        f"  WHY    {action.get('why') or _action_why(fn, node)}",
    ]
    if fn.writes or fn.reads:
        write_bits = [
            f"{fn.contract}::{name}"
            for name in fn.writes
        ]
        read_bits = [
            f"{fn.contract}::{name}"
            for name in fn.reads
            if name not in (fn.writes or [])
        ]
        if write_bits:
            lines.append(
                f"  STORAGE {_paint('WRITE', 'red')} → "
                + ", ".join(write_bits[:5])
            )
        if read_bits:
            lines.append(
                f"  STORAGE {_paint('READ', 'blue')}  → "
                + ", ".join(read_bits[:5])
            )
    internal = [
        str(call.get("function") or "")
        for call in fn.calls or []
        if call.get("kind") == "internal-call"
    ]
    if internal:
        lines.append(
            f"  INTERNAL {_paint('→', 'yellow')} "
            + ", ".join(dict.fromkeys(internal[:5]))
        )

    result = action.get("result") or {}
    if result.get("ok"):
        lines.append(f"  RESULT {_status_icon('PASS')} chain accepted this simulation.")
    elif result:
        msg, rec = _friendly_error(result.get("decoded_error"), result.get("raw",""))
        lines.append(f"  RESULT {_status_icon('BLOCKED')} {msg}")
        lines.append(f"  NEXT   {_paint(rec, 'yellow')}")
        for item in action.get("diagnosis", [])[:4]:
            lines.append(f"         evidence: {item}")
    return "\n".join(lines)



def _trace_transaction(
    root: Path,
    rpc: str,
    tx_hash: str,
) -> dict[str, Any] | None:
    """Best-effort EVM call-tree trace for an already-mined transaction."""
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}", str(tx_hash or "")):
        return None
    try:
        payload = _rpc(
            rpc,
            "debug_traceTransaction",
            [tx_hash, {"tracer": "callTracer"}],
        )
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _send_transaction_hash(send: dict[str, Any]) -> str | None:
    text = "\n".join(
        str(send.get(key) or "")
        for key in ("stdout", "stderr")
    )
    match = re.search(
        r"(?im)^\s*(?:transactionHash|transaction\s+hash)\s*[: ]\s*(0x[0-9a-fA-F]{64})\b",
        text,
    )
    if match:
        return match.group(1)
    matches = re.findall(r"\b0x[0-9a-fA-F]{64}\b", text)
    return matches[0] if matches else None


def _trace_contract_label(
    address: str,
    nodes: list[LiveNode],
) -> str:
    for node in nodes:
        if node.address.lower() == str(address or "").lower():
            return node.artifact_contract or node.name
    return _short_address(address)


def _trace_function_label(
    frame: dict[str, Any],
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    root_node: LiveNode,
    root_fn: FunctionInfo,
    *,
    is_root: bool = False,
) -> str:
    if is_root:
        return f"{root_node.artifact_contract or root_node.name}.{root_fn.name}()"

    to = str(frame.get("to") or "")
    contract_name = _trace_contract_label(to, nodes)
    data = str(frame.get("input") or "")
    selector = data[:10].lower() if data.startswith("0x") and len(data) >= 10 else ""
    if selector:
        funcs = functions_by_contract.get(contract_name, [])
        for candidate in funcs:
            if _keccak_selector(candidate.signature).lower() == selector:
                return f"{contract_name}.{candidate.name}()"
    if data.startswith("0x") and len(data) >= 10:
        return f"{contract_name}.<selector {selector}>"
    return contract_name


def _flatten_call_trace(
    trace: Any,
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    root_node: LiveNode,
    root_fn: FunctionInfo,
    *,
    max_depth: int = 4,
    max_frames: int = 20,
) -> list[tuple[int, str, str | None, str | None, str]]:
    rows: list[tuple[int, str, str | None, str | None, str]] = []

    def visit(frame: Any, depth: int, is_root: bool = False) -> None:
        if len(rows) >= max_frames or not isinstance(frame, dict) or depth > max_depth:
            return
        label = _trace_function_label(
            frame,
            nodes,
            functions_by_contract,
            root_node,
            root_fn,
            is_root=is_root,
        )
        kind = str(frame.get("type") or "CALL").upper()
        to = str(frame.get("to") or "")
        error = frame.get("error") or frame.get("revertReason")
        rows.append((depth, kind, label, error, to))
        for child in frame.get("calls") or []:
            visit(child, depth + 1)
            if len(rows) >= max_frames:
                break

    visit(trace, 0, True)
    return rows


def _storage_effect_label(
    fn: FunctionInfo,
    state_name: str,
    contracts: dict[str, ContractInfo],
    actor_name: str,
    args: list[Any],
) -> str:
    contract = contracts.get(fn.contract)
    state = next(
        (
            item for item in (contract.state_vars or [])
            if str(item.get("name") or "") == state_name
        ),
        None,
    ) if contract else None

    raw_type = str((state or {}).get("type") or "")
    target = f"{fn.contract}::{state_name}"

    if raw_type.lower().startswith("mapping"):
        body = fn.body or ""
        if re.search(rf"\b{re.escape(state_name)}\s*\[\s*msg\.sender\s*\]", body):
            return f"{target}[{actor_name}]"
        for index, param in enumerate(fn.inputs):
            pname = str(param.get("name") or "")
            if not pname or index >= len(args):
                continue
            if re.search(rf"\b{re.escape(state_name)}\s*\[\s*{re.escape(pname)}\s*\]", body):
                return f"{target}[{_render_value(args[index])}]"
    return target


def _other_storage_paths(
    fn: FunctionInfo,
    state_name: str,
    functions: list[FunctionInfo],
) -> list[str]:
    peers = [
        candidate.name
        for candidate in functions
        if candidate.name != fn.name
        and (
            state_name in (candidate.reads or [])
            or state_name in (candidate.writes or [])
        )
    ]
    return list(dict.fromkeys(peers))[:5]


def _render_execution_trace(
    root: Path,
    action: dict[str, Any],
    nodes: list[LiveNode],
    functions_by_contract: dict[str, list[FunctionInfo]],
    contracts: dict[str, ContractInfo],
    *,
    links: bool = True,
) -> list[str]:
    node: LiveNode = action["node"]
    fn: FunctionInfo = action["function"]
    actor = str(action.get("actor_name") or "Unknown")
    status = str(action.get("status") or "READY").upper()
    label = f"{node.artifact_contract or node.name}.{fn.name}"
    if links and fn.source and fn.line:
        label = _source_link(root, fn.source, fn.line, label)

    lines = [
        _section(
            f"EXECUTION / {action.get('phase', 'STEP')}",
            "cyan",
        ),
        f"  {_paint(actor, 'magenta')} → {_paint(label, 'bold')}",
        f"  ARGS   {_render_value(action.get('args') or [])}",
        f"  STATUS {_paint(status, 'green' if status == 'SUCCESS' else 'yellow' if status in {'READY', 'RUNNING'} else 'red')}",
    ]

    result = action.get("result") or {}
    trace = result.get("trace")
    rows = _flatten_call_trace(
        trace,
        nodes,
        functions_by_contract,
        node,
        fn,
    ) if trace else []

    if rows:
        lines.append(f"  {_paint('EVM CALL TREE / OBSERVED', 'cyan')}")
        for depth, kind, call_label, error, _ in rows:
            prefix = "      " + ("│  " * max(0, depth - 1))
            branch = "└─ " if depth else ""
            detail = f"{prefix}{branch}{kind}  {call_label}"
            if error:
                detail += f"  {_paint(str(error), 'red')}"
            lines.append(detail)
    else:
        lines.append("  EVM CALL TREE / no runtime trace available")

    lines.append(f"  {_paint('INTERNAL PATH / SOURCE-CORRELATED', 'yellow')}")
    internal = [
        str(call.get("function") or "")
        for call in fn.calls or []
        if call.get("kind") == "internal-call"
    ]
    if internal:
        unique = list(dict.fromkeys(x for x in internal if x))
        chain = f"{fn.name}() → " + " → ".join(f"{name}()" for name in unique[:6])
        lines.append(f"      {chain}")
    else:
        lines.append("      no internal/private helper call proven for this entry point")

    touched = list(dict.fromkeys((fn.writes or []) + (fn.reads or [])))
    if touched:
        lines.append(f"  {_paint('SHARED STATE / THIS EXECUTION', 'blue')}")
        write_set = set(fn.writes or [])
        for state_name in touched[:10]:
            mode = "WRITE" if state_name in write_set else "READ"
            effect = _storage_effect_label(
                fn,
                state_name,
                contracts,
                actor,
                list(action.get("args") or []),
            )
            color = "red" if mode == "WRITE" else "cyan"
            lines.append(
                f"      {fn.name}() ──[{_paint(mode, color)}]──▶ "
                f"{_paint(effect, 'blue')}"
            )
            peers = _other_storage_paths(fn, state_name, functions_by_contract.get(fn.contract, []))
            if peers:
                lines.append(
                    f"          ↳ same storage is also touched by: "
                    + ", ".join(f"{name}()" for name in peers)
                )

    if result.get("decoded_error"):
        msg, rec = _friendly_error(result.get("decoded_error"), result.get("raw", ""))
        lines.append(f"  RESULT {_status_icon('BLOCKED')} {msg}")
        lines.append(f"  NEXT   {_paint(rec, 'yellow')}")
    elif result.get("ok"):
        lines.append(
            f"  RESULT {_status_icon('PASS')} "
            "transaction/call completed successfully."
        )

    tx_hash = str(action.get("send", {}).get("transaction_hash") or "")
    if tx_hash:
        lines.append(f"  TX     {tx_hash}")

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
    live: bool = False,
) -> str:
    meta = meta if isinstance(meta, dict) else {}
    live_nodes = [n for n in nodes if n.code_size > 0]
    target = str(meta.get("target") or "")
    target_node = next(
        (n for n in live_nodes if n.address.lower() == target.lower()),
        None,
    )
    focus = _focus_node(meta, nodes, contracts)
    target_name = (
        focus.artifact_contract or focus.name
        if focus else
        (target_node.artifact_contract or target_node.name if target_node else "Not resolved")
    )

    lines = [
        _paint("╭────────────────────────────────────────────────────────────╮", "cyan"),
        _paint("│ LOWKEY  /  PROTOCOL WALKTHROUGH                            │", "bold"),
        _paint("╰────────────────────────────────────────────────────────────╯", "cyan"),
        f"  Environment  Local RPC • {len(live_nodes)} live contract(s) • {len(_canonical_actor_names(actors))} actor(s)",
        f"  Focus target {target_name} • {_short_address(target) if target else 'no target'}",
    ]

    source = str(meta.get("target_source") or "")
    if "mismatch" in source:
        lines.append(f"  Identity     {_paint('✗ stale/mismatched target evidence', 'red')}")
    elif "exact" in source:
        lines.append(f"  Identity     {_paint('✓ bytecode matches local artifact', 'green')}")
    elif "current broadcast" in source:
        lines.append(f"  Identity     {_paint('✓ current local deployment', 'green')}")
    else:
        lines.append(f"  Identity     {_paint('• identity not fully proven', 'yellow')}")

    boot = meta.get("auto_bootstrap") or {}
    if boot:
        ok = boot.get("status") == "success"
        lines.append(
            f"  Bootstrap    {_paint('✓ local setup ready' if ok else '! setup incomplete', 'green' if ok else 'yellow')}"
            f"  {boot.get('reason','')}"
        )

    names = _canonical_actor_names(actors)
    if names:
        lines.append(f"  Actors       {_paint(' / '.join(names), 'magenta')}")

    if live:
        if actions and current is not None and 0 <= current < len(actions):
            lines += [""] + _render_execution_trace(
                root,
                actions[current],
                nodes,
                functions_by_contract,
                contracts,
                links=links,
            )
        elif actions:
            lines += ["", _section("EXECUTION", "cyan")]
            lines.append("  No current execution step selected.")
        else:
            lines += ["", _section("EXECUTION", "cyan")]
            lines.append("  No executable transition selected from the current state.")
        lines += [
            "",
            _paint("BLUE","blue") + " storage  " +
            _paint("CYAN","cyan") + " runtime call tree  " +
            _paint("GREEN","green") + " success  " +
            _paint("RED","red") + " revert/blocked  " +
            _paint("YELLOW","yellow") + " source-correlated internal path" +
            "  |  " +
            _paint("MAGENTA","magenta") + " actors",
        ]
        return "\n".join(lines)

    lines += ["", _section("SYSTEM CONNECTION WEB", "cyan")]
    lines += _render_connection_web(
        nodes,
        _system_edges(nodes, functions_by_contract, contracts),
        actions,
    )
    lines += [""] + _render_shared_state_flow(
        functions_by_contract, contracts, nodes
    )
    lines += [""] + _render_lifecycle_summary(functions_by_contract, nodes)
    lines += [""] + _render_component_surfaces(nodes, functions_by_contract, contracts)

    if focus:
        cname = focus.artifact_contract or focus.name
        contract = contracts.get(cname)
        funcs = functions_by_contract.get(cname, [])
        if contract:
            lines += ["", _paint(f"FOCUS CONTRACT / {cname}", "bold")]
            lines.append(f"  {_contract_purpose(cname, funcs)}")
            lines.append("")
            lines += _render_live_state(
                (meta.get("runtime_getters") or {}).get(focus.address.lower(), {})
            )
            lines.append("")
            lines += _render_contract_surface(contract, funcs)

    if actions:
        diagnosis = _render_state_diagnosis(actions)
        if diagnosis:
            lines += [""] + diagnosis
        lines += ["", _section("CURRENT WALKTHROUGH STEP", "cyan")]
        if current is not None and 0 <= current < len(actions):
            lines.append(_render_action_card(root, actions[current], current, len(actions), links))
            if current + 1 < len(actions):
                nxt = actions[current + 1]
                lines.append(
                    f"  {_paint('NEXT','yellow')} {current+2:02d}/{len(actions):02d} "
                    f"{nxt.get('phase','STEP')} → "
                    f"{nxt['node'].artifact_contract or nxt['node'].name}.{nxt['function'].name}"
                )
        else:
            done = sum(_step_status_word(a) == "DONE" for a in actions)
            ready = sum(_step_status_word(a) == "READY" for a in actions)
            blocked = sum(_step_status_word(a) == "BLOCKED" for a in actions)
            failed = sum(_step_status_word(a) == "FAILED" for a in actions)
            lines.append(f"  {len(actions)} candidate(s) examined")
            lines.append(
                f"  {_paint('✓','green')} done {done}  "
                f"{_paint('→','cyan')} ready {ready}  "
                f"{_paint('✗','red')} blocked {blocked}  "
                f"{_paint('!','yellow')} send-failed {failed}"
            )
    else:
        lines += ["", _section("CURRENT WALKTHROUGH STEP", "cyan")]
        lines.append("  No coherent state-changing action was found from the current state.")

    lines += [
        "",
        _paint("BLUE","blue") + " storage  " +
        _paint("CYAN","cyan") + " connections  " +
        _paint("GREEN","green") + " success  " +
        _paint("RED","red") + " blocked  " +
        _paint("YELLOW","yellow") + " next/warning  " +
        _paint("MAGENTA","magenta") + " actors",
    ]
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
    Colors auto-enable on terminals; LOWKEY_COLOR=1 forces them and NO_COLOR=1 disables them.
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
    deployment_label = _deployment_contract_label(bootstrap, target)
    if deployment_label and label == "Target":
        label = deployment_label
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
    deployment_label = _deployment_contract_label(bootstrap, target)
    if deployment_label and label == "Target":
        label = deployment_label
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
        "target_contract": _deployment_contract_label(bootstrap, target) or str(config.get("target_contract") or ""),
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


def _walkthrough_is_setup_action(fn: FunctionInfo) -> bool:
    n = fn.name.lower()
    return n.startswith("initialize") or n in {
        "setstaketokenallowed", "pause", "unpause", "upgrade",
        "renounceownership", "transferownership", "acceptownership",
    }


def _candidate_actions(
    root: Path,
    meta: dict[str, Any],
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
    actors: dict[str, str],
    known: dict[str, str],
    all_errors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rpc = str(meta["rpc"])
    now = int(meta["chain_timestamp"])
    candidates: list[tuple[int, int, LiveNode, FunctionInfo, list[Any], str | None]] = []

    for node in nodes:
        if node.code_size == 0:
            continue
        funcs = functions_by_contract.get(node.artifact_contract or node.name, [])
        for fn in funcs:
            if not _is_protocol_entrypoint(fn, node, funcs):
                continue
            score = _rank_function(fn)
            phase_priority, _ = _walkthrough_phase_priority(fn)
            if score <= 0 or phase_priority <= 0 or _walkthrough_is_setup_action(fn):
                continue
            args, reason = _semantic_args(
                node, fn, functions_by_contract, nodes, actors, known,
                now, root, rpc,
            )
            if args is None:
                continue
            candidates.append((phase_priority, score, node, fn, args, reason))

    candidates.sort(
        key=lambda x: (-x[0], -x[1], x[2].name, x[3].name, x[3].signature)
    )

    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for _, _, node, fn, args, reason in candidates:
        key = (node.address.lower(), fn.signature)
        if key in seen:
            continue
        seen.add(key)

        caller, actor_name = _choose_caller(
            root, rpc, node, fn, actors, nodes, functions_by_contract
        )

        # Factory creation gates are often against the owner of the supplied agreement.
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
                    root, rpc, args[agreement_pos], "owner()(address)", []
                )
                if code == 0:
                    owner = re.search(r"0x[0-9a-fA-F]{40}", out)
                    if owner:
                        caller, actor_name = owner.group(0), "Agreement Owner"

        if not caller:
            continue

        precheck = _preflight_failure(
            root, rpc, node, fn, args, caller, all_errors
        )
        diagnosis = (
            []
            if precheck["ok"]
            else _known_preconditions(
                root, rpc, node, fn, args, caller,
                functions_by_contract, nodes, known, actors,
            )
        )
        actions.append({
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
                "ABI + source role synthesis" if not reason else reason
            ),
            "result": precheck,
            "diagnosis": diagnosis,
        })
    return actions


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
    # Compatibility helper: callers receive an ordered state-aware candidate list.
    return _candidate_actions(
        root, meta, functions_by_contract, nodes, actors, known, all_errors
    )[: max(1, int(steps))]




def _initializer_recovery_action(
    root: Path,
    rpc: str,
    blocked: dict[str, Any],
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
    actors: dict[str, str],
    known: dict[str, str],
    all_errors: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Recover an evidently uninitialized focus component on a local chain.

    A zero owner alone is not enough because ownership may have been deliberately
    renounced. Require at least one critical initializer-owned address to still
    be zero as well.
    """
    node: LiveNode = blocked["node"]
    funcs = functions_by_contract.get(node.artifact_contract or node.name, [])
    owner_fn = _function_by_name(funcs, "owner")
    initialize = _function_by_name(funcs, "initialize")
    if owner_fn is None or initialize is None:
        return None

    owner, _ = _read_simple_getter(root, rpc, node, owner_fn)
    if not _is_address(owner) or owner.lower() != ZERO.lower():
        return None

    critical_zero = False
    for getter_name in (
        "safeHarborRegistry",
        "poolImplementation",
        "defaultOutcomeModerator",
    ):
        getter = _function_by_name(funcs, getter_name)
        if getter is None:
            continue
        value, _ = _read_simple_getter(root, rpc, node, getter)
        if _is_address(value) and value.lower() == ZERO.lower():
            critical_zero = True
            break
    if not critical_zero:
        return None

    local_accounts = _eth_accounts(rpc)
    if not local_accounts:
        return {
            "node": node,
            "function": initialize,
            "args": [],
            "caller": None,
            "actor_name": "Setup Signer",
            "status": "BLOCKED",
            "phase": "SETUP",
            "what": f"Initialize {node.artifact_contract or node.name} before continuing the protocol walkthrough.",
            "why": "The live component has zero ownership and at least one initializer-owned critical address is still zero.",
            "semantic_reason": "derived from live zero-owner + zero-critical-state evidence",
            "result": {"ok": False, "decoded_error": None, "raw": "no local RPC signer is available"},
            "diagnosis": ["initializer appears required but eth_accounts returned no local signer"],
            "setup_recovery": True,
        }

    args, reason = _semantic_args(
        node,
        initialize,
        functions_by_contract,
        nodes,
        actors,
        known,
        _latest_timestamp(rpc),
        root,
        rpc,
    )
    if args is None:
        return {
            "node": node,
            "function": initialize,
            "args": [],
            "caller": local_accounts[0],
            "actor_name": "Setup Signer",
            "status": "BLOCKED",
            "phase": "SETUP",
            "what": f"Initialize {node.artifact_contract or node.name} before continuing the protocol walkthrough.",
            "why": "The live component is evidently uninitialized, but Lowkey could not synthesize every initializer argument safely.",
            "semantic_reason": reason or "initializer argument synthesis failed",
            "result": {"ok": False, "decoded_error": None, "raw": reason or "initializer arguments unavailable"},
            "diagnosis": [reason or "initializer arguments unavailable"],
            "setup_recovery": True,
        }

    caller = local_accounts[0]
    precheck = _preflight_failure(
        root,
        rpc,
        node,
        initialize,
        args,
        caller,
        all_errors,
    )

    return {
        "node": node,
        "function": initialize,
        "args": args,
        "caller": caller,
        "actor_name": "Setup Signer",
        "status": "READY" if precheck["ok"] else "BLOCKED",
        "phase": "SETUP",
        "what": (
            f"Initialize {node.artifact_contract or node.name} before continuing the protocol walkthrough."
        ),
        "why": (
            "The live component has owner() == address(0) and initializer-owned "
            "critical state is still zero."
        ),
        "semantic_reason": (
            "derived from live zero-owner + zero-critical-state evidence"
            + (f"; {reason}" if reason else "")
        ),
        "result": precheck,
        "diagnosis": [
            "owner() currently returns address(0)",
            "initializer-owned critical state is still zero",
            f"local setup signer: {_short_address(caller)}",
        ],
        "setup_recovery": True,
    }


def _next_transition_action(
    root: Path,
    meta: dict[str, Any],
    functions_by_contract: dict[str, list[FunctionInfo]],
    nodes: list[LiveNode],
    actors: dict[str, str],
    known: dict[str, str],
    all_errors: list[dict[str, Any]],
    require_local_signer: bool = False,
) -> dict[str, Any] | None:
    candidates = _candidate_actions(
        root, meta, functions_by_contract, nodes, actors, known, all_errors
    )
    if not candidates:
        return None

    # In live-send mode, execution authority is part of readiness. A simulated
    # eth_call can impersonate address(0), so it must never make an impossible
    # owner action look executable.
    blocked = candidates[0]
    if require_local_signer:
        caller = str(blocked.get("caller") or "")
        if not _sender_available_for_local_send(str(meta["rpc"]), caller):
            recovery = _initializer_recovery_action(
                root,
                str(meta["rpc"]),
                blocked,
                functions_by_contract,
                nodes,
                actors,
                known,
                all_errors,
            )
            if recovery:
                return recovery

    # Prefer an actually executable protocol transition.
    ready = [
        action for action in candidates
        if action.get("status") == "READY"
        and (
            not require_local_signer
            or _sender_available_for_local_send(
                str(meta["rpc"]),
                str(action.get("caller") or ""),
            )
        )
    ]
    if ready:
        return ready[0]

    # When the core transition is blocked by a source-backed state gate, walk
    # backward one hop and execute the legitimate enabling transition first.
    prerequisite = _prerequisite_from_blocked_action(
        root,
        str(meta["rpc"]),
        blocked,
        functions_by_contract,
        nodes,
        actors,
        known,
        all_errors,
    )
    return prerequisite or blocked


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
        target_source = str(meta.get("target_source") or "")
        needs_bootstrap = (
            "identity mismatch" in target_source.lower()
            or not any(
                isinstance(node, dict) and int(node.get("code_size") or 0) > 0
                for node in live_nodes
            )
        )
        if needs_bootstrap:
            bootstrap_ok, bootstrap_reason = _auto_bootstrap_local(
                root, config, meta.get("bootstrap") or {}
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
    payload = {
        "mode": "walkthrough",
        "started_at": time.time(),
        "model": meta,
        "actions": [],
    }

    if flags.get("bootstrap") or not meta.get("target"):
        _print_bootstrap_discovery(meta)

    live_send = bool(flags.get("send"))
    for step_index in range(max(1, int(flags["steps"]))):
        if step_index > 0:
            # A successful --send transition changes the world. Rebuild every
            # layer instead of replaying actions planned from the old state.
            meta, fns, nodes, getter_data, contracts, actors, known = _build_model(
                root, config
            )
            errors = _all_errors(_load_artifacts(root)[0])

        deployment_label = _deployment_contract_label(
            meta.get("bootstrap"), meta.get("target")
        )
        if deployment_label and not meta.get("target_contract"):
            meta["target_contract"] = deployment_label
            payload["model"] = meta

        action = _next_transition_action(
            root,
            meta,
            fns,
            nodes,
            actors,
            known,
            errors,
            require_local_signer=live_send,
        )

        if action is None:
            print(_render_story(
                root, nodes, fns, contracts, [], actors, None,
                flags.get("links", True), meta
            ))
            print(
                "\n" + _paint(
                    "No semantically executable lifecycle transition is currently discoverable.",
                    "yellow",
                )
            )
            print(
                "The important next audit step is state reconstruction, not random mutation."
            )
            break

        # Show exactly the current transition, not a precomputed wall of stale steps.
        if not live_send:
            action["result"] = _preflight_failure(
                root,
                str(meta["rpc"]),
                action["node"],
                action["function"],
                action["args"],
                str(action["caller"]),
                errors,
                include_trace=True,
            )
            action["status"] = "READY" if action["result"].get("ok") else "BLOCKED"

        print(_render_story(
            root,
            nodes,
            fns,
            contracts,
            [action],
            actors,
            0,
            flags.get("links", True),
            meta,
            live=True,
        ))

        if not live_send:
            payload["actions"].append({
                **{k: v for k, v in action.items() if k not in {"node", "function"}},
                "node": asdict(action["node"]),
                "function": asdict(action["function"]),
            })
            payload["model"] = meta
            _persist(root, payload)
            print(
                "\n" + _paint(
                    (
                        "Current transition is blocked; Lowkey will not advance "
                        "past a state it cannot satisfy."
                        if str(action.get("status")) == "BLOCKED"
                        else
                        "Simulation only: --auto does not mutate local state. "
                        "Add --send to advance the protocol."
                    ),
                    "red" if str(action.get("status")) == "BLOCKED" else "yellow",
                )
            )
            break

        if str(action.get("status")) == "BLOCKED":
            payload["actions"].append({
                **{k: v for k, v in action.items() if k not in {"node", "function"}},
                "node": asdict(action["node"]),
                "function": asdict(action["function"]),
            })
            payload["model"] = meta
            _persist(root, payload)
            print(
                "\n" + _paint(
                    "Walkthrough stopped at the current state; the transition is blocked.",
                    "red",
                )
            )
            break

        if not _is_local_rpc(str(meta["rpc"])):
            action["status"] = "FAILED"
            action["send_skipped"] = (
                "refusing remote mutating send without explicit local RPC"
            )
            payload["actions"].append({
                **{k: v for k, v in action.items() if k not in {"node", "function"}},
                "node": asdict(action["node"]),
                "function": asdict(action["function"]),
            })
            payload["model"] = meta
            _persist(root, payload)
            print("\n" + _paint(action["send_skipped"], "red"))
            break

        node: LiveNode = action["node"]
        fn: FunctionInfo = action["function"]
        caller = str(action["caller"])

        # eth_call can impersonate an arbitrary from-address, but a local
        # mutating send requires that address to be exposed by the RPC node.
        if not _sender_available_for_local_send(str(meta["rpc"]), caller):
            available = _eth_accounts(str(meta["rpc"]))
            action["status"] = "BLOCKED"
            action["result"] = {
                "ok": False,
                "decoded_error": None,
                "raw": (
                    f"selected sender {caller} is not an unlocked local RPC account"
                ),
                "trace": None,
            }
            action["diagnosis"] = [
                f"selected role sender {caller} is not exposed by eth_accounts",
                "local send requires an unlocked Anvil account; eth_call alone can impersonate arbitrary addresses",
                "available local accounts: " + (", ".join(_short_address(x) for x in available) if available else "none"),
            ]
            payload["actions"].append({
                **{k: v for k, v in action.items() if k not in {"node", "function"}},
                "node": asdict(action["node"]),
                "function": asdict(action["function"]),
            })
            payload["model"] = meta
            _persist(root, payload)
            print(_render_story(
                root,
                nodes,
                fns,
                contracts,
                [action],
                actors,
                0,
                flags.get("links", True),
                meta,
                live=True,
            ))
            print(
                "\n" + _paint(
                    "Walkthrough stopped: selected role cannot sign on this local RPC node.",
                    "red",
                )
            )
            print(
                "  Available local signers: " +
                (", ".join(_short_address(x) for x in available) if available else "none")
            )
            break

        pre = _preflight_failure(
            root,
            str(meta["rpc"]),
            node,
            fn,
            action["args"],
            caller,
            errors,
            include_trace=True,
        )
        action["result"] = pre
        if not pre["ok"]:
            action["status"] = "BLOCKED"
            action["diagnosis"] = _known_preconditions(
                root, str(meta["rpc"]), node, fn, action["args"], caller,
                fns, nodes, known, actors
            )
            payload["actions"].append({
                **{k: v for k, v in action.items() if k not in {"node", "function"}},
                "node": asdict(action["node"]),
                "function": asdict(action["function"]),
            })
            payload["model"] = meta
            _persist(root, payload)
            print(
                "\n" + _paint(
                    "State changed between planning and execution; transition is now blocked.",
                    "red",
                )
            )
            break

        code, out, err = _cast_send(
            root,
            str(meta["rpc"]),
            node.address,
            fn,
            _arg_values_to_strings(action["args"]),
            caller,
        )
        action["send"] = {
            "exit_code": code,
            "stdout": out,
            "stderr": err,
        }
        tx_hash = _send_transaction_hash(action["send"])
        if tx_hash:
            action["send"]["transaction_hash"] = tx_hash
            tx_trace = _trace_transaction(root, str(meta["rpc"]), tx_hash)
            if tx_trace:
                action["result"]["trace"] = tx_trace
        action["status"] = "SUCCESS" if code == 0 else "FAILED"

        payload["actions"].append({
            **{k: v for k, v in action.items() if k not in {"node", "function"}},
            "node": asdict(action["node"]),
            "function": asdict(action["function"]),
        })
        payload["model"] = meta
        _persist(root, payload)

        if code != 0:
            raw_send_error = "\n".join(
                x.strip()
                for x in (err, out)
                if x and x.strip()
            )
            print(
                "\n" + _paint(
                    "The live transaction submission failed; Lowkey will not invent the next state.",
                    "red",
                )
            )
            if raw_send_error:
                print("  SEND ERROR " + raw_send_error[-2000:])
            print(
                "  SEND FROM  " + caller
            )
            print(
                "  SEND TO    " + node.address
            )
            print(
                "  RPC        " + str(meta["rpc"])
            )
            print(
                "  The preceding simulation passed; this failure is in transaction submission, not the source-level precondition."
            )
            break

        print(
            "\n" + _paint(
                "TRANSITION COMPLETE — observed execution trace:",
                "green",
            )
        )
        print(
            _render_story(
                root,
                nodes,
                fns,
                contracts,
                [action],
                actors,
                0,
                flags.get("links", True),
                meta,
                live=True,
            )
        )
        print(
            _paint(
                "Rebuilding the protocol model from the new chain state…",
                "green",
            )
        )

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
