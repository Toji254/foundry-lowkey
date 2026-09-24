"""
Lowkey protocol walkthrough engine.

This module is intentionally dependency-free.  It builds a source/build model,
plans a conservative workflow, executes real local-Anvil transactions, records
state/evidence, and renders the result as a terminal "protocol board".

The renderer is presentation only: all state shown as LIVE comes from the chain
or compiler artifacts. Heuristic labels are explicitly marked INFERRED.
"""

from __future__ import annotations

import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import textwrap
import time
from urllib.parse import quote
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
MAGENTA = "\033[35m"
BLUE = "\033[34m"
RED = "\033[31m"
WHITE = "\033[97m"
GRAY = "\033[90m"

BLOCK = "████"
ARROW = "────▶"
DOTTED = "⋯⋯⋯▶"
RETURN = "◀────"
EXTERNAL = "⇢"
STATE = "◆"
ACTOR = "◉"
EVENT = "✦"
FUNCTION = "⟦"
STORAGE = "▓"
MAPPING = "▣"
STRUCT = "▤"
ARRAY = "▥"
WARNING = "△"


@dataclass
class Field:
    name: str
    type: str
    offset: int | None = None
    slot: str | None = None


@dataclass
class ContractModel:
    name: str
    source: str
    artifact: str
    abi: list[dict[str, Any]] = field(default_factory=list)
    storage: dict[str, Any] = field(default_factory=dict)
    bases: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    structs: dict[str, list[Field]] = field(default_factory=dict)
    mappings: list[dict[str, Any]] = field(default_factory=list)
    arrays: list[dict[str, Any]] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    kind: str = "contract"
    function_locations: dict[str, int] = field(default_factory=dict)
    type_bindings: dict[str, str] = field(default_factory=dict)
    imports: list[str] = field(default_factory=list)


@dataclass
class Actor:
    name: str
    address: str
    index: int


@dataclass
class RuntimeContract:
    address: str
    model: str
    label: str
    relation: str = "target"
    parent: str | None = None
    discovered_at_step: int = 0
    implementation: str | None = None


@dataclass
class Step:
    index: int
    actor: str
    contract: str
    address: str
    function: str
    args: list[Any]
    value_wei: int = 0
    reason: str = ""
    inferred: bool = True
    status: str = "planned"
    tx_hash: str | None = None
    calldata: str | None = None
    gas_used: int | None = None
    error: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    trace_edges: list[str] = field(default_factory=list)
    storage_before: list[dict[str, Any]] = field(default_factory=list)
    storage_after: list[dict[str, Any]] = field(default_factory=list)
    storage_changes: list[dict[str, Any]] = field(default_factory=list)
    balance_before: dict[str, str] = field(default_factory=dict)
    balance_after: dict[str, str] = field(default_factory=dict)
    token_balance_before: dict[str, int] = field(default_factory=dict)
    token_balance_after: dict[str, int] = field(default_factory=dict)
    error_reason: str | None = None
    discovered_contracts: list[dict[str, Any]] = field(default_factory=list)
    preflight: str | None = None
    runtime_contracts: list[dict[str, Any]] = field(default_factory=list)
    execution_edges: list[dict[str, Any]] = field(default_factory=list)
    failure_origin: str | None = None
    diagnostics: list[str] = field(default_factory=list)


def _box(title: str, lines: Iterable[str], width: int = 72, left: str = "╭", right: str = "╮") -> str:
    inner = max(20, width - 4)
    body = []
    for line in lines:
        line = str(line)
        if len(line) > inner:
            line = line[: inner - 1] + "…"
        body.append("│ " + line.ljust(inner) + " │")
    return "\n".join(
        [f"{left}─ {title} " + "─" * max(0, width - len(title) - 5) + right]
        + body
        + ["╰" + "─" * (width - 2) + "╯"]
    )


def _addr(address: str | None) -> str:
    if not address:
        return "?"
    return f"{address[:10]}…{address[-8:]}"


def is_address(value: Any) -> bool:
    """Local address validator; walkthrough must not depend on lk.py helpers."""
    return isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value.strip()))


def _ansi_enabled(static: bool = False) -> bool:
    return not static and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _paint(value: str, color: str, enabled: bool) -> str:
    return f"{color}{value}{RESET}" if enabled else value


def _rpc_call(url: str, method: str, params: list[Any] | None = None) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    try:
        from urllib.request import Request, urlopen

        req = Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode())
        if isinstance(data, dict) and "error" in data:
            return None
        return data.get("result") if isinstance(data, dict) else None
    except Exception:
        return None


def _cmd(args: list[str], cwd: Path | None = None, timeout: int = 30) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout or "", p.stderr or ""
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)


def _json_file(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def _foundry_src_dir(root: Path) -> str:
    try:
        text = (root / "foundry.toml").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "src"
    match = re.search(r'(?m)^\s*src\s*=\s*"([^"]+)"', text)
    return match.group(1).strip().rstrip("/") if match else "src"


def _source_kind(source_text: str, name: str) -> str:
    if re.search(r"\binterface\s+" + re.escape(name) + r"\b", source_text):
        return "interface"
    if re.search(r"\blibrary\s+" + re.escape(name) + r"\b", source_text):
        return "library"
    if re.search(r"\babstract\s+contract\s+" + re.escape(name) + r"\b", source_text):
        return "abstract"
    if re.search(r"\bcontract\s+" + re.escape(name) + r"\b", source_text):
        return "contract"
    return "unknown"


def _function_locations(source_text: str) -> dict[str, int]:
    locations: dict[str, int] = {}
    for match in re.finditer(r"\bfunction\s+(\w+)\s*\(", source_text):
        locations.setdefault(match.group(1), source_text.count("\n", 0, match.start()) + 1)
    return locations


def _source_imports(source_text: str) -> list[str]:
    return [
        str(match.group(1)).replace("\\", "/")
        for match in re.finditer(r'import(?:\s+[^"]+\s+from)?\s*"([^"]+)"\s*;', source_text)
    ]


def _type_bindings(source_text: str) -> dict[str, str]:
    bindings: dict[str, str] = {}

    # Covers both state variables and local typed variables used for calls.
    declaration = re.compile(
        r"\b([A-Za-z_]\w*)\s+(?:public\s+|private\s+|internal\s+|external\s+|memory\s+|storage\s+|calldata\s+)*([A-Za-z_]\w*)\s*(?:=|;|,|\))"
    )
    primitive = {
        "address", "bool", "string", "bytes", "uint", "uint8", "uint16",
        "uint32", "uint64", "uint128", "uint256", "int", "int8", "int16",
        "int32", "int64", "int128", "int256", "bytes32", "mapping",
    }
    for match in declaration.finditer(source_text):
        typ, name = match.groups()
        if typ not in primitive:
            bindings.setdefault(name, typ)

    # Explicit interface/contract casts.
    for match in re.finditer(
        r"\b([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*([A-Za-z_]\w+)\s*\(",
        source_text,
    ):
        bindings.setdefault(match.group(2), match.group(1))
    return bindings


def _balanced_block(source_text: str, opening_index: int) -> str:
    depth = 0
    for index in range(opening_index, len(source_text)):
        char = source_text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source_text[opening_index + 1:index]
    return source_text[opening_index + 1:]


def _build_source_calls(model: ContractModel, models: list[ContractModel], source_text: str) -> list[dict[str, Any]]:
    by_name = {item.name: item for item in models}
    implementations: dict[str, str] = {}
    for item in models:
        implementations.setdefault(item.name, item.name)
        for base in item.bases:
            implementations.setdefault(base, item.name)

    edges: list[dict[str, Any]] = []
    current_names = {sig.split("(", 1)[0] for sig in model.functions}

    functions = list(re.finditer(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\{", source_text, re.S))
    for fn_match in functions:
        caller = fn_match.group(1)
        body = _balanced_block(source_text, fn_match.end() - 1)
        line = source_text.count("\n", 0, fn_match.start()) + 1
        bindings = model.type_bindings

        # interface(addressVar).function(...)
        for match in re.finditer(
            r"\b([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*)\s*\)\s*\.\s*([A-Za-z_]\w+)\s*\(",
            body,
        ):
            typ, variable, called = match.groups()
            target = implementations.get(typ, typ)
            edges.append({
                "kind": "cross-contract" if target != model.name else "internal",
                "from": caller,
                "to_contract": target,
                "to_function": called,
                "via": variable,
                "interface": typ,
                "line": line + body[:match.start()].count("\n"),
                "certainty": "INFERRED",
            })

        # typedVariable.function(...)
        for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w+)\s*\(", body):
            variable, called = match.groups()
            typ = bindings.get(variable)
            if not typ:
                continue
            target = implementations.get(typ, typ)
            if target == model.name and called in current_names:
                continue
            edges.append({
                "kind": "cross-contract",
                "from": caller,
                "to_contract": target,
                "to_function": called,
                "via": variable,
                "interface": typ,
                "line": line + body[:match.start()].count("\n"),
                "certainty": "INFERRED",
            })

        for called in current_names:
            if called == caller:
                continue
            if re.search(r"(?<![.\w])" + re.escape(called) + r"\s*\(", body):
                signature = next((sig for sig in model.functions if sig.startswith(called + "(")), called + "()")
                edges.append({
                    "kind": "internal",
                    "from": caller,
                    "to_contract": model.name,
                    "to_function": signature,
                    "line": line,
                    "certainty": "INFERRED",
                })

    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for edge in edges:
        key = (
            edge.get("kind"),
            edge.get("from"),
            edge.get("to_contract"),
            edge.get("to_function"),
            edge.get("via"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)
    return unique


def _artifact_models(root: Path) -> list[ContractModel]:
    models: list[ContractModel] = []
    out = root / "out"
    if not out.is_dir():
        return models
    src_prefix = _foundry_src_dir(root).replace("\\", "/").strip("/") or "src"

    for path in out.rglob("*.json"):
        if "build-info" in path.parts:
            continue
        data = _json_file(path)
        if not data or not isinstance(data.get("abi"), list):
            continue

        name = str(data.get("contractName") or path.stem)
        source = str(data.get("sourceName") or "").replace("\\", "/").lstrip("./")
        if not source:
            candidates = sorted((root / src_prefix).rglob(f"{name}.sol")) if (root / src_prefix).is_dir() else []
            if candidates:
                source = candidates[0].relative_to(root).as_posix()

        if not (source == src_prefix or source.startswith(src_prefix + "/")):
            continue

        source_path = root / source
        if not source_path.is_file():
            continue
        try:
            source_text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        kind = _source_kind(source_text, name)
        if kind == "library":
            continue

        abi = data["abi"]
        functions = [_signature(x) for x in abi if x.get("type") == "function" and x.get("name")]
        events = [_signature(x) for x in abi if x.get("type") == "event" and x.get("name")]
        bases: list[str] = []
        for match in re.finditer(r"\b(?:abstract\s+)?contract\s+(\w+)\s+is\s+([^{]+)\{", source_text):
            if match.group(1) == name:
                bases = [re.sub(r"\s+", "", value).split("(")[0] for value in match.group(2).split(",") if value.strip()]

        model = ContractModel(
            name=name,
            source=source,
            artifact=str(path.relative_to(root)),
            abi=abi,
            storage=data.get("storageLayout") or {},
            bases=bases,
            functions=functions,
            modifiers=re.findall(r"\bmodifier\s+(\w+)", source_text),
            structs=_parse_structs(source_text),
            mappings=_parse_mappings(source_text),
            arrays=_parse_arrays(source_text),
            events=events,
            kind=kind,
            function_locations=_function_locations(source_text),
            type_bindings=_type_bindings(source_text),
            imports=_source_imports(source_text),
        )
        if any(m.name == name and m.source == source for m in models):
            continue
        models.append(model)

    for model in models:
        source_path = root / model.source
        try:
            source_text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        model.calls = _build_source_calls(model, models, source_text)

    return sorted(models, key=lambda m: (m.name.lower(), m.source))

def _parse_structs(source: str) -> dict[str, list[Field]]:
    result: dict[str, list[Field]] = {}
    for match in re.finditer(r"\bstruct\s+(\w+)\s*\{([^}]*)\}", source, re.S):
        fields: list[Field] = []
        for raw in match.group(2).split(";"):
            raw = re.sub(r"//.*", "", raw).strip()
            if not raw:
                continue
            bits = raw.split()
            if len(bits) >= 2:
                fields.append(Field(name=bits[-1], type=" ".join(bits[:-1])))
        result[match.group(1)] = fields
    return result


def _parse_mappings(source: str) -> list[dict[str, Any]]:
    found = []
    rx = re.compile(
        r"mapping\s*\(([^=]+?)\s*=>\s*([^\)]+?)\)\s+(?:(?:public|private|internal|external|constant)\s+)*(\w+)\s*(?:;|=)",
        re.S,
    )
    for match in rx.finditer(source):
        key = " ".join(match.group(1).split())
        value = " ".join(match.group(2).split())
        found.append({"name": match.group(3), "key_type": key, "value_type": value})
    return found


def _parse_arrays(source: str) -> list[dict[str, Any]]:
    found = []
    rx = re.compile(r"\b([A-Za-z_][\w]*(?:\[[^\]]*\])+)\s+(?:(?:public|private|internal|constant)\s+)*(\w+)\s*(?:;|=)")
    for match in rx.finditer(source):
        found.append({"name": match.group(2), "type": match.group(1)})
    return found


def _canonical_type(item: dict[str, Any]) -> str:
    raw = str(item.get("type") or "")
    if raw.startswith("tuple"):
        suffix = raw[len("tuple") :]
        comps = ",".join(_canonical_type(x) for x in item.get("components", []))
        return "(" + comps + ")" + suffix
    return raw


def _signature(item: dict[str, Any]) -> str:
    return f"{item.get('name', '<anonymous>')}({','.join(_canonical_type(x) for x in item.get('inputs', []))})"


def _find_model(models: list[ContractModel], name: str | None, target_contract: str | None) -> ContractModel | None:
    query = (name or target_contract or "").lower().strip()
    if query:
        matches = [m for m in models if m.name.lower() == query]
        if matches:
            return matches[0]
        matches = [m for m in models if query in m.name.lower()]
        if matches:
            return matches[0]
    deployable = [m for m in models if any(
        x.get("type") == "constructor" for x in m.abi
    ) or any(x.get("type") == "function" for x in m.abi)]
    return deployable[0] if deployable else (models[0] if models else None)


def _mutators(model: ContractModel) -> list[dict[str, Any]]:
    return [
        x for x in model.abi
        if x.get("type") == "function"
        and x.get("name")
        and x.get("stateMutability") not in {"view", "pure"}
    ]

_ADMIN_TOKENS = ("upgrade","setadmin","transferownership","renounceownership","selfdestruct","pause","unpause","acceptownership")

def _lifecycle_candidate(name: str) -> bool:
    low=name.lower()
    if any(token in low for token in _ADMIN_TOKENS):
        return False
    if low == "initialize" or low.startswith("initialize"):
        return False
    return True


_PHASES = [
    ("bootstrap", ("initialize", "init", "setup", "configure", "register", "create")),
    ("fund", ("deposit", "fund", "contribute", "join", "stake", "approve", "mint")),
    ("action", ("buy", "swap", "place", "commit", "submit", "add", "remove", "borrow", "lend", "claim")),
    ("settle", ("close", "finalize", "settle", "release", "execute", "resolve")),
    ("exit", ("withdraw", "redeem", "refund", "cancel", "unstake", "collect")),
]


def _phase_score(name: str) -> tuple[int, int]:
    lower = name.lower()
    if "flagoutcome" in lower or (lower.startswith("flag") and "outcome" in lower):
        return 2, -1000
    if lower.startswith("claim"):
        return 4, -100
    for index, (_, names) in enumerate(_PHASES):
        for token in names:
            if lower.startswith(token) or token in lower:
                return index, -len(token)
    return 3, -999


def _arg_for(
    param: dict[str, Any],
    actors: list[Actor],
    target: str,
    now: int,
    observed: dict[str, Any] | None = None,
) -> Any:
    ptype = _canonical_type(param)
    name = str(param.get("name") or "arg").lower()
    observed = observed or {}
    compact = re.sub(r"[^a-z0-9]", "", name)
    alice = actors[0].address if actors else target
    bob = actors[1].address if len(actors) > 1 else alice
    attacker = actors[2].address if len(actors) > 2 else bob

    if compact in {
        "staketoken", "safeharborregistry", "poolimplementation",
        "defaultoutcomemoderator", "outcomemoderator", "agreement",
        "factory", "registry", "moderator", "attackregistry",
    } and observed.get(compact):
        return observed[compact]

    if ptype.startswith("address[]"):
        return observed.get(compact, [alice, bob])
    if ptype == "address":
        if observed.get(compact):
            return observed[compact]
        if any(x in name for x in ("attacker", "malicious", "evil")):
            return attacker
        if any(x in name for x in ("recipient", "receiver", "to", "user", "beneficiary", "recovery", "moderator")):
            return bob
        return alice
    if ptype.startswith("uint") or ptype.startswith("int"):
        if any(x in name for x in ("expiry", "expires")):
            return now + 31 * 24 * 60 * 60
        if "deadline" in name:
            return now + 3600
        if any(x in name for x in ("amount", "stake", "value", "price", "limit")):
            return 10**18
        if any(x in name for x in ("id", "index", "nonce")):
            return 0
        if "count" in name:
            return 2
        if any(x in name for x in ("bps", "basis", "fee")):
            return 100
        return 1
    if ptype == "bool":
        return True
    if ptype == "bytes32":
        return "0x" + ("42" * 32)
    if ptype == "bytes":
        return "0x"
    if ptype == "string":
        return name + "-lowkey"
    if ptype.startswith("tuple"):
        return [
            _arg_for(comp, actors, target, now, observed)
            for comp in param.get("components", [])
        ]
    if ptype.endswith("[]"):
        return []
    return 0


def _value_for(fn: dict[str, Any]) -> int:
    if fn.get("stateMutability") != "payable":
        return 0
    name = str(fn.get("name") or "").lower()
    return 10**15 if any(x in name for x in ("deposit", "fund", "pay", "contribute", "stake")) else 0


def _actor_for_function(name: str, actors: list[Actor], observed: dict[str, Any]) -> Actor:
    if not actors:
        return Actor("Alice", observed.get("target") or "0x" + "00" * 20, 0)
    low = str(name or "").lower()
    moderator = observed.get("defaultoutcomemoderator") or observed.get("outcomemoderator")
    if moderator:
        for actor in actors:
            if actor.address.lower() == str(moderator).lower() and ("flag" in low or "outcome" in low or "moderator" in low):
                return actor
    if any(token in low for token in ("createpool", "setstake", "setrecovery", "transferownership")):
        return actors[0]
    if any(token in low for token in ("claim", "withdraw", "redeem", "refund", "sweep")) and len(actors) > 1:
        return actors[1]
    return actors[0]

def plan_workflow(
    model: ContractModel,
    actors: list[Actor],
    target: str,
    now: int,
    max_steps: int,
    observed: dict[str, Any] | None = None,
) -> list[Step]:
    observed = observed or {}
    candidates = [x for x in _mutators(model) if _lifecycle_candidate(str(x.get("name") or ""))]
    candidates.sort(key=lambda item: (_phase_score(str(item.get("name") or "")), str(item.get("name") or "")))

    steps: list[Step] = []
    used: set[str] = set()
    for item in candidates:
        name = str(item.get("name") or "")
        if not name or name in used:
            continue
        # Do not auto-trigger clearly administrative or destructive controls.
        low = name.lower()
        if any(x in low for x in ("upgrade", "setadmin", "transferownership", "selfdestruct", "pause", "unpause")):
            continue
        actor = _actor_for_function(name, actors, observed)
        args = [_arg_for(p, actors, target, now, observed) for p in item.get("inputs", [])]
        sig = _signature(item)
        steps.append(Step(
            index=len(steps) + 1,
            actor=actor.name,
            contract=model.name,
            address=target,
            function=sig,
            args=args,
            value_wei=_value_for(item),
            reason=f"source-guided { _phase_score(name)[0] and 'workflow' or 'bootstrap'} phase",
        ))
        used.add(name)
        if len(steps) >= max_steps:
            break

    # The sequence should cover at least two phases when the ABI permits it.
    phases = {_phase_score(s.function.split("(", 1)[0])[0] for s in steps}
    if len(phases) == 1 and len(candidates) > len(steps):
        for item in candidates[len(steps):]:
            sig = _signature(item)
            if sig.split("(", 1)[0] in used:
                continue
            actor = actors[1] if len(actors) > 1 else actors[0]
            steps.append(Step(
                index=len(steps) + 1,
                actor=actor.name,
                contract=model.name,
                address=target,
                function=sig,
                args=[_arg_for(p, actors, target, now) for p in item.get("inputs", [])],
                value_wei=_value_for(item),
                reason="source-guided secondary phase",
            ))
            break
    return steps


def _cli_arg(value: Any) -> str:
    """Render a Solidity argument in a cast-friendly command-line form."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_cli_arg(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(f"{key}:{_cli_arg(item)}" for key, item in value.items()) + "}"
    return str(value)
def _lab_runtime(config: dict[str, Any], target: str, model: ContractModel) -> list[RuntimeContract]:
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    if not system:
        return [RuntimeContract(target, model.name, model.name, "target")]

    definitions = [
        ("factory", "ConfidencePoolFactory", "system", None),
        ("pool_implementation", "ConfidencePool", "IMPLEMENTATION", "factory"),
        ("pool", "ConfidencePool", "CLONE", "factory"),
        ("stake_token", "StakeToken", "DEPENDENCY", "pool"),
        ("agreement", "MockAgreement", "DEPENDENCY", "pool"),
        ("safe_harbor_registry", "MockSafeHarborRegistry", "DEPENDENCY", "pool"),
        ("attack_registry", "MockAttackRegistry", "DEPENDENCY", "safe_harbor_registry"),
        ("moderator", "MockConfidencePoolModerator", "DEPENDENCY", "pool"),
    ]
    runtime=[]
    address_by_key={k:system.get(k) for k,_,_,_ in definitions}
    for key,label,relation,parent_key in definitions:
        address=address_by_key.get(key)
        if not address:
            continue
        parent=address_by_key.get(parent_key) if parent_key else None
        runtime.append(RuntimeContract(address,label,label,relation,parent))
    if not any(x.address.lower()==target.lower() for x in runtime):
        runtime.append(RuntimeContract(target,model.name,model.name,"target"))
    return runtime



def _confidence_pool_factory_recipe(
    config: dict[str, Any],
    actors: list[Actor],
    now: int,
) -> list[Step]:
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    factory = system.get("factory") or config.get("target")
    token = system.get("stake_token")
    agreement = system.get("agreement")
    if not factory or not token or not agreement:
        return []

    alice = actors[0] if actors else Actor("Alice", factory, 0)
    bob = actors[1] if len(actors) > 1 else alice
    expiry = now + 31 * 24 * 60 * 60
    scope = [alice.address, bob.address]

    return [
        Step(
            0, alice.name, "ConfidencePoolFactory", factory,
            "setStakeTokenAllowed(address,bool)", [token, True],
            reason="factory owner enables the stake token",
            inferred=False,
        ),
        Step(
            0, alice.name, "ConfidencePoolFactory", factory,
            "createPool(address,address,uint256,uint256,address,address[])",
            [agreement, token, expiry, 10**18, bob.address, scope],
            reason="factory validates dependencies, clones the pool, and initializes it",
            inferred=False,
        ),
    ]


def _confidence_pool_recipe(
    config: dict[str, Any],
    actors: list[Actor],
    pool_override: str | None = None,
    now: int | None = None,
) -> list[Step]:
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    pool = pool_override or system.get("pool") or config.get("target")
    token = system.get("stake_token")
    attack_registry = system.get("attack_registry")
    moderator = system.get("moderator")
    if not pool or not token or not attack_registry or not moderator:
        return []

    timestamp = int(now if now is not None else time.time())
    alice = actors[0] if actors else Actor("Alice", pool, 0)
    bob = actors[1] if len(actors) > 1 else alice
    amount = 10**18
    max_uint = 2**256 - 1

    return [
        Step(0, alice.name, "StakeToken", token, "approve(address,uint256)", [pool, max_uint],
             reason="Alice gives the pool permission to pull her stake tokens", inferred=False),
        Step(0, bob.name, "StakeToken", token, "approve(address,uint256)", [pool, max_uint],
             reason="Bob gives the pool permission to pull his stake tokens", inferred=False),
        Step(0, alice.name, "ConfidencePool", pool, "contributeBonus(uint256)", [amount],
             reason="Alice seeds the pool's bonus reserve", inferred=False),
        Step(0, alice.name, "ConfidencePool", pool, "stake(uint256)", [amount],
             reason="Alice deposits her stake", inferred=False),
        Step(0, bob.name, "ConfidencePool", pool, "stake(uint256)", [amount],
             reason="Bob deposits his stake", inferred=False),
        Step(0, alice.name, "MockAttackRegistry", attack_registry, "setAgreementState(uint8)", [3],
             reason="LAB CONTROL: agreement enters UNDER_ATTACK", inferred=False),
        Step(0, alice.name, "ConfidencePool", pool, "pokeRiskWindow()",
             [], reason="pool observes the external registry and seals the risk window", inferred=False),
        Step(0, alice.name, "MockAttackRegistry", attack_registry, "setAgreementState(uint8)", [5],
             reason="LAB CONTROL: agreement reaches PRODUCTION", inferred=False),
        Step(0, alice.name, "MockConfidencePoolModerator", moderator, "flagSurvived(address)", [pool],
             reason="moderator records the survived outcome", inferred=False),
        Step(0, alice.name, "ConfidencePool", pool, "claimSurvived()",
             [], reason="Alice claims principal plus her bonus share", inferred=False),
        Step(0, bob.name, "ConfidencePool", pool, "claimSurvived()",
             [], reason="Bob claims principal plus his bonus share", inferred=False),
    ]



def _render_shape_legend(enabled: bool) -> str:
    return (
        f"  {ACTOR} actor   {FUNCTION} function   {MAPPING} mapping   "
        f"{STRUCT} struct   {ARRAY} array   {STATE} state   "
        f"{EXTERNAL} external   {DOTTED} inherit/impl"
    )


def _render_contract_shapes(model: ContractModel, enabled: bool) -> str:
    functions=[x for x in model.abi if x.get("type")=="function" and x.get("name")][:5]
    chunks=["  "+_paint("SHAPES",BOLD+WHITE,enabled)]
    if functions:
        chunks.append("  "+ "  ".join(f"{FUNCTION} {x.get('name')}()" for x in functions))
    for item in model.mappings[:3]:
        chunks.append(f"  {MAPPING} {item.get('name')}[{item.get('key_type')}] → {item.get('value_type')}")
    for name,fields in list(model.structs.items())[:2]:
        field_names=", ".join(f.name for f in fields[:4])
        chunks.append(f"  {STRUCT} {name}{{{field_names}}}")
    if model.arrays:
        chunks.append(f"  {ARRAY} {model.arrays[0].get('name')}: {model.arrays[0].get('type')}")
    if model.bases:
        chunks.append("  "+f"inherit {DOTTED} " + ", ".join(model.bases[:3]))
    return "\n".join(chunks)





def _osc8(label: str, target: str) -> str:
    if os.environ.get("LOWKEY_NO_LINKS") or os.environ.get("NO_COLOR") == "1":
        return label
    return f"\033]8;;{target}\033\\{label}\033]8;;\033\\"


def _source_target(root: Path, source: str, line: int | None = None) -> str:
    path = (root / source).resolve()
    if os.environ.get("TERM_PROGRAM", "").lower() == "vscode" or os.environ.get("VSCODE_PID"):
        target = f"vscode://file/{quote(str(path), safe='/')}"
        if line:
            target += f":{int(line)}"
        return target
    target = f"file://{quote(str(path), safe='/')}"
    if line:
        target += f"#L{int(line)}"
    return target


def _function_link(root: Path, model: ContractModel | None, function: str) -> str:
    if not model:
        return function
    name = str(function).split("(", 1)[0]
    line = model.function_locations.get(name)
    if not line:
        return function
    return _osc8(function, _source_target(root, model.source, line))


def _actor_for_address(address: str | None, actors: list[Actor]) -> str | None:
    if not address:
        return None
    lowered = str(address).lower()
    for actor in actors:
        if actor.address.lower() == lowered:
            return actor.name
    return None


def _friendly_value(value: Any) -> str:
    """Render generic Solidity values in a human-readable form."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if value == 2**256 - 1:
            return "MAX"
        if abs(value) >= 10**9:
            return f"{value:,}"
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_friendly_value(item) for item in list(value)[:4]) + (", …" if len(value) > 4 else "") + "]"
    return str(value)
def _friendly_eth(value_wei: int | None) -> str:
    try:
        value = int(value_wei or 0)
    except (TypeError, ValueError):
        return str(value_wei)
    if value % 10**18 == 0:
        return f"{value // 10**18:g} ETH"
    return f"{value / 10**18:g} ETH"


def _friendly_arg(value: Any, actors: list[Actor]) -> str:
    if isinstance(value, str) and is_address(value):
        actor = _actor_for_address(value, actors)
        return actor or _addr(value)
    return _friendly_value(value)


def _friendly_contract_name(step: Step) -> str:
    return str(step.contract or "Contract").replace("MockConfidencePoolModerator", "Moderator")


def _short_error(raw: str | None) -> str:
    text = " ".join(str(raw or "").split())
    for prefix in ("PRECONDITION BLOCKED: ", "Error: execution reverted: ", "execution reverted: ", "Error: "):
        if text.startswith(prefix):
            text = text[len(prefix):]
    return text[-420:] if text else "unknown failure"


def _explain_failure(step: Step, raw: str | None, actor: str) -> str:
    """Translate low-level failures into a plain-English reason."""
    text = " ".join(str(raw or "").split())
    lower = text.lower().replace(" ", "")
    rules = [
        ("stakingclosed", "the pool is past its staking deadline, so new deposits are closed"),
        ("notmoderator", f"{actor} is not the configured outcome moderator"),
        ("ownableunauthorizedaccount", f"{actor} is not the contract owner"),
        ("outcomenotset", "the pool has no terminal outcome yet, so this claim path is unavailable"),
        ("outcomenotaligibleforsweep", "the pool is not in a state where this sweep is allowed"),
        ("poolnotexpired", "the pool has not reached its expiry time yet"),
        ("withdrawsdisabled", "withdrawals are disabled because the risk window or a later registry state has been reached"),
        ("invalidamount", "the supplied amount is invalid"),
        ("belowminstake", "the supplied stake is below the pool's minimum stake"),
        ("notattacker", "this caller is not the recorded attacker"),
        ("bountyalreadyclaimed", "the attacker bounty has already been claimed"),
        ("claimwindowexpired", "the attacker claim window has expired"),
        ("mustclaimbountyfirst", "the bounty must be claimed before the recovery sweep"),
        ("nothingtosweep", "there is no free balance available to sweep"),
        ("riskwindownotreached", "the registry has not reached an active or terminal state that seals a risk window"),
        ("agreementcorruptedawaitingmoderator", "the agreement is corrupted, but the moderator grace period is still active"),
    ]
    for token, explanation in rules:
        if token in lower:
            return explanation
    if "parsererror" in lower or "invalidboolean" in lower or "expectedhexdigits" in lower:
        return "Lowkey could not encode the argument for cast, so Solidity was never reached"
    if 'data:"0x"' in lower:
        return "the call reverted without a decoded reason; an external dependency or protocol fixture may still be unconfigured"
    if "executionreverted" in lower:
        return "the contract rejected this call under the current on-chain state"
    return "the live call was not accepted"


def _explain_success(step: Step) -> str:
    function = str(step.function or "").split("(", 1)[0].lower()
    if function == "approve":
        return "the token contract accepted the allowance, so the pool can pull this actor's stake tokens"
    if function == "stake":
        return "the pool is unresolved and before expiry, the amount meets minStake, and the token transfer succeeded"
    if function == "contributebonus":
        return "the pool is unresolved and before expiry, and the bonus token transfer succeeded"
    if function == "setagreementstate":
        return "the local registry fixture accepted the new state; this is a lab-control action"
    if function == "pokeriskwindow":
        return "the registry reached an observable risk/terminal state, so the pool could seal its risk-window marker"
    if function == "flagsurvived":
        return "the moderator contract is authorized and the registry is in a terminal state accepted for SURVIVED"
    if function == "claimsurvived":
        return "the pool is resolved as SURVIVED and this staker has an outstanding eligible balance"
    if function.startswith("claim"):
        return "the pool is in the state required by this claim path and the caller has an eligible claim"
    return "the live contract's preconditions were satisfied"


def _human_action_summary(step: Step, actors: list[Actor]) -> str:
    actor = step.actor or "Caller"
    contract = _friendly_contract_name(step)
    function = str(step.function or "").split("(", 1)[0]
    lower = function.lower()
    args = step.args
    if lower == "approve":
        return f"{actor} approves {contract} to spend their stake tokens"
    if lower in {"stake", "deposit"}:
        amount = _friendly_value(args[0]) if args else "the requested amount"
        verb = "deposits" if step.status == "success" else "tries to deposit"
        return f"{actor} {verb} {amount} stake tokens into {contract}"
    if lower == "contributebonus":
        amount = _friendly_value(args[0]) if args else "the requested amount"
        verb = "adds" if step.status == "success" else "tries to add"
        return f"{actor} {verb} {amount} to {contract}'s bonus pool"
    if lower == "withdraw":
        verb = "withdraws" if step.status == "success" else "tries to withdraw"
        return f"{actor} {verb} their stake from {contract}"
    if lower.startswith("claim"):
        verb = "claims" if step.status == "success" else "tries to claim"
        return f"{actor} {verb} their payout from {contract}"
    if lower == "flagsurvived":
        return f"{actor} asks the moderator to mark {contract} as survived"
    if lower == "flagcorruptedgoodfaith":
        return f"{actor} asks the moderator to mark {contract} corrupted and name an attacker"
    if lower == "flagcorruptedbadfaith":
        return f"{actor} asks the moderator to mark {contract} corrupted for recovery"
    if lower == "setrecoveryaddress":
        return f"{actor} changes the recovery address to {_friendly_arg(args[0], actors) if args else 'unknown'}"
    if lower == "setexpiry":
        return f"{actor} changes the pool expiry to {_friendly_value(args[0]) if args else 'unknown'}"
    if lower == "setpoolscope":
        return f"{actor} changes the allowed pool scope to {_friendly_arg(args[0], actors) if args else '[]'}"
    if lower == "pokeriskwindow":
        return f"{actor} asks {contract} to check the external attack registry"
    return f"{actor} calls {contract}.{function}()"


def _friendly_action(step: Step, actors: list[Actor]) -> list[str]:
    actor = step.actor or "Caller"
    contract = _friendly_contract_name(step)
    function = str(step.function or "").split("(", 1)[0]
    args = ", ".join(_friendly_arg(x, actors) for x in step.args)
    lines = []

    call_text = f"{contract}.{function}({args})" if args else f"{contract}.{function}()"
    lines.append(f"{actor} {ARROW} {call_text}")

    lower = function.lower()

    # Explicit value transfer is rendered as a real asset edge, separate from
    # calldata. This prevents a payable call from looking like an ordinary function.
    if step.value_wei:
        lines.append(f"    ├─ sends {_friendly_eth(step.value_wei)} with the call")
        lines.append(f"    │       {actor} ── ETH ──▶ {contract}")

    # Address arguments often identify the second human actor in the story.
    address_args = [
        _actor_for_address(x, actors)
        for x in step.args
        if isinstance(x, str) and is_address(x)
    ]
    address_args = [x for x in address_args if x and x != actor]
    if address_args:
        lines.append(f"    ├─ destination / related actor: {address_args[0]}")

    if lower == "approve":
        lines.append(f"    └─ {actor} authorizes {contract} to spend tokens")
    elif lower in {"stake", "deposit", "contributebonus", "fund", "contribute"}:
        amount = _friendly_value(step.args[0]) if step.args else "the requested amount"
        lines.append(f"    ├─ token flow: {actor} ── {amount} ──▶ {contract}")
        lines.append(f"    ├─ requested amount: {amount}")
        lines.append("    └─ actual token movement/state writes are shown below when observed")
    elif lower in {
        "withdraw", "redeem", "refund", "collect",
        "claimsurvived", "claimcorrupted", "claimattackerbounty",
        "claimexpired",
    }:
        lines.append(f"    ├─ asset movement: {contract} ──▶ {actor}")
        lines.append("    └─ contract reduces / closes this actor's claimable position")
    elif lower.startswith("createpool"):
        lines.append("    ├─ factory creates a new pool")
        lines.append("    ├─ child pool is initialized")
        lines.append(f"    └─ {contract} now owns the next step in the flow")
    elif lower.startswith("flagoutcome"):
        lines.append("    ├─ outcome is recorded")
        lines.append("    └─ claim path is now determined by protocol state")
    elif lower.startswith("set") or lower in {"initialize", "configure", "register"}:
        lines.append("    └─ protocol configuration/state is updated")
    elif lower.startswith("poke"):
        lines.append("    └─ pool reads the external registry and updates its risk-window state")
    else:
        lines.append("    └─ contract state is evaluated and observed live")

    return lines



def _flatten_mapping_changes(change: dict[str, Any]) -> list[str]:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return []

    before_map = before.get("mapping")
    after_map = after.get("mapping")
    if not isinstance(before_map, dict) or not isinstance(after_map, dict):
        return []

    before_rows = {
        str(row.get("key")): row
        for row in before_map.get("rows", [])
        if isinstance(row, dict)
    }
    after_rows = {
        str(row.get("key")): row
        for row in after_map.get("rows", [])
        if isinstance(row, dict)
    }

    lines = []
    for key in sorted(set(before_rows) | set(after_rows))[:6]:
        old_row = before_rows.get(key)
        new_row = after_rows.get(key)
        if old_row is None or new_row is None:
            continue
        actor_key = key
        if is_address(key):
            actor_key = key
        old_value = old_row.get("value")
        new_value = new_row.get("value")
        if old_value != new_value and old_value is not None and new_value is not None:
            lines.append(
                f"{change.get('label', 'mapping')}[{actor_key}] : "
                f"{_friendly_value(old_value)} → {_friendly_value(new_value)}"
            )
        old_struct = old_row.get("struct")
        new_struct = new_row.get("struct")
        if isinstance(old_struct, dict) and isinstance(new_struct, dict):
            old_fields = {str(x.get("name")): x for x in old_struct.get("fields", []) if isinstance(x, dict)}
            new_fields = {str(x.get("name")): x for x in new_struct.get("fields", []) if isinstance(x, dict)}
            for field_name in sorted(set(old_fields) | set(new_fields))[:8]:
                old_field = old_fields.get(field_name, {})
                new_field = new_fields.get(field_name, {})
                if old_field.get("value") != new_field.get("value"):
                    lines.append(
                        f"{change.get('label', 'mapping')}[{actor_key}].{field_name} : "
                        f"{_friendly_value(old_field.get('value'))} → {_friendly_value(new_field.get('value'))}"
                    )
    return lines



def _snapshot_balances(rpc: str, addresses: list[str]) -> dict[str, int]:
    result: dict[str, int] = {}
    for address in dict.fromkeys(addresses):
        raw = _rpc_call(rpc, "eth_getBalance", [address, "latest"])
        try:
            result[address.lower()] = int(raw, 16)
        except (TypeError, ValueError):
            continue
    return result


def _snapshot_token_balances(rpc: str, token: str | None, addresses: list[str]) -> dict[str, int]:
    if not is_address(token):
        return {}
    result: dict[str, int] = {}
    for address in dict.fromkeys(addresses):
        code, out, _err = _cmd(["cast","call",token,"balanceOf(address)",address,"--rpc-url",rpc],timeout=8)
        if code != 0:
            continue
        raw = (out or "").strip().splitlines()
        if not raw:
            continue
        try:
            result[address.lower()] = int(raw[-1], 0)
        except (TypeError, ValueError):
            try:
                result[address.lower()] = int(raw[-1])
            except (TypeError, ValueError):
                pass
    return result


def _friendly_token_balance_lines(step: Step, actors: list[Actor]) -> list[str]:
    if not step.token_balance_before or not step.token_balance_after:
        return []
    names = {actor.address.lower(): actor.name for actor in actors}
    lines = []
    for address in sorted(set(step.token_balance_before) | set(step.token_balance_after)):
        before = step.token_balance_before.get(address)
        after = step.token_balance_after.get(address)
        if before is None or after is None or before == after:
            continue
        label = names.get(address, _addr(address))
        delta = after - before
        sign = "+" if delta > 0 else "-"
        lines.append(f"STAKE BALANCE {label}: {sign}{_friendly_value(abs(delta))}")
    return lines


def _friendly_balance_lines(step: Step, actors: list[Actor]) -> list[str]:
    if not step.balance_before or not step.balance_after:
        return []
    lines = []
    addresses = set(step.balance_before) | set(step.balance_after)
    names = {actor.address.lower(): actor.name for actor in actors}
    for address in addresses:
        before = step.balance_before.get(address)
        after = step.balance_after.get(address)
        if before is None or after is None:
            continue
        delta = after - before
        # Ignore tiny native-balance movement caused only by gas when this wasn't
        # a value-bearing call. Native value movement is rendered explicitly below.
        if not step.value_wei and abs(delta) < 10**12:
            continue
        if not step.value_wei and abs(delta) < 10**15:
            continue
        if delta == 0:
            continue
        label = names.get(address, _addr(address))
        direction = "+" if delta > 0 else "-"
        lines.append(f"ETH {label}: {direction}{_friendly_eth(abs(delta))}")
    return lines


def _friendly_state_lines(step: Step, actors: list[Actor]) -> list[str]:
    lines = []
    for change in step.storage_changes[:10]:
        label = str(change.get("label") or "state")
        nested = _flatten_mapping_changes(change)
        if nested:
            for item in nested[:6]:
                shown = item
                if is_address(shown.split("[", 1)[-1].split("]", 1)[0] if "[" in shown else ""):
                    address = shown.split("[", 1)[-1].split("]", 1)[0]
                    actor = _actor_for_address(address, actors)
                    if actor:
                        shown = shown.replace(address, actor, 1)
                lines.append("    ◆ " + shown)
            continue

        before = change.get("before")
        after = change.get("after")
        if isinstance(before, dict) and isinstance(after, dict):
            old = before.get("value")
            new = after.get("value")
            if old != new:
                lines.append(
                    f"    ◆ {label} : {_friendly_value(old)} → {_friendly_value(new)}"
                )
    return lines


def _friendly_event_lines(step: Step) -> list[str]:
    lines = []
    for event in step.events[:4]:
        if not isinstance(event, dict):
            continue
        name = event.get("event")
        if name:
            lines.append(f"    ✦ event: {name}")
    return lines


def _label_for_balance_address(address: str, step: Step, actors: list[Actor]) -> str:
    actor = _actor_for_address(address, actors)
    if actor:
        return actor
    if str(address).lower() == str(step.address).lower():
        return _friendly_contract_name(step)
    return _addr(address)



def _input_story(step: Step, model: ContractModel | None, actors: list[Actor]) -> list[str]:
    if not model:
        return []
    target = next(
        (item for item in model.abi if item.get("type") == "function" and _signature(item) == step.function),
        None,
    )
    if not target:
        return []

    lines: list[str] = []
    inputs = target.get("inputs") or []
    for index, param in enumerate(inputs):
        if index >= len(step.args):
            break
        label = str(param.get("name") or f"arg{index + 1}")
        value = _friendly_arg(step.args[index], actors)
        lines.append(f"{label} = {value}")

    return lines



def _render_interaction_graph_full(
    root: Path,
    step: Step,
    actors: list[Actor],
    model: ContractModel | None,
    models: list[ContractModel],
    enabled: bool,
) -> str:
    actor = step.actor or "Caller"
    contract = _friendly_contract_name(step)
    function = str(step.function or "").split("(", 1)[0]
    args = ", ".join(_friendly_arg(x, actors) for x in step.args) or "∅"
    linked_function = _function_link(root, model, function)
    status = "✓ SUCCESS" if step.status == "success" else "✕ BLOCKED" if step.status in {"blocked", "reverted"} else "● CHECKING"
    color = GREEN if step.status == "success" else RED if step.status in {"blocked", "reverted"} else YELLOW

    lines = [
        _paint(f"  ╭─ FUNCTION {step.index:02d}  {status}", color, enabled),
        "  │",
        f"  │   { _human_action_summary(step, actors) }",
        f"  │   [{actor}] ── CALL {linked_function}({args}) ──▶ [{contract}]",
        "  │                              │",
    ]

    if step.value_wei:
        lines += [
            f"  │                              ├─ sends {_friendly_eth(step.value_wei)}",
            f"  │                              │      [{actor}] ── ETH ──▶ [{contract}]",
        ]

    input_lines = _input_story(step, model, actors)
    for item in input_lines[:8]:
        lines.append(f"  │                              ├─ input: {item}")

    related = [
        _actor_for_address(value, actors)
        for value in step.args
        if isinstance(value, str) and is_address(value)
    ]
    related = [name for name in related if name and name != actor]
    if related:
        lines.append(f"  │                              ├─ references [{related[0]}]")

    if step.execution_edges:
        lines.append("  │                              │")
        for edge in step.execution_edges[:7]:
            dst = edge.get("to_contract") or _addr(edge.get("to_address"))
            fn = str(edge.get("function") or "")
            lines.append(
                f"  │                              ├─ {contract} ──▶ "
                f"{dst}.{fn}  [{edge.get('type') or 'CALL'}]"
            )

    if step.discovered_contracts:
        for node in step.discovered_contracts[:4]:
            lines.append(
                f"  │                              ├─ CREATE2 ──▶ "
                f"{node.get('label') or node.get('model')} {_addr(node.get('address'))}"
            )

    if step.status == "success":
        state_lines = _friendly_state_lines(step, actors)
        balance_lines = _friendly_token_balance_lines(step, actors) + _friendly_balance_lines(step, actors)
        event_lines = _friendly_event_lines(step)
        for item in state_lines[:6]:
            lines.append(f"  │                              ├─ STATE: {item.strip()[2:] if item.strip().startswith('◆ ') else item.strip()}")
        for item in balance_lines[:4]:
            lines.append(f"  │                              ├─ BALANCE: {item.strip()}")
        for item in event_lines[:3]:
            lines.append(f"  │                              ├─ {item.strip()}")
        if not state_lines and not balance_lines and not event_lines:
            lines.append("  │                              └─ live state checked; no tracked delta")
    elif step.status in {"blocked", "reverted"}:
        reason = step.error_reason or _explain_failure(step, step.error, actor)
        lines.append(f"  │                              ├─ WHY IT FAILED: {reason}")
        if step.failure_origin:
            lines.append(f"  │                              ├─ LIKELY ORIGIN: {step.failure_origin}")
        for diagnosis in step.diagnostics[:4]:
            lines.append(f"  │                              ├─ {diagnosis}")
        lines.append(f"  │                              └─ {_short_error(step.error)}")

    lines.append("  │")
    if step.reason:
        marker = "INFERRED" if step.inferred else "LAB CONTROL"
        lines.append(f"  │   WHY THIS STEP: {step.reason}  [{marker}]")
    lines.append(f"  ╰{'─' * 86}╯")
    return "\n".join(lines)



def _render_protocol_story_full(
    root: Path,
    steps: list[Step],
    current: Step | None,
    actors: list[Actor],
    models: list[ContractModel],
    enabled: bool,
) -> str:
    lines = [_paint("PROTOCOL STORY", BOLD + CYAN, enabled)]
    if not steps and not current:
        return "\n".join(lines + [
            "  SYSTEM READY",
            "       │",
            "       ▼",
            "  Press Enter to execute the first live interaction.",
        ])

    visible = list(steps[-6:])
    if current is not None and current not in visible:
        visible.append(current)

    for index, step in enumerate(visible):
        last = index == len(visible) - 1
        if current is step or last:
            model = next((m for m in models if m.name == step.contract), None)
            frame = _render_interaction_graph_full(root, step, actors, model, models, enabled)
            if current is step:
                frame += "\n  ◀ NOW"
            lines.append(frame)
        else:
            icon = "✓" if step.status == "success" else "✕" if step.status in {"blocked", "reverted"} else "●"
            status = "done" if step.status == "success" else "blocked" if step.status in {"blocked", "reverted"} else "checked"
            args = ", ".join(_friendly_arg(x, actors) for x in step.args) or "∅"
            fn = str(step.function or "").split("(", 1)[0]
            step_model = next((m for m in models if m.name == step.contract), None)
            linked = _function_link(root, step_model, fn)
            lines.append(f"  STEP {step.index:02d} {icon} [{step.actor}] ──▶ {_friendly_contract_name(step)}.{linked}({args}) • {status}")
            lines.append("       │")
            lines.append("       ▼")
    return "\n".join(lines)



def _render_interaction_graph(
    *args: Any,
    **kwargs: Any,
) -> str:
    # Legacy API: (step, actors, enabled=False)
    # Rich API:   (root, step, actors, model, models, enabled)
    if args and isinstance(args[0], Step):
        step = args[0]
        actors = args[1] if len(args) > 1 else []
        enabled = args[2] if len(args) > 2 else bool(kwargs.get("enabled", False))
        root = Path.cwd()
        model = kwargs.get("model")
        models = kwargs.get("models") or []
    else:
        root, step, actors, model, models, enabled = args[:6]
    return _render_interaction_graph_full(root, step, actors, model, models, enabled)


def _render_protocol_story(
    *args: Any,
    **kwargs: Any,
) -> str:
    # Legacy API: (steps, current, actors, enabled=False)
    # Rich API:   (root, steps, current, actors, models, enabled)
    if args and isinstance(args[0], (str, Path)):
        root, steps, current, actors, models, enabled = args[:6]
    else:
        steps, current, actors = args[:3]
        enabled = kwargs.get("enabled", args[3] if len(args) > 3 else False)
        root = Path.cwd()
        models = []
    return _render_protocol_story_full(root, steps, current, actors, models, enabled)


def _render_pseudocode_flow(steps: list[Step], current: Step | None, enabled: bool) -> str:
    return _render_protocol_story(steps, current, [], enabled)

def _wait_for_next_interaction(no_prompt: bool) -> str:
    if no_prompt:
        return ""
    if not sys.stdin.isatty():
        try:
            return input("\n  ⏎ next  |  q stop  ").strip().lower()
        except EOFError:
            return ""
    fd=None
    old=None
    try:
        import termios
        fd=sys.stdin.fileno()
        old=termios.tcgetattr(fd)
        new=termios.tcgetattr(fd)
        new[3] &= ~(termios.ECHO | termios.ICANON)
        new[6][termios.VMIN]=1
        new[6][termios.VTIME]=0
        termios.tcsetattr(fd,termios.TCSADRAIN,new)
        sys.stdout.write("\n  ⏎ next  |  q stop  ")
        sys.stdout.flush()
        return os.read(fd,1).decode(errors="ignore").lower()
    except Exception:
        try:
            return input("\n  ⏎ next  |  q stop  ").strip().lower()
        except EOFError:
            return ""
    finally:
        if fd is not None and old is not None:
            try:
                termios.tcsetattr(fd,termios.TCSADRAIN,old)
            except Exception:
                pass



_SELECTOR_CACHE: dict[str, str] = {}


def _selector_for(signature: str) -> str | None:
    cached = _SELECTOR_CACHE.get(signature)
    if cached:
        return cached
    code, out, _err = _cmd(["cast", "sig", signature], timeout=5)
    if code != 0:
        return None
    lines = (out or "").strip().splitlines()
    selector = lines[-1].strip().lower() if lines else None
    if selector:
        _SELECTOR_CACHE[signature] = selector
    return selector


def _selector_maps(models: list[ContractModel]) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    for model in models:
        for signature in model.functions:
            selector = _selector_for(signature)
            if selector:
                found[selector] = (model.name, signature)
    return found


def _trace_execution_edges(
    root: Path,
    rpc: str,
    models: list[ContractModel],
    trace: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if not trace:
        return []
    selector_map = _selector_maps(models)
    result: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], depth: int = 0, caller_contract: str | None = None) -> None:
        if not isinstance(node, dict):
            return
        typ = str(node.get("type") or "CALL").upper()
        to = node.get("to")
        inp = str(node.get("input") or node.get("data") or "")
        selector = inp[:10].lower() if inp.startswith("0x") and len(inp) >= 10 else ""
        known_contract, signature = selector_map.get(selector, (None, None))
        if isinstance(to, str) and is_address(to):
            if not known_contract:
                matched, _impl = _match_runtime_model(root, rpc, models, to)
                known_contract = matched if matched != "External" else None
            result.append({
                "type": typ,
                "to_address": to,
                "from_contract": caller_contract or "caller",
                "to_contract": known_contract or _addr(to),
                "function": signature or selector or typ,
                "depth": depth,
                "error": node.get("error"),
                "revert": node.get("revertReason"),
            })
        child_contract = known_contract or caller_contract
        for child in node.get("calls") or []:
            walk(child, depth + 1, child_contract)

    walk(trace)
    return result[:32]


def _dependency_diagnostics(
    root: Path,
    rpc: str,
    step: Step,
    model: ContractModel,
) -> tuple[str | None, list[str]]:
    diagnostics: list[str] = []
    origin: str | None = None
    names = (
        "registry", "implementation", "moderator", "token", "agreement",
        "recovery", "owner", "router", "oracle", "manager", "factory",
    )
    for item in model.abi:
        if item.get("type") != "function" or item.get("inputs"):
            continue
        if not any(token in str(item.get("name") or "").lower() for token in names):
            continue
        outputs = item.get("outputs") or []
        if not outputs or str(outputs[0].get("type") or "") != "address":
            continue
        code, out, err = _cmd(
            ["cast", "call", step.address, _signature(item), "--rpc-url", rpc],
            timeout=6,
        )
        if code != 0:
            continue
        values = (out or err or "").strip().splitlines()
        value = values[-1].strip() if values else ""
        if not is_address(value):
            continue
        zero = value.lower() == "0x" + "00" * 20
        diagnostics.append(
            f"dependency {item.get('name')} = {_addr(value)} "
            + ("✕ UNSET" if zero else "✓ configured")
        )
        if zero and origin is None:
            origin = f"{model.name} → {item.get('name')}() → unconfigured address"

    return origin, diagnostics


def _diagnose_failed_call(
    root: Path,
    rpc: str,
    step: Step,
    model: ContractModel,
    models: list[ContractModel],
) -> tuple[str | None, list[str]]:
    origin, diagnostics = _dependency_diagnostics(root, rpc, step, model)
    try:
        code, calldata, _err = _cmd(
            ["cast", "calldata", step.function, *[_cli_arg(x) for x in step.args]],
            timeout=6,
        )
        if code == 0 and calldata:
            trace = _rpc_call(
                rpc,
                "debug_traceCall",
                [{
                    "from": step.address,
                    "to": step.address,
                    "data": calldata,
                    "value": hex(int(step.value_wei or 0)),
                }, {"tracer": "callTracer", "timeout": "10s"}],
            )
            edges = _trace_execution_edges(root, rpc, models, trace)
            for edge in edges[:8]:
                target = edge.get("to_contract") or _addr(edge.get("to_address"))
                fn = edge.get("function") or edge.get("type")
                diagnostics.append(f"call path: {target}.{fn} [{edge.get('type')}]")
            failed = next((edge for edge in reversed(edges) if edge.get("error") or edge.get("revert")), None)
            if failed:
                target = failed.get("to_contract") or _addr(failed.get("to_address"))
                fn = failed.get("function") or "unknown()"
                origin = origin or f"{model.name} → {target}.{fn}"
                if failed.get("revert"):
                    diagnostics.append(f"dependency returned: {failed.get('revert')}")
        else:
            diagnostics.append("revert tracing could not encode the failing calldata")
    except Exception as exc:
        diagnostics.append(f"revert trace unavailable: {exc}")
    return origin, list(dict.fromkeys(diagnostics))


def _preflight(rpc: str, step: Step, actor_address: str | None = None) -> tuple[bool, str]:
    try:
        command=["cast","call",step.address,step.function,*[_cli_arg(x) for x in step.args],"--rpc-url",rpc]
        if actor_address:
            command += ["--from",actor_address]
        if step.value_wei:
            command += ["--value",str(step.value_wei)]
        code,out,err=_cmd(command,timeout=10)
        text=(out or err or "").strip()
        return code==0,text[-1200:] or ("eth_call succeeded" if code==0 else "eth_call reverted")
    except Exception as exc:
        return False,str(exc)


    try:
        code, out, err = _cmd(
            ["cast","call",step.address,step.function,*[
                _cli_arg(x)
                for x in step.args
            ],"--rpc-url",rpc] + (["--value",str(step.value_wei)] if step.value_wei else []),
            timeout=10,
        )
        text=(out or err or "").strip()
        return code == 0, text[-1200:] or ("eth_call succeeded" if code==0 else "eth_call reverted")
    except Exception as exc:
        return False, str(exc)

def _cast_json(host: Any, args: list[str], config: dict[str, Any]) -> Any:
    # Prefer the already-integrated Lowkey cast wrapper; fall back to subprocess.
    if hasattr(host, "cast_output"):
        code, out, _err = host.cast_output(args)
        if code == 0:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return out.strip()
        return None
    rpc = config.get("rpc") or ""
    code, out, _err = _cmd(["cast", *args] + (["--rpc-url", rpc] if rpc else []))
    if code != 0:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return out.strip()


def _actor_rpc_setup(rpc: str, address: str) -> None:
    _rpc_call(rpc, "anvil_impersonateAccount", [address])
    _rpc_call(rpc, "anvil_setBalance", [address, hex(10**20)])


def _send(host: Any, config: dict[str, Any], actor: Actor, target: str, signature: str, args: list[Any], value: int) -> tuple[str | None, str]:
    rpc = config.get("rpc") or getattr(host, "effective_rpc", lambda c: None)(config)
    if not rpc:
        return None, "no RPC"
    _actor_rpc_setup(rpc, actor.address)

    encoded_args = [_cli_arg(x) for x in args]
    command = [
        "send", target, signature, *encoded_args,
        "--rpc-url", rpc,
        "--unlocked", "--from", actor.address,
    ]
    if value:
        command += ["--value", str(value)]
    if hasattr(host, "run_cast"):
        # run_cast understands configured actors but --from is kept explicit for
        # impersonated local accounts.
        code, out, err = _cmd(["cast", *command])
    else:
        code, out, err = _cmd(["cast", *command])
    if code != 0:
        return None, (err or out).strip()[-1200:]
    tx = _extract_tx_hash(out)
    return tx, (out or "").strip()


def _prepare_lab_allowance(
    host: Any,
    config: dict[str, Any],
    actor: Actor,
    pool_address: str,
    token_address: str,
    rpc: str,
    steps: list[Step],
) -> Step | None:
    """Make the local mock token usable and record that prerequisite as a live step."""
    if not is_address(token_address) or not is_address(pool_address):
        return None
    code, out, _err = _cmd([
        "cast", "call", token_address,
        "allowance(address,address)",
        actor.address, pool_address,
        "--rpc-url", rpc,
    ], timeout=10)
    allowance_value = 0
    if code == 0:
        raw = (out or "").strip().splitlines()
        if raw:
            try:
                allowance_value = int(raw[-1], 0)
            except ValueError:
                allowance_value = 0
    if allowance_value > 0:
        return None

    amount = 2**256 - 1
    tx, output = _send(
        host, config, actor, token_address,
        "approve(address,uint256)", [pool_address, amount], 0,
    )
    step = Step(
        index=len(steps) + 1,
        actor=actor.name,
        contract="StakeToken",
        address=token_address,
        function="approve(address,uint256)",
        args=[pool_address, amount],
        reason="local lab prerequisite for pool staking",
        inferred=False,
        status="success" if tx else "reverted",
        tx_hash=tx,
        calldata=_transaction_input(rpc,tx) if tx else None,
        error=None if tx else (output or "token approval failed"),
    )
    steps.append(step)
    return step

def _extract_tx_hash(text: str) -> str | None:
    matches = re.findall(r"0x[0-9a-fA-F]{64}", text or "")
    return matches[-1] if matches else None


def _transaction_input(rpc: str, tx: str) -> str | None:
    """Return the exact calldata sent by a successful transaction."""
    value = _rpc_call(rpc, "eth_getTransactionByHash", [tx])
    if not isinstance(value, dict):
        return None
    data = value.get("input") or value.get("data")
    if not isinstance(data, str) or not re.fullmatch(r"0x[0-9a-fA-F]*", data):
        return None
    return data

def _quarantine_generated_replays(root: Path) -> int:
    """Move stale generated walkthrough scripts out of script/ before forge build."""
    script_dir = root / "script"
    if not script_dir.is_dir():
        return 0
    candidates = sorted(script_dir.glob("LowkeyWalkthrough_*.s.sol"))
    if not candidates:
        return 0
    archive = root / ".audit" / "walkthrough" / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    moved = 0
    for path in candidates:
        target = archive / path.name
        try:
            if target.exists():
                target = archive / f"{path.stem}_{int(time.time())}{path.suffix}"
            shutil.move(str(path), str(target))
            moved += 1
        except OSError:
            continue
    return moved

def _receipt(rpc: str, tx: str) -> dict[str, Any] | None:
    value = _rpc_call(rpc, "eth_getTransactionReceipt", [tx])
    return value if isinstance(value, dict) else None


def _block_timestamp(rpc: str) -> int:
    block = _rpc_call(rpc, "eth_getBlockByNumber", ["latest", False])
    try:
        return int(block["timestamp"], 16)
    except Exception:
        return int(time.time())


def _balance(rpc: str, address: str) -> str:
    value = _rpc_call(rpc, "eth_getBalance", [address, "latest"])
    try:
        return str(int(value, 16))
    except Exception:
        return "0"


def _storage_read(rpc: str, address: str, slot: str) -> str:
    value = _rpc_call(rpc, "eth_getStorageAt", [address, hex(int(slot, 0) if str(slot).startswith("0x") else int(str(slot))), "latest"])
    return str(value or "0x" + "00" * 32)


def _extract_packed(word: str, offset: int = 0, size: int = 32) -> str:
    raw = (word or "").lower().removeprefix("0x").rjust(64, "0")
    start = max(0, 64 - (offset + size) * 2)
    end = 64 - offset * 2 if offset else 64
    return "0x" + raw[start:end].rjust(size * 2, "0")


def _decode_word(word: str, typ: str, offset: int = 0, size: int = 32) -> Any:
    raw = _extract_packed(word, offset, size).removeprefix("0x").rjust(size * 2, "0")
    try:
        if typ == "address":
            return "0x" + raw[-40:]
        if typ == "bool":
            return int(raw, 16) != 0
        if typ.startswith(("uint", "int")):
            value = int(raw, 16)
            bits = max(8, size * 8)
            if typ.startswith("int") and value >= 1 << (bits - 1):
                value -= 1 << bits
            return value
        return "0x" + raw
    except Exception:
        return "0x" + raw


def _snapshot_storage(model: ContractModel, rpc: str, address: str, actor_addresses: list[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    entries = model.storage.get("storage") or []
    types = model.storage.get("types") or {}

    def type_info(type_id: str) -> dict[str, Any]:
        return types.get(type_id, {}) if type_id else {}

    def type_label(type_id: str) -> str:
        info = type_info(type_id)
        return str(info.get("label") or type_id or "bytes32")

    for entry in entries[:64]:
        slot = str(entry.get("slot", "0"))
        typ = str(entry.get("type") or "")
        info = type_info(typ)
        label = str(entry.get("label") or "slot")
        encoding = info.get("encoding")
        item = {
            "label": label,
            "slot": slot,
            "type": type_label(typ),
            "encoding": encoding,
        }

        if encoding == "mapping":
            key_type = str(info.get("key") or "")
            value_type = str(info.get("value") or "")
            value_info = type_info(value_type)
            mapping = {
                "key_type": type_label(key_type),
                "value_type": type_label(value_type),
                "rows": [],
            }
            keys: list[str] = []
            key_label = type_label(key_type)
            if key_label == "address":
                keys = actor_addresses[:4]
            elif key_label.startswith("uint") or key_label.startswith("int"):
                keys = ["0", "1"]
            elif key_label == "bytes32":
                keys = ["0x" + "00" * 32]
            for key in keys:
                code, out, _err = _cmd(["cast", "index", key_label, key, slot], timeout=5)
                if code != 0:
                    continue
                mapped_slot = out.strip().splitlines()[-1].strip()
                row = {"key": key, "slot": mapped_slot}
                if value_info.get("members"):
                    fields = []
                    for member in value_info.get("members", [])[:24]:
                        member_slot = int(mapped_slot, 0) + int(member.get("slot", 0))
                        member_info = type_info(str(member.get("type") or ""))
                        member_word = _storage_read(rpc, address, str(member_slot))
                        fields.append({
                            "name": member.get("label") or member.get("name") or "field",
                            "type": type_label(str(member.get("type") or "")),
                            "slot": str(member_slot),
                            "value": _decode_word(
                                member_word,
                                type_label(str(member.get("type") or "")),
                                int(member.get("offset", 0)),
                                int(member_info.get("numberOfBytes", 32) or 32),
                            ),
                        })
                    row["struct"] = {"type": type_label(value_type), "fields": fields}
                else:
                    word = _storage_read(rpc, address, mapped_slot)
                    row["value"] = _decode_word(
                        word,
                        type_label(value_type),
                        0,
                        int(value_info.get("numberOfBytes", 32) or 32),
                    )
                mapping["rows"].append(row)
            item["mapping"] = mapping

        elif encoding == "inplace":
            word = _storage_read(rpc, address, slot)
            item["value"] = _decode_word(
                word,
                type_label(typ),
                int(entry.get("offset", 0) or 0),
                int(info.get("numberOfBytes", 32) or 32),
            )
            members = info.get("members") or []
            if members:
                fields = []
                for member in members[:24]:
                    member_slot = int(slot) + int(member.get("slot", 0))
                    member_type = str(member.get("type") or "")
                    member_info = type_info(member_type)
                    member_word = _storage_read(rpc, address, str(member_slot))
                    fields.append({
                        "name": member.get("label") or member.get("name") or "field",
                        "type": type_label(member_type),
                        "slot": str(member_slot),
                        "offset": int(member.get("offset", 0) or 0),
                        "value": _decode_word(
                            member_word,
                            type_label(member_type),
                            int(member.get("offset", 0) or 0),
                            int(member_info.get("numberOfBytes", 32) or 32),
                        ),
                    })
                item["struct"] = {"type": type_label(typ), "fields": fields}

        else:
            # Dynamic bytes/string/array values still expose their anchor slot.
            word = _storage_read(rpc, address, slot)
            item["value"] = word

        result.append(item)
    return result


def _snapshot_runtime(
    runtime: list[RuntimeContract],
    models: list[ContractModel],
    rpc: str,
    actor_addresses: list[str],
) -> list[dict[str, Any]]:
    by_name = {model.name: model for model in models}
    result: list[dict[str, Any]] = []
    for node in runtime:
        model = by_name.get(node.model)
        if not model:
            continue
        for item in _snapshot_storage(model, rpc, node.address, actor_addresses):
            item["contract"] = node.model
            item["address"] = node.address
            result.append(item)
    return result


def _storage_changed(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key = {(str(x.get("slot")), str(x.get("label"))): x for x in before}
    changes = []
    for item in after:
        key = (str(item.get("slot")), str(item.get("label")))
        old = by_key.get(key)
        if old and old != item:
            changes.append({"label": item.get("label"), "slot": item.get("slot"), "before": old, "after": item})
    return changes


def _trace_edges(rpc: str, tx: str) -> list[str]:
    code, out, _err = _cmd(["cast", "run", tx, "--rpc-url", rpc], timeout=20)
    if code != 0:
        return []
    edges = []
    for line in out.splitlines():
        s = line.strip()
        if any(kind in s for kind in ("CALL", "STATICCALL", "DELEGATECALL", "CREATE", "CREATE2")):
            if len(s) > 180:
                s = s[-180:]
            edges.append(s)
    return edges[-24:]


def _trace_tree(rpc: str, tx: str) -> dict[str, Any] | None:
    value = _rpc_call(rpc, "debug_traceTransaction", [tx, {"tracer": "callTracer", "timeout": "20s"}])
    return value if isinstance(value, dict) else None


def _artifact_runtime_code(root: Path, model: ContractModel) -> str:
    data=_json_file(root/model.artifact) or {}
    bytecode=data.get("deployedBytecode")
    return str(bytecode.get("object") if isinstance(bytecode,dict) else bytecode or "")


def _runtime_code(rpc: str, address: str) -> str:
    return str(_rpc_call(rpc,"eth_getCode",[address,"latest"]) or "")


def _normalize_code(value: str) -> str:
    return re.sub(r"^0x","",str(value or "")).lower()


def _clone_impl(code: str) -> str | None:
    raw=_normalize_code(code)
    if raw.startswith("363d3d373d3d3d363d73") and len(raw)>=60:
        candidate=raw[20:60]
        if re.fullmatch(r"[0-9a-f]{40}",candidate):
            return "0x"+candidate
    return None


def _match_runtime_model(root: Path, rpc: str, models: list[ContractModel], address: str) -> tuple[str,str|None]:
    code=_runtime_code(rpc,address)
    if code in {"","0x"}: return "External",None
    normalized=_normalize_code(code)
    for model in models:
        expected=_normalize_code(_artifact_runtime_code(root,model))
        if expected and normalized==expected: return model.name,None
    impl=_clone_impl(code)
    if impl:
        impl_code=_normalize_code(_runtime_code(rpc,impl))
        for model in models:
            expected=_normalize_code(_artifact_runtime_code(root,model))
            if expected and impl_code==expected: return model.name,impl
    return "External",impl


def _trace_addresses(trace: dict[str,Any]|None) -> list[tuple[str,str,str|None]]:
    found=[]
    def walk(node):
        if not isinstance(node,dict): return
        typ=str(node.get("type") or "CALL").upper()
        if typ in {"CREATE","CREATE2"}:
            created=node.get("result") or node.get("to")
            if isinstance(created,str) and re.fullmatch(r"0x[0-9a-fA-F]{40}",created):
                found.append((created,typ,node.get("from")))
        target=node.get("to")
        if isinstance(target,str) and re.fullmatch(r"0x[0-9a-fA-F]{40}",target):
            found.append((target,typ,node.get("from")))
        for child in node.get("calls") or []: walk(child)
    walk(trace); return found


def _discover_runtime_contracts(root: Path, rpc: str, models: list[ContractModel], known: list[RuntimeContract], receipt: dict[str,Any]|None, trace: dict[str,Any]|None, step_index: int, parent: str) -> list[RuntimeContract]:
    candidates=_trace_addresses(trace)
    for log in (receipt or {}).get("logs",[]):
        address=log.get("address")
        if isinstance(address,str) and re.fullmatch(r"0x[0-9a-fA-F]{40}",address):
            candidates.append((address,"EVENT",parent))
    existing={x.address.lower() for x in known}; result=[]
    for address,relation,origin in candidates:
        if address.lower() in existing: continue
        code=_runtime_code(rpc,address)
        if code in {"","0x"}: continue
        model_name,impl=_match_runtime_model(root,rpc,models,address)
        siblings=sum(1 for x in known+result if x.model==model_name)
        label=model_name if model_name!="External" else "External"
        if model_name!="External" and siblings: label += f" #{siblings+1}"
        result.append(RuntimeContract(address,model_name,label,"CLONE" if impl else relation,origin or parent,step_index,impl))
        existing.add(address.lower())
    return result

def _event_rows(host: Any, config: dict[str, Any], receipt: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not receipt:
        return []
    result = []
    for log in receipt.get("logs", []):
        decoded = None
        try:
            if hasattr(host, "decode_event_log"):
                decoded = host.decode_event_log(config, log)
        except Exception:
            decoded = None
        result.append(decoded or {
            "address": log.get("address"),
            "topics": log.get("topics", []),
            "data": log.get("data", "0x"),
        })
    return result


def _models_payload(models: list[ContractModel]) -> list[dict[str, Any]]:
    return [asdict(m) for m in models]


def _save_artifacts(root: Path, model_payload: dict[str, Any], steps: list[Step]) -> None:
    directory = root / ".audit" / "walkthrough"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "model.json").write_text(json.dumps(model_payload, indent=2, default=str) + "\n", encoding="utf-8")
    (directory / "latest.json").write_text(
        json.dumps({
            "version": model_payload.get("version", 2),
            "steps": [asdict(x) for x in steps],
            "runtime_contracts": model_payload.get("runtime_contracts", []),
            "observed_inputs": model_payload.get("observed_inputs", {}),
        }, indent=2, default=str) + "\n",
        encoding="utf-8",
    )

def _sol_address_literal(value: Any) -> str:
    """Emit an address literal without Solidity checksum rules."""
    raw = str(value or "").strip()
    if not is_address(raw):
        return "address(0)"
    return f"address(uint160(0x{raw[2:]}))"


def _sol_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_sol_literal(item) for item in value) + "]"
    if isinstance(value, str):
        if is_address(value):
            return _sol_address_literal(value)
        if value.startswith("0x") and len(value) == 66:
            return f"bytes32(0x{value[2:]})"
        return json.dumps(value)
    return "0"



def _rpc_snapshot(rpc: str) -> str | None:
    value = _rpc_call(rpc, "evm_snapshot", [])
    return str(value) if value is not None else None


def _rpc_revert(rpc: str, snapshot: str | None) -> bool:
    if snapshot is None:
        return False
    return bool(_rpc_call(rpc, "evm_revert", [snapshot]))


def _random_sol_value(
    param: dict[str, Any],
    actors: list[Actor],
    target: str,
    rng: random.Random,
) -> Any:
    raw_type = str(param.get("type") or "")
    typ = _canonical_type(param)
    name = str(param.get("name") or "").lower()

    if typ == "address":
        pool = [a.address for a in actors] + [target, "0x" + "00" * 20]
        if any(token in name for token in ("recipient", "receiver", "to", "user", "owner", "moderator")) and len(actors) > 1:
            pool = [actors[1].address, actors[0].address] + pool
        if any(token in name for token in ("attacker", "malicious")) and len(actors) > 2:
            pool.insert(0, actors[2].address)
        return rng.choice(pool)

    if typ == "bool":
        return rng.choice([False, True])

    if typ.startswith("uint"):
        bits_text = re.sub(r"[^0-9]", "", typ)
        bits = int(bits_text or "256")
        maximum = (1 << min(bits, 256)) - 1
        return rng.choice([0, 1, maximum, rng.randrange(0, min(maximum, 10**18) + 1)])

    if typ.startswith("int"):
        bits_text = re.sub(r"[^0-9]", "", typ)
        bits = int(bits_text or "256")
        magnitude = (1 << max(1, min(bits, 256) - 1)) - 1
        return rng.choice([-magnitude - 1, -1, 0, 1, magnitude])

    if typ == "bytes32":
        return "0x" + rng.randbytes(32).hex()

    if typ == "bytes":
        return "0x" + rng.randbytes(rng.randint(0, 48)).hex()

    if typ == "string":
        return rng.choice(["", "lowkey", "A" * 32, "0xdeadbeef"])

    if raw_type.startswith("tuple") and not raw_type.endswith("[]"):
        return [_random_sol_value(component, actors, target, rng) for component in param.get("components", [])]

    if raw_type.endswith("[]"):
        base = dict(param)
        base["type"] = raw_type[:-2]
        return [_random_sol_value(base, actors, target, rng) for _ in range(rng.randint(0, 4))]

    return 0


def _adversarial_functions(model: ContractModel) -> list[dict[str, Any]]:
    return [
        item for item in model.abi
        if item.get("type") == "function"
        and item.get("name")
        and item.get("stateMutability") not in {"view", "pure"}
        and not any(token in str(item.get("name") or "").lower() for token in ("upgrade", "selfdestruct"))
    ]



def _system_test_targets(
    config: dict[str, Any],
    target: str,
    model: ContractModel,
    models: list[ContractModel],
) -> list[tuple[str, str, ContractModel]]:
    """Collect live application instances known to this audit lab."""
    result: list[tuple[str, str, ContractModel]] = []
    seen: set[tuple[str, str]] = set()

    def add(label: str, address: Any, contract_name: str | None) -> None:
        if not is_address(address):
            return
        candidate = None
        for item in models:
            if contract_name and item.name.lower() == str(contract_name).lower():
                candidate = item
                break
        if candidate is None and contract_name:
            candidate = next((item for item in models if str(contract_name).lower() in item.name.lower()), None)
        if candidate is None:
            return
        # Never fuzz implementation-only initializer bytecode as a live instance.
        runtime_address = str(address)
        key = (candidate.name.lower(), runtime_address.lower())
        if key in seen:
            return
        seen.add(key)
        result.append((label, runtime_address, candidate))

    add(model.name, target, model.name)

    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    known_names = {
        "factory": "ConfidencePoolFactory",
        "pool": "ConfidencePool",
        "pool_implementation": "ConfidencePool",
    }
    for key, address in system.items():
        if key not in known_names:
            continue
        if key == "pool_implementation":
            # The implementation is not a live protocol instance; the clone is.
            continue
        add(key, address, known_names[key])

    return result



def _run_adversarial_test(
    root: Path,
    config: dict[str, Any],
    host: Any,
    target: str,
    model: ContractModel,
    models: list[ContractModel],
    actors: list[Actor],
    rpc: str,
    total_cases: int,
    seed: int | None,
    system_targets: list[tuple[str, str, ContractModel]] | None = None,
) -> int:
    actual_seed = seed if seed is not None else int(time.time())
    rng = random.Random(actual_seed)
    targets = system_targets or [(model.name, target, model)]
    targets = [item for item in targets if _adversarial_functions(item[2])]

    if not targets:
        print("No mutating functions available for adversarial testing.")
        return 0

    total_cases = max(1, min(200, int(total_cases)))
    results: list[Step] = []

    print(_paint("LOWKEY // ADVERSARIAL WALKTHROUGH TEST", BOLD + MAGENTA, _ansi_enabled(False)))
    print(f"  system : {len(targets)} application instance(s)")
    print("  engine : random arguments → SEND → trace → diagnose → restore")
    print(f"  seed   : {actual_seed}")
    print("")

    schedules: list[tuple[str, str, ContractModel, dict[str, Any]]] = []
    for label, address, target_model in targets:
        functions = list(_adversarial_functions(target_model))
        rng.shuffle(functions)
        for fn in functions:
            schedules.append((label, address, target_model, fn))
    rng.shuffle(schedules)

    for index in range(1, total_cases + 1):
        label, active_target, active_model, fn = schedules[(index - 1) % len(schedules)]
        actor = rng.choice(actors) if actors else Actor("Alice", active_target, 0)
        args = [_random_sol_value(param, actors, active_target, rng) for param in fn.get("inputs", [])]
        value = rng.choice([0, 1, 10**6, 10**15, 10**18]) if fn.get("stateMutability") == "payable" else 0

        step = Step(
            index=index,
            actor=actor.name,
            contract=active_model.name,
            address=active_target,
            function=_signature(fn),
            args=args,
            value_wei=value,
            reason="randomized adversarial probe",
            inferred=False,
        )

        snapshot = _rpc_snapshot(rpc)
        if snapshot is None:
            print("Error: Anvil did not provide an evm_snapshot; aborting adversarial test.", file=sys.stderr)
            return 1

        tx, output = _send(host, config, actor, active_target, step.function, args, value)
        step.tx_hash = tx

        if tx:
            receipt = _receipt(rpc, tx)
            trace = _trace_tree(rpc, tx)
            step.status = "success" if receipt and receipt.get("status") in (None, "0x1", 1) else "reverted"
            step.events = _event_rows(host, config, receipt)
            step.execution_edges = _trace_execution_edges(root, rpc, models, trace)
            if step.status != "success":
                step.error = output or "transaction reverted"
        else:
            step.status = "reverted"
            step.error = output or "transaction was rejected"

        if step.status != "success":
            step.error_reason = _explain_failure(step, step.error, actor.name)
            step.failure_origin, step.diagnostics = _diagnose_failed_call(root, rpc, step, active_model, models, actor.address)

        results.append(step)

        linked = _function_link(root, active_model, str(step.function).split("(", 1)[0])
        shown_args = ", ".join(_friendly_arg(value, actors) for value in args) or "∅"
        marker = "✓" if step.status == "success" else "✕"
        color = GREEN if step.status == "success" else RED
        print(_paint(
            f"  {index:02d} {marker} {label}: [{actor.name}] ──▶ {active_model.name}.{linked}({shown_args})",
            color,
            _ansi_enabled(False),
        ))
        if step.error_reason:
            print(f"     ↳ {step.error_reason}")
        if step.failure_origin:
            print(f"     ↳ origin: {step.failure_origin}")
        for diagnostic in step.diagnostics[:2]:
            print(f"     ↳ {diagnostic}")

        if not _rpc_revert(rpc, snapshot):
            print("     ⚠ Anvil snapshot could not be restored; aborting.", file=sys.stderr)
            return 1

    accepted = sum(item.status == "success" for item in results)
    reverted = len(results) - accepted
    evidence = root / ".audit" / "walkthrough" / "test.json"
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_text(
        json.dumps(
            {
                "version": 1,
                "mode": "randomized-isolated",
                "seed": actual_seed,
                "target": target,
                "contract": model.name,
                "cases": [asdict(item) for item in results],
                "summary": {
                    "cases": len(results),
                    "accepted": accepted,
                    "reverted": reverted,
                },
            },
            indent=2,
            default=str,
        ) + "\n",
        encoding="utf-8",
    )

    print("")
    print(f"  RESULT : {accepted} accepted • {reverted} reverted • {len(results)} probes")
    print(f"  EVIDENCE: {evidence.relative_to(root)}")
    print("  Every probe was restored to its pre-test Anvil snapshot.")
    return 0


def _generate_replay_script(root: Path, model: ContractModel, target: str, steps: list[Step]) -> Path:
    path = root / "script" / f"LowkeyWalkthrough_{model.name}.s.sol"
    path.parent.mkdir(parents=True, exist_ok=True)
    contract_name = f"LowkeyWalkthrough_{re.sub(r'[^A-Za-z0-9_]', '_', model.name)}"
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.20;",
        "",
        'import "forge-std/Script.sol";',
        "",
        f"contract {contract_name} is Script {{",
        "    // Generated from successful observations captured by Lowkey on local Anvil.",
        "    // The script replays the exact transaction calldata whenever available.",
        "    function run() external {",
    ]

    broadcast_actor = None
    replay_index = 0
    for step in steps:
        if step.status != "success":
            continue

        replay_index += 1
        env = "LOWKEY_" + re.sub(r"[^A-Za-z0-9]", "_", step.actor.upper()) + "_KEY"
        if broadcast_actor != env:
            if broadcast_actor is not None:
                lines.append("        vm.stopBroadcast();")
            lines.append(f'        vm.startBroadcast(vm.envUint("{env}"));')
            broadcast_actor = env

        target_literal = _sol_address_literal(step.address)
        lines.append(f"        address target_{replay_index} = {target_literal};")

        if step.calldata and re.fullmatch(r"0x[0-9a-fA-F]*", step.calldata):
            calldata_literal = step.calldata[2:]
            if len(calldata_literal) % 2:
                calldata_literal = "0" + calldata_literal
            call = (
                f"        (bool ok_{replay_index}, ) = target_{replay_index}"
                f".call{{value: {int(step.value_wei or 0)}}}(hex\"{calldata_literal}\");"
            )
        else:
            arg_text = ", ".join(_sol_literal(x) for x in step.args)
            if arg_text:
                call = (
                    f"        (bool ok_{replay_index}, ) = target_{replay_index}.call"
                    f"(abi.encodeWithSignature({json.dumps(step.function)}, {arg_text}));"
                )
            else:
                call = (
                    f"        (bool ok_{replay_index}, ) = target_{replay_index}.call"
                    f"(abi.encodeWithSignature({json.dumps(step.function)}));"
                )
            if step.value_wei:
                call = call.replace(
                    f"target_{replay_index}.call(",
                    f"target_{replay_index}.call{{value: {int(step.value_wei)}}}(",
                    1,
                )

        lines.append(call)
        lines.append(f'        require(ok_{replay_index}, "walkthrough replay step reverted");')

    if broadcast_actor is not None:
        lines.append("        vm.stopBroadcast();")
    lines += [
        "    }",
        "}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path




def _target_is_live_instance(root: Path, rpc: str, target: str, model: ContractModel) -> tuple[bool, str | None]:
    """Reject implementation-only addresses for upgradeable contracts."""
    has_initializer = any(
        item.get("type") == "function"
        and str(item.get("name") or "").lower().startswith("initialize")
        for item in model.abi
    )
    if not has_initializer:
        return True, None

    runtime = _normalize_code(_runtime_code(rpc, target))
    implementation = _artifact_runtime_code(root, model)
    expected = _normalize_code(implementation)
    if runtime and expected and runtime == expected:
        return False, (
            f"{model.name} exposes initialize() and the live address matches its implementation bytecode; "
            "this is an implementation contract, not a configured proxy instance"
        )
    return True, None



def _target_from_host(host: Any, config: dict[str, Any], root: Path, contract: str | None, auto: bool) -> tuple[str | None, str | None]:
    # Auto mode always goes through the project bootstrap resolver so stale
    # implementation targets cannot bypass proxy/fixture selection.
    target = None
    if auto:
        try:
            info = host.anvil_rpc_info(config)
            if not info and not config.get("rpc"):
                info = host.ensure_project_anvil(config, root)
            if info:
                host._bind_detected_anvil(config, info)
            target = host._bootstrap_audit_target(config, root, allow_deploy=True)
        except Exception:
            target = None
    else:
        try:
            target = host.active_project_target(config, root)
        except Exception:
            target = config.get("target")
    if target and contract:
        aliases = getattr(host, "target_aliases", lambda c: {})(config)
        selected = aliases.get(contract)
        if selected:
            target = selected
    if auto and not contract:
        system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
        factory = system.get("factory")
        if is_address(factory):
            return factory, "ConfidencePoolFactory"
    resolved_target = target if auto else (target or config.get("target"))
    return resolved_target, config.get("target_contract") or contract


def _actors(host: Any, config: dict[str, Any], count: int = 4) -> list[Actor]:
    info = host.anvil_rpc_info(config) if hasattr(host, "anvil_rpc_info") else None
    if not info:
        return []
    accounts = info.get("accounts") or []
    names = ["Alice", "Bob", "Attacker", "Treasury", "Charlie", "Protocol"]
    return [
        Actor(names[i] if i < len(names) else f"Actor{i}", addr, i)
        for i, addr in enumerate(accounts[:count])
    ]


def _render_actor_row(actors: list[Actor], enabled: bool) -> str:
    chunks = []
    for actor in actors:
        label = _paint(f"{ACTOR} {actor.name}", CYAN if actor.name != "Attacker" else RED, enabled)
        chunks.append(f"{label} {_addr(actor.address)}")
    return "    ".join(chunks)


def _render_system_graph(models: list[ContractModel], enabled: bool) -> str:
    lines = [_paint("SYSTEM FLOW", BOLD + WHITE, enabled)]
    if not models:
        return "\n".join(lines + ["  <no compiled contracts>"])
    shown = models[:12]
    for model in shown:
        base_text = ", ".join(model.bases) if model.bases else "root"
        line = f"  {STATE} {model.name:<24} {DIM}bases:{RESET if enabled else ''}{base_text}"
        if model.bases:
            line += f"  {DOTTED}  inheritance"
        lines.append(_paint(line, MAGENTA if model.bases else WHITE, enabled))
    return "\n".join(lines)


def _render_storage(storage: list[dict[str, Any]], enabled: bool) -> str:
    out: list[str] = []
    for item in storage[:16]:
        encoding = item.get("encoding")
        if encoding == "mapping":
            lines = [
                f"key   → {item.get('mapping', {}).get('key_type')}",
                f"value → {item.get('mapping', {}).get('value_type')}",
            ]
            for row in item.get("mapping", {}).get("rows", [])[:4]:
                if row.get("struct"):
                    lines.append(f"{_addr(row.get('key'))}  @ {row.get('slot')}")
                    for field in row["struct"].get("fields", [])[:8]:
                        lines.append(f"  ├─ {field['name']:<14} = {field['value']}  [{field['type']}]")
                else:
                    lines.append(f"{_addr(row.get('key'))} → {row.get('value')}  @ {row.get('slot')}")
            out.append(_box(f"{MAPPING} MAPPING {item.get('label')}", lines, width=82))
        elif item.get("struct"):
            fields = item["struct"]["fields"]
            out.append(_box(
                f"{STRUCT} STRUCT {item['struct']['type']}",
                [
                    f"base slot: {item.get('slot')}",
                    *[
                        f"{f['name']:<18} = {f['value']}   [{f['type']}] @ {f['slot']}"
                        for f in fields
                    ],
                ],
                width=82,
                left="╔",
                right="╗",
            ))
        elif isinstance(item.get("type"), str) and "[" in str(item.get("type")):
            out.append(_box(
                f"{ARRAY} ARRAY {item.get('label')}",
                [f"type: {item.get('type')}", f"slot: {item.get('slot')}", f"anchor: {item.get('value')}"],
                width=82,
            ))
        else:
            out.append(_box(
                f"{STORAGE} SLOT {item.get('slot')}",
                [f"{item.get('label')}: {item.get('value')}", f"type: {item.get('type')}"],
                width=82,
            ))
    return "\n\n".join(out) if out else "  <storage layout unavailable>"


def _render_step(step: Step, storage: list[dict[str, Any]], enabled: bool) -> str:
    status_color = GREEN if step.status == "success" else (RED if step.status == "reverted" else YELLOW)
    header = _paint(
        f"{BLOCK} STEP {step.index:02d}  {step.actor} {ARROW} {step.contract}.{step.function}",
        status_color,
        enabled,
    )
    args = ", ".join(repr(x) for x in step.args) or "∅"
    lines = [
        header,
        f"  caller : {step.actor}",
        f"  target : {_addr(step.address)}",
        f"  args   : {args}",
        f"  value  : {step.value_wei} wei",
        f"  why    : {step.reason}  {WARNING} INFERRED",
    ]
    if step.tx_hash:
        lines.append(f"  tx     : {_addr(step.tx_hash)}")
    if step.gas_used is not None:
        lines.append(f"  gas    : {step.gas_used}")
    if step.error:
        lines.append(f"  error  : {step.error[-500:]}")
    if step.events:
        lines.append(f"  {EVENT} events : {len(step.events)}")
    if step.trace_edges:
        lines.append(f"  {EXTERNAL} trace edges : {len(step.trace_edges)}")
    if step.storage_changes:
        lines.append(f"  {STATE} storage changes : {len(step.storage_changes)}")
    return _box("LIVE EXECUTION", lines, width=92)


def _render_connections(
    root: Path,
    models: list[ContractModel],
    model: ContractModel,
    enabled: bool,
) -> str:
    lines = [_paint("SYSTEM CONNECTIONS", BOLD + WHITE, enabled)]
    by_name = {item.name: item for item in models}

    for base in model.bases[:10]:
        lines.append(f"  {model.name} {DOTTED} {base}  [INHERITS]")

    for edge in model.calls[:24]:
        target = by_name.get(str(edge.get("to_contract") or ""))
        fn = str(edge.get("to_function") or "unknown()")
        linked = _function_link(root, target, fn)
        via = f"  via {edge.get('via')}" if edge.get("via") else ""
        lines.append(
            f"  {model.name}.{edge.get('from')} {EXTERNAL} "
            f"{edge.get('to_contract')}.{linked}{via}  "
            f"[{edge.get('certainty') or 'INFERRED'}]"
        )

    if len(lines) == 1:
        lines.append("  no source-level cross-contract calls resolved")
    return "\n".join(lines)



def _render_event_log(step: Step, enabled: bool) -> str:
    lines = [_paint(f"{EVENT} EVENT STREAM", BOLD + YELLOW, enabled)]
    for event in step.events[:8]:
        if isinstance(event, dict) and event.get("event"):
            lines.append(f"  {EVENT} {event.get('event')}  {event}")
        elif isinstance(event, dict):
            lines.append(f"  {EVENT} raw log @ {_addr(event.get('address'))}")
        else:
            lines.append(f"  {EVENT} {event}")
    return "\n".join(lines)


def _render_trace(step: Step) -> str:
    if not step.trace_edges:
        return "  <trace unavailable>"
    return "\n".join(["  " + EXTERNAL + " " + x for x in step.trace_edges[-10:]])


def _render_live_path(steps: list[Step], runtime: list[RuntimeContract], enabled: bool) -> str:
    lines = [_paint("LIVE INTERACTION PATH", BOLD + CYAN, enabled)]
    if not steps:
        return "\n".join(lines + ["  <waiting for the first interaction>"])
    runtime_by_addr = {node.address.lower(): node for node in runtime}
    for step in steps[-10:]:
        status_icon = "✓" if step.status == "success" else "!" if step.status in {"blocked", "reverted"} else "•"
        color = GREEN if step.status == "success" else RED if step.status in {"blocked", "reverted"} else YELLOW
        args = ", ".join(_cli_arg(x) for x in step.args) or "∅"
        target = runtime_by_addr.get(step.address.lower())
        target_label = target.label if target else step.contract
        lines.append(
            f"  {_paint(status_icon, color, enabled)} {step.actor} {ARROW} "
            f"{target_label}.{step.function}  ({args})"
        )
        if target and target.parent and target.parent.lower() != step.address.lower():
            lines.append(f"       {DOTTED} parent {_addr(target.parent)}")
        if step.status == "success":
            if step.events:
                lines.append(f"       {EXTERNAL} {len(step.events)} event(s)  →  state observed")
            if step.discovered_contracts:
                for node in step.discovered_contracts[:4]:
                    lines.append(f"       {ARROW} {node.label}  {_addr(node.address)}  [{node.relation}]")
        elif step.error:
            compact_error = " ".join(str(step.error).split())[-180:]
            lines.append(f"       {WARNING} {compact_error}")
    return "\n".join(lines)

def _render_runtime_graph(runtime: list[RuntimeContract], enabled: bool) -> str:
    lines = [_paint("SYSTEM MAP", BOLD + WHITE, enabled)]
    if not runtime:
        return "\n".join(lines + ["  <no live contracts>"])

    children: dict[str, list[RuntimeContract]] = {}
    roots: list[RuntimeContract] = []
    by_addr = {node.address.lower(): node for node in runtime}
    for node in runtime:
        if node.parent and node.parent.lower() in by_addr:
            children.setdefault(node.parent.lower(), []).append(node)
        else:
            roots.append(node)

    seen: set[str] = set()

    def render(node: RuntimeContract, prefix: str = "  ", last: bool = True) -> None:
        if node.address.lower() in seen:
            return
        seen.add(node.address.lower())
        connector = "└─ " if last else "├─ "
        icon = "◆" if node.relation == "system" else "●"
        lines.append(
            f"{prefix}{connector}{icon} {node.label:<28} {_addr(node.address)}"
        )
        kids = children.get(node.address.lower(), [])
        for i, child in enumerate(kids[:10]):
            child_prefix = prefix + ("   " if last else "│  ")
            edge = DOTTED + " " if child.relation in {"CLONE", "IMPLEMENTATION"} else ARROW + " "
            if i < len(kids[:10]) - 1:
                branch_prefix = child_prefix + edge
            else:
                branch_prefix = child_prefix + edge
            render(child, branch_prefix, i == len(kids[:10]) - 1)

    for i, root_node in enumerate(roots):
        render(root_node, "  ", i == len(roots) - 1)

    for node in runtime:
        if node.address.lower() not in seen:
            render(node, "  ", True)

    return "\n".join(lines)

def _slither_status(root: Path) -> str:
    path = root / ".audit" / "slither" / "latest.json"
    if not path.is_file():
        return "Slither: no evidence file in this project context"
    data = _json_file(path) or {}
    results = data.get("results")
    if isinstance(results, dict):
        findings = results.get("detectors") or []
    elif isinstance(results, list):
        findings = results
    else:
        findings = data.get("findings") or []
    return f"Slither: {len(findings)} recorded finding(s) [context evidence]"


def _render_board(
    root: Path,
    model: ContractModel,
    models: list[ContractModel],
    runtime: list[RuntimeContract],
    actors: list[Actor],
    steps: list[Step],
    current: Step | None,
    storage: list[dict[str, Any]],
    enabled: bool,
    static: bool = False,
) -> str:
    success = sum(1 for x in steps if x.status == "success")
    blocked = sum(1 for x in steps if x.status in {"blocked", "reverted"})
    board = [
        _paint("LOWKEY // LIVE PROTOCOL WALKTHROUGH", BOLD + CYAN, enabled),
        f"  {model.name}   •   {success} successful   •   {blocked} blocked   •   {len(steps)} observed",
        "  ENTER = execute next live function   Q = stop",
        "  arrows = actual call path   boxes = state   links = Ctrl+Click source",
        "",
        _box("ACTORS", [
            "   ".join(f"{ACTOR} {actor.name} {_addr(actor.address)}" for actor in actors)
        ], width=92),
        "",
        _render_runtime_graph(runtime, enabled),
        "",
        _render_connections(root, models, model, enabled),
        "",
        _render_protocol_story_full(root, steps, current, actors, models, enabled),
    ]
    if current and current.storage_after:
        board += ["", _paint("CURRENT STATE", BOLD + GREEN, enabled), _render_storage(current.storage_after[:4], enabled)]
    board += ["", "  " + _slither_status(root)]
    if static:
        board.append(_paint("STATIC MODEL ONLY", YELLOW, enabled))
    return "\n".join(board)


def _render_plan(model: ContractModel, steps: list[Step], enabled: bool) -> str:
    lines=[_paint("STATIC PROTOCOL HYPOTHESIS",BOLD+CYAN,enabled),f"  {model.name} {ARROW}"]
    for step in steps:
        lines.append(f"  {step.index:02d} {ACTOR} {step.actor:<9} {ARROW} {FUNCTION} {step.function}")
    lines += ["",_paint("Static ordering/arguments are hypotheses. Live mode does not pre-render them.",YELLOW,enabled)]
    return "\n".join(lines)


def run(config: dict[str, Any], args: list[str] | None = None, host: Any | None = None) -> int:
    args=list(args or [])
    host=host or sys.modules.get("__main__")
    root=Path(getattr(host,"audit_context").foundry_project_root() if host and hasattr(host,"audit_context") else os.getcwd())
    if not root or not (root/"foundry.toml").is_file():
        print("Error: 'lk walkthrough' must be run inside a Foundry project.",file=sys.stderr)
        return 2
    test_mode=any(str(x).lower()=="test" for x in args) or "--test" in args
    auto="--auto" in args or "auto" in args
    static="--static" in args or "--no-exec" in args
    no_prompt="--yes" in args or "--non-interactive" in args or not sys.stdin.isatty()
    contract=None; max_steps=8; test_cases=24; test_seed=None
    for i,arg in enumerate(args):
        if arg=="--contract" and i+1<len(args): contract=args[i+1]
        elif arg=="--steps" and i+1<len(args):
            try: max_steps=max(1,min(24,int(args[i+1])))
            except ValueError: pass
        elif arg=="--cases" and i+1<len(args):
            try: test_cases=max(1,min(200,int(args[i+1])))
            except ValueError: pass
        elif arg=="--seed" and i+1<len(args):
            try: test_seed=int(args[i+1])
            except ValueError: pass

    if hasattr(host,"_sync_audit_context"):
        try: host._sync_audit_context(config,root)
        except Exception: pass

    print(_paint("LOWKEY PROTOCOL WALKTHROUGH",BOLD+CYAN,_ansi_enabled(static)))
    print("  LIVE mode: execute → observe → explain → redraw.")
    if test_mode:
        print("  TEST mode: randomized mutating calls are sent on isolated Anvil snapshots.")
    archived = _quarantine_generated_replays(root)
    if archived:
        print(f"  refreshed {archived} previous generated walkthrough replay(s)")
    code,out,err=_cmd(["forge","build"],cwd=root,timeout=120)
    if code!=0:
        print(out+err,file=sys.stderr); return code or 1

    models=_artifact_models(root)
    if not models:
        print("Error: no project application contracts found under the configured src directory.",file=sys.stderr)
        return 2

    target,target_contract=_target_from_host(host,config,root,contract,auto)
    model=_find_model(models,contract,target_contract)
    if not model:
        print("Error: unable to choose an executable application contract.",file=sys.stderr); return 2
    actors=_actors(host,config,4) if host else []

    if test_mode:
        rpc=host.effective_rpc(config) if host and hasattr(host,"effective_rpc") else config.get("rpc")
        if not rpc:
            print("Error: adversarial test mode needs a local Anvil RPC.", file=sys.stderr)
            return 2
        if not target:
            print("Error: adversarial test mode needs a live target.", file=sys.stderr)
            return 2
        system_targets = _system_test_targets(config, target, model, models)
        return _run_adversarial_test(
            root, config, host, target, model, models, actors, rpc,
            total_cases=test_cases, seed=test_seed,
            system_targets=system_targets,
        )

    if static:
        plan=plan_workflow(model,actors,target or "0x"+"00"*20,int(time.time()),max_steps)
        runtime=[RuntimeContract(target or "0x"+"00"*20,model.name,model.name,"target")]
        print("\n"+_render_plan(model,plan,_ansi_enabled(static)))
        print("\n"+_render_board(root,model,models,runtime,actors,plan,None,[],_ansi_enabled(static),True))
        _save_artifacts(root,{"version":3,"mode":"source-guided-static","target":target,"contract":asdict(model),"contracts":_models_payload(models),"actors":[asdict(x) for x in actors],"workflow":[asdict(x) for x in plan],"runtime_contracts":[asdict(x) for x in runtime]},plan)
        return 0

    rpc=host.effective_rpc(config) if host and hasattr(host,"effective_rpc") else config.get("rpc")
    if not rpc:
        print("Error: no RPC. Use an existing local Anvil or 'lk walkthrough --auto'.",file=sys.stderr); return 2
    if not actors:
        print("Error: no local Anvil actors detected. Live walkthrough requires Anvil actors.",file=sys.stderr); return 2
    if not target:
        if auto:
            print("Error: auto mode could not provision a live protocol target.", file=sys.stderr)
        else:
            print("Error: no live target. Use 'lk target <address>' or 'lk walkthrough --auto'.", file=sys.stderr)
        return 2

    live_ok, live_reason = _target_is_live_instance(root, rpc, target, model)
    if not live_ok:
        print("Error: live target is not a configured protocol instance.", file=sys.stderr)
        print(f"Reason: {live_reason}", file=sys.stderr)
        print("Lowkey will not continue with misleading precondition failures.", file=sys.stderr)
        return 2

    runtime=_lab_runtime(config,target,model)
    steps=[]
    completed=set()
    prepared_pools: set[tuple[str, str]] = set()
    observed=dict(config.get("_walkthrough_observed") or {})
    system=config.get("lab_system") if isinstance(config.get("lab_system"),dict) else {}
    observed.update({str(k).replace("_",""):v for k,v in system.items() if isinstance(v,str) and is_address(v)})
    recipe=[]
    if config.get("_walkthrough_recipe")=="confidence-pool":
        now=_block_timestamp(rpc)
        if model.name.lower().endswith("factory"):
            recipe=_confidence_pool_factory_recipe(config,actors,now)
        elif model.name.lower()=="confidencepool":
            recipe=_confidence_pool_recipe(config,actors,now=now)
    pending=recipe[:max_steps] if recipe else plan_workflow(model,actors,target,_block_timestamp(rpc),max_steps,observed)

    def draw(current=None, storage=None):
        if sys.stdout.isatty():
            # Fixed terminal canvas: each live observation replaces the previous
            # frame instead of scrolling the workflow downward.
            sys.stdout.write("\033[2J\033[H\033[3J")
            sys.stdout.flush()
        print(_render_board(
            root, model, models, runtime, actors, steps, current, storage or [],
            _ansi_enabled(False)
        ))
        sys.stdout.flush()

    draw()

    while pending and len(steps)<max_steps:
        step=pending.pop(0)
        step.index=len(steps)+1
        current_model=next((m for m in models if m.name==step.contract),model)
        abi_item=next((x for x in current_model.abi if x.get("type")=="function" and _signature(x)==step.function),None)
        if abi_item:
            step.args=[_arg_for(p,actors,step.address,_block_timestamp(rpc),observed) for p in abi_item.get("inputs",[])]
            step.value_wei=_value_for(abi_item)

        key=(step.contract,step.address.lower(),step.function)
        if key in completed: continue

        step.status = "checking"
        steps.append(step)
        draw(step)

        actor=next((a for a in actors if a.name==step.actor),actors[0])
        ok,preflight=_preflight(rpc,step,actor.address)
        steps.pop()
        step.preflight=preflight
        if not ok:
            step.status="blocked"
            step.error="PRECONDITION BLOCKED: "+preflight
            step.error_reason=_explain_failure(step, preflight, step.actor)
            step.failure_origin, step.diagnostics = _diagnose_failed_call(root, rpc, step, current_model, models, actor.address)
            steps.append(step)
            draw(step)
        else:
            actor=next((a for a in actors if a.name==step.actor),actors[0])
            balance_addresses = [a.address for a in actors] + [node.address for node in runtime]
            step.balance_before = _snapshot_balances(rpc, balance_addresses)
            step.token_balance_before = _snapshot_token_balances(
                rpc, observed.get("staketoken"),
                [a.address for a in actors] + [node.address for node in runtime],
            )
            before=_snapshot_runtime(runtime,models,rpc,[a.address for a in actors])
            tx,output=_send(host,config,actor,step.address,step.function,step.args,step.value_wei)
            if not tx:
                step.status="reverted"
                step.error=output or "transaction failed"
                step.error_reason=_explain_failure(step, step.error, step.actor)
                step.failure_origin, step.diagnostics = _diagnose_failed_call(root, rpc, step, current_model, models, actor.address)
                steps.append(step)
                draw(step, before)
            else:
                receipt=_receipt(rpc,tx)
                trace=_trace_tree(rpc,tx)
                step.tx_hash=tx
                step.calldata=_transaction_input(rpc,tx)
                step.gas_used=int(receipt.get("gasUsed"),16) if receipt and isinstance(receipt.get("gasUsed"),str) else None
                step.events=_event_rows(host,config,receipt)
                step.trace_edges=_trace_edges(rpc,tx)
                step.execution_edges=_trace_execution_edges(root,rpc,models,trace)
                step.status="success" if receipt and receipt.get("status") in (None,"0x1",1) else "reverted"
                step.error_reason = (
                    "preflight passed and the live transaction was accepted"
                    if step.status == "success"
                    else _explain_failure(step, output, step.actor)
                )
                discovered=_discover_runtime_contracts(root,rpc,models,runtime,receipt,trace,step.index,step.address)
                if discovered:
                    runtime.extend(discovered); step.discovered_contracts=[asdict(x) for x in discovered]

                # Record the actual protocol interaction before any environment
                # preparation that it causes. This preserves create -> discover ->
                # approve ordering in the live path and saved evidence.
                steps.append(step); completed.add(key)

                # Visible local-lab prerequisite: once a real pool clone exists,
                # approve the recorded mock stake token for that clone.
                token_address = observed.get("staketoken")
                use_pool_recipe = config.get("_walkthrough_recipe") == "confidence-pool"
                if token_address and discovered and not use_pool_recipe:
                    for node in discovered:
                        if "pool" not in str(node.model).lower():
                            continue
                        pool_key = (token_address.lower(), node.address.lower())
                        if pool_key in prepared_pools:
                            continue
                        approval = _prepare_lab_allowance(
                            host, config, actor, node.address, token_address, rpc, steps,
                        )
                        prepared_pools.add(pool_key)
                        if approval:
                            draw(approval)

                after=_snapshot_runtime(runtime,models,rpc,[a.address for a in actors])
                step.balance_after = _snapshot_balances(rpc, balance_addresses)
                step.token_balance_after = _snapshot_token_balances(
                    rpc, observed.get("staketoken"),
                    [a.address for a in actors] + [node.address for node in runtime],
                )
                step.storage_before=before; step.storage_after=after; step.storage_changes=_storage_changed(before,after)
                step.runtime_contracts=[asdict(x) for x in runtime]
                draw(step, after)
                for node in discovered:
                    child=next((m for m in models if m.name==node.model),None)
                    if not child:
                        continue

                    child_steps = []
                    if config.get("_walkthrough_recipe") == "confidence-pool" and child.name.lower() == "confidencepool":
                        child_steps = _confidence_pool_recipe(
                            config, actors, pool_override=node.address, now=_block_timestamp(rpc)
                        )

                    selected = child_steps or plan_workflow(
                        child, actors, node.address, _block_timestamp(rpc), max_steps, observed
                    )
                    for candidate in reversed(selected):
                        ckey=(candidate.contract,candidate.address.lower(),candidate.function)
                        if ckey not in completed:
                            pending.insert(0,candidate)
                for candidate in reversed(plan_workflow(current_model,actors,step.address,_block_timestamp(rpc),max_steps,observed)):
                    ckey=(candidate.contract,candidate.address.lower(),candidate.function)
                    if ckey not in completed: pending.append(candidate)

        _save_artifacts(root,{
            "version":5,"mode":"source-guided-live","target":target,
            "contract":asdict(model),"contracts":_models_payload(models),
            "actors":[asdict(x) for x in actors],"workflow":[asdict(x) for x in steps],
            "runtime_contracts":[asdict(x) for x in runtime],
        },steps)

        if not no_prompt:
            try:
                choice = _wait_for_next_interaction(no_prompt)
                if choice == "q":
                    break
            except EOFError:
                no_prompt=True

    replay=_generate_replay_script(root,model,target,steps)
    print("\n"+_paint("WALKTHROUGH COMPLETE",BOLD+GREEN,_ansi_enabled(False)))
    print("  Every state frame was produced after a live preflight or transaction.")
    print("  model    : .audit/walkthrough/model.json")
    print("  evidence : .audit/walkthrough/latest.json")
    print(f"  replay   : {replay.relative_to(root)}")
    print(f"  {_slither_status(root)}")
    return 0

