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
import re
import shlex
import subprocess
import sys
import textwrap
import time
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
    gas_used: int | None = None
    error: str | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    trace_edges: list[str] = field(default_factory=list)
    storage_before: list[dict[str, Any]] = field(default_factory=list)
    storage_after: list[dict[str, Any]] = field(default_factory=list)
    storage_changes: list[dict[str, Any]] = field(default_factory=list)
    balance_before: dict[str, str] = field(default_factory=dict)
    balance_after: dict[str, str] = field(default_factory=dict)
    discovered_contracts: list[dict[str, Any]] = field(default_factory=list)
    preflight: str | None = None
    runtime_contracts: list[dict[str, Any]] = field(default_factory=list)


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


def _artifact_models(root: Path) -> list[ContractModel]:
    models: list[ContractModel] = []
    out = root / "out"
    if not out.is_dir():
        return models
    src_prefix = _foundry_src_dir(root).replace("\\","/").strip("/") or "src"
    for path in out.rglob("*.json"):
        if "build-info" in path.parts:
            continue
        data = _json_file(path)
        if not data or not isinstance(data.get("abi"), list):
            continue
        name = str(data.get("contractName") or path.stem)
        source = str(data.get("sourceName") or "").replace("\\","/").lstrip("./")
        if not source:
            try:
                relative_artifact = path.relative_to(out)
                if len(relative_artifact.parts) >= 2:
                    source = str(Path(src_prefix) / relative_artifact.parent.name)
            except ValueError:
                source = ""
        if not (source == src_prefix or source.startswith(src_prefix + "/")):
            continue
        source_text = ""
        source_path = root / source
        if source_path.is_file():
            try:
                source_text = source_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        if _source_kind(source_text, name) in {"interface","library"}:
            continue
        abi = data["abi"]
        functions = [_signature(x) for x in abi if x.get("type")=="function" and x.get("name")]
        events = [_signature(x) for x in abi if x.get("type")=="event" and x.get("name")]
        bases=[]
        for match in re.finditer(r"\b(?:abstract\s+)?contract\s+(\w+)\s+is\s+([^\{]+)\{", source_text):
            if match.group(1)==name:
                bases=[re.sub(r"\s+","",x).split("(")[0] for x in match.group(2).split(",") if x.strip()]
        if any(m.name==name and m.source==source for m in models):
            continue
        models.append(ContractModel(
            name=name, source=source, artifact=str(path.relative_to(root)), abi=abi,
            storage=data.get("storageLayout") or {}, bases=bases, functions=functions,
            modifiers=re.findall(r"\bmodifier\s+(\w+)",source_text),
            structs=_parse_structs(source_text), mappings=_parse_mappings(source_text),
            arrays=_parse_arrays(source_text), events=events))
    known={m.name:m for m in models}
    for model in models:
        try: source_text=(root/model.source).read_text(encoding="utf-8",errors="replace")
        except OSError: source_text=""
        edges=[]
        for fn in model.functions:
            name=fn.split("(",1)[0]; pos=source_text.find("function "+name)
            if pos<0: continue
            segment=source_text[pos:pos+16000]
            for target_fn in model.functions:
                target_name=target_fn.split("(",1)[0]
                if target_name!=name and re.search(r"\b"+re.escape(target_name)+r"\s*\(",segment):
                    edges.append({"kind":"internal","from":name,"to_contract":model.name,"to_function":target_fn})
            for other_name,other in known.items():
                if other_name==model.name or not re.search(r"\b"+re.escape(other_name)+r"\b",segment): continue
                for target_fn in other.functions:
                    target_name=target_fn.split("(",1)[0]
                    if re.search(r"\.\s*"+re.escape(target_name)+r"\s*\(",segment):
                        edges.append({"kind":"cross-contract","from":name,"to_contract":other_name,"to_function":target_fn})
        seen=set(); model.calls=[]
        for edge in edges:
            key=(str(edge.get("kind")),str(edge.get("from")),str(edge.get("to_contract")),str(edge.get("to_function")))
            if key not in seen: seen.add(key); model.calls.append(edge)
    return sorted(models,key=lambda m:(m.name.lower(),m.source))

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

    if compact in {"staketoken", "safeharborregistry", "poolimplementation", "defaultoutcomemoderator", "outcomemoderator"} and observed.get(compact):
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
        if any(x in name for x in ("deadline", "expiry", "expires")):
            return now + 31 * 24 * 60 * 60
        if any(x in name for x in ("id", "index", "nonce", "count")):
            return 0
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
    if isinstance(value, (list, tuple, dict)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _lab_runtime(config: dict[str, Any], target: str, model: ContractModel) -> list[RuntimeContract]:
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    if not system:
        return [RuntimeContract(target, model.name, model.name, "target")]

    definitions = [
        ("factory", "ConfidencePoolFactory", "system"),
        ("pool_implementation", "ConfidencePool", "IMPLEMENTATION"),
        ("stake_token", "StakeToken", "DEPENDENCY"),
        ("attack_registry", "MockAttackRegistry", "DEPENDENCY"),
        ("safe_harbor_registry", "MockSafeHarborRegistry", "DEPENDENCY"),
        ("agreement", "MockAgreement", "DEPENDENCY"),
        ("moderator", "MockConfidencePoolModerator", "DEPENDENCY"),
        ("pool", "ConfidencePool", "CLONE"),
    ]
    runtime=[]
    factory_addr=system.get("factory")
    for key,label,relation in definitions:
        address=system.get(key)
        if not address:
            continue
        parent=factory_addr if key in {"pool","pool_implementation"} else None
        runtime.append(RuntimeContract(address, label, label, relation, parent))
    if not any(x.address.lower()==target.lower() for x in runtime):
        runtime.append(RuntimeContract(target, model.name, model.name, "target"))
    return runtime


def _confidence_pool_recipe(config: dict[str, Any], actors: list[Actor]) -> list[Step]:
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    pool=system.get("pool") or config.get("target")
    token=system.get("stake_token")
    attack_registry=system.get("attack_registry")
    moderator=system.get("moderator")
    if not pool or not token or not attack_registry or not moderator:
        return []
    alice=actors[0] if actors else Actor("Alice", system.get("alice") or pool, 0)
    bob=actors[1] if len(actors)>1 else alice
    amount=10**18
    max_uint=2**256-1
    return [
        Step(0,alice.name,"StakeToken",token,"approve(address,uint256)",[pool,max_uint],
             reason="allow Alice to fund the pool",inferred=False),
        Step(0,bob.name,"StakeToken",token,"approve(address,uint256)",[pool,max_uint],
             reason="allow Bob to fund the pool",inferred=False),
        Step(0,alice.name,"ConfidencePool",pool,"contributeBonus(uint256)",[amount],
             reason="sponsor seeds the bonus pool",inferred=False),
        Step(0,alice.name,"ConfidencePool",pool,"stake(uint256)",[amount],
             reason="Alice joins the confidence pool",inferred=False),
        Step(0,bob.name,"ConfidencePool",pool,"stake(uint256)",[amount],
             reason="Bob joins the confidence pool",inferred=False),
        Step(0,alice.name,"MockAttackRegistry",attack_registry,"setAgreementState(uint8)",[3],
             reason="LAB CONTROL: agreement enters UNDER_ATTACK",inferred=False),
        Step(0,alice.name,"ConfidencePool",pool,"pokeRiskWindow()",[],
             reason="pool observes and seals risk-window start",inferred=False),
        Step(0,alice.name,"MockAttackRegistry",attack_registry,"setAgreementState(uint8)",[4],
             reason="LAB CONTROL: agreement reaches PRODUCTION",inferred=False),
        Step(0,alice.name,"MockConfidencePoolModerator",moderator,"flagSurvived(address)",[pool],
             reason="moderator records the survived outcome",inferred=False),
        Step(0,alice.name,"ConfidencePool",pool,"claimSurvived()",[],
             reason="Alice claims principal plus time-weighted bonus",inferred=False),
        Step(0,bob.name,"ConfidencePool",pool,"claimSurvived()",[],
             reason="Bob claims principal plus time-weighted bonus",inferred=False),
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



def _render_pseudocode_flow(steps: list[Step], current: Step | None, enabled: bool) -> str:
    lines=[_paint("LIVE PSEUDOCODE FLOW",BOLD+CYAN,enabled)]
    if not steps:
        return "\n".join(lines+[
            "  SYSTEM READY",
            "      ↓",
            f"  {FUNCTION} choose interaction",
            "      ↓",
            "  execute → observe → redraw → choose next",
        ])
    for step in steps[-10:]:
        icon="✓" if step.status=="success" else "!" if step.status in {"blocked","reverted"} else "→"
        lines.append(f"  {icon} {step.actor}")
        lines.append(f"     └─ {FUNCTION} {step.contract}.{step.function}")
        if step.args:
            lines.append(f"        args: {', '.join(_cli_arg(x) for x in step.args)}")
        if step.status=="success":
            for change in step.storage_changes[:3]:
                label=change.get("label") or f"slot {change.get('slot')}"
                before=change.get("before",{}).get("value") if isinstance(change.get("before"),dict) else "?"
                after=change.get("after",{}).get("value") if isinstance(change.get("after"),dict) else "?"
                lines.append(f"        ├─ {STATE} {label}: {before} → {after}")
            if step.discovered_contracts:
                lines.append(f"        ├─ {EXTERNAL} runtime contract discovered")
            if step.events and not step.storage_changes:
                lines.append(f"        └─ {EVENT} {len(step.events)} event(s)")
            elif not step.storage_changes and not step.discovered_contracts:
                lines.append("        └─ ✓ state observed")
        elif step.error:
            lines.append(f"        └─ {WARNING} {' '.join(str(step.error).split())[-200:]}")
        lines.append("        ↓")
    if current:
        lines.append(f"  {ARROW} YOU ARE HERE  {current.actor} → {current.contract}.{current.function}")
    return "\n".join(lines)


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
        error=None if tx else (output or "token approval failed"),
    )
    steps.append(step)
    return step

def _extract_tx_hash(text: str) -> str | None:
    matches = re.findall(r"0x[0-9a-fA-F]{64}", text or "")
    return matches[-1] if matches else None


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

def _generate_replay_script(root: Path, model: ContractModel, target: str, steps: list[Step]) -> Path:
    path = root / "script" / f"LowkeyWalkthrough_{model.name}.s.sol"
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.20;",
        "",
        'import "forge-std/Script.sol";',
        "",
        f"contract LowkeyWalkthrough_{re.sub(r'[^A-Za-z0-9_]', '_', model.name)} is Script {{",
        f"    address constant TARGET = {target};",
        "",
        "    // Generated from a real Lowkey local-Anvil walkthrough.",
        "    // Actor keys are deliberately supplied through environment variables.",
        "    function run() external {",
    ]
    current_actor = None
    for step in steps:
        if step.status != "success":
            continue
        env = "LOWKEY_" + re.sub(r"[^A-Za-z0-9]", "_", step.actor.upper()) + "_KEY"
        if current_actor != env:
            if current_actor is not None:
                lines.append("        vm.stopBroadcast();")
            lines.append(f'        vm.startBroadcast(vm.envUint("{env}"));')
            current_actor = env
        arg_text = ", ".join(_sol_literal(x) for x in step.args)
        if arg_text:
            call = f"        (bool ok, ) = TARGET.call(abi.encodeWithSignature({json.dumps(step.function)}, {arg_text}));"
        else:
            call = f"        (bool ok, ) = TARGET.call(abi.encodeWithSignature({json.dumps(step.function)}));"
        lines.append(call)
        lines.append('        require(ok, "walkthrough replay step reverted");')
    if current_actor is not None:
        lines.append("        vm.stopBroadcast();")
    lines += [
        "    }",
        "}",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _sol_literal(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[]"
    if isinstance(value, str):
        if value.startswith("0x") and len(value) == 42:
            return value
        if value.startswith("0x") and len(value) == 66:
            return value
        return json.dumps(value)
    return "0"


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
    return target or config.get("target"), config.get("target_contract") or contract


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


def _render_connections(models: list[ContractModel], model: ContractModel, enabled: bool) -> str:
    lines = [_paint("CONNECTION GRAPH", BOLD + WHITE, enabled)]
    by_name = {m.name: m for m in models}
    for base in model.bases:
        parent = by_name.get(base)
        if parent:
            shared = sorted(set(parent.functions) & set(model.functions))
            if shared:
                for fn in shared[:8]:
                    lines.append(f"  {base}.{fn}  {DOTTED}  {model.name}.{fn}  (override)")
            else:
                lines.append(f"  {base}  {DOTTED}  {model.name}  (inheritance)")
        else:
            lines.append(f"  {base}  {DOTTED}  {model.name}  (inherited source)")
    for edge in model.calls[:24]:
        kind = edge.get("kind")
        arrow = EXTERNAL if kind == "cross-contract" else ARROW
        lines.append(
            f"  {model.name}.{edge.get('from')}  {arrow}  "
            f"{edge.get('to_contract')}.{edge.get('to_function')}  "
            f"(source edge, INFERRED)"
        )
    # Source-level qualified calls are shown as INFERRED. Runtime trace edges
    # below are the execution authority.
    names = {m.name for m in models if m.name != model.name}
    for other in sorted(names):
        source_path = Path(model.source)
        try:
            source_text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            source_text = ""
        if re.search(r"\b" + re.escape(other) + r"\b", source_text):
            lines.append(f"  {model.name}  {EXTERNAL}  {other}  (source reference, INFERRED)")
    if len(lines) == 1:
        lines.append("  No explicit inheritance/source reference was resolved.")
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
    lines=[_paint("LIVE SYSTEM GRAPH",BOLD+WHITE,enabled)]
    if not runtime:
        return "\n".join(lines+["  <no live contracts>"])
    children={}
    roots=[]
    for node in runtime:
        if node.parent:
            children.setdefault(node.parent.lower(),[]).append(node)
        else:
            roots.append(node)
    seen=set()
    def render(node,indent="  "):
        if node.address.lower() in seen:
            return
        seen.add(node.address.lower())
        icon="◆" if node.relation=="system" else "●"
        lines.append(f"{indent}{icon} {node.label:<28} {_addr(node.address)}")
        for child in children.get(node.address.lower(),[])[:12]:
            arrow=DOTTED if child.relation in {"CLONE","IMPLEMENTATION"} else EXTERNAL
            lines.append(f"{indent}   {arrow} {child.label:<24} {_addr(child.address)}")
    for node in roots:
        render(node)
    for node in runtime:
        if node.address.lower() not in seen:
            render(node)
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


def _render_board(root: Path, model: ContractModel, models: list[ContractModel], runtime: list[RuntimeContract], actors: list[Actor], steps: list[Step], current: Step | None, storage: list[dict[str, Any]], enabled: bool, static: bool = False) -> str:
    success=sum(1 for x in steps if x.status=="success")
    blocked=sum(1 for x in steps if x.status in {"blocked","reverted"})
    board=[
        _paint("LOWKEY // PROTOCOL CANVAS",BOLD+CYAN,enabled),
        _paint(
            f"  live  {success}✓  {blocked}!  {len(steps)} observed   |   ⏎ next   q stop",
            DIM,enabled
        ),
        "",
        _box("SYSTEM",[
            f"{STATE} {model.name}",
            f"target  {_addr(runtime[-1].address) if runtime else _addr(current.address if current else None)}",
            _render_shape_legend(enabled),
        ],width=92),
        "",
        _render_runtime_graph(runtime,enabled),
        "",
        _render_contract_shapes(model,enabled),
        "",
        _render_pseudocode_flow(steps,current,enabled),
    ]
    if storage:
        board += ["",_paint(f"{STATE} LIVE STATE",BOLD+GREEN,enabled),_render_storage(storage[:3],enabled)]
    if current:
        board += ["",_box("OBSERVATION",[
            f"{current.actor} {ARROW} {FUNCTION} {current.contract}.{current.function}",
            f"status : {current.status}",
            f"preflight: {'PASS' if current.preflight and current.status=='success' else (current.preflight or 'pending')}",
            f"trace/events/writes : {len(current.trace_edges)} / {len(current.events)} / {len(current.storage_changes)}",
        ],width=92)]
    board += ["", "  "+_slither_status(root)]
    if static:
        board.append(_paint("STATIC MODEL ONLY",YELLOW,enabled))
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
    auto="--auto" in args or "auto" in args
    static="--static" in args or "--no-exec" in args
    no_prompt="--yes" in args or "--non-interactive" in args or not sys.stdin.isatty()
    contract=None; max_steps=8
    for i,arg in enumerate(args):
        if arg=="--contract" and i+1<len(args): contract=args[i+1]
        elif arg=="--steps" and i+1<len(args):
            try: max_steps=max(1,min(24,int(args[i+1])))
            except ValueError: pass

    if hasattr(host,"_sync_audit_context"):
        try: host._sync_audit_context(config,root)
        except Exception: pass

    print(_paint("LOWKEY PROTOCOL WALKTHROUGH",BOLD+CYAN,_ansi_enabled(static)))
    print("  LIVE mode: each interaction is executed, observed, then rendered.")
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

    if static:
        plan=plan_workflow(model,actors,target or "0x"+"00"*20,int(time.time()),max_steps)
        runtime=[RuntimeContract(target or "0x"+"00"*20,model.name,model.name,"target")]
        print("\n"+_render_plan(model,plan,_ansi_enabled(static)))
        print("\n"+_render_board(root,model,models,runtime,actors,plan,None,[],_ansi_enabled(static),True))
        _save_artifacts(root,{"version":2,"mode":"source-guided-static","target":target,"contract":asdict(model),"contracts":_models_payload(models),"actors":[asdict(x) for x in actors],"workflow":[asdict(x) for x in plan],"runtime_contracts":[asdict(x) for x in runtime]},plan)
        return 0

    rpc=host.effective_rpc(config) if host and hasattr(host,"effective_rpc") else config.get("rpc")
    if not rpc:
        print("Error: no RPC. Use an existing local Anvil or 'lk walkthrough --auto'.",file=sys.stderr); return 2
    if not actors:
        print("Error: no local Anvil actors detected. Live walkthrough requires Anvil actors.",file=sys.stderr); return 2
    target=target or config.get("target")
    if not target:
        print("Error: no live target. Use 'lk target <address>' or 'lk walkthrough --auto'.",file=sys.stderr); return 2

    runtime=_lab_runtime(config,target,model)
    steps=[]
    completed=set()
    prepared_pools: set[tuple[str, str]] = set()
    observed=dict(config.get("_walkthrough_observed") or {})
    system=config.get("lab_system") if isinstance(config.get("lab_system"),dict) else {}
    observed.update({str(k).replace("_",""):v for k,v in system.items() if isinstance(v,str) and is_address(v)})
    recipe=_confidence_pool_recipe(config,actors) if config.get("_walkthrough_recipe")=="confidence-pool" else []
    pending=recipe[:max_steps] if recipe else plan_workflow(model,actors,target,_block_timestamp(rpc),max_steps,observed)

    def draw(current=None, storage=None):
        if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
            sys.stdout.write("\033[2J\033[H")
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
            steps.append(step)
            draw(step)
        else:
            actor=next((a for a in actors if a.name==step.actor),actors[0])
            before=_snapshot_runtime(runtime,models,rpc,[a.address for a in actors])
            tx,output=_send(host,config,actor,step.address,step.function,step.args,step.value_wei)
            if not tx:
                step.status="reverted"; step.error=output or "transaction failed"; steps.append(step)
                draw(step, before)
            else:
                receipt=_receipt(rpc,tx)
                trace=_trace_tree(rpc,tx)
                step.tx_hash=tx
                step.gas_used=int(receipt.get("gasUsed"),16) if receipt and isinstance(receipt.get("gasUsed"),str) else None
                step.events=_event_rows(host,config,receipt)
                step.trace_edges=_trace_edges(rpc,tx)
                step.status="success" if receipt and receipt.get("status") in (None,"0x1",1) else "reverted"
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
                if token_address and discovered:
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
                step.storage_before=before; step.storage_after=after; step.storage_changes=_storage_changed(before,after)
                step.runtime_contracts=[asdict(x) for x in runtime]
                draw(step, after)
                for node in discovered:
                    child=next((m for m in models if m.name==node.model),None)
                    if child:
                        for candidate in reversed(plan_workflow(child,actors,node.address,_block_timestamp(rpc),max_steps,observed)):
                            ckey=(candidate.contract,candidate.address.lower(),candidate.function)
                            if ckey not in completed: pending.insert(0,candidate)
                for candidate in reversed(plan_workflow(current_model,actors,step.address,_block_timestamp(rpc),max_steps,observed)):
                    ckey=(candidate.contract,candidate.address.lower(),candidate.function)
                    if ckey not in completed: pending.append(candidate)

        _save_artifacts(root,{
            "version":2,"mode":"source-guided-live","target":target,
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

