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


@dataclass
class Actor:
    name: str
    address: str
    index: int


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


def _artifact_models(root: Path) -> list[ContractModel]:
    models: list[ContractModel] = []
    out = root / "out"
    if not out.is_dir():
        return models

    for path in out.rglob("*.json"):
        if "build-info" in path.parts:
            continue
        data = _json_file(path)
        if not data or not isinstance(data.get("abi"), list):
            continue
        name = data.get("contractName")
        if not name:
            name = path.stem
        abi = data["abi"]
        if not abi:
            # Empty ABI artifacts can still be interfaces, but are not useful
            # as execution targets.
            continue
        source = str(data.get("sourceName") or path)
        if "/test/" in "/" + source + "/" or source.startswith("test/"):
            continue

        functions = [
            _signature(item)
            for item in abi
            if item.get("type") == "function" and item.get("name")
        ]
        events = [
            _signature(item)
            for item in abi
            if item.get("type") == "event" and item.get("name")
        ]
        storage = data.get("storageLayout") or {}
        source_text = ""
        source_path = root / source
        if source_path.is_file():
            try:
                source_text = source_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

        bases: list[str] = []
        for match in re.finditer(
            r"\b(?:contract|abstract\s+contract)\s+(\w+)\s+is\s+([^\{]+)\{",
            source_text,
        ):
            clause = match.group(2)
            if match.group(1) == name:
                bases = [x.strip().split("(")[0].split()[-1] for x in clause.split(",") if x.strip()]

        structs = _parse_structs(source_text)
        mappings = _parse_mappings(source_text)
        arrays = _parse_arrays(source_text)
        modifiers = re.findall(r"\bmodifier\s+(\w+)", source_text)

        # Avoid duplicate artifacts for the same contract name/source.
        if any(m.name == name and m.source == source for m in models):
            continue
        models.append(
            ContractModel(
                name=name,
                source=source,
                artifact=str(path.relative_to(root)),
                abi=abi,
                storage=storage,
                bases=bases,
                functions=functions,
                modifiers=modifiers,
                structs=structs,
                mappings=mappings,
                arrays=arrays,
                events=events,
            )
        )
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
        r"mapping\s*\(([^=]+?)\s*=>\s*([^\)]+?)\)\s+(\w+)\s*(?:;|=)",
        re.S,
    )
    for match in rx.finditer(source):
        key = " ".join(match.group(1).split())
        value = " ".join(match.group(2).split())
        found.append({"name": match.group(3), "key_type": key, "value_type": value})
    return found


def _parse_arrays(source: str) -> list[dict[str, Any]]:
    found = []
    rx = re.compile(r"\b([A-Za-z_][\w]*(?:\[[^\]]*\])+)\s+(\w+)\s*(?:;|=)")
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
        and x.get("stateMutability") != "view"
        and x.get("stateMutability") != "pure"
    ]


_PHASES = [
    ("bootstrap", ("initialize", "init", "setup", "configure", "register", "create")),
    ("fund", ("deposit", "fund", "contribute", "join", "stake", "approve", "mint")),
    ("action", ("buy", "swap", "place", "commit", "submit", "add", "remove", "borrow", "lend", "claim")),
    ("settle", ("close", "finalize", "settle", "release", "execute", "resolve")),
    ("exit", ("withdraw", "redeem", "refund", "cancel", "unstake", "collect")),
]


def _phase_score(name: str) -> tuple[int, int]:
    lower = name.lower()
    for index, (_, names) in enumerate(_PHASES):
        for token in names:
            if lower.startswith(token) or token in lower:
                return index, -len(token)
    return 3, -999


def _arg_for(param: dict[str, Any], actors: list[Actor], target: str, now: int) -> Any:
    ptype = _canonical_type(param)
    name = str(param.get("name") or "arg").lower()
    alice = actors[0].address if actors else target
    bob = actors[1].address if len(actors) > 1 else alice
    attacker = actors[2].address if len(actors) > 2 else bob

    if ptype.startswith("address[]"):
        return [alice, bob]
    if ptype == "address":
        if any(x in name for x in ("attacker", "malicious", "evil")):
            return attacker
        if any(x in name for x in ("recipient", "receiver", "to", "user", "beneficiary")):
            return bob
        return alice
    if ptype.startswith("uint") or ptype.startswith("int"):
        if any(x in name for x in ("deadline", "expiry", "expires")):
            return now + 3600
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
            _arg_for(comp, actors, target, now)
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


def plan_workflow(model: ContractModel, actors: list[Actor], target: str, now: int, max_steps: int) -> list[Step]:
    candidates = _mutators(model)
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
        actor = actors[0] if actors else Actor("Alice", target, 0)
        if any(x in low for x in ("withdraw", "claim", "redeem", "release", "refund", "settle", "finalize", "cancel")) and len(actors) > 1:
            actor = actors[1]
        args = [_arg_for(p, actors, target, now) for p in item.get("inputs", [])]
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

    encoded_args = [json.dumps(x, separators=(",", ":")) if isinstance(x, list) else str(x) for x in args]
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
        json.dumps({"version": 1, "steps": [asdict(x) for x in steps]}, indent=2, default=str) + "\n",
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
        lines.append("        require(ok, "walkthrough replay step reverted");")
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
    # Reuse the existing project-scoped target resolver and local lab bootstrap.
    target = None
    try:
        target = host.active_project_target(config, root)
    except Exception:
        target = config.get("target")

    if not target and auto:
        try:
            info = host.anvil_rpc_info(config)
            if not info and not config.get("rpc"):
                info = host.ensure_project_anvil(config, root)
            if info:
                host._bind_detected_anvil(config, info)
            target = host._bootstrap_audit_target(config, root, allow_deploy=True)
        except Exception:
            target = None
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
    return "

".join(out) if out else "  <storage layout unavailable>"


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
    return "
".join(lines)


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


def _render_board(model: ContractModel, models: list[ContractModel], actors: list[Actor], steps: list[Step], current: Step | None,
                  storage: list[dict[str, Any]], enabled: bool, static: bool = False) -> str:
    title = _paint("LOWKEY  //  PROTOCOL WALKTHROUGH", BOLD + CYAN, enabled)
    subtitle = _paint(
        "SOURCE + BUILD + LIVE EXECUTION  |  heuristics are INFERRED; state is LIVE",
        DIM,
        enabled,
    )
    signal_file = Path(".audit") / "slither" / "latest.json"
    signal_text = ""
    if signal_file.is_file():
        data = _json_file(signal_file) or {}
        findings = data.get("results") or data.get("findings") or []
        if isinstance(findings, list):
            signal_text = f"  {WARNING} Slither evidence: {len(findings)} recorded finding(s)"
    board = [
        title,
        subtitle,
        "",
        _box(f"{STATE} CONTRACT", [f"{model.name}", f"source: {model.source}", f"artifact: {model.artifact}"], width=92),
        "",
        _render_actor_row(actors, enabled),
        "",
        _render_system_graph(models, enabled),
        "",
        _render_connections(models, model, enabled),
        signal_text if signal_text else "  Slither evidence: not present in current project context",
    ]
    if current:
        board += ["", _render_step(current, storage, enabled)]
        if current.storage_changes:
            board += ["", _paint("STATE DELTA  ⇣", BOLD + GREEN, enabled), _render_storage(current.storage_after, enabled)]
        if current.events:
            board += ["", _render_event_log(current, enabled)]
        if current.trace_edges:
            board += ["", _paint("CALL TRACE", BOLD + MAGENTA, enabled), _render_trace(current)]
    board += ["", _paint(f"WORKFLOW  {len([x for x in steps if x.status == 'success'])}/{len(steps)} successful steps", BOLD + WHITE, enabled)]
    if static:
        board.append(_paint("STATIC MODEL ONLY", YELLOW, enabled))
    return "\n".join(board)


def _render_plan(model: ContractModel, steps: list[Step], enabled: bool) -> str:
    lines = [
        _paint("PLANNED PROTOCOL WORKFLOW", BOLD + CYAN, enabled),
        "  " + f"{model.name} {ARROW} ",
    ]
    for step in steps:
        lines.append(
            f"  {step.index:02d}  {ACTOR} {step.actor:<9} "
            f"{ARROW} {FUNCTION} {step.function} "
            f"{' + ' + str(step.value_wei) + ' wei' if step.value_wei else ''}"
        )
    lines.append("")
    lines.append(_paint("These are source-guided hypotheses, not claims about developer intent.", YELLOW, enabled))
    return "\n".join(lines)


def run(config: dict[str, Any], args: list[str] | None = None, host: Any | None = None) -> int:
    args = list(args or [])
    host = host or sys.modules.get("__main__")
    root = Path(getattr(host, "audit_context").foundry_project_root() if host and hasattr(host, "audit_context") else os.getcwd())
    if not root or not (root / "foundry.toml").is_file():
        print("Error: 'lk walkthrough' must be run inside a Foundry project.", file=sys.stderr)
        return 2

    auto = "--auto" in args or "auto" in args
    static = "--static" in args or "--no-exec" in args
    no_slither = "--no-slither" in args
    no_prompt = "--yes" in args or "--non-interactive" in args or not sys.stdin.isatty()
    contract = None
    max_steps = 8
    for i, arg in enumerate(args):
        if arg == "--contract" and i + 1 < len(args):
            contract = args[i + 1]
        if arg == "--steps" and i + 1 < len(args):
            try:
                max_steps = max(1, min(24, int(args[i + 1])))
            except ValueError:
                pass

    print(_paint("LOWKEY PROTOCOL WALKTHROUGH", BOLD + CYAN, _ansi_enabled(static)))
    print("  compile → model → plan → execute → diff → visualize → save evidence")
    build_code, build_out, build_err = _cmd(["forge", "build"], cwd=root, timeout=120)
    if build_code != 0:
        print(build_out + build_err, file=sys.stderr)
        return build_code or 1

    models = _artifact_models(root)
    if not models:
        print("Error: no usable compiled contract artifacts found.", file=sys.stderr)
        return 2

    target, target_contract = _target_from_host(host, config, root, contract, auto)
    model = _find_model(models, contract, target_contract)
    if not model:
        print("Error: unable to choose an executable contract model.", file=sys.stderr)
        return 2

    target = target or config.get("target")
    if not target and not static:
        print("Error: no live target. Use 'lk target <address>' or 'lk walkthrough --auto'.", file=sys.stderr)
        return 2

    rpc = None
    if host and hasattr(host, "effective_rpc"):
        rpc = host.effective_rpc(config)
    actors = _actors(host, config, 4) if host else []
    now = _block_timestamp(rpc) if rpc else int(time.time())
    plan = plan_workflow(model, actors, target or "0x" + "00" * 20, now, max_steps)

    enabled = _ansi_enabled(static)
    if not static and not actors:
        print(_paint("△ no local Anvil actors detected; falling back to static model", YELLOW, enabled))
        static = True

    model_payload = {
        "version": 1,
        "mode": "source-guided-live" if not static else "source-guided-static",
        "target": target,
        "contract": asdict(model),
        "contracts": _models_payload(models),
        "actors": [asdict(x) for x in actors],
        "workflow": [asdict(x) for x in plan],
        "notes": [
            "Compiler/build artifacts are authoritative for ABI/storage metadata.",
            "Runtime values and events are captured from local chain execution.",
            "Workflow order/arguments are heuristics and are marked INFERRED.",
        ],
    }

    print()
    print(_render_plan(model, plan, enabled))
    if static:
        print()
        print(_render_board(model, models, actors, plan, None, [], enabled, static=True))
        _save_artifacts(root, model_payload, plan)
        return 0

    if not no_prompt:
        try:
            input("Press ENTER to start the live walkthrough  ")
        except EOFError:
            no_prompt = True

    for step in plan:
        try:
            step_actor = next(a for a in actors if a.name == step.actor)
        except StopIteration:
            step.status = "reverted"
            step.error = "actor unavailable"
            continue

        before_storage = _snapshot_storage(model, rpc, target, [a.address for a in actors])
        before_balances = {a.name: _balance(rpc, a.address) for a in actors}
        tx, output = _send(host, config, step_actor, target, step.function, step.args, step.value_wei)
        if not tx:
            step.status = "reverted"
            step.error = output or "transaction failed"
            _save_artifacts(root, model_payload, plan)
            print("\n" + _render_board(model, models, actors, plan, step, before_storage, enabled))
            try:
                input("\nPress ENTER for the next source-guided step…  ")
            except EOFError:
                break
            continue

        receipt = _receipt(rpc, tx)
        after_storage = _snapshot_storage(model, rpc, target, [a.address for a in actors])
        after_balances = {a.name: _balance(rpc, a.address) for a in actors}
        step.tx_hash = tx
        step.status = "success" if receipt and receipt.get("status") in (None, "0x1", 1) else "reverted"
        try:
            step.gas_used = int(receipt.get("gasUsed"), 16) if receipt and isinstance(receipt.get("gasUsed"), str) else None
        except Exception:
            step.gas_used = None
        step.events = _event_rows(host, config, receipt)
        step.trace_edges = _trace_edges(rpc, tx)
        step.storage_before = before_storage
        step.storage_after = after_storage
        step.storage_changes = _storage_changed(before_storage, after_storage)
        step.balance_before = before_balances
        step.balance_after = after_balances
        model_payload["workflow"] = [asdict(x) for x in plan]
        _save_artifacts(root, model_payload, plan)
        print("\033[2J\033[H" if enabled else "")
        print(_render_board(model, models, actors, plan, step, after_storage, enabled))
        print("")
        print(_paint("STATE TRANSITION", BOLD + GREEN, enabled))
        print(f"  {step.actor} {ARROW} {step.function} {ARROW} storage/events/trace captured")
        if step.status != "success":
            print(_paint("  execution reverted; the board preserves the actual failure.", RED, enabled))
        if enabled:
            time.sleep(0.35)
        if not no_prompt:
            try:
                answer = input("\nPress ENTER for next step (q to stop)  ").strip().lower()
                if answer == "q":
                    break
            except EOFError:
                no_prompt = True

    replay = _generate_replay_script(root, model, target, plan)
    model_payload["replay_script"] = str(replay.relative_to(root))
    _save_artifacts(root, model_payload, plan)
    print()
    print(_paint("WALKTHROUGH COMPLETE", BOLD + GREEN, enabled))
    print(f"  model    : .audit/walkthrough/model.json")
    print(f"  evidence : .audit/walkthrough/latest.json")
    print(f"  replay   : {replay.relative_to(root)}")
    if no_slither:
        print("  Slither  : skipped by flag")
    else:
        print("  Slither  : existing audit evidence retained; workflow execution does not replace static analysis")
    return 0
