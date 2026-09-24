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
    semantics: dict[str, dict[str, Any]] = field(default_factory=dict)


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


def _simple_call_argument_names(text: str) -> list[str]:
    """Extract obvious identifier arguments from a source call."""
    text = str(text or "")
    if not text:
        return []
    parts: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    result: list[str] = []
    for part in parts:
        match = re.fullmatch(r"[A-Za-z_]\w*", part)
        result.append(match.group(0) if match else "<expression>")
    return result



def _build_source_calls(model: ContractModel, models: list[ContractModel], source_text: str) -> list[dict[str, Any]]:
    by_name = {item.name: item for item in models}
    implementations: dict[str, str] = {item.name: item.name for item in models}
    implementations.update(_implementation_mapping(models))

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
            r"\b([A-Za-z_]\w*)\s*\(\s*((?:[A-Za-z_]\w*|[A-Za-z_]\w*\(\s*[A-Za-z_]\w*\s*\)))\s*\)\s*\.\s*([A-Za-z_]\w+)\s*\(",
            body,
        ):
            typ, expression, called = match.groups()
            variable_match = re.search(r"([A-Za-z_]\w*)\s*\)?\s*$", expression)
            variable = variable_match.group(1) if variable_match else expression
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


def _build_info_ast_calls(root: Path, model: ContractModel) -> list[dict[str, Any]]:
    """Extract cross-contract/internal calls from Solidity compiler AST when available."""
    source_name = str(model.source).replace("\\", "/").lstrip("./")
    ast = None
    for payload in _build_info_payloads(root):
        sources = ((payload.get("output") or {}).get("sources") or {})
        if not isinstance(sources, dict):
            continue
        for name, entry in sources.items():
            if str(name).replace("\\", "/").lstrip("./") == source_name and isinstance(entry, dict):
                candidate = entry.get("ast")
                if isinstance(candidate, dict):
                    ast = candidate
                    break
        if ast:
            break
    if not isinstance(ast, dict):
        return []

    def walk(node: Any):
        if isinstance(node, dict):
            if isinstance(node.get("nodeType"), str):
                yield node
            for value in node.values():
                yield from walk(value)
        elif isinstance(node, list):
            for value in node:
                yield from walk(value)

    def src_start(node: dict[str, Any]) -> int | None:
        raw = str(node.get("src") or "")
        try:
            return int(raw.split(":", 1)[0])
        except (TypeError, ValueError):
            return None

    nodes = list(walk(ast))
    declarations = {int(node["id"]): node for node in nodes if isinstance(node.get("id"), int)}

    def declared_contract_name(node: dict[str, Any]) -> str | None:
        ref = node.get("referencedDeclaration")
        declaration = declarations.get(ref) if isinstance(ref, int) else None
        if isinstance(declaration, dict):
            desc = declaration.get("typeDescriptions") or {}
            type_string = str(desc.get("typeString") or "")
            match = re.search(r"\b(?:contract|interface|library)\s+([A-Za-z_]\w*)", type_string)
            if match:
                return match.group(1)
        desc = node.get("typeDescriptions") or {}
        type_string = str(desc.get("typeString") or "")
        match = re.search(r"\b(?:contract|interface|library)\s+([A-Za-z_]\w*)", type_string)
        return match.group(1) if match else None

    source_text = ""
    try:
        source_text = (root / model.source).read_text(encoding="utf-8", errors="replace")
    except OSError:
        pass
    result: list[dict[str, Any]] = []

    for fn in walk(ast):
        if fn.get("nodeType") != "FunctionDefinition" or not fn.get("name"):
            continue
        caller = str(fn.get("name"))
        body = fn.get("body")
        if not isinstance(body, dict):
            continue
        fn_start = src_start(fn) or 0
        for call in walk(body):
            if call.get("nodeType") != "FunctionCall":
                continue
            expression = call.get("expression")
            if not isinstance(expression, dict):
                continue
            called = str(expression.get("memberName") or expression.get("name") or "")
            if not called:
                continue
            kind = "internal"
            via = None
            interface = None
            target_contract = model.name

            if expression.get("nodeType") == "MemberAccess":
                base = expression.get("expression")
                kind = "cross-contract"
                if isinstance(base, dict):
                    if base.get("nodeType") == "Identifier":
                        via = str(base.get("name") or "") or None
                        interface = declared_contract_name(base)
                    elif base.get("nodeType") == "FunctionCall":
                        inner = base.get("expression") or {}
                        if isinstance(inner, dict):
                            interface = str(inner.get("name") or inner.get("memberName") or "") or None
                        arguments = base.get("arguments") or []
                        if arguments and isinstance(arguments[0], dict):
                            via = str(arguments[0].get("name") or "") or None
                target_contract = interface or target_contract
            elif expression.get("nodeType") == "Identifier":
                called = str(expression.get("name") or called)
                kind = "internal"

            argument_names = []
            for argument in call.get("arguments") or []:
                if isinstance(argument, dict):
                    if argument.get("nodeType") == "Identifier":
                        argument_names.append(str(argument.get("name") or ""))
                    elif argument.get("nodeType") == "Literal":
                        argument_names.append("<literal>")
                    else:
                        argument_names.append(str(
                            argument.get("name")
                            or argument.get("memberName")
                            or "<expression>"
                        ))

            start = src_start(call)
            line = source_text.count("\n", 0, start if start is not None else fn_start) + 1 if source_text else None
            result.append({
                "kind": kind,
                "from": caller,
                "to_contract": target_contract,
                "to_function": called,
                "via": via,
                "interface": interface,
                "argument_names": argument_names,
                "line": line,
                "certainty": "AST",
                "source": "compiler-ast",
            })
        for new_node in walk(body):
            if new_node.get("nodeType") != "NewExpression":
                continue
            type_name = new_node.get("typeName") or {}
            if not isinstance(type_name, dict):
                continue
            created = str(type_name.get("name") or type_name.get("namePath") or "")
            if not created:
                continue
            start = src_start(new_node)
            line = source_text.count("\n", 0, start if start is not None else fn_start) + 1 if source_text else None
            result.append({
                "kind": "create",
                "from": caller,
                "to_contract": created.split(".")[-1],
                "to_function": "<constructor>",
                "via": None,
                "interface": None,
                "line": line,
                "certainty": "AST",
                "source": "compiler-ast",
            })

    return result

def _merge_source_call_edges(root: Path, model: ContractModel, regex_edges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Use compiler AST edges first; retain regex edges only where AST cannot prove the edge."""
    ast_edges = _build_info_ast_calls(root, model)
    combined = ast_edges + regex_edges
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for edge in combined:
        key = (edge.get("kind"), edge.get("from"), edge.get("to_contract"), edge.get("to_function"), edge.get("via"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(edge)
    return unique

def _function_semantics(model: ContractModel, source_text: str) -> dict[str, dict[str, Any]]:
    """Build conservative, source-derived semantic notes for each function."""
    semantics: dict[str, dict[str, Any]] = {}
    state_names = {
        str(item.get("label") or "")
        for item in (model.storage.get("storage") or [])
        if item.get("label")
    }
    state_names.update(str(x.get("name")) for x in model.mappings if x.get("name"))
    state_names.update(str(x.get("name")) for x in model.arrays if x.get("name"))

    functions = list(re.finditer(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\{", source_text, re.S))
    for match in functions:
        name = match.group(1)
        body = _balanced_block(source_text, match.end() - 1)
        reads: list[str] = []
        writes: list[str] = []
        guards: list[str] = []
        creates = re.findall(r"\bnew\s+([A-Za-z_]\w*)\s*\(", body)
        emitted = re.findall(r"\bemit\s+([A-Za-z_]\w*)\s*\(", body)

        for state_name in sorted(x for x in state_names if x):
            if not re.search(r"\b" + re.escape(state_name) + r"\b", body):
                continue
            reads.append(state_name)
            write_pattern = (
                r"\b" + re.escape(state_name)
                + r"\b[^;{}]*(?:=|\+=|-=|\*=|/=|\+\+|--)"
            )
            if re.search(write_pattern, body, re.S):
                writes.append(state_name)

        for expression in re.findall(r"\brequire\s*\((.*?)\)\s*;", body, re.S):
            guards.append("require(" + " ".join(expression.split()) + ")")
        for condition, error_name in re.findall(
            r"\bif\s*\((.*?)\)\s*(?:\{\s*)?revert\s+([A-Za-z_]\w*)\s*\(",
            body,
            re.S,
        ):
            guards.append("if(" + " ".join(condition.split()) + ") -> revert " + error_name)
        for error_name in re.findall(r"\brevert\s+([A-Za-z_]\w*)\s*\(", body):
            if not any(error_name in item for item in guards):
                guards.append("revert " + error_name + "(...)")

        semantics[name + "()"] = {
            "reads": list(dict.fromkeys(reads))[:12],
            "writes": list(dict.fromkeys(writes))[:12],
            "guards": list(dict.fromkeys(guards))[:12],
            "creates": list(dict.fromkeys(creates))[:8],
            "emits": list(dict.fromkeys(emitted))[:8],
            "external_calls": _source_edges_for_name(model, name),
            "line": source_text.count("\n", 0, match.start()) + 1,
        }
    return semantics


def _source_edges_for_name(model: ContractModel, function_name: str) -> list[dict[str, Any]]:
    return [
        edge for edge in model.calls
        if str(edge.get("from") or "") == function_name
    ]

def _artifact_models(root: Path, include_aux: bool = False) -> list[ContractModel]:
    """Build models for application sources, plus optional project-local fixtures."""
    models: list[ContractModel] = []
    out = root / "out"
    if not out.is_dir():
        return models
    src_prefix = _foundry_src_dir(root).replace("\\", "/").strip("/") or "src"
    allowed_prefixes = [src_prefix]
    if include_aux:
        allowed_prefixes.extend(["test", "script"])

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

        if not any(source == prefix or source.startswith(prefix + "/") for prefix in allowed_prefixes):
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

        if kind == "abstract":
            continue

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
        model.calls = _merge_source_call_edges(root, model, _build_source_calls(model, models, source_text))
        model.semantics = _function_semantics(model, source_text)

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


def _contract_requirement_for_parameter(
    model: ContractModel | None,
    function_name: str,
    param_name: str,
) -> str | None:
    """Infer whether an address parameter is actually expected to be a contract."""
    if not model or not param_name:
        return None
    for edge in model.calls:
        if str(edge.get("from") or "") != function_name:
            continue
        if str(edge.get("via") or "").lower() != str(param_name).lower():
            continue
        if edge.get("kind") != "cross-contract":
            continue
        return str(edge.get("interface") or edge.get("to_contract") or "") or None
    return None


def _normalize_observed_keys(observed: dict[str, Any]) -> dict[str, Any]:
    return {
        re.sub(r"[^a-z0-9]", "", str(key).lower()): value
        for key, value in observed.items()
    }


def _merge_protocol_observations(
    observed: dict[str, Any] | None = None,
    config: dict[str, Any] | None = None,
    runtime: list[RuntimeContract] | None = None,
) -> dict[str, Any]:
    """Merge live lab roles, aliases, and runtime contracts into one catalog."""
    merged: dict[str, Any] = dict(observed or {})
    config = config or {}

    for container_name in ("_walkthrough_observed", "lab_system", "aliases", "targets"):
        container = config.get(container_name)
        if not isinstance(container, dict):
            continue
        for key, value in container.items():
            if not is_address(value):
                continue
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            merged[str(key)] = value
            if normalized:
                merged[normalized] = value

    for node in runtime or []:
        if not is_address(node.address):
            continue
        for key in (node.model, node.label):
            normalized = re.sub(r"[^a-z0-9]", "", str(key or "").lower())
            if normalized:
                merged[normalized] = node.address
            if key:
                merged[str(key)] = node.address

    return merged


def _observed_address_for_parameter(
    param: dict[str, Any],
    observed: dict[str, Any],
    requirement: str | None = None,
) -> str | None:
    aliases = _normalize_observed_keys(observed)
    compact = re.sub(r"[^a-z0-9]", "", str(param.get("name") or "").lower())

    direct = aliases.get(compact)
    if is_address(direct):
        return str(direct)

    semantic = {
        "agreement": ("agreement",),
        "staketoken": ("staketoken", "token"),
        "token": ("staketoken", "token"),
        "safeharborregistry": ("safeharborregistry", "registry"),
        "registry": ("safeharborregistry", "registry", "attackregistry"),
        "attackregistry": ("attackregistry",),
        "poolimplementation": ("poolimplementation", "implementation"),
        "implementation": ("poolimplementation", "implementation"),
        "moderator": ("defaultoutcomemoderator", "outcomemoderator", "moderator"),
        "factory": ("factory",),
        "router": ("router",),
        "oracle": ("oracle",),
        "manager": ("manager",),
    }
    for key in semantic.get(compact, ()):
        value = aliases.get(re.sub(r"[^a-z0-9]", "", key))
        if is_address(value):
            return str(value)

    requirement_name = re.sub(r"[^a-z0-9]", "", str(requirement or "").lower())
    if requirement_name:
        candidates = [requirement_name]
        if requirement_name.startswith("i"):
            candidates.append(requirement_name[1:])
        for key, value in aliases.items():
            if not is_address(value):
                continue
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if any(candidate in normalized_key or normalized_key in candidate for candidate in candidates):
                return str(value)

    for key, value in aliases.items():
        if not is_address(value):
            continue
        normalized_key = re.sub(r"[^a-z0-9]", "", str(key).lower())
        if compact and (compact in normalized_key or normalized_key in compact):
            return str(value)

    return None


def _arg_for(
    param: dict[str, Any],
    actors: list[Actor],
    target: str,
    now: int,
    observed: dict[str, Any] | None = None,
    model: ContractModel | None = None,
    function_name: str | None = None,
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
        value = observed.get(compact)
        return value if isinstance(value, list) else [alice, bob]

    if ptype == "address":
        requirement = _contract_requirement_for_parameter(
            model, function_name or "", str(param.get("name") or "")
        )
        live_value = _observed_address_for_parameter(param, observed, requirement)
        if live_value:
            return live_value

        # Do not substitute a human account for an address the source later treats
        # as a contract. Unresolved dependencies are blocked explicitly later.
        if requirement:
            return None

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
            _arg_for(comp, actors, target, now, observed, model, function_name)
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

def _test_flow_hints(root: Path | None, model: ContractModel) -> dict[str, tuple[int, int]]:
    """Mine project tests for ordered calls to this model's ABI functions."""
    if not root or not root.is_dir():
        return {}
    names = {
        str(item.get("name")): 0
        for item in model.abi
        if item.get("type") == "function" and item.get("name")
    }
    if not names:
        return {}
    occurrences: dict[str, list[int]] = {name: [] for name in names}
    test_files = []
    for directory_name in ("test", "tests"):
        directory = root / directory_name
        if directory.is_dir():
            test_files.extend(sorted(directory.rglob("*.sol")))
    for path in test_files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name in names:
            for match in re.finditer(r"\.\\s*" + re.escape(name) + r"\s*\\(", source):
                # Calls inside test contracts are behavioral evidence; ignore function definitions.
                prefix = source[max(0, match.start() - 24):match.start()]
                if re.search(r"function\\s*$", prefix):
                    continue
                occurrences[name].append(match.start())
    ordered = []
    for name, positions in occurrences.items():
        if positions:
            ordered.append((min(positions), -len(positions), name))
    ordered.sort()
    return {name: (index, -count) for index, (_pos, count, name) in enumerate(ordered)}

def plan_workflow(
    model: ContractModel,
    actors: list[Actor],
    target: str,
    now: int,
    max_steps: int,
    observed: dict[str, Any] | None = None,
    root: Path | None = None,
) -> list[Step]:
    observed = observed or {}
    candidates = [x for x in _mutators(model) if _lifecycle_candidate(str(x.get("name") or ""))]
    test_hints = _test_flow_hints(root, model)
    candidates.sort(
        key=lambda item: (
            0 if str(item.get("name") or "") in test_hints else 1,
            test_hints.get(str(item.get("name") or ""), (999999, 0))[0],
            _phase_score(str(item.get("name") or "")),
            str(item.get("name") or ""),
        )
    )

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
        args = [
            _arg_for(p, actors, target, now, observed, model, name)
            for p in item.get("inputs", [])
        ]
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
def _lab_runtime(config: dict[str, Any], target: str, model: ContractModel, models: list[ContractModel] | None = None) -> list[RuntimeContract]:
    """Build a protocol runtime graph from generic lab metadata and observed addresses."""
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    catalog = models or []
    runtime: list[RuntimeContract] = []
    seen: set[str] = set()

    def model_for(key: str) -> str:
        explicit = system.get(key + "_model")
        if explicit:
            return str(explicit)
        compact = re.sub(r"[^a-z0-9]", "", str(key).lower())
        candidates = []
        for item in catalog:
            name = re.sub(r"[^a-z0-9]", "", item.name.lower())
            if compact and (compact == name or compact in name or name in compact):
                candidates.append(item)
        if candidates:
            candidates.sort(key=lambda item: (len(item.name), item.name.lower()))
            return candidates[0].name
        return str(system.get("root_model") or model.name) if key in {"root", "entry", "target"} else str(key).replace("_", " ").title()

    def relation_for(key: str) -> str:
        low = str(key).lower()
        if key in {"root", "entry", "target"}:
            return "ROOT" if key != "target" else "target"
        if "implementation" in low:
            return "IMPLEMENTATION"
        if any(token in low for token in ("child", "clone", "instance")):
            return "CHILD"
        return "DEPENDENCY"

    for key, value in system.items():
        if key.endswith("_model") or key.endswith("_parent") or not is_address(value):
            continue
        if key in {"implementation"} and not system.get("implementation_model"):
            continue
        address = str(value)
        if address.lower() in seen:
            continue
        model_name = model_for(str(key))
        parent = system.get(str(key) + "_parent") if is_address(system.get(str(key) + "_parent")) else None
        runtime.append(RuntimeContract(address, model_name, model_name, relation_for(str(key)), parent))
        seen.add(address.lower())

    if is_address(target) and target.lower() not in seen:
        runtime.insert(0, RuntimeContract(target, model.name, model.name, "target"))
    elif is_address(target):
        for node in runtime:
            if node.address.lower() == target.lower():
                node.relation = "target"
                node.parent = None
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
    target = _source_target(root, model.source, line)
    # Keep the visible function signature readable while making the exact source
    # location clickable in OSC8-capable terminals (Ctrl+Click in common terminals).
    return _osc8(function, target)


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


_ERROR_SELECTOR_CACHE: dict[str, str] = {}


def _error_signature(item: dict[str, Any]) -> str:
    return f"{item.get('name', '<error>')}({','.join(_canonical_type(x) for x in item.get('inputs', []))})"


def _error_selector(signature: str) -> str | None:
    cached = _ERROR_SELECTOR_CACHE.get(signature)
    if cached:
        return cached
    code, out, _err = _cmd(["cast", "sig", signature], timeout=5)
    if code != 0:
        return None
    lines = (out or "").strip().splitlines()
    selector = lines[-1].strip().lower() if lines else None
    if selector and re.fullmatch(r"0x[0-9a-f]{8}", selector):
        _ERROR_SELECTOR_CACHE[signature] = selector
        return selector
    return None


def _extract_hex_payloads(value: Any) -> list[str]:
    text = str(value or "")
    found = re.findall(r"0x[0-9a-fA-F]{8,}", text)
    return list(dict.fromkeys(found))


def _decode_custom_error(value: Any, models: list[ContractModel]) -> str | None:
    """Decode custom-error selectors from cast/revert/trace text using project ABIs."""
    payloads = _extract_hex_payloads(value)
    if not payloads:
        return None

    by_selector: dict[str, str] = {
        "0x08c379a0": "Error(string)",
        "0x4e487b71": "Panic(uint256)",
    }
    for model in models:
        for item in model.abi:
            if item.get("type") != "error" or not item.get("name"):
                continue
            signature = _error_signature(item)
            selector = _error_selector(signature)
            if selector:
                by_selector.setdefault(selector, signature)

    for payload in payloads:
        selector = payload[:10].lower()
        signature = by_selector.get(selector)
        if signature:
            return signature
    return None


def _read_zero_address_diagnostics(
    rpc: str,
    address: str,
    model: ContractModel,
) -> tuple[str | None, list[str]]:
    """Inspect initializer-style configuration getters before blaming a dependency."""
    if not any(
        item.get("type") == "function"
        and str(item.get("name") or "").lower().startswith("initialize")
        for item in model.abi
    ):
        return None, []

    preferred_terms = (
        "owner", "registry", "implementation", "moderator", "token",
        "agreement", "router", "manager", "oracle", "factory",
    )
    origin = None
    diagnostics: list[str] = []

    getters = []
    for item in model.abi:
        if item.get("type") != "function" or item.get("inputs"):
            continue
        outputs = item.get("outputs") or []
        if len(outputs) != 1 or str(outputs[0].get("type") or "") != "address":
            continue
        name = str(item.get("name") or "")
        lower = name.lower()
        if lower == "owner" or any(term in lower for term in preferred_terms if term != "owner"):
            getters.append(item)

    seen = set()
    for item in getters:
        name = str(item.get("name") or "")
        if name in seen:
            continue
        seen.add(name)
        code, out, err = _cmd(
            ["cast", "call", address, _output_signature(item), "--rpc-url", rpc],
            timeout=6,
        )
        if code != 0:
            continue
        value = (out or err or "").strip().splitlines()
        value = value[-1].strip() if value else ""
        if not is_address(value):
            continue
        zero = value.lower() == "0x" + "00" * 20
        diagnostics.append(
            f"{name} = {_addr(value)} " + ("✕ unset" if zero else "✓ configured")
        )
        if zero and (name.lower() == "owner" or origin is None):
            origin = f"{model.name}.{name}() is unset"
    return origin, diagnostics


def _implementation_mapping(models: list[ContractModel]) -> dict[str, str]:
    """Map interfaces to concrete implementations without inventing relationships."""
    mapping: dict[str, str] = {}
    concrete = [m for m in models if m.kind not in {"interface", "library", "abstract"}]
    by_name = {m.name.lower(): m for m in concrete}

    # Explicit inheritance is authoritative.
    for model in concrete:
        for base in model.bases:
            mapping.setdefault(base, model.name)

    # Prefer IThing -> Thing. Otherwise match by ABI function-name overlap.
    for model in models:
        if model.kind != "interface":
            continue
        stem = model.name[1:] if model.name.startswith("I") else model.name
        direct = by_name.get(stem.lower())
        if direct:
            mapping[model.name] = direct.name
            continue
        interface_names = {sig.split("(", 1)[0] for sig in model.functions}
        if not interface_names:
            continue
        scored = []
        for candidate in concrete:
            candidate_names = {sig.split("(", 1)[0] for sig in candidate.functions}
            overlap = len(interface_names & candidate_names)
            if overlap:
                scored.append((overlap, candidate.name))
        if scored:
            scored.sort(key=lambda item: (-item[0], item[1].lower()))
            mapping[model.name] = scored[0][1]
    return mapping
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
    if "argument resolution blocked" in lower or "no matching protocol dependency" in lower:
        return "Lowkey could not resolve a required contract address, so it refused to send an impossible call"
    if 'data:"0x"' in lower:
        return "the node returned an empty revert payload; Lowkey will inspect initialized dependencies and the traced call path next"
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
    if lower == "setstaketokenallowed":
        token = _friendly_arg(args[0], actors) if args else "the supplied token"
        enabled = _friendly_arg(args[1], actors) if len(args) > 1 else "true"
        return f"{actor} marks {token} as an allowed stake token ({enabled})"
    if lower == "createpool":
        agreement = _friendly_arg(args[0], actors) if args else "the Agreement"
        token = _friendly_arg(args[1], actors) if len(args) > 1 else "the stake token"
        recipient = _friendly_arg(args[4], actors) if len(args) > 4 else "the recovery address"
        return f"{actor} asks {contract} to create a new pool for {agreement} using {token}; recovery goes to {recipient}"
    if lower == "stake":
        amount = _friendly_value(args[0]) if args else "the requested amount"
        verb = "deposits" if step.status == "success" else "tries to deposit"
        return f"{actor} {verb} {amount} stake tokens into {contract}"
    if lower == "deposit":
        recipient = _friendly_arg(args[0], actors) if args else "the recipient"
        verb = "deposits" if step.status == "success" else "tries to deposit"
        if step.value_wei:
            return f"{actor} sends {_friendly_eth(step.value_wei)} to {contract} to fund the escrow for {recipient}"
        return f"{actor} {verb} funds into {contract} for {recipient}"
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
        if lower == "deposit" and step.args and isinstance(step.args[0], str) and is_address(step.args[0]):
            recipient = _friendly_arg(step.args[0], actors)
            lines.append(f"    ├─ {actor} names {recipient} as the recipient")
            lines.append("    └─ native ETH movement is shown separately above when applicable")
        else:
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
        lines.append("    ├─ factory checks: token allowed, expiry valid, agreement valid, caller owns agreement")
        lines.append("    ├─ factory deploys a child pool clone")
        lines.append("    ├─ child pool.initialize(...) wires the agreement, token, registry, moderator, owner and scope — the new pool is now initialized")
        lines.append("    └─ PoolCreated records the new pool in the factory")
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
    args = ", ".join(_friendly_arg(x, actors) for x in step.args)
    raw_call = f"{function}({args})" if args else f"{function}()"
    call_target = (
        _source_target(root, model.source, model.function_locations.get(function))
        if model and model.function_locations.get(function)
        else None
    )
    call_display = _osc8(raw_call, call_target) if call_target else raw_call
    status = "✓ SUCCESS" if step.status == "success" else "✕ BLOCKED" if step.status in {"blocked", "reverted"} else "● CHECKING"
    color = GREEN if step.status == "success" else RED if step.status in {"blocked", "reverted"} else YELLOW

    lines = [
        _paint(f"  ╭─ FUNCTION {step.index:02d}  {status}", color, enabled),
        "  │",
        f"  │   {ACTOR} {actor} {ARROW} {contract}.{call_display}",
        f"  │       ↳ {_human_action_summary(step, actors)}",
        f"  │       ↳ CALL: {actor} ──▶ {contract}",
    ]

    input_lines = _input_story(step, model, actors) if model else []
    if input_lines:
        lines += ["  │", "  │   INPUTS"]
        for item in input_lines[:8]:
            lines.append(f"  │   ├─ {item}")

    source_guard_lines = _source_guard_lines(model, step) if model else []
    if source_guard_lines:
        lines += ["  │", "  │   WHAT THE CODE CHECKS"]
        for item in source_guard_lines[:8]:
            lines.append(f"  │   ├─ {item}")

    source_edges = _source_edges_for_step(model, step) if model else []
    if source_edges:
        impls = _implementation_mapping(models)
        by_name = {item.name: item for item in models}
        lines += ["  │", "  │   SOURCE LOGIC OF THIS FUNCTION"]
        seen = set()
        for edge in source_edges[:10]:
            target_name = str(edge.get("to_contract") or edge.get("interface") or "external")
            concrete = impls.get(target_name, target_name)
            fn = str(edge.get("to_function") or "unknown")
            target_model = by_name.get(concrete) or by_name.get(target_name)
            key = (concrete, fn, edge.get("via"))
            if key in seen:
                continue
            seen.add(key)
            description = _connection_summary(model, edge, concrete, target_model, root)
            lines.append(f"  │   ├─ {description}")
            link = _function_link(root, target_model, fn) if target_model else fn
            lines.append(f"  │   └─ {EXTERNAL} {concrete}.{link}")

    lower = function.lower()
    if step.value_wei:
        lines += ["  │", f"  │   ETH FLOW      {actor} ── {_friendly_eth(step.value_wei)} ──▶ {contract}"]
    if lower in {"stake", "deposit", "contributebonus", "fund", "contribute"} and step.args:
        lines.append(f"  │   token flow: {actor} ── {_friendly_value(step.args[0])} ──▶ {contract}")
    elif lower in {"withdraw", "redeem", "refund", "collect", "claimsurvived", "claimcorrupted", "claimattackerbounty", "claimexpired"}:
        lines.append(f"  │   token flow: {contract} ──▶ {actor}")

    if step.execution_edges:
        lines += ["  │", "  │   ACTUAL RUNTIME PATH", "  │      caller", "  │        │"]
        runtime_count = min(8, len(step.execution_edges))
        for index, edge in enumerate(step.execution_edges[:runtime_count]):
            dst = edge.get("to_contract") or _addr(edge.get("to_address"))
            resolved_label = edge.get("to_label") or dst
            fn = str(edge.get("function") or edge.get("type") or "")
            branch = "└─" if index == runtime_count - 1 else "├─"
            mark = " ✕" if edge.get("error") or edge.get("revert") else " ✓"
            lines.append(f"  │       {branch} {EXTERNAL} {resolved_label}.{fn}{mark}")

    if step.discovered_contracts:
        lines += ["  │", "  │   NEW CONTRACTS DISCOVERED"]
        for node in step.discovered_contracts[:5]:
            lines.append(f"  │   ├─ {ARROW} {node.get('label') or node.get('model')} {_addr(node.get('address'))} [{node.get('relation') or 'contract'}]")

    if step.execution_edges:
        call_tree = _render_actual_call_tree(step, [], enabled)
        if call_tree:
            lines += ["  │", call_tree]

    if step.status == "success":
        state_lines = _friendly_state_lines(step, actors)
        balance_lines = _friendly_token_balance_lines(step, actors) + _friendly_balance_lines(step, actors)
        event_lines = _friendly_event_lines(step)
        lines += ["  │", "  │   WHAT CHANGED"]
        changes = [item.strip() for item in state_lines[:7] + balance_lines[:5] + event_lines[:4] if item.strip()]
        if changes:
            lines.extend(f"  │   ├─ {item}" for item in changes)
        else:
            lines.append("  │   └─ no tracked storage, balance, or event delta")
    elif step.status in {"blocked", "reverted"}:
        reason = step.error_reason or _explain_failure(step, step.error, actor)
        lines += ["  │", "  │   WHY IT FAILED", f"  │   ├─ {reason}"]
        if step.failure_origin:
            lines.append(f"  │   ├─ likely origin: {step.failure_origin}")
        for diagnosis in step.diagnostics[:7]:
            lines.append(f"  │   ├─ {diagnosis}")
        decoded = _decode_custom_error(step.error, models)
        if decoded:
            lines.append(f"  │   ├─ decoded error: {decoded}")
        lines.append(f"  │   └─ raw node result: {_short_error(step.error)}")

    marker = "INFERRED" if step.inferred else "LAB CONTROL"
    lines += ["  │", f"  │   WHY THIS STEP: {step.reason} [{marker}]", "  ╰" + "─" * 86 + "╯"]
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
        step_model = next((m for m in models if m.name == step.contract), None)
        frame = _render_interaction_graph_full(
            root, step, actors, step_model, models, enabled
        )
        if current is step:
            frame += "\n  ◀ NOW  •  LIVE\n  ◀ LIVE"
        lines.append(frame)
        if index != len(visible) - 1:
            lines.append("                 │")
            lines.append("                 ▼")
            lines.append("             next live step")

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


def _function_inputs(model: ContractModel, signature: str) -> list[dict[str, Any]]:
    if not model:
        return []

    wanted = str(signature).lower()
    name = wanted.split("(", 1)[0]

    # Prefer a unique ABI-name match. This keeps lightweight/test-built models
    # usable even when their precomputed function signature index is incomplete.
    direct_matches = [
        item for item in model.abi
        if item.get("type") == "function"
        and str(item.get("name") or "").lower() == name
    ]
    if len(direct_matches) == 1:
        return list(direct_matches[0].get("inputs") or [])

    # Overloads still require the canonical signature.
    for item in direct_matches:
        if _signature(item).lower() == wanted:
            return list(item.get("inputs") or [])

    return []


def _source_edges_for_step(model: ContractModel, step: Step) -> list[dict[str, Any]]:
    name = str(step.function or "").split("(", 1)[0]
    return [edge for edge in model.calls if str(edge.get("from") or "") == name]


def _pretty_identifier(value: str | None) -> str:
    text = re.sub(r"[^A-Za-z0-9_]+", " ", str(value or "")).strip()
    text = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    return text.title() if text else "contract"


def _source_dependency_address(rpc: str, model: ContractModel, edge: dict[str, Any], step: Step) -> tuple[str | None, str | None]:
    """Resolve a source-level dependency variable to a live address."""
    via = str(edge.get("via") or "")
    if not via:
        return None, None
    inputs = _function_inputs(model, step.function)
    by_param = {
        str(param.get("name") or "").lower(): step.args[index]
        for index, param in enumerate(inputs)
        if index < len(step.args)
    }
    direct = by_param.get(via.lower())
    if is_address(direct):
        return direct, via
    getter = next(
        (
            item for item in model.abi
            if item.get("type") == "function"
            and not item.get("inputs")
            and str(item.get("name") or "").lower() == via.lower()
            and item.get("outputs")
            and str(item["outputs"][0].get("type") or "") == "address"
        ),
        None,
    )
    if not getter:
        return None, via
    code, out, _err = _cmd(["cast", "call", step.address, _output_signature(getter), "--rpc-url", rpc], timeout=6)
    if code != 0:
        return None, via
    values = (out or "").strip().splitlines()
    value = values[-1].strip() if values else ""
    return (value if is_address(value) else None), via


def _probe_boolean_getters(rpc: str, step: Step, model: ContractModel) -> list[str]:
    """Probe cheap ABI predicates to explain empty revert payloads."""
    inputs = _function_inputs(model, step.function)
    observations: list[str] = []
    for index, param in enumerate(inputs):
        if index >= len(step.args) or not is_address(step.args[index]):
            continue
        param_name = str(param.get("name") or "").lower()
        wanted = []
        if "token" in param_name:
            wanted += ["allowed", "whitelisted", "enabled", "supported", "valid"]
        if "agreement" in param_name:
            wanted += ["valid", "registered", "enabled", "active"]
        if "account" in param_name or "user" in param_name:
            wanted += ["allowed", "enabled", "active"]
        for item in [item for item in model.abi
                     if item.get("type") == "function"
                     and len(item.get("inputs") or []) == 1
                     and len(item.get("outputs") or []) == 1
                     and str(item["outputs"][0].get("type") or "") == "bool"
                     and any(token in str(item.get("name") or "").lower() for token in wanted)][:4]:
            code, out, err = _cmd(["cast", "call", step.address, _output_signature(item), str(step.args[index]), "--rpc-url", rpc], timeout=6)
            if code != 0:
                continue
            value = " ".join((out or err or "").strip().split()).lower()
            if value in {"true", "false"}:
                observations.append(f"{_signature(item)} = {value} for {_pretty_identifier(param_name)}")
    return observations


def _source_guard_lines(model: ContractModel, step: Step) -> list[str]:
    """Return concise source-level guards and state writes for the current function."""
    name = str(step.function or "").split("(", 1)[0]
    semantics = model.semantics.get(name + "()") or model.semantics.get(name)
    if not isinstance(semantics, dict):
        return []
    lines: list[str] = []
    for guard in semantics.get("guards", [])[:8]:
        lines.append("source guard: " + str(guard))
    for edge in semantics.get("external_calls", [])[:8]:
        target = edge.get("interface") or edge.get("to_contract") or "dependency"
        fn = edge.get("to_function") or "unknown"
        via = edge.get("via")
        suffix = " via " + str(via) if via else ""
        lines.append(f"source dependency: {target}.{fn}(){suffix}")
    for item in semantics.get("writes", [])[:8]:
        lines.append("state write candidate: " + str(item))
    return list(dict.fromkeys(lines))

def _forge_build_with_info(root: Path) -> tuple[int, str, str]:
    code, out, err = _cmd(["forge", "build", "--build-info"], cwd=root, timeout=180)
    if code == 0:
        return code, out, err
    combined = (out + "\n" + err).lower()
    if "unknown option" in combined or "unexpected argument" in combined or "unrecognized option" in combined:
        return _cmd(["forge", "build"], cwd=root, timeout=180)
    return code, out, err

def _build_info_payloads(root: Path) -> list[dict[str, Any]]:
    directory = root / "out" / "build-info"
    if not directory.is_dir():
        return []
    result = []
    for path in sorted(directory.glob("*.json")):
        data = _json_file(path)
        if isinstance(data, dict):
            result.append(data)
    return result

def _build_info_function_abi(root: Path, contract_name: str, function_name: str) -> dict[str, Any] | None:
    wanted_contract = str(contract_name or "").lower()
    wanted_function = str(function_name or "").lower()
    for payload in _build_info_payloads(root):
        contracts = ((payload.get("output") or {}).get("contracts") or {})
        if not isinstance(contracts, dict):
            continue
        for _source, contract_map in contracts.items():
            if not isinstance(contract_map, dict):
                continue
            for name, data in contract_map.items():
                if str(name).lower() != wanted_contract or not isinstance(data, dict):
                    continue
                abi = data.get("abi")
                if not isinstance(abi, list):
                    continue
                for item in abi:
                    if item.get("type") == "function" and str(item.get("name") or "").lower() == wanted_function:
                        return item
    return None

def _output_signature(item: dict[str, Any]) -> str:
    inputs = ",".join(_canonical_type(x) for x in item.get("inputs", []))
    outputs = ",".join(_canonical_type(x) for x in item.get("outputs", []))
    return f"{item.get('name', '<anonymous>')}({inputs})({outputs})"

def _read_contract_getter(rpc: str, address: str, getter: dict[str, Any], args: list[Any] | None = None) -> tuple[bool, str]:
    command = ["cast", "call", address, _output_signature(getter)]
    command.extend(_cli_arg(value) for value in (args or []))
    command.extend(["--rpc-url", rpc])
    code, out, err = _cmd(command, timeout=8)
    return code == 0, " ".join((out or err or "").strip().split())

def _dependency_argument_values(step: Step, caller_model: ContractModel, dependency_fn: dict[str, Any]) -> list[Any]:
    caller_inputs = _function_inputs(caller_model, step.function)
    caller_values = {}
    for index, param in enumerate(caller_inputs):
        if index < len(step.args):
            caller_values[str(param.get("name") or "").lower()] = step.args[index]
    values = []
    for param in dependency_fn.get("inputs") or []:
        value = caller_values.get(str(param.get("name") or "").lower())
        if value is None and len(dependency_fn.get("inputs") or []) == 1:
            candidates = [
                step.args[index] for index, source_param in enumerate(caller_inputs)
                if index < len(step.args) and _canonical_type(source_param) == "address"
            ]
            if candidates:
                value = candidates[0]
        if value is not None:
            values.append(value)
    return values

def _probe_source_dependency_result(
    rpc: str,
    step: Step,
    model: ContractModel,
    edge: dict[str, Any],
    dependency_address: str,
    models: list[ContractModel],
    caller_address: str | None = None,
) -> tuple[str | None, str | None]:
    """Read the source-discovered dependency call and report its real return value."""
    target_name = str(edge.get("to_contract") or edge.get("interface") or "")
    concrete = _implementation_mapping(models).get(target_name, target_name)
    target_model = next((item for item in models if item.name.lower() == concrete.lower()), None)
    if target_model is None:
        target_model = next((item for item in models if item.name.lower() == target_name.lower()), None)
    fn_name = str(edge.get("to_function") or "")
    if target_model is None and fn_name:
        target_model = next(
            (
                item for item in models
                if (
                    any(
                        str(sig).split("(", 1)[0].lower() == fn_name.lower()
                        for sig in item.functions
                    )
                    or any(
                        item_abi.get("type") == "function"
                        and str(item_abi.get("name") or "").lower() == fn_name.lower()
                        for item_abi in item.abi
                    )
                )
            ),
            None,
        )
    fn_item = _function_by_name(target_model, fn_name)
    if not fn_item:
        return None, None

    caller_inputs = _function_inputs(model, step.function)
    caller_values = {
        str(param.get("name") or "").lower(): step.args[index]
        for index, param in enumerate(caller_inputs)
        if index < len(step.args)
    }
    values: list[Any] = []
    for param in fn_item.get("inputs") or []:
        pname = str(param.get("name") or "").lower()
        value = caller_values.get(pname)
        if value is None and len(fn_item.get("inputs") or []) == 1:
            address_values = [
                step.args[index]
                for index, source_param in enumerate(caller_inputs)
                if index < len(step.args) and _canonical_type(source_param) == "address"
            ]
            if address_values:
                value = address_values[0]
        if value is None:
            return None, None
        values.append(value)

    code, out, err = _cmd(
        ["cast", "call", dependency_address, _signature(fn_item),
         *[_cli_arg(value) for value in values], "--rpc-url", rpc],
        timeout=8,
    )
    if code != 0:
        return None, f"{concrete}.{_signature(fn_item)} could not be read at {_addr(dependency_address)}"

    rendered = " ".join((out or err or "").strip().split())[-240:] or "empty result"
    origin = None
    lowered = rendered.lower()
    if lowered == "false" or lowered.endswith(" false"):
        origin = f"{concrete}.{fn_name} returned false"
    elif caller_address and is_address(rendered):
        if rendered.lower() != str(caller_address).lower():
            origin = (
                f"{concrete}.{fn_name} returned {_addr(rendered)}, "
                f"which does not match caller {_addr(caller_address)}"
            )
    return origin, f"{concrete}.{_signature(fn_item)} → {rendered}"

def _diagnose_argument_contracts(
    rpc: str,
    step: Step,
    model: ContractModel,
    models: list[ContractModel] | None = None,
    caller_address: str | None = None,
) -> tuple[str | None, list[str]]:
    """Trace source-discovered address dependencies and probe their real behavior."""
    origin = None
    diagnostics: list[str] = []
    model_catalog = models or [model]

    for edge in _source_edges_for_step(model, step):
        via = str(edge.get("via") or "")
        if not via:
            continue
        candidate, label = _source_dependency_address(rpc, model, edge, step)
        if not candidate:
            continue

        code = _runtime_code(rpc, candidate)
        target_desc = f"{edge.get('interface') or edge.get('to_contract')}.{edge.get('to_function')}()"
        if code in {"", "0x"}:
            origin = origin or f"{model.name}.{step.function.split('(', 1)[0]} -> {target_desc}"
            diagnostics.append(
                f"{_pretty_identifier(label)} = {_addr(candidate)} has no contract code; "
                f"the source expects {target_desc}"
            )
            continue

        diagnostics.append(
            f"{_pretty_identifier(label)} = {_addr(candidate)} has live contract code; "
            f"the source expects {target_desc}"
        )
        probe_origin, probe = _probe_source_dependency_result(
            rpc,
            step,
            model,
            edge,
            candidate,
            model_catalog,
            caller_address=caller_address,
        )
        if probe:
            diagnostics.append(f"dependency result: {probe}")
        if probe_origin and origin is None:
            origin = probe_origin

    diagnostics.extend(_probe_boolean_getters(rpc, step, model))
    return origin, list(dict.fromkeys(diagnostics))

def _constant_duration_seconds(source_text: str, name: str) -> int | None:
    match = re.search(
        r"\b(?:uint\d*\s+)?(?:public\s+|private\s+|internal\s+)?constant\s+"
        + re.escape(name) + r"\s*=\s*([0-9]+)\s*(seconds?|minutes?|hours?|days?|weeks?)\b",
        source_text,
    )
    if not match:
        return None
    value = int(match.group(1))
    multipliers = {
        "second": 1, "seconds": 1,
        "minute": 60, "minutes": 60,
        "hour": 3600, "hours": 3600,
        "day": 86400, "days": 86400,
        "week": 604800, "weeks": 604800,
    }
    return value * multipliers[match.group(2).lower()]
def _mapping_argument_for_function(body: str, mapping_name: str, inputs: list[dict[str, Any]], args: list[Any]) -> tuple[str | None, Any]:
    match = re.search(r"\b" + re.escape(mapping_name) + r"\s*\\[\\s*([A-Za-z_]\\w*)\\s*\\]", body)
    if not match:
        return None, None
    wanted = match.group(1).lower()
    for index, param in enumerate(inputs):
        if index < len(args) and str(param.get("name") or "").lower() == wanted:
            return str(param.get("name") or ""), args[index]
    return None, None

def _probe_source_guards(root: Path, rpc: str, step: Step, model: ContractModel, models: list[ContractModel], actor_address: str | None) -> tuple[str | None, list[str]]:
    """Evaluate cheap source-visible guards against actual local state."""
    try:
        source = (root / model.source).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, []
    name = str(step.function or "").split("(", 1)[0]
    match = re.search(r"\bfunction\\s+" + re.escape(name) + r"\s*\\([^)]*\\)[^{;]*\\{", source, re.S)
    header = match.group(0) if match else ""
    body = _balanced_block(source, match.end() - 1) if match else ""
    guard_region = header + "\n" + body
    inputs = _function_inputs(model, step.function)
    by_name = {str(param.get("name") or ("arg" + str(i + 1))).lower(): step.args[i] for i, param in enumerate(inputs) if i < len(step.args)}
    diagnostics: list[str] = []
    origin = None

    for index, param in enumerate(inputs):
        if index >= len(step.args) or _canonical_type(param) != "address":
            continue
        pname = str(param.get("name") or ("arg" + str(index + 1)))
        value = step.args[index]
        if re.search(r"\b" + re.escape(pname) + r"\s*==\\s*address\\(0\\)", body):
            if is_address(value) and value.lower() == "0x" + "00" * 20:
                diagnostics.append("✕ " + pname + " = zero address; source rejects it")
                origin = origin or (model.name + "." + name + " → " + pname + " == address(0)")
            else:
                diagnostics.append("✓ " + pname + " is non-zero")

    owner = next((item for item in model.abi if item.get("type") == "function" and item.get("name") == "owner" and not item.get("inputs") and item.get("outputs")), None)
    if owner and actor_address and "onlyOwner" in guard_region:
        ok, rendered = _read_contract_getter(rpc, step.address, owner)
        value = rendered.splitlines()[-1].strip() if rendered else ""
        if ok and is_address(value):
            if value.lower() == actor_address.lower():
                diagnostics.append("✓ owner() = " + _addr(value) + " matches " + step.actor)
            else:
                diagnostics.append("✕ owner() = " + _addr(value) + "; caller is " + step.actor)
                origin = origin or (model.name + ".owner() does not match " + step.actor)

    paused = next((item for item in model.abi if item.get("type") == "function" and item.get("name") == "paused" and not item.get("inputs") and item.get("outputs") and _canonical_type(item["outputs"][0]) == "bool"), None)
    if paused and "whenNotPaused" in guard_region:
        ok, rendered = _read_contract_getter(rpc, step.address, paused)
        value = rendered.splitlines()[-1].strip().lower() if rendered else ""
        if ok and value in {"true", "false"}:
            if value == "true":
                diagnostics.append("✕ paused() = true; not-paused gate rejects the call")
                origin = origin or (model.name + ".paused() = true")
            else:
                diagnostics.append("✓ paused() = false; pause gate is open")

    for mapping in model.mappings:
        mapping_name = str(mapping.get("name") or "")
        if not mapping_name or not re.search(r"\b" + re.escape(mapping_name) + r"\s*\\[", body):
            continue
        getter = next((item for item in model.abi if item.get("type") == "function" and item.get("name") == mapping_name and len(item.get("inputs") or []) == 1), None)
        if not getter:
            continue
        key_name, key_value = _mapping_argument_for_function(body, mapping_name, inputs, step.args)
        if key_name is None:
            continue
        ok, rendered = _read_contract_getter(rpc, step.address, getter, [key_value])
        value = rendered.splitlines()[-1].strip() if rendered else ""
        if not ok:
            continue
        marker = "✕" if value.lower() == "false" else "✓"
        suffix = "; this mapping gate blocks the call" if marker == "✕" else ""
        diagnostics.append(marker + " " + _pretty_identifier(mapping_name) + "(" + _friendly_arg(key_value, []) + ") = " + value + suffix)
        if marker == "✕":
            origin = origin or (model.name + "." + name + " → " + mapping_name + "[" + key_name + "] is false")

    for param in inputs:
        pname = str(param.get("name") or "")
        value = by_name.get(pname.lower())
        if not isinstance(value, int):
            continue
        tm = re.search(r"\b" + re.escape(pname) + r"\s*<\\s*block\\.timestamp\\s*\\+\\s*([A-Za-z_]\\w*)", body)
        if not tm:
            continue
        seconds = _constant_duration_seconds(source, tm.group(1))
        if seconds is None:
            continue
        required = _block_timestamp(rpc) + seconds
        if value < required:
            diagnostics.append("✕ " + pname + " is too soon; required timestamp is " + str(required))
            origin = origin or (model.name + "." + name + " → " + pname + " violates the time guard")
        else:
            diagnostics.append("✓ " + pname + " clears the time guard")

    for edge in _source_edges_for_step(model, step):
        if edge.get("kind") != "cross-contract":
            continue
        via = str(edge.get("via") or "")
        dependency, _ = _source_dependency_address(rpc, model, edge, step)
        if not via or not dependency:
            continue
        code = _runtime_code(rpc, dependency)
        target_name = str(edge.get("interface") or edge.get("to_contract") or "External")
        dep_fn_name = str(edge.get("to_function") or "")
        if code in {"", "0x"}:
            diagnostics.append("✕ " + _pretty_identifier(via) + " = " + _addr(dependency) + " has no contract code")
            origin = origin or (model.name + " → " + target_name + "." + dep_fn_name + " has no runtime code")
            continue
        dep_model = next((item for item in models if item.name.lower() == target_name.lower()), None)
        dep_fn = _function_by_name(dep_model, dep_fn_name) if dep_model else None
        if not dep_fn:
            dep_fn = _build_info_function_abi(root, target_name, dep_fn_name)
        if not dep_fn:
            continue
        ok, rendered = _read_contract_getter(rpc, dependency, dep_fn, _dependency_argument_values(step, model, dep_fn))
        value = rendered.splitlines()[-1].strip() if rendered else ""
        if not ok:
            diagnostics.append("? " + target_name + "." + dep_fn_name + "(...) could not be read at " + _addr(dependency))
            continue
        if value.lower() == "false":
            diagnostics.append("✕ " + target_name + "." + _signature(dep_fn) + " → false; dependency guard rejects the call")
            origin = origin or (model.name + " → " + target_name + "." + dep_fn_name + " returned false")
        elif dep_fn.get("outputs") and _canonical_type(dep_fn["outputs"][0]) == "address" and actor_address and is_address(value) and dep_fn_name.lower() == "owner":
            if value.lower() == actor_address.lower():
                diagnostics.append("✓ " + target_name + ".owner() = " + _addr(value) + " matches " + step.actor)
            else:
                diagnostics.append("✕ " + target_name + ".owner() = " + _addr(value) + "; " + step.actor + " is not the owner")
                origin = origin or (target_name + ".owner() does not match " + step.actor)
        else:
            diagnostics.append("✓ " + target_name + "." + _signature(dep_fn) + " → " + value)

    return origin, list(dict.fromkeys(diagnostics))

def _is_local_rpc(rpc: str) -> bool:
    try:
        host = urlsplit(str(rpc)).hostname or ""
        return host in {"127.0.0.1", "localhost", "::1"}
    except ValueError:
        return False

def _function_body(root: Path, model: ContractModel, function_name: str) -> str:
    try:
        source = (root / model.source).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    match = re.search(r"\bfunction\\s+" + re.escape(function_name) + r"\s*\\([^)]*\\)[^{;]*\\{", source, re.S)
    return _balanced_block(source, match.end() - 1) if match else ""

def _find_mapping_setter(root: Path, model: ContractModel, mapping_name: str) -> dict[str, Any] | None:
    normalized = re.sub(r"[^a-z0-9]", "", mapping_name.lower()).replace("allowed", "")
    candidates = []
    for item in model.abi:
        if item.get("type") != "function" or item.get("stateMutability") in {"view", "pure"}:
            continue
        inputs = item.get("inputs") or []
        if len(inputs) != 2 or _canonical_type(inputs[0]) != "address" or _canonical_type(inputs[1]) != "bool":
            continue
        name = str(item.get("name") or "")
        compact = re.sub(r"[^a-z0-9]", "", name.lower()).replace("set", "", 1)
        score = 0
        if normalized and normalized in compact.replace("allowed", ""):
            score += 100
        if "allow" in name.lower() or "enable" in name.lower() or "active" in name.lower():
            score += 25
        body = _function_body(root, model, name)
        if mapping_name and re.search(r"\b" + re.escape(mapping_name) + r"\s*\\[", body):
            score += 100
        if re.search(r"\]\s*=", body):
            score += 10
        if score:
            candidates.append((score, name.lower(), item))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][2] if candidates else None

def _owner_actor_for_target(rpc: str, target: str, model: ContractModel, actors: list[Actor]) -> Actor | None:
    owner = next((item for item in model.abi if item.get("type") == "function" and item.get("name") == "owner" and not item.get("inputs") and item.get("outputs") and _canonical_type(item["outputs"][0]) == "address"), None)
    if not owner:
        return None
    ok, rendered = _read_contract_getter(rpc, target, owner)
    value = rendered.splitlines()[-1].strip() if rendered else ""
    if not ok or not is_address(value):
        return None
    return next((actor for actor in actors if actor.address.lower() == value.lower()), None)

def _dependency_setter(root: Path, dependency_model: ContractModel | None, dependency_function: str) -> dict[str, Any] | None:
    if not dependency_model:
        return None
    hint = re.sub(r"^(is|get|has|check)", "", dependency_function.lower())
    candidates = []
    for item in dependency_model.abi:
        if item.get("type") != "function" or item.get("stateMutability") in {"view", "pure"}:
            continue
        inputs = item.get("inputs") or []
        if len(inputs) != 2 or _canonical_type(inputs[0]) != "address" or _canonical_type(inputs[1]) != "bool":
            continue
        name = str(item.get("name") or "")
        compact = re.sub(r"[^a-z0-9]", "", name.lower())
        score = 0
        if hint and hint in compact:
            score += 100
        if any(token in compact for token in ("valid", "allowed", "enabled", "active", "registered", "approved")):
            score += 30
        if compact.startswith("set") or compact.startswith("allow") or compact.startswith("enable"):
            score += 15
        if score:
            candidates.append((score, compact, item))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][2] if candidates else None

def _prepare_obvious_prerequisite(root: Path, rpc: str, host: Any, config: dict[str, Any], step: Step, model: ContractModel, models: list[ContractModel], actors: list[Actor]) -> str | None:
    """Apply a source-proven, local-only prerequisite and return a human-readable action."""
    if not _is_local_rpc(rpc):
        return None
    actor = next((item for item in actors if item.name == step.actor), actors[0] if actors else None)
    if not actor:
        return None
    origin, diagnostics = _probe_source_guards(root, rpc, step, model, models, actor.address)
    if not origin:
        return None

    # A time-window guard can be repaired without inventing protocol state.
    function_name = str(step.function).split("(", 1)[0]
    source = ""
    try:
        source = (root / model.source).read_text(encoding="utf-8", errors="replace")
    except OSError:
        source = ""
    inputs = _function_inputs(model, step.function)
    for index, param in enumerate(inputs):
        pname = str(param.get("name") or "")
        if index >= len(step.args) or _canonical_type(param) not in {"uint256", "uint128", "uint64", "uint32"}:
            continue
        tm = re.search(r"\b" + re.escape(pname) + r"\s*<\\s*block\\.timestamp\\s*\\+\\s*([A-Za-z_]\\w*)", source, re.S)
        if not tm:
            continue
        seconds = _constant_duration_seconds(source, tm.group(1))
        if seconds is None:
            continue
        if any(pname + " is too soon" in line for line in diagnostics):
            step.args[index] = _block_timestamp(rpc) + seconds + 1
            return "PREREQUISITE ✓ adjusted " + pname + " to satisfy the source time window"

    # When the source proves this is an owner mismatch, switch to a local Anvil
    # actor representing the real owner instead of forging an identity.
    if any("is not the owner" in line or "caller is" in line for line in diagnostics):
        owner_actor = _owner_actor_for_target(rpc, step.address, model, actors)
        if owner_actor and owner_actor.name != step.actor:
            step.actor = owner_actor.name
            return "PREREQUISITE ✓ switched caller to owner actor " + owner_actor.name

    # Missing public mapping permission → execute its obvious address/bool setter.
    for mapping in model.mappings:
        name = str(mapping.get("name") or "")
        if not name:
            continue
        false_line = next((line for line in diagnostics if line.startswith("✕") and _pretty_identifier(name) in line and "= false" in line), None)
        if not false_line:
            continue
        setter = _find_mapping_setter(root, model, name)
        if not setter:
            continue
        key_name, key_value = _mapping_argument_for_function(_function_body(root, model, str(step.function).split("(",1)[0]), name, _function_inputs(model, step.function), step.args)
        if key_name is None or not is_address(key_value):
            continue
        owner_actor = _owner_actor_for_target(rpc, step.address, model, actors) or actor
        tx, output = _send(host, config, owner_actor, step.address, _signature(setter), [key_value, True], 0)
        if tx:
            return "PREREQUISITE ✓ " + _signature(setter) + " → enabled " + _pretty_identifier(name) + " for " + _friendly_arg(key_value, actors)
        return "PREREQUISITE ✕ " + _signature(setter) + " failed: " + _short_error(output)

    # Dependency boolean guard false → call an obvious local test-fixture setter.
    for edge in _source_edges_for_step(model, step):
        if edge.get("kind") != "cross-contract":
            continue
        via = str(edge.get("via") or "")
        dep_address, _ = _source_dependency_address(rpc, model, edge, step)
        if not via or not dep_address:
            continue
        dep_name = str(edge.get("interface") or edge.get("to_contract") or "")
        dep_fn_name = str(edge.get("to_function") or "")
        dep_model = next((item for item in models if item.name.lower() == dep_name.lower()), None)
        if dep_model is None:
            dep_model = next((item for item in models if item.name.lower().replace("mock", "") == dep_name.lower().lstrip("i")), None)
        setter = _dependency_setter(root, dep_model, dep_fn_name)
        if not setter:
            continue
        dep_owner_actor = _owner_actor_for_target(rpc, dep_address, dep_model, actors) if dep_model else None
        setter_actor = dep_owner_actor or actor
        dep_args = _dependency_argument_values(step, model, _function_by_name(dep_model, dep_fn_name) if dep_model else {})
        if len(setter.get("inputs") or []) != 2 or not dep_args:
            continue
        tx, output = _send(host, config, setter_actor, dep_address, _signature(setter), [dep_args[0], True], 0)
        if tx:
            return "PREREQUISITE ✓ " + _signature(setter) + " → configured " + _pretty_identifier(dep_name)
        return "PREREQUISITE ✕ " + _signature(setter) + " failed: " + _short_error(output)

    return None

def _failure_flow_summary(root: Path, model: ContractModel, step: Step, origin: str | None) -> list[str]:
    """Explain where a known blocker sits in the function's execution order."""
    if not origin:
        return []
    name = str(step.function or "").split("(", 1)[0]
    try:
        source = (root / model.source).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    match = re.search(r"\bfunction\s+" + re.escape(name) + r"\s*\([^)]*\)[^{;]*\{", source, re.S)
    body = _balanced_block(source, match.end() - 1) if match else ""
    if not body:
        return []
    blocker = origin.split(" → ", 1)[-1]
    compact = re.sub(r"\s+", " ", blocker).strip()
    marker = compact
    # Map diagnostic origins to a source substring so downstream calls can be shown as not reached.
    candidate_terms = []
    mapping_match = re.match(r"([A-Za-z_]\w*)\[", compact)
    if mapping_match:
        candidate_terms.append(mapping_match.group(1))
    dep_match = re.match(r"([A-Za-z_]\w*)\.", compact)
    if dep_match:
        candidate_terms.append(dep_match.group(1))
    param_match = re.match(r"([A-Za-z_]\w*)\s*==", compact)
    if param_match:
        candidate_terms.append(param_match.group(1))
    blocker_pos = min((body.find(term) for term in candidate_terms if term and body.find(term) >= 0), default=-1)
    lines = ["FIRST BLOCKER → " + marker]
    downstream = []
    for edge in sorted(_source_edges_for_step(model, step), key=lambda e: int(e.get("line") or 0)):
        fn = str(edge.get("to_function") or "")
        if not fn:
            continue
        positions = [m.start() for m in re.finditer(r"\b" + re.escape(fn) + r"\s*\(", body)]
        if blocker_pos >= 0 and positions and min(positions) > blocker_pos:
            downstream.append(str(edge.get("interface") or edge.get("to_contract") or "External") + "." + fn + "()")
    if downstream:
        lines.append("NOT REACHED → " + ", ".join(dict.fromkeys(downstream[:5])))
    return lines

def _diagnose_failed_call(
    root: Path,
    rpc: str,
    step: Step,
    model: ContractModel,
    models: list[ContractModel],
    actor_address: str | None = None,
) -> tuple[str | None, list[str]]:
    guard_origin, guard_lines = _probe_source_guards(root, rpc, step, model, models, actor_address)
    origin = guard_origin
    diagnostics = list(guard_lines)
    zero_origin, zero_lines = _read_zero_address_diagnostics(rpc, step.address, model)
    origin = origin or zero_origin
    diagnostics.extend(zero_lines)
    source_lines = _source_guard_lines(model, step)
    diagnostics.extend(source_lines[:8])
    diagnostics = _failure_flow_summary(root, model, step, origin) + diagnostics
    arg_origin, arg_diagnostics = _diagnose_argument_contracts(
        rpc, step, model, models, caller_address=actor_address
    )
    origin = origin or arg_origin
    diagnostics.extend(arg_diagnostics)

    try:
        code, calldata, err = _cmd(["cast", "calldata", step.function, *[_cli_arg(x) for x in step.args]], timeout=6)
        if code != 0:
            diagnostics.append("Lowkey could not encode the failing calldata for trace analysis")
            decoded = _decode_custom_error(err, models)
            if decoded:
                diagnostics.append(f"decoded revert: {decoded}")
            return origin, list(dict.fromkeys(diagnostics))

        trace = _rpc_call(rpc, "debug_traceCall", [{
            "from": actor_address or "0x" + "00" * 20,
            "to": step.address,
            "data": calldata,
            "value": hex(int(step.value_wei or 0)),
        }, {"tracer": "callTracer", "timeout": "10s"}])

        if isinstance(trace, dict):
            payload = trace.get("output") or trace.get("error") or trace.get("revertReason")
            decoded = _decode_custom_error(payload, models)
            if decoded:
                diagnostics.append(f"root revert decoded as {decoded}")

        edges = _trace_execution_edges(root, rpc, models, trace)
        for edge in edges[:10]:
            target = edge.get("to_contract") or _addr(edge.get("to_address"))
            fn = edge.get("function") or edge.get("type")
            diagnostics.append(
                f"actual call: {edge.get('from_contract') or 'caller'} ──▶ {target}.{fn}"
            )

        failed = next((edge for edge in reversed(edges) if edge.get("error") or edge.get("revert")), None)
        if failed:
            target = failed.get("to_contract") or _addr(failed.get("to_address"))
            fn = failed.get("function") or "unknown()"
            origin = origin or f"{model.name} → {target}.{fn}"
            raw = failed.get("revert") or failed.get("error")
            decoded = _decode_custom_error(raw, models)
            if decoded:
                diagnostics.append(f"failed call decoded as {decoded}")
            elif raw:
                diagnostics.append(f"failed call returned: {raw}")

        if not edges and not diagnostics:
            diagnostics.append("the local node exposed no internal call frames; the exact failing instruction could not be proven")
    except Exception as exc:
        diagnostics.append(f"revert trace unavailable: {exc}")
    return origin, list(dict.fromkeys(diagnostics))
def _validate_step_arguments(step: Step, model: ContractModel) -> tuple[bool, str | None]:
    """Reject unresolved semantic dependencies before calldata is built."""
    inputs = _function_inputs(model, step.function)
    function_name = str(step.function).split("(", 1)[0]

    if len(step.args) != len(inputs):
        direct_matches = [
            item for item in model.abi
            if item.get("type") == "function"
            and str(item.get("name") or "").lower() == function_name.lower()
        ]
        if len(direct_matches) == 1:
            inputs = list(direct_matches[0].get("inputs") or [])

        # Last safe fallback: source-proven dependency variables can expose
        # address parameter names even when an ABI index is incomplete.
        if len(step.args) != len(inputs):
            dependency_names = []
            for edge in _source_edges_for_step(model, step):
                via = str(edge.get("via") or "")
                if edge.get("kind") == "cross-contract" and via and via not in dependency_names:
                    dependency_names.append(via)
            if len(dependency_names) == len(step.args):
                inputs = [{"name": name, "type": "address"} for name in dependency_names]

        if len(step.args) != len(inputs):
            return False, f"{function_name} expects {len(inputs)} argument(s); Lowkey supplied {len(step.args)}"
    for index, param in enumerate(inputs):
        if _canonical_type(param) != "address":
            continue
        requirement = _contract_requirement_for_parameter(
            model, function_name, str(param.get("name") or "")
        )
        if requirement and not is_address(step.args[index]):
            label = str(param.get("name") or f"arg{index + 1}")
            return (
                False,
                f"{label} must reference a live contract implementing {requirement}; "
                "no matching protocol dependency was resolved",
            )
    return True, None


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


def _model_uses_token_allowance(model: ContractModel | None) -> bool:
    """Return True when a child model visibly interacts with ERC20 allowance/spend flows."""
    if not model:
        return False
    names = {str(item.get("name") or "").lower() for item in model.abi if item.get("type") == "function"}
    calls = {str(edge.get("to_function") or "").lower() for edge in model.calls if edge.get("kind") == "cross-contract"}
    return bool({"transferfrom", "allowance"} & names) or "transferfrom" in calls

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


def _snapshot_storage(model: ContractModel, rpc: str, address: str, actor_addresses: list[str], observed_keys: list[Any] | None = None) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    entries = model.storage.get("storage") or []
    observed_keys = list(observed_keys or [])
    observed_addresses = [x for x in observed_keys if isinstance(x, str) and is_address(x)]
    observed_numbers = [str(x) for x in observed_keys if isinstance(x, int) or (isinstance(x, str) and x.isdigit())]
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
                keys = list(dict.fromkeys(actor_addresses + observed_addresses))[:12]
            elif key_label.startswith("uint") or key_label.startswith("int"):
                keys = list(dict.fromkeys(["0", "1"] + observed_numbers))[:12]
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
    observed_keys: list[Any] | None = None,
) -> list[dict[str, Any]]:
    by_name = {model.name: model for model in models}
    result: list[dict[str, Any]] = []
    for node in runtime:
        model = by_name.get(node.model)
        if not model:
            continue
        for item in _snapshot_storage(model, rpc, node.address, actor_addresses, observed_keys):
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
    observed: dict[str, Any] | None = None,
    model: ContractModel | None = None,
    function_name: str | None = None,
) -> Any:
    """Generate adversarial values while respecting known contract dependencies."""
    raw_type = str(param.get("type") or "")
    typ = _canonical_type(param)
    name = str(param.get("name") or "").lower()
    observed = observed or {}

    if typ == "address":
        requirement = _contract_requirement_for_parameter(
            model, function_name or "", str(param.get("name") or "")
        )
        normalized = _normalize_observed_keys(observed)
        observed_addresses = [value for value in normalized.values() if is_address(value)]

        if requirement:
            requirement_key = re.sub(r"[^a-z0-9]", "", requirement.lower())
            requirement_key = requirement_key[1:] if requirement_key.startswith("i") else requirement_key
            valid = [
                value for key, value in normalized.items()
                if is_address(value) and (
                    requirement_key in key
                    or key in requirement_key
                )
            ]
            valid = list(dict.fromkeys(valid))
            invalid = [a.address for a in actors if a.address.lower() not in {str(x).lower() for x in valid}]
            pool = list(dict.fromkeys(valid + invalid + ["0x" + "00" * 20]))
            return rng.choice(pool)

        pool = list(dict.fromkeys(
            [a.address for a in actors]
            + [target, "0x" + "00" * 20]
            + observed_addresses
        ))
        if any(token in name for token in ("recipient", "receiver", "to", "user", "owner", "moderator")) and len(actors) > 1:
            pool = [actors[1].address, actors[0].address] + pool
        if any(token in name for token in ("attacker", "malicious")) and len(actors) > 2:
            pool.insert(0, actors[2].address)
        return rng.choice(list(dict.fromkeys(pool)))

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
        return [
            _random_sol_value(component, actors, target, rng, observed, model, function_name)
            for component in param.get("components", [])
        ]

    if raw_type.endswith("[]"):
        base = dict(param)
        base["type"] = raw_type[:-2]
        return [
            _random_sol_value(base, actors, target, rng, observed, model, function_name)
            for _ in range(rng.randint(0, 4))
        ]

    return 0


def _adversarial_functions(model: ContractModel) -> list[dict[str, Any]]:
    return [
        item for item in model.abi
        if item.get("type") == "function"
        and item.get("name")
        and item.get("stateMutability") not in {"view", "pure"}
        and not any(token in str(item.get("name") or "").lower() for token in ("upgrade", "selfdestruct"))
    ]



def _system_test_targets(config: dict[str, Any], target: str, model: ContractModel, models: list[ContractModel]) -> list[tuple[str, str, ContractModel]]:
    """Return all live application instances in the current protocol system."""
    result: list[tuple[str, str, ContractModel]] = []
    seen: set[tuple[str, str]] = set()

    def find_model(name: str | None, key: str) -> ContractModel | None:
        if name:
            exact = next((item for item in models if item.name.lower() == str(name).lower()), None)
            if exact:
                return exact
        compact = re.sub(r"[^a-z0-9]", "", key.lower())
        candidates = [item for item in models if compact and (compact == re.sub(r"[^a-z0-9]", "", item.name.lower()) or compact in re.sub(r"[^a-z0-9]", "", item.name.lower()))]
        return sorted(candidates, key=lambda item: (len(item.name), item.name.lower()))[0] if candidates else None

    def add(label: str, address: Any, name: str | None, key: str) -> None:
        if not is_address(address):
            return
        candidate = find_model(name, key)
        if not candidate:
            return
        pair = (candidate.name.lower(), str(address).lower())
        if pair in seen:
            return
        seen.add(pair)
        result.append((label, str(address), candidate))

    add(model.name, target, model.name, "target")
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    for key, address in system.items():
        if key.endswith("_model") or key.endswith("_parent") or key.endswith("_implementation") or not is_address(address):
            continue
        add(str(key), address, system.get(str(key) + "_model"), str(key))

    runtime = config.get("_walkthrough_runtime_instances")
    if isinstance(runtime, list):
        for entry in runtime:
            if not isinstance(entry, dict):
                continue
            add(str(entry.get("label") or entry.get("contract") or "runtime"), entry.get("address"), str(entry.get("contract") or entry.get("model") or ""), str(entry.get("contract") or entry.get("model") or "runtime"))
    return result

def _generic_walkthrough_warmup(
    root: Path,
    config: dict[str, Any],
    host: Any,
    target: str,
    model: ContractModel,
    models: list[ContractModel],
    actors: list[Actor],
    rpc: str,
    limit: int = 4,
) -> list[str]:
    """Execute a few semantically valid lifecycle steps before randomized probes."""
    notes: list[str] = []
    observed = _merge_protocol_observations(
        config.get("_walkthrough_observed") or {},
        config=config,
    )
    pending = plan_workflow(
        model,
        actors,
        target,
        _block_timestamp(rpc),
        max(1, limit),
        observed,
    )
    runtime = _lab_runtime(config, target, model)
    successes = 0

    for candidate in pending:
        if successes >= limit:
            break
        active_model = next(
            (item for item in models if item.name == candidate.contract),
            model,
        )
        abi_item = next(
            (
                item for item in active_model.abi
                if item.get("type") == "function"
                and _signature(item) == candidate.function
            ),
            None,
        )
        if not abi_item:
            continue

        if candidate.inferred:
            observed_now = _merge_protocol_observations(
                observed, config=config, runtime=runtime
            )
            candidate.args = [
                _arg_for(
                    param,
                    actors,
                    candidate.address,
                    _block_timestamp(rpc),
                    observed_now,
                    active_model,
                    str(candidate.function).split("(", 1)[0],
                )
                for param in abi_item.get("inputs") or []
            ]
            candidate.value_wei = _value_for(abi_item)

        valid, reason = _validate_step_arguments(candidate, active_model)
        if not valid:
            notes.append(f"{candidate.function}: skipped — {reason}")
            continue

        actor = next(
            (item for item in actors if item.name == candidate.actor),
            actors[0] if actors else None,
        )
        if not actor:
            continue

        ok, preflight = _preflight(rpc, candidate, actor.address)
        if not ok:
            notes.append(
                f"{candidate.function}: preflight blocked — {_short_error(preflight)}"
            )
            continue

        tx, output = _send(
            host, config, actor, candidate.address,
            candidate.function, candidate.args, candidate.value_wei,
        )
        if not tx:
            notes.append(
                f"{candidate.function}: send failed — {_short_error(output)}"
            )
            continue

        successes += 1
        notes.append(f"{candidate.function}: established")

        receipt = _receipt(rpc, tx)
        trace = _trace_tree(rpc, tx)
        discovered = _discover_runtime_contracts(
            root,
            rpc,
            models,
            runtime,
            receipt,
            trace,
            successes,
            candidate.address,
        )
        runtime.extend(discovered)
        for node in discovered:
            records = config.setdefault("_walkthrough_runtime_instances", [])
            records.append({
                "address": node.address,
                "contract": node.model,
                "label": node.label,
                "relation": node.relation,
                "parent": node.parent,
            })
        observed = _merge_protocol_observations(
            observed, config=config, runtime=discovered
        )

    return notes


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

    # Establish a useful baseline once, then isolate every randomized probe from
    # that baseline. For known local multi-contract fixtures this also forces the
    # entry point to create its child so the child contract participates in fuzzing.
    cleanup_snapshot = _rpc_snapshot(rpc)
    if cleanup_snapshot is None:
        print("Error: Anvil did not provide an evm_snapshot; aborting adversarial test.", file=sys.stderr)
        return 1

    warmup_notes: list[str] = []
    if config.get("_walkthrough_recipe") != "confidence-pool":
        warmup_notes.extend(
            _generic_walkthrough_warmup(
                root, config, host, target, model, models,
                actors, rpc, limit=4,
            )
        )
    if (
        config.get("_walkthrough_recipe") == "confidence-pool"
        and model.name.lower() == "confidencepoolfactory"
    ):
        recipe = _confidence_pool_factory_recipe(config, actors, _block_timestamp(rpc))
        for warmup in recipe[:2]:
            actor = next((a for a in actors if a.name == warmup.actor), actors[0] if actors else None)
            if not actor:
                continue
            tx, output = _send(host, config, actor, warmup.address, warmup.function, warmup.args, warmup.value_wei)
            if not tx:
                warmup_notes.append(
                    f"{warmup.function}: bootstrap probe did not succeed — { _short_error(output) }"
                )
                break
            warmup_notes.append(f"{warmup.function}: established")
            if warmup.function.startswith("createPool("):
                receipt = _receipt(rpc, tx)
                trace = _trace_tree(rpc, tx)
                discovered = _discover_runtime_contracts(
                    root,
                    rpc,
                    models,
                    [],
                    receipt,
                    trace,
                    0,
                    warmup.address,
                )
                lab = config.get("lab_system")
                if isinstance(lab, dict):
                    for node in discovered:
                        if node.model and node.model != "External":
                            child_model = str(lab.get("child_model") or "").lower()
                            if child_model and node.model.lower() == child_model:
                                lab["pool"] = node.address
                                config["lab_system"] = lab
                                if hasattr(host, "save_config"):
                                    host.save_config(config)
                break

    if system_targets and len(system_targets) > 1:
        targets = system_targets
    else:
        targets = _system_test_targets(config, target, model, models)
    targets = [item for item in targets if _adversarial_functions(item[2])]

    if not targets:
        _rpc_revert(rpc, cleanup_snapshot)
        print("No mutating functions available for adversarial testing.")
        return 0

    total_cases = max(1, min(200, int(total_cases)))
    results: list[Step] = []

    print(_paint("LOWKEY // ADVERSARIAL WALKTHROUGH TEST", BOLD + MAGENTA, _ansi_enabled(False)))
    print(f"  system : {len(targets)} live application instance(s)")
    print("  engine : randomized args/roles/extremes → SEND → trace → diagnose → restore")
    print(f"  seed   : {actual_seed}")
    if warmup_notes:
        print("  baseline:")
        for note in warmup_notes:
            print(f"    ↳ {note}")
    print("")

    # Capture the post-warmup baseline. Every case is reverted to this state, and
    # the entire test is finally reverted to cleanup_snapshot.
    baseline_snapshot = _rpc_snapshot(rpc)
    if baseline_snapshot is None:
        _rpc_revert(rpc, cleanup_snapshot)
        print("Error: could not snapshot the prepared adversarial baseline.", file=sys.stderr)
        return 1

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
        args = [
            _random_sol_value(
                param,
                actors,
                active_target,
                rng,
                _merge_protocol_observations(
                    config.get("_walkthrough_observed") or {},
                    config=config,
                ),
                active_model,
                str(fn.get("name") or ""),
            )
            for param in fn.get("inputs", [])
        ]
        value = rng.choice([0, 1, 10**6, 10**15, 10**18]) if fn.get("stateMutability") == "payable" else 0

        step = Step(
            index=index,
            actor=actor.name,
            contract=active_model.name,
            address=active_target,
            function=_signature(fn),
            args=args,
            value_wei=value,
            reason="randomized adversarial probe: role swaps, boundary values, and random calldata",
            inferred=False,
        )

        snapshot = _rpc_snapshot(rpc)
        if snapshot is None:
            print("Error: Anvil did not provide an evm_snapshot; aborting adversarial test.", file=sys.stderr)
            _rpc_revert(rpc, cleanup_snapshot)
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
            _rpc_revert(rpc, cleanup_snapshot)
            return 1

    # Leave the project exactly as it was before the adversarial run, including
    # any temporary child protocol created during warmup.
    _rpc_revert(rpc, cleanup_snapshot)

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




def _target_is_live_instance(
    root: Path,
    rpc: str,
    target: str,
    model: ContractModel,
) -> tuple[bool, str | None]:
    """Reject implementation-only or uninitialized initializer-style addresses."""
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
            f"{model.name} exposes initialize() and the live address matches its "
            "implementation bytecode; this is not a configured protocol instance"
        )

    origin, diagnostics = _read_zero_address_diagnostics(rpc, target, model)
    zero_lines = [line for line in diagnostics if "✕ unset" in line]
    if origin and (any("owner = " in line.lower() for line in zero_lines) or len(zero_lines) >= 2):
        return False, (
            f"{model.name} has initialize() but its live configuration is unset; "
            + "; ".join(zero_lines[:4])
        )

    return True, None



def _all_artifact_entries(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    """Return every compiled artifact, including dependency proxy artifacts."""
    out = root / "out"
    if not out.is_dir():
        return []
    found: list[tuple[Path, dict[str, Any]]] = []
    for path in out.rglob("*.json"):
        if "build-info" in path.parts:
            continue
        data = _json_file(path)
        if isinstance(data, dict) and isinstance(data.get("abi"), list):
            found.append((path, data))
    return found


def _artifact_entry_by_name(root: Path, contract_name: str) -> tuple[Path, dict[str, Any]] | None:
    target = str(contract_name or "").lower()
    exact: list[tuple[Path, dict[str, Any]]] = []
    loose: list[tuple[Path, dict[str, Any]]] = []
    for path, data in _all_artifact_entries(root):
        name = str(data.get("contractName") or path.stem)
        if name.lower() == target:
            exact.append((path, data))
        elif target and target in name.lower():
            loose.append((path, data))
    return (exact or loose or [None])[0]


def _artifact_fqn(entry: tuple[Path, dict[str, Any]] | None) -> str | None:
    if not entry:
        return None
    path, data = entry
    source = str(data.get("sourceName") or "").replace("\\", "/").lstrip("./")
    name = str(data.get("contractName") or path.stem)
    return f"{source}:{name}" if source else None


def _fixture_model(
    models: list[ContractModel],
    *,
    exact: Iterable[str] = (),
    tokens: Iterable[str] = (),
    required_functions: Iterable[str] = (),
) -> ContractModel | None:
    exact_lower = {str(x).lower() for x in exact}
    token_list = [str(x).lower() for x in tokens]
    required = {str(x).lower() for x in required_functions}

    ranked: list[tuple[int, ContractModel]] = []
    for model in models:
        haystack = f"{model.name} {model.source}".lower()
        names = {str(sig).split("(", 1)[0].lower() for sig in model.functions}
        score = 0
        if model.name.lower() in exact_lower:
            score += 1000
        if "mock" in model.name.lower() or "/mocks/" in model.source.lower() or "test/mocks" in model.source.lower():
            score += 100
        score += sum(20 for token in token_list if token in haystack)
        score += sum(30 for fn in required if fn in names)
        if score:
            ranked.append((score, model))
    ranked.sort(key=lambda item: (-item[0], item[1].name.lower()))
    if ranked:
        return ranked[0][1]

    # Generic fallback: a plain application contract with no lifecycle naming
    # is still a valid walkthrough target. Prefer a contract with state-changing
    # ABI functions, then any concrete application contract.
    mutating = [
        item for item in models
        if item.kind == "contract"
        and any(
            x.get("type") == "function"
            and x.get("stateMutability") not in {"view", "pure"}
            for x in item.abi
        )
    ]
    if mutating:
        return sorted(mutating, key=lambda item: item.name.lower())[0]

    concrete = [item for item in models if item.kind == "contract"]
    return sorted(concrete, key=lambda item: item.name.lower())[0] if concrete else None


def _function_by_name(model: ContractModel | None, name: str) -> dict[str, Any] | None:
    if not model:
        return None
    wanted = str(name).lower()
    for item in model.abi:
        if item.get("type") == "function" and str(item.get("name") or "").lower() == wanted:
            return item
    return None


def _model_has_function(model: ContractModel | None, names: Iterable[str]) -> bool:
    if not model:
        return False
    wanted = {str(x).lower() for x in names}
    return any(str(sig).split("(", 1)[0].lower() in wanted for sig in model.functions)


def _infer_protocol_root(models: list[ContractModel]) -> ContractModel | None:
    """Find a likely protocol entry point for upgradeable and ordinary systems."""
    ranked: list[tuple[int, ContractModel]] = []
    root_words = ("factory", "manager", "router", "registry", "controller", "gateway", "vault", "engine")
    lifecycle_prefixes = ("create", "deploy", "open", "register", "clone", "initialize", "setup", "configure")
    for model in models:
        if model.kind in {"interface", "library", "abstract"}:
            continue
        names = {
            str(sig).split("(", 1)[0].lower()
            for sig in model.functions
        }
        names.update(
            str(item.get("name") or "").lower()
            for item in model.abi
            if item.get("type") == "function"
        )
        score = 0
        lower = model.name.lower()

        if any(word in lower for word in root_words):
            score += 80
        for name in names:
            if any(name.startswith(prefix) for prefix in lifecycle_prefixes):
                score += 45
            if name.startswith(("create", "deploy", "clone")):
                score += 55

        cross_calls = sum(
            1 for edge in model.calls
            if edge.get("kind") == "cross-contract"
        )
        score += min(60, cross_calls * 10)

        if model.semantics:
            if any(item.get("creates") for item in model.semantics.values()):
                score += 40
        source_lower = str(model.source).lower()
        if any(token in source_lower for token in ("clone", "create2", "new ", "deploy")):
            score += 25

        # Ordinary single-contract protocols still get a deterministic fallback.
        if score:
            ranked.append((score, model))

    ranked.sort(key=lambda item: (-item[0], item[1].name.lower()))
    return ranked[0][1] if ranked else None


def _infer_child_model(root_model: ContractModel, models: list[ContractModel]) -> ContractModel | None:
    """Resolve a root contract's created/initialized child from source call edges."""
    by_name = {item.name.lower(): item for item in models}
    impls = _implementation_mapping(models)
    candidates: list[tuple[int, ContractModel]] = []

    for edge in root_model.calls:
        if str(edge.get("to_function") or "").lower() != "initialize":
            continue
        target_name = str(edge.get("to_contract") or "").strip()
        concrete = impls.get(target_name, target_name)
        child = by_name.get(concrete.lower())
        if not child:
            continue
        score = 100
        if "pool" in child.name.lower():
            score += 40
        candidates.append((score, child))

    if candidates:
        candidates.sort(key=lambda item: (-item[0], item[1].name.lower()))
        return candidates[0][1]

    # Fallback: create/clone roots commonly have one sibling application contract.
    siblings = [
        item for item in models
        if item.name != root_model.name
        and not item.kind in {"interface", "library", "abstract"}
        and any(
            str(sig).split("(", 1)[0].lower().startswith(prefix)
            for sig in item.functions
            for prefix in ("stake", "deposit", "claim", "withdraw", "initialize")
        )
    ]
    return sorted(siblings, key=lambda item: ("pool" not in item.name.lower(), item.name.lower()))[0] if siblings else None


def _encode_calldata(signature: str, args: list[Any]) -> str | None:
    command = ["cast", "calldata", signature, *[_cli_arg(item) for item in args]]
    code, out, err = _cmd(command, timeout=8)
    if code != 0:
        return None
    value = (out or err or "").strip().splitlines()
    return value[-1].strip() if value else None


def _parse_local_deployed_address(output: str) -> str | None:
    patterns = [
        r"(?i)\bDeployed to:\s*(0x[0-9a-fA-F]{40})",
        r"(?i)\bContract Address:\s*(0x[0-9a-fA-F]{40})",
        r'(?i)"deployedTo"\s*:\s*"(0x[0-9a-fA-F]{40})"',
        r'(?i)"contractAddress"\s*:\s*"(0x[0-9a-fA-F]{40})"',
    ]
    for pattern in patterns:
        match = re.search(pattern, str(output or ""))
        if match:
            return match.group(1)
    return None


def _deploy_local_artifact(
    root: Path,
    rpc: str,
    private_key: str,
    entry: tuple[Path, dict[str, Any]] | None,
    args: list[Any] | None = None,
) -> str | None:
    fqn = _artifact_fqn(entry)
    if not fqn:
        return None
    command = ["forge", "create", fqn]
    values = list(args or [])
    if values:
        command += ["--constructor-args", *[_cli_arg(item) for item in values]]
    command += ["--rpc-url", rpc, "--private-key", private_key, "--broadcast"]
    code, out, err = _cmd(command, cwd=root, timeout=90)
    if code != 0:
        return None
    return _parse_local_deployed_address(out or err)


def _send_lab_control(
    host: Any,
    config: dict[str, Any],
    actor: Actor,
    target: str,
    signature: str,
    args: list[Any],
) -> str | None:
    tx, _output = _send(host, config, actor, target, signature, args, 0)
    return tx


def _candidate_proxy_artifact(root: Path) -> tuple[Path, dict[str, Any]] | None:
    return _artifact_entry_by_name(root, "ERC1967Proxy")


def _looks_like_confidence_pool_system(root_model: ContractModel, child: ContractModel | None) -> bool:
    names = {str(sig).split("(", 1)[0].lower() for sig in root_model.functions}
    return (
        root_model.name.lower() == "confidencepoolfactory"
        and child is not None
        and child.name.lower() == "confidencepool"
        and "createpool" in names
    )


def _generic_constructor_args(model: ContractModel, root: Path, actor: Actor) -> list[Any] | None:
    """Return only conservative constructor arguments; None means unsafe/unknown."""
    entry = _artifact_entry_by_name(root, model.name)
    if not entry:
        return None
    _path, artifact = entry
    constructors = [
        item for item in (artifact.get("abi") or [])
        if item.get("type") == "constructor"
    ]
    if not constructors:
        return []
    values: list[Any] = []
    for param in constructors[0].get("inputs") or []:
        name = str(param.get("name") or "").lower()
        ptype = _canonical_type(param)
        compact = re.sub(r"[^a-z0-9]", "", name)
        if ptype == "address":
            if any(token in compact for token in ("owner", "admin", "authority", "guardian")):
                values.append(actor.address)
            else:
                return None
        elif ptype == "bool":
            values.append(False)
        elif ptype.startswith(("uint", "int")):
            values.append(0)
        elif ptype == "bytes":
            values.append("0x")
        elif ptype == "bytes32":
            values.append("0x" + "00" * 32)
        elif ptype == "string":
            values.append("lowkey")
        else:
            return None
    return values


def _find_generic_dependency_model(
    interface_name: str,
    function_name: str,
    models: list[ContractModel],
    support_models: list[ContractModel],
    excluded: set[str],
) -> ContractModel | None:
    """Resolve a source dependency to a compiled disposable implementation."""
    impl_name = interface_name[1:] if interface_name.startswith("I") else interface_name
    app_by_name = {m.name.lower(): m for m in models}
    candidates = [
        m for m in support_models
        if m.name.lower() not in excluded
        and m.kind not in {"interface", "library", "abstract"}
    ]
    exact = {
        impl_name.lower(),
        ("Mock" + impl_name).lower(),
        interface_name.lower(),
    }
    ranked: list[tuple[int, ContractModel]] = []
    for candidate in candidates:
        names = {str(sig).split("(", 1)[0].lower() for sig in candidate.functions}
        haystack = (candidate.name + " " + candidate.source).lower()
        score = 0
        if candidate.name.lower() in exact:
            score += 1000
        if candidate.name.lower() == impl_name.lower():
            score += 800
        if candidate.name.lower().startswith("mock"):
            score += 120
        if function_name.lower() in names:
            score += 120
        for token in (impl_name, interface_name[1:] if interface_name.startswith("I") else interface_name):
            if token and token.lower() in haystack:
                score += 30
        if score:
            ranked.append((score, candidate))
    direct = app_by_name.get(impl_name.lower())
    if direct and direct.name.lower() not in excluded:
        ranked.append((900, direct))
    ranked.sort(key=lambda item: (-item[0], item[1].name.lower()))
    return ranked[0][1] if ranked else None


def _generic_dependency_keys(interface_name: str, via: str, concrete: str) -> list[str]:
    keys: list[str] = []
    for value in (via, interface_name, concrete):
        compact = re.sub(r"[^a-z0-9]", "", str(value or "").lower())
        if compact:
            keys.append(compact[1:] if compact.startswith("i") else compact)
    return list(dict.fromkeys(keys))


def _configure_generic_fixture(
    root: Path,
    rpc: str,
    host: Any,
    config: dict[str, Any],
    actor: Actor,
    fixture: ContractModel,
    fixture_address: str,
    system: dict[str, Any],
) -> None:
    """Apply only setters whose names/types clearly describe fixture configuration."""
    functions = list(fixture.abi)
    for item in functions:
        if item.get("type") != "function":
            continue
        name = str(item.get("name") or "").lower()
        inputs = item.get("inputs") or []
        if len(inputs) != 2:
            continue
        if _canonical_type(inputs[0]) != "address" or _canonical_type(inputs[1]) != "bool":
            continue
        if not any(token in name for token in (
            "valid", "allowed", "enabled", "active",
            "scoped", "registered", "approved", "support"
        )):
            continue
        pname = str(inputs[0].get("name") or "").lower()
        compact = re.sub(r"[^a-z0-9]", "", pname)
        address_value = system.get(compact)
        if not is_address(address_value):
            for key, value in system.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if is_address(value) and compact and (
                    compact in normalized or normalized in compact
                ):
                    address_value = value
                    break
        if is_address(address_value):
            _send_lab_control(
                host, config, actor, fixture_address,
                _signature(item), [address_value, True],
            )

    mint = next(
        (
            item for item in functions
            if item.get("type") == "function"
            and str(item.get("name") or "").lower() in {"mint", "faucet"}
            and len(item.get("inputs") or []) == 2
            and _canonical_type(item["inputs"][0]) == "address"
            and _canonical_type(item["inputs"][1]).startswith(("uint", "int"))
        ),
        None,
    )
    if mint:
        _send_lab_control(
            host, config, actor, fixture_address,
            _signature(mint), [actor.address, 10**24],
        )


def _synthesize_generic_protocol_fixture(
    root: Path,
    rpc: str,
    host: Any,
    config: dict[str, Any],
    actors: list[Actor],
    models: list[ContractModel],
    support_models: list[ContractModel],
) -> tuple[bool, str]:
    """Build a generic disposable system from source-discovered dependencies."""
    root_model = _infer_protocol_root(models)
    if not root_model:
        return False, "no initializer/create-style protocol root could be inferred"
    child = _infer_child_model(root_model, models)
    if not child:
        return False, f"no concrete child contract could be inferred from {root_model.name}"

    actor = actors[0] if actors else Actor("Alice", "0x" + "00" * 20, 0)
    private_key = host.derive_default_anvil_key(0) if hasattr(host, "derive_default_anvil_key") else None
    if not private_key:
        return False, "could not derive the default Anvil deployer key"

    impls = _implementation_mapping(models)
    excluded = {root_model.name.lower(), child.name.lower()}
    system: dict[str, Any] = {}
    dependency_models: dict[str, ContractModel] = {}

    # Walk the application dependency graph recursively. A root may depend on a
    # child, which may depend on a token/registry/oracle, which may have another
    # configured contract behind it. Stopping at one hop produces false "empty
    # revert" failures; recursive discovery gives the lab a chance to wire the
    # actual protocol chain.
    dependency_queue: list[ContractModel] = [root_model, child]
    visited_models: set[str] = set()

    while dependency_queue:
        source_model = dependency_queue.pop(0)
        source_key = source_model.name.lower()
        if source_key in visited_models:
            continue
        visited_models.add(source_key)

        for edge in source_model.calls:
            if edge.get("kind") != "cross-contract":
                continue
            interface_name = str(edge.get("to_contract") or edge.get("interface") or "")
            if not interface_name:
                continue
            concrete_name = impls.get(interface_name, interface_name)
            candidate = _find_generic_dependency_model(
                concrete_name,
                str(edge.get("to_function") or ""),
                models,
                support_models,
                excluded,
            )
            if not candidate:
                continue
            dependency_models[candidate.name.lower()] = candidate
            for key in _generic_dependency_keys(
                interface_name,
                str(edge.get("via") or ""),
                candidate.name,
            ):
                system.setdefault(key, None)
            if candidate.name.lower() not in visited_models:
                dependency_queue.append(candidate)

    def deploy(model: ContractModel, ctor_args: list[Any] | None = None) -> str | None:
        values = ctor_args
        if values is None:
            values = _generic_constructor_args(model, root, actor)
        if values is None:
            return None
        return _deploy_local_artifact(
            root,
            rpc,
            private_key,
            _artifact_entry_by_name(root, model.name),
            values,
        )

    child_address = deploy(child)
    if not is_address(child_address):
        return False, (
            f"{child.name} requires constructor configuration that "
            "generic bootstrap cannot prove safe"
        )
    system["implementation"] = child_address
    system[re.sub(r"[^a-z0-9]", "", child.name.lower())] = child_address

    deployed: dict[str, str] = {}
    for dependency in dependency_models.values():
        if dependency.name.lower() == child.name.lower():
            continue
        address = deploy(dependency)
        if not is_address(address):
            continue
        deployed[dependency.name.lower()] = address
        for key in _generic_dependency_keys(
            dependency.name, "", dependency.name
        ):
            system[key] = address

    for edge in root_model.calls:
        via = re.sub(r"[^a-z0-9]", "", str(edge.get("via") or "").lower())
        interface_name = str(edge.get("to_contract") or edge.get("interface") or "")
        concrete_name = impls.get(interface_name, interface_name)
        address = system.get(via) or system.get(
            re.sub(r"[^a-z0-9]", "", concrete_name.lower())
        )
        if is_address(address):
            system[via] = address
            if interface_name:
                system[re.sub(
                    r"[^a-z0-9]", "", interface_name.lower().lstrip("i")
                )] = address

    root_impl = deploy(root_model)
    if not is_address(root_impl):
        return False, (
            f"failed to deploy {root_model.name}; "
            "constructor arguments are not safely inferable"
        )

    init = next(
        (
            item for item in root_model.abi
            if item.get("type") == "function"
            and str(item.get("name") or "").lower() == "initialize"
        ),
        None,
    )
    target = root_impl
    if init:
        values: list[Any] = []
        for param in init.get("inputs") or []:
            ptype = _canonical_type(param)
            name = str(param.get("name") or "")
            compact = re.sub(r"[^a-z0-9]", "", name.lower())
            if ptype == "address":
                value = system.get(compact)
                if not is_address(value) and compact in {
                    "implementation", "poolimplementation", "childimplementation"
                }:
                    value = child_address
                if not is_address(value) and compact in {
                    "owner", "owneraddress", "admin", "adminaddress", "authority"
                }:
                    value = actor.address
                if not is_address(value):
                    return False, (
                        f"initializer dependency '{name or 'address'}' "
                        "could not be resolved from source-discovered fixtures"
                    )
                values.append(value)
            elif ptype == "bool":
                values.append(False)
            elif ptype.startswith(("uint", "int")):
                values.append(0)
            elif ptype == "bytes":
                values.append("0x")
            elif ptype == "bytes32":
                values.append("0x" + "00" * 32)
            elif ptype == "string":
                values.append("lowkey")
            else:
                return False, (
                    f"initializer parameter '{name or ptype}' "
                    "needs protocol-specific configuration"
                )

        data = _encode_calldata(_signature(init), values)
        if not data:
            return False, f"failed to encode {root_model.name}.initialize(...) safely"

        proxy = _candidate_proxy_artifact(root)
        if proxy:
            target = _deploy_local_artifact(
                root, rpc, private_key, proxy, [root_impl, data]
            )
            if not is_address(target):
                return False, f"failed to deploy proxy for {root_model.name}"
        else:
            tx = _send_lab_control(
                host, config, actor, root_impl, _signature(init), values
            )
            if not tx:
                return False, (
                    f"failed to initialize {root_model.name} "
                    "from its source-defined initializer"
                )

    for dependency in dependency_models.values():
        address = deployed.get(dependency.name.lower())
        if address:
            _configure_generic_fixture(
                root, rpc, host, config, actor, dependency, address, system
            )

    config["target"] = target
    config["target_contract"] = root_model.name
    config["_walkthrough_recipe"] = "generic-system"
    config["lab_system"] = {
        **{key: value for key, value in system.items() if is_address(value)},
        "root": target,
        "root_model": root_model.name,
        "child": child_address,
        "child_model": child.name,
        "child_model_address": child_address,
    }
    for dependency in dependency_models.values():
        dep_address = deployed.get(dependency.name.lower())
        if is_address(dep_address):
            dep_key = re.sub(r"[^a-z0-9]+", "_", dependency.name.lower()).strip("_")
            config["lab_system"][dep_key] = dep_address
            config["lab_system"][dep_key + "_model"] = dependency.name
    if any(
        str(sig).split("(", 1)[0].lower().startswith(
            prefix
        )
        for sig in root_model.functions
        for prefix in ("create", "deploy", "open", "register", "clone")
    ):
        config["lab_system"]["factory"] = target

    if hasattr(host, "set_lab_target"):
        host.set_lab_target(
            config, root, target, root_model.name, str(root / root_model.artifact)
        )
    if hasattr(host, "save_config"):
        host.save_config(config)
    audit_context.set_target(
        root,
        address=target,
        contract=root_model.name,
        artifact=str(root / root_model.artifact),
        source="generic-system-synthesis",
    )
    audit_context.update(root, actor=actor.name, rpc=rpc)
    return True, f"synthesized generic system {root_model.name} + {child.name}"


def _synthesize_local_protocol_fixture(
    root: Path,
    rpc: str,
    host: Any,
    config: dict[str, Any],
    actors: list[Actor],
    models: list[ContractModel],
    support_models: list[ContractModel],
) -> tuple[bool, str]:
    """
    Build a disposable protocol instance from compiled project + test fixtures.

    This is deliberately semantic rather than hard-coded to one address layout:
    the engine identifies an entry-point, its created child, then supplies matching
    mock dependencies from project fixtures. Projects without enough safe fixtures
    fall back to the ordinary generic lab path instead of inventing addresses.
    """
    root_model = _infer_protocol_root(models)
    if not root_model:
        return False, "no upgradeable/create-style application root was inferred"

    child = _infer_child_model(root_model, models)
    if not child:
        return False, f"no concrete child contract was inferred from {root_model.name}"

    if not _looks_like_confidence_pool_system(root_model, child):
        return _synthesize_generic_protocol_fixture(
            root, rpc, host, config, actors, models, support_models
        )

    # The full multi-contract bootstrap needs disposable mocks. Prefer the project's
    # own test doubles; never substitute an EOA where the source treats an address
    # as a contract.
    token = _fixture_model(
        support_models,
        exact=("MockERC20",),
        tokens=("erc20", "token"),
        required_functions=("mint", "balanceof", "transfer"),
    )
    registry = _fixture_model(
        support_models,
        exact=("MockSafeHarborRegistry",),
        tokens=("safeharborregistry", "safeharbor", "registry"),
        required_functions=("isagreementvalid",),
    )
    agreement = _fixture_model(
        support_models,
        exact=("MockAgreement",),
        tokens=("agreement",),
        required_functions=("owner",),
    )
    attack_registry = _fixture_model(
        support_models,
        exact=("MockAttackRegistry",),
        tokens=("attackregistry",),
        required_functions=("getagreementstate", "setagreementstate"),
    )
    moderator = _fixture_model(
        support_models,
        exact=("MockConfidencePoolModerator",),
        tokens=("moderator",),
        required_functions=("flag",),
    )

    if not all([token, registry, agreement]):
        return False, "project test fixtures do not expose enough safe token/registry/agreement mocks"

    needs_proxy = any(
        str(item.get("name") or "").lower() == "initialize"
        and item.get("type") == "function"
        for item in root_model.abi
    )
    proxy = _candidate_proxy_artifact(root) if needs_proxy else None
    if needs_proxy and not proxy:
        return False, f"{root_model.name} is initializer-based but no compiled ERC1967Proxy artifact was found"

    private_key = host.derive_default_anvil_key(0) if hasattr(host, "derive_default_anvil_key") else None
    if not private_key:
        return False, "could not derive the default Anvil deployer key"

    alice = actors[0] if actors else Actor("Alice", "0x" + "00" * 20, 0)
    bob = actors[1] if len(actors) > 1 else alice

    def deploy_model(model: ContractModel, ctor_args: list[Any] | None = None) -> str | None:
        return _deploy_local_artifact(root, rpc, private_key, _artifact_entry_by_name(root, model.name), ctor_args)

    system: dict[str, Any] = {}

    system["stake_token"] = deploy_model(token)
    system["stake_token_model"] = token.name
    system["safe_harbor_registry"] = deploy_model(registry)
    system["safe_harbor_registry_model"] = registry.name
    if attack_registry:
        system["attack_registry"] = deploy_model(attack_registry)
        system["attack_registry_model"] = attack_registry.name
    if moderator:
        system["moderator"] = deploy_model(moderator)
        system["moderator_model"] = moderator.name
    system["pool_implementation"] = deploy_model(child)
    system["pool_implementation_model"] = child.name
    system["agreement"] = deploy_model(agreement, [alice.address])
    system["agreement_model"] = agreement.name

    if not all(is_address(system.get(k)) for k in ("stake_token", "safe_harbor_registry", "pool_implementation", "agreement")):
        return False, "one or more core protocol fixtures failed to deploy"

    # Fund the named local actors when the project fixture exposes a mint() hook.
    # The live ConfidencePool lifecycle needs enough tokens for Alice's bonus + stake
    # and Bob's stake; other protocols simply skip this optional fixture capability.
    mint_fn = next(
        (
            item for item in token.abi
            if item.get("type") == "function"
            and str(item.get("name") or "").lower() == "mint"
            and len(item.get("inputs") or []) == 2
        ),
        None,
    )
    if mint_fn:
        mint_signature = _signature(mint_fn)
        for actor, amount in ((alice, 2 * 10**18), (bob, 2 * 10**18)):
            _send_lab_control(
                host,
                config,
                alice,
                system["stake_token"],
                mint_signature,
                [actor.address, amount],
            )

    # Wire the disposable registry/Agreement fixtures before the root creates a child.
    if system.get("attack_registry"):
        if not _send_lab_control(
            host, config, alice, system["safe_harbor_registry"],
            "setAttackRegistry(address)", [system["attack_registry"]],
        ):
            return False, "failed to wire Safe Harbor Registry -> Attack Registry"

    if not _send_lab_control(
        host, config, alice, system["safe_harbor_registry"],
        "setAgreementValid(address,bool)", [system["agreement"], True],
    ):
        return False, "failed to mark the synthetic Agreement valid in the Safe Harbor Registry"

    # Agreement scope is required by child.initialize in systems with the same
    # scope-validation pattern. Ignore the optional call for other fixtures.
    agreement_scope_fn = next(
        (
            item for item in agreement.abi
            if item.get("type") == "function"
            and str(item.get("name") or "").lower() == "setcontractinscope"
        ),
        None,
    )
    if agreement_scope_fn:
        if not _send_lab_control(
            host, config, alice, system["agreement"],
            _signature(agreement_scope_fn), [alice.address, True],
        ):
            return False, "failed to add Alice to the Agreement scope"
        if bob.address.lower() != alice.address.lower():
            if not _send_lab_control(
                host, config, alice, system["agreement"],
                _signature(agreement_scope_fn), [bob.address, True],
            ):
                return False, "failed to add Bob to the Agreement scope"

    factory_impl = deploy_model(root_model)
    if not is_address(factory_impl):
        return False, f"failed to deploy {root_model.name} implementation"

    init = next(
        (
            item for item in root_model.abi
            if item.get("type") == "function"
            and str(item.get("name") or "").lower() == "initialize"
        ),
        None,
    )

    root_target = factory_impl
    if init:
        # Resolve initializer address parameters by semantic role. The child implementation
        # and fixture contracts are concrete, not placeholder EOAs.
        values: list[Any] = []
        for param in init.get("inputs", []):
            name = str(param.get("name") or "").lower()
            ptype = _canonical_type(param)
            compact = re.sub(r"[^a-z0-9]", "", name)
            if ptype == "address":
                mapping = {
                    "safeharborregistry": system["safe_harbor_registry"],
                    "registry": system["safe_harbor_registry"],
                    "poolimplementation": system["pool_implementation"],
                    "implementation": system["pool_implementation"],
                    "defaultoutcomemoderator": system.get("moderator"),
                    "outcomemoderator": system.get("moderator"),
                    "moderator": system.get("moderator"),
                    "owner": alice.address,
                    "owneraddress": alice.address,
                    "admin": alice.address,
                    "adminaddress": alice.address,
                }
                resolved = mapping.get(compact) or system.get(compact)
                if not is_address(resolved):
                    return False, f"initializer dependency '{name or 'address'}' could not be resolved safely"
                values.append(resolved)
            elif ptype == "bool":
                values.append(False)
            elif ptype.startswith("uint") or ptype.startswith("int"):
                values.append(0)
            elif ptype == "bytes":
                values.append("0x")
            elif ptype == "bytes32":
                values.append("0x" + "00" * 32)
            elif ptype == "string":
                values.append("lowkey")
            elif ptype.endswith("[]"):
                values.append([])
            else:
                values.append(0)

        init_data = _encode_calldata(_signature(init), values)
        if not init_data:
            return False, f"failed to encode {root_model.name}.initialize(...)"

        if proxy:
            proxy_args = [factory_impl, init_data]
            root_target = _deploy_local_artifact(root, rpc, private_key, proxy, proxy_args)
            if not is_address(root_target):
                return False, f"failed to deploy ERC1967Proxy for {root_model.name}"
        else:
            tx = _send_lab_control(host, config, alice, factory_impl, _signature(init), values)
            if not tx:
                return False, f"failed to initialize {root_model.name}"
    system["factory"] = root_target
    system["factory_model"] = root_model.name

    # Configure the common token allowlist gate after the root is initialized.
    allow_fn = next(
        (
            item for item in root_model.abi
            if item.get("type") == "function"
            and str(item.get("name") or "").lower() in {"setstaketokenallowed", "settokenallowed"}
        ),
        None,
    )
    if allow_fn:
        if not _send_lab_control(
            host, config, alice, root_target,
            _signature(allow_fn), [system["stake_token"], True],
        ):
            return False, "failed to allowlist the synthetic stake token on the protocol entry point"

    # Publish the complete discovered environment into the shared audit context.
    config["target"] = root_target
    config["target_contract"] = root_model.name
    config["_walkthrough_recipe"] = "confidence-pool" if _looks_like_confidence_pool_system(root_model, child) else "generic-system"
    config["lab_system"] = {
        **{key: value for key, value in system.items() if is_address(value)},
        "root": root_target,
        "root_model": root_model.name,
        "child": None,
        "child_model": child.name,
        "factory_model": root_model.name,
    }
    if hasattr(host, "set_lab_target"):
        artifact_path = str(root / root_model.artifact)
        host.set_lab_target(config, root, root_target, root_model.name, artifact_path)
    else:
        config.setdefault("aliases", {})[root_model.name] = root_target
        config.setdefault("targets", {})[root_model.name] = root_target
        config.setdefault("abi_paths", {})[root_target] = str(root / root_model.artifact)
        config["actor"] = "lab-deployer"

    if hasattr(host, "save_config"):
        host.save_config(config)
    audit_context.set_target(
        root,
        address=root_target,
        contract=root_model.name,
        artifact=str(root / root_model.artifact),
        source="synthesized-project-lab",
    )
    audit_context.update(root, actor=alice.name, rpc=rpc)
    return True, f"synthesized {root_model.name} + {child.name} protocol environment"


def _system_has_live_core(config: dict[str, Any], rpc: str | None) -> bool:
    """Generic validity check for a persisted local protocol system."""
    if not rpc:
        return False
    system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
    entry = (
        system.get("root")
        or system.get("entry")
        or system.get("factory")
        or system.get("target")
        or config.get("target")
    )
    if not is_address(entry):
        return False
    if _runtime_code(rpc, str(entry)) in {"", "0x"}:
        return False

    # Validate recorded contract addresses when the project has explicitly
    # described them. Never require protocol-specific dependency names.
    for key, value in system.items():
        if key.endswith("_model") or key.endswith("_parent") or not is_address(value):
            continue
        if _runtime_code(rpc, str(value)) in {"", "0x"}:
            return False
    return True


def _target_from_host(
    host: Any,
    config: dict[str, Any],
    root: Path,
    contract: str | None,
    auto: bool,
) -> tuple[str | None, str | None]:
    # Auto mode is allowed to rebuild a disposable local system when a project
    # adapter exists but the persisted target has no verified system context.
    target = None

    if auto:
        try:
            info = host.anvil_rpc_info(config)
            if not info and not config.get("rpc"):
                info = host.ensure_project_anvil(config, root)
            if info:
                host._bind_detected_anvil(config, info)

            rpc = (
                info.get("url")
                if isinstance(info, dict)
                else (host.effective_rpc(config) if hasattr(host, "effective_rpc") else config.get("rpc"))
            )

            system_ready = _system_has_live_core(config, rpc)

            adapter = host.discover_local_lab_script(root) if hasattr(host, "discover_local_lab_script") else None

            if adapter and not system_ready and hasattr(host, "run_lab"):
                code = host.run_lab(config, [])
                if code != 0:
                    system_ready = _system_has_live_core(config, rpc)

            if not system_ready:
                synthesized, synthesis_reason = _synthesize_local_protocol_fixture(
                    root,
                    rpc,
                    host,
                    config,
                    _actors(host, config, 4),
                    _artifact_models(root),
                    _artifact_models(root, include_aux=True),
                )
                if synthesized:
                    system_ready = True
                elif synthesis_reason:
                    print(f"  Auto protocol lab synthesis: {synthesis_reason}")

            system = config.get("lab_system") if isinstance(config.get("lab_system"), dict) else {}
            root_address = (
                system.get("root")
                or system.get("entry")
                or system.get("factory")
                or system.get("target")
            )
            root_model = (
                system.get("root_model")
                or system.get("entry_model")
                or system.get("factory_model")
                or config.get("target_contract")
            )

            # A system-aware walkthrough begins at the explicitly recorded protocol root.
            if not contract and is_address(root_address) and (
                not rpc or _runtime_code(rpc, root_address) not in {"", "0x"}
            ):
                return root_address, root_model

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
        root_address = system.get("root") or system.get("entry") or system.get("factory") or system.get("target")
        root_model = system.get("root_model") or system.get("factory_model") or config.get("target_contract")
        if is_address(root_address):
            return root_address, root_model

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


def _connection_summary(source: ContractModel, edge: dict[str, Any], concrete: str, target_model: ContractModel | None, root: Path) -> str:
    caller = str(edge.get("from") or "")
    fn = str(edge.get("to_function") or "")
    via = str(edge.get("via") or "")
    interface = str(edge.get("interface") or edge.get("to_contract") or "")
    fn_link = _function_link(root, target_model, fn)

    low_caller = caller.lower()
    low_fn = fn.lower()

    if caller == "createPool" and low_fn == "owner":
        return "checks who owns the Agreement before allowing the pool to be created"
    if caller == "createPool" and low_fn == "isagreementvalid":
        return "asks the Safe Harbor Registry whether the Agreement is valid"
    if caller == "createPool" and low_fn == "initialize":
        return f"creates a new {concrete} clone and initializes it with the pool configuration"
    if low_fn in {"safetransferfrom", "transferfrom"}:
        return f"pulls stake tokens from the user through {concrete}.{fn_link}"
    if low_fn == "safetransfer":
        return f"sends stake tokens out through {concrete}.{fn_link}"
    if low_fn == "balanceof":
        return f"reads the token balance through {concrete}.{fn_link}"
    if low_fn == "getagreementstate":
        return f"reads the Agreement's attack state through {concrete}.{fn_link}"
    if low_fn == "getattackregistry":
        return f"finds the Attack Registry through {concrete}.{fn_link}"
    if low_fn == "iscontractinscope":
        return "checks whether the account belongs to the Agreement's scope"
    if caller == "_replaceScope" and low_fn == "push":
        return "records the updated scope account in the pool's internal array"
    if caller == "_markRiskWindowStart" and low_fn == "expiry":
        return "reads the pool expiry while calculating the risk-window boundary"

    via_text = f" via {via}" if via else ""
    return f"calls {concrete}.{fn_link}{via_text} to use that contract's interface"

def _runtime_node_label(runtime: list[RuntimeContract], address: Any) -> str | None:
    if not is_address(address):
        return None
    for node in runtime:
        if node.address.lower() == str(address).lower():
            return node.label
    return None

def _render_connections(
    root: Path,
    models: list[ContractModel],
    model: ContractModel,
    enabled: bool,
    runtime: list[RuntimeContract] | None = None,
) -> str:
    lines = [
        _paint("SYSTEM CONNECTIONS", BOLD + WHITE, enabled),
        "  Source-backed relationships, grouped by the function that causes them.",
    ]
    by_name = {item.name: item for item in models}
    impls = _implementation_mapping(models)

    for source_model in models:
        cross: list[tuple[dict[str, Any], str]] = []
        for edge in source_model.calls:
            target_name = str(edge.get("to_contract") or edge.get("interface") or "")
            concrete = impls.get(target_name, target_name)
            if edge.get("kind") == "cross-contract" and concrete:
                cross.append((edge, concrete))

        if not cross:
            continue

        grouped: dict[str, list[tuple[dict[str, Any], str]]] = {}
        for edge, concrete in cross:
            grouped.setdefault(str(edge.get("from") or "unknown"), []).append((edge, concrete))

        lines.append("")
        lines.append(f"  {STATE} {source_model.name}")
        for caller, edges in list(grouped.items())[:8]:
            caller_link = _function_link(root, source_model, caller)
            lines.append(f"    {FUNCTION} {caller_link}()")

            seen: set[tuple[str, str, str | None]] = set()
            for edge, concrete in edges[:6]:
                fn = str(edge.get("to_function") or "unknown")
                via = str(edge.get("via") or "")
                key = (concrete, fn, via)
                if key in seen:
                    continue
                seen.add(key)

                target_model = by_name.get(concrete) or by_name.get(str(edge.get("to_contract") or ""))
                description = _connection_summary(source_model, edge, concrete, target_model, root)
                lines.append(f"      ├─ {description}")
                if target_model:
                    linked = _function_link(root, target_model, fn)
                    lines.append(f"      └─ {EXTERNAL} {target_model.name}.{linked}")
                else:
                    lines.append(f"      └─ {EXTERNAL} {concrete}.{fn}")

    inheritance = []
    for source_model in models:
        for base in source_model.bases[:8]:
            inheritance.append((source_model.name, base))
    if inheritance:
        lines += ["", "  INHERITANCE"]
        for child, base in inheritance[:24]:
            lines.append(f"    {child} {DOTTED} {base}   [inherits]")

    if len(lines) == 2:
        lines.append("  no source-level cross-contract calls resolved")
    return "\n".join(lines)


def _render_actual_call_tree(step: Step, runtime: list[RuntimeContract], enabled: bool) -> str:
    """Render the observed EVM call tree as a human-readable protocol chain."""
    if not step.execution_edges:
        return ""

    runtime_by_addr = {
        node.address.lower(): node.label
        for node in runtime
        if is_address(node.address)
    }
    root_fn = str(step.function or "").split("(", 1)[0]
    lines = [
        _paint("  │   LIVE CALL CHAIN", BOLD + BLUE, enabled),
        f"  │      {ACTOR} {step.actor} ──▶ {_friendly_contract_name(step)}.{root_fn}()",
        "  │      │",
    ]

    edges = step.execution_edges[:16]
    for edge_index, edge in enumerate(edges):
        depth = max(0, int(edge.get("depth") or 0))
        target = edge.get("to_label") or edge.get("to_contract") or runtime_by_addr.get(
            str(edge.get("to_address") or "").lower()
        ) or _addr(edge.get("to_address"))
        fn = str(edge.get("function") or edge.get("type") or "unknown")
        error = bool(edge.get("error") or edge.get("revert"))
        mark = "✕" if error else "✓"

        # The root call is already shown in the header. Descendants become branches.
        if depth == 0 and str(target).lower() == str(step.contract).lower():
            continue

        prefix = "  │      " + "    " * min(depth, 5)
        connector = "└─▶" if edge_index == len(edges) - 1 else "├─▶"
        lines.append(f"{prefix}{connector} {target}.{fn}  {mark}")

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

def _render_system_workflow_graph(
    root: Path,
    models: list[ContractModel],
    runtime: list[RuntimeContract],
    root_model: ContractModel,
    enabled: bool,
) -> str:
    """Draw the whole known contract relationship graph, then live instances."""
    by_name = {item.name.lower(): item for item in models}
    impls = _implementation_mapping(models)
    runtime_by_model: dict[str, list[RuntimeContract]] = {}
    for node in runtime:
        if node.model and node.model != "External":
            runtime_by_model.setdefault(node.model.lower(), []).append(node)

    lines = [_paint("SYSTEM WORKFLOW", BOLD + CYAN, enabled)]
    root_nodes = runtime_by_model.get(root_model.name.lower(), [])
    root_address = _addr(root_nodes[0].address) if root_nodes else "not live"
    lines.append(
        f"  {ACTOR} {_pretty_identifier(root_model.name)}  {root_address}  [entry point]"
    )

    emitted: set[tuple[str, str, str]] = set()
    edge_lines = 0

    # Source map: every first-party cross-contract relationship gets a compact edge.
    for source_model in models:
        for edge in source_model.calls:
            if edge.get("kind") != "cross-contract":
                continue
            raw_target = str(edge.get("to_contract") or edge.get("interface") or "")
            concrete = impls.get(raw_target, raw_target)
            target_model = by_name.get(concrete.lower()) or by_name.get(raw_target.lower())
            if target_model is None:
                continue

            caller = str(edge.get("from") or "function")
            fn_name = str(edge.get("to_function") or "unknown")
            key = (source_model.name.lower(), target_model.name.lower(), fn_name.lower())
            if key in emitted:
                continue
            emitted.add(key)

            caller_link = _function_link(root, source_model, caller)
            target_link = _function_link(root, target_model, fn_name)
            lines.append(
                f"  │  ○ {source_model.name}.{caller_link}() "
                f"──▶ {target_model.name}.{target_link}()"
            )
            edge_lines += 1
            if edge_lines >= 18:
                break
        if edge_lines >= 18:
            break

    # Live deployment edges: actual child instances observed in traces.
    for node in runtime:
        if not node.parent or not is_address(node.parent):
            continue
        parent = next(
            (item for item in runtime if item.address.lower() == str(node.parent).lower()),
            None,
        )
        if parent:
            relation = "CLONE" if node.relation == "CLONE" else node.relation or "CALL"
            lines.append(
                f"  │  ● {parent.label} ──{relation}──▶ "
                f"{node.label} {_addr(node.address)}"
            )

    if edge_lines == 0:
        lines.append("  │  ○ no first-party cross-contract relationship resolved yet")

    lines.append("  │")
    lines.append("  └─ ○ source relationship   ● observed live")
    return "\n".join(lines)


def _render_runtime_graph(runtime: list[RuntimeContract], enabled: bool) -> str:
    lines = [_paint("SYSTEM MAP", BOLD + WHITE, enabled)]
    if not runtime:
        return "\n".join(lines + ["  <no live contracts>"])

    by_addr = {node.address.lower(): node for node in runtime}
    children: dict[str, list[RuntimeContract]] = {}
    roots: list[RuntimeContract] = []

    for node in runtime:
        if node.parent and node.parent.lower() in by_addr:
            children.setdefault(node.parent.lower(), []).append(node)
        else:
            roots.append(node)

    relation_text = {
        "system": "protocol entry point",
        "target": "current entry point",
        "CLONE": "creates / clones",
        "IMPLEMENTATION": "uses implementation",
        "DEPENDENCY": "depends on",
        "CREATE2": "creates",
        "CREATE": "creates",
        "EVENT": "emits events to",
    }

    seen: set[str] = set()

    def render(node: RuntimeContract, indent: str = "  ", last: bool = True) -> None:
        key = node.address.lower()
        if key in seen:
            return
        seen.add(key)

        marker = "◆" if node.relation in {"system", "target"} else "●"
        suffix = f"  [{relation_text.get(node.relation, node.relation)}]" if node.relation else ""
        lines.append(f"{indent}{marker} {node.label} {_addr(node.address)}{suffix}")

        kids = children.get(key, [])
        for index, child in enumerate(kids[:10]):
            branch = "└──" if index == len(kids[:10]) - 1 else "├──"
            relation = relation_text.get(child.relation, child.relation)
            lines.append(f"{indent}{branch} {DOTTED} {relation} {DOTTED}▶ {child.label} {_addr(child.address)}")

    for index, node in enumerate(roots):
        render(node, "  ", index == len(roots) - 1)

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
    support_models: list[ContractModel] | None = None,
) -> str:
    success = sum(1 for x in steps if x.status == "success")
    blocked = sum(1 for x in steps if x.status in {"blocked", "reverted"})
    board = [
        _paint("LOWKEY // LIVE PROTOCOL WALKTHROUGH", BOLD + CYAN, enabled),
        f"  {model.name}   •   {success} successful   •   {blocked} blocked   •   {len(steps)} observed",
        "  ENTER = next live interaction   Q = stop   |   RANDOM TEST: lk walkthrough test",
        "  the story is live: no future step is rendered before it is observed",
        "  arrows = actual call path   boxes = state   function names = Ctrl+Click source",
        "",
        _box("ACTORS", [
            "   ".join(f"{ACTOR} {actor.name} {_addr(actor.address)}" for actor in actors)
        ], width=92),
        "",
        _render_system_workflow_graph(
            root,
            models + [m for m in (support_models or []) if m.name not in {x.name for x in models}],
            runtime,
            model,
            enabled,
        ),
        "",
        _render_protocol_story_full(
            root,
            steps,
            current,
            actors,
            models + [m for m in (support_models or []) if m.name not in {x.name for x in models}],
            enabled,
        ),
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
    test_mode=any(str(x).lower() in {"test", "random"} for x in args) or "--test" in args or "--random" in args
    auto="--auto" in args or "auto" in args
    # Adversarial walkthroughs are local-only and may bootstrap the disposable
    # project fixture automatically when no live target exists.
    if test_mode:
        auto = True if "--no-auto" not in args else False
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
    code,out,err=_forge_build_with_info(root)
    if code!=0:
        print(out+err,file=sys.stderr); return code or 1

    models=_artifact_models(root)
    support_models=_artifact_models(root, include_aux=True)
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
        live_ok, live_reason = _target_is_live_instance(root, rpc, target, model)
        if not live_ok:
            print("Error: adversarial test target is not a configured protocol instance.", file=sys.stderr)
            print(f"Reason: {live_reason}", file=sys.stderr)
            return 2
        system_targets = _system_test_targets(config, target, model, models)
        return _run_adversarial_test(
            root, config, host, target, model, models, actors, rpc,
            total_cases=test_cases, seed=test_seed,
            system_targets=system_targets,
        )

    if static:
        plan=plan_workflow(model,actors,target or "0x"+"00"*20,int(time.time()),max_steps,root=root)
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

    model_catalog = models + [
        item for item in support_models
        if item.name not in {x.name for x in models}
    ]
    runtime=_lab_runtime(config,target,model,model_catalog)
    steps=[]
    completed=set()
    prepared_pools: set[tuple[str, str]] = set()
    observed=_merge_protocol_observations(
        config.get("_walkthrough_observed") or {},
        config=config,
        runtime=runtime,
    )
    system=config.get("lab_system") if isinstance(config.get("lab_system"),dict) else {}
    recipe=[]
    if config.get("_walkthrough_recipe")=="confidence-pool":
        now=_block_timestamp(rpc)
        if model.name.lower().endswith("factory"):
            recipe=_confidence_pool_factory_recipe(config,actors,now)
        elif model.name.lower()=="confidencepool":
            recipe=_confidence_pool_recipe(config,actors,now=now)
    pending=recipe[:max_steps] if recipe else plan_workflow(model,actors,target,_block_timestamp(rpc),max_steps,observed,root=root)

    def draw(current=None, storage=None):
        if sys.stdout.isatty():
            # Fixed terminal canvas: each live observation replaces the previous
            # frame instead of scrolling the workflow downward.
            sys.stdout.write("\033[2J\033[H\033[3J")
            sys.stdout.flush()
        print(_render_board(
            root, model, models, runtime, actors, steps, current, storage or [],
            _ansi_enabled(False),
            support_models=model_catalog,
        ))
        sys.stdout.flush()

    draw()

    while pending and len(steps)<max_steps:
        step=pending.pop(0)
        step.index=len(steps)+1
        current_model=next((m for m in model_catalog if m.name==step.contract),model)
        abi_item=next((x for x in current_model.abi if x.get("type")=="function" and _signature(x)==step.function),None)
        if abi_item:
            # Recipe/LAB_CONTROL steps already contain authoritative arguments
            # derived from the live protocol fixture. Only inferred steps are
            # re-derived from the generic semantic planner.
            if step.inferred:
                step.args = [
                    _arg_for(
                        p,
                        actors,
                        step.address,
                        _block_timestamp(rpc),
                        _merge_protocol_observations(
                            observed, config=config, runtime=runtime
                        ),
                        current_model,
                        str(step.function).split("(", 1)[0],
                    )
                    for p in abi_item.get("inputs", [])
                ]
                step.value_wei = _value_for(abi_item)

        key=(step.contract,step.address.lower(),step.function)
        if key in completed: continue

        step.status = "checking"
        steps.append(step)
        draw(step)

        actor=next((a for a in actors if a.name==step.actor),actors[0])

        valid_args, argument_error = _validate_step_arguments(step, current_model)
        if not valid_args:
            steps.pop()
            step.status = "blocked"
            step.error = "ARGUMENT RESOLUTION BLOCKED: " + str(argument_error)
            step.error_reason = _explain_failure(step, step.error, step.actor)
            step.diagnostics = [
                "No transaction was sent because a required contract dependency could not be resolved safely"
            ]
            steps.append(step)
            draw(step)
            if not no_prompt:
                choice = _wait_for_next_interaction(no_prompt)
                if choice == "q":
                    break
            continue

        repair_attempts = 0
        repair_notes: list[str] = []
        while auto and repair_attempts < 3:
            repair = _prepare_obvious_prerequisite(
                root, rpc, host, config, step, current_model, model_catalog, actors
            )
            if not repair:
                break
            repair_attempts += 1
            repair_notes.append(repair)
            step.diagnostics.append(repair)
            # Re-read the source-derived guards after every setup transaction.
            if repair.startswith("PREREQUISITE ✕"):
                break
            actor = next((a for a in actors if a.name == step.actor), actor)
            draw(step)
        ok,preflight=_preflight(rpc,step,actor.address)
        steps.pop()
        step.preflight=preflight
        if not ok:
            step.status="blocked"
            step.error="PRECONDITION BLOCKED: "+preflight
            step.error_reason=_explain_failure(step, preflight, step.actor)
            step.failure_origin, step.diagnostics = _diagnose_failed_call(root, rpc, step, current_model, model_catalog, actor.address)
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
            before=_snapshot_runtime(runtime,models,rpc,[a.address for a in actors], step.args + list(system.values()))
            tx,output=_send(host,config,actor,step.address,step.function,step.args,step.value_wei)
            if not tx:
                step.status="reverted"
                step.error=output or "transaction failed"
                step.error_reason=_explain_failure(step, step.error, step.actor)
                step.failure_origin, step.diagnostics = _diagnose_failed_call(root, rpc, step, current_model, model_catalog, actor.address)
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
                step.execution_edges=_trace_execution_edges(root,rpc,model_catalog,trace)
                runtime_by_addr = {node.address.lower(): node.label for node in runtime}
                for edge in step.execution_edges:
                    address = edge.get("to_address")
                    if isinstance(address, str):
                        edge["to_label"] = runtime_by_addr.get(address.lower())
                step.status="success" if receipt and receipt.get("status") in (None,"0x1",1) else "reverted"
                step.error_reason = (
                    "preflight passed and the live transaction was accepted"
                    if step.status == "success"
                    else _explain_failure(step, output, step.actor)
                )
                discovered=_discover_runtime_contracts(root,rpc,models,runtime,receipt,trace,step.index,step.address)
                if discovered:
                    runtime.extend(discovered)
                    observed.update(_merge_protocol_observations({}, config=config, runtime=discovered))
                    step.discovered_contracts=[asdict(x) for x in discovered]
                    # Feed discovered application instances back into the shared
                    # protocol system so the next live/test operation can use them.
                    lab = config.get("lab_system")
                    if isinstance(lab, dict):
                        for node in discovered:
                            child_model = str(lab.get("child_model") or "").strip().lower()
                            if (
                                child_model
                                and node.model
                                and node.model != "External"
                                and node.model.lower() == child_model
                            ):
                                lab["child"] = node.address
                        config["lab_system"] = lab
                        if hasattr(host, "save_config"):
                            host.save_config(config)

                # Record the actual protocol interaction before any environment
                # preparation that it causes. This preserves create -> discover ->
                # approve ordering in the live path and saved evidence.
                steps.append(step); completed.add(key)

                # Visible local-lab prerequisite: once a real pool clone exists,
                # approve the recorded mock stake token for that clone.
                token_address = observed.get("staketoken")
                use_pool_recipe = config.get("_walkthrough_recipe") == "confidence-pool"
                if token_address and discovered and not use_pool_recipe:
                    child_model_name = str(config.get("lab_system", {}).get("child_model") or "").strip().lower()
                    for node in discovered:
                        if child_model_name and str(node.model).lower() != child_model_name:
                            continue
                        if not _model_uses_token_allowance(
                            next((item for item in model_catalog if item.name.lower() == str(node.model).lower()), None)
                        ):
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

                after=_snapshot_runtime(runtime,models,rpc,[a.address for a in actors], step.args + list(system.values()))
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
                        child, actors, node.address, _block_timestamp(rpc), max_steps, observed, root=root
                    )
                    for candidate in reversed(selected):
                        ckey=(candidate.contract,candidate.address.lower(),candidate.function)
                        if ckey not in completed:
                            pending.insert(0,candidate)
                for candidate in reversed(plan_workflow(current_model,actors,step.address,_block_timestamp(rpc),max_steps,observed,root=root)):
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

