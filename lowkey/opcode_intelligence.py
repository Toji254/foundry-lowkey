"""Fork-aware EVM opcode registry and bounded OpcodeStep v1 normalizer.

This module is deliberately separate from trace_schema.TraceEvent v2:
TraceEvent models call frames; OpcodeStep models individual interpreter
instructions. Missing backend fields remain unavailable rather than zero.
"""
from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

OPCODE_SCHEMA_VERSION = 1
MAX_BYTECODE_BYTES = 1_000_000
MAX_TRACE_STEPS = 250_000
MAX_STACK_DEPTH = 1024
MAX_CAPTURE_MEMORY_WORDS = 4096

FORK_ORDER = (
    "frontier", "homestead", "byzantium", "constantinople", "istanbul",
    "berlin", "london", "paris", "shanghai", "cancun", "prague", "osaka",
)
_FORK_RANK = {name: index for index, name in enumerate(FORK_ORDER)}
_FORK_ALIASES = {
    "fusaka": "osaka",
    "pectra": "prague",
    "glamsterdam": "glamsterdam-preview",
    "amsterdam": "glamsterdam-preview",
    "glamsterdam-preview": "glamsterdam-preview",
}

# name, pops, pushes, introduced fork, category
_BASE = {
    0x00: ("STOP", 0, 0, "frontier", "control"),
    0x01: ("ADD", 2, 1, "frontier", "arithmetic"),
    0x02: ("MUL", 2, 1, "frontier", "arithmetic"),
    0x03: ("SUB", 2, 1, "frontier", "arithmetic"),
    0x04: ("DIV", 2, 1, "frontier", "arithmetic"),
    0x05: ("SDIV", 2, 1, "frontier", "arithmetic"),
    0x06: ("MOD", 2, 1, "frontier", "arithmetic"),
    0x07: ("SMOD", 2, 1, "frontier", "arithmetic"),
    0x08: ("ADDMOD", 3, 1, "frontier", "arithmetic"),
    0x09: ("MULMOD", 3, 1, "frontier", "arithmetic"),
    0x0A: ("EXP", 2, 1, "frontier", "arithmetic"),
    0x0B: ("SIGNEXTEND", 2, 1, "frontier", "arithmetic"),
    0x10: ("LT", 2, 1, "frontier", "comparison"),
    0x11: ("GT", 2, 1, "frontier", "comparison"),
    0x12: ("SLT", 2, 1, "frontier", "comparison"),
    0x13: ("SGT", 2, 1, "frontier", "comparison"),
    0x14: ("EQ", 2, 1, "frontier", "comparison"),
    0x15: ("ISZERO", 1, 1, "frontier", "comparison"),
    0x16: ("AND", 2, 1, "frontier", "bitwise"),
    0x17: ("OR", 2, 1, "frontier", "bitwise"),
    0x18: ("XOR", 2, 1, "frontier", "bitwise"),
    0x19: ("NOT", 1, 1, "frontier", "bitwise"),
    0x1A: ("BYTE", 2, 1, "frontier", "bitwise"),
    0x1B: ("SHL", 2, 1, "constantinople", "bitwise"),
    0x1C: ("SHR", 2, 1, "constantinople", "bitwise"),
    0x1D: ("SAR", 2, 1, "constantinople", "bitwise"),
    0x20: ("KECCAK256", 2, 1, "frontier", "crypto"),
    0x30: ("ADDRESS", 0, 1, "frontier", "environment"),
    0x31: ("BALANCE", 1, 1, "frontier", "environment"),
    0x32: ("ORIGIN", 0, 1, "frontier", "environment"),
    0x33: ("CALLER", 0, 1, "frontier", "environment"),
    0x34: ("CALLVALUE", 0, 1, "frontier", "environment"),
    0x35: ("CALLDATALOAD", 1, 1, "frontier", "environment"),
    0x36: ("CALLDATASIZE", 0, 1, "frontier", "environment"),
    0x37: ("CALLDATACOPY", 3, 0, "frontier", "environment"),
    0x38: ("CODESIZE", 0, 1, "frontier", "environment"),
    0x39: ("CODECOPY", 3, 0, "frontier", "environment"),
    0x3A: ("GASPRICE", 0, 1, "frontier", "environment"),
    0x3B: ("EXTCODESIZE", 1, 1, "frontier", "environment"),
    0x3C: ("EXTCODECOPY", 4, 0, "frontier", "environment"),
    0x3D: ("RETURNDATASIZE", 0, 1, "byzantium", "environment"),
    0x3E: ("RETURNDATACOPY", 3, 0, "byzantium", "environment"),
    0x3F: ("EXTCODEHASH", 1, 1, "constantinople", "environment"),
    0x40: ("BLOCKHASH", 1, 1, "frontier", "environment"),
    0x41: ("COINBASE", 0, 1, "frontier", "environment"),
    0x42: ("TIMESTAMP", 0, 1, "frontier", "environment"),
    0x43: ("NUMBER", 0, 1, "frontier", "environment"),
    0x44: ("DIFFICULTY", 0, 1, "frontier", "environment"),
    0x45: ("GASLIMIT", 0, 1, "frontier", "environment"),
    0x46: ("CHAINID", 0, 1, "istanbul", "environment"),
    0x47: ("SELFBALANCE", 0, 1, "istanbul", "environment"),
    0x48: ("BASEFEE", 0, 1, "london", "environment"),
    0x49: ("BLOBHASH", 1, 1, "cancun", "environment"),
    0x4A: ("BLOBBASEFEE", 0, 1, "cancun", "environment"),
    0x50: ("POP", 1, 0, "frontier", "stack"),
    0x51: ("MLOAD", 1, 1, "frontier", "memory"),
    0x52: ("MSTORE", 2, 0, "frontier", "memory"),
    0x53: ("MSTORE8", 2, 0, "frontier", "memory"),
    0x54: ("SLOAD", 1, 1, "frontier", "storage"),
    0x55: ("SSTORE", 2, 0, "frontier", "storage"),
    0x56: ("JUMP", 1, 0, "frontier", "control"),
    0x57: ("JUMPI", 2, 0, "frontier", "control"),
    0x58: ("PC", 0, 1, "frontier", "control"),
    0x59: ("MSIZE", 0, 1, "frontier", "memory"),
    0x5A: ("GAS", 0, 1, "frontier", "environment"),
    0x5B: ("JUMPDEST", 0, 0, "frontier", "control"),
    0x5C: ("TLOAD", 1, 1, "cancun", "transient-storage"),
    0x5D: ("TSTORE", 2, 0, "cancun", "transient-storage"),
    0x5E: ("MCOPY", 3, 0, "cancun", "memory"),
    0xF0: ("CREATE", 3, 1, "frontier", "creation"),
    0xF1: ("CALL", 7, 1, "frontier", "external-call"),
    0xF2: ("CALLCODE", 7, 1, "frontier", "external-call"),
    0xF3: ("RETURN", 2, 0, "frontier", "control"),
    0xF4: ("DELEGATECALL", 6, 1, "homestead", "external-call"),
    0xF5: ("CREATE2", 4, 1, "constantinople", "creation"),
    0xFA: ("STATICCALL", 6, 1, "byzantium", "external-call"),
    0xFD: ("REVERT", 2, 0, "byzantium", "control"),
    0xFE: ("INVALID", 0, 0, "frontier", "exception"),
    0xFF: ("SELFDESTRUCT", 1, 0, "frontier", "destruction"),
}

_PREVIEW = {
    0x4B: ("SLOTNUM", 0, 1, "environment", 0),
    0xE6: ("DUPN", None, None, "stack", 1),
    0xE7: ("SWAPN", None, None, "stack", 1),
    0xE8: ("EXCHANGE", None, None, "stack", 1),
}
_NAME_ALIASES = {
    "SHA3": "KECCAK256",
    "PREVRANDAO": "PREVRANDAO",
    "DIFFICULTY": "DIFFICULTY",
}
_HEX_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_WORD_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{1,64}\Z")


def _normalize_fork(fork: str) -> str:
    if not isinstance(fork, str) or not fork.strip():
        raise ValueError("fork must be a non-empty string")
    value = fork.strip().casefold().replace("_", "-")
    value = _FORK_ALIASES.get(value, value)
    if value not in _FORK_RANK and value != "glamsterdam-preview":
        raise ValueError(
            "Unsupported fork profile. Supported mainnet profiles: "
            + ", ".join(FORK_ORDER)
            + "; optional preview: glamsterdam-preview."
        )
    return value


def _status_for(introduced: str, fork: str) -> str:
    # The preview profile inherits the latest mainnet profile. Only the
    # separately registered Glamsterdam candidate opcodes are preview-only.
    if fork == "glamsterdam-preview":
        return "ACTIVE" if introduced in _FORK_RANK else "PREVIEW_ONLY"
    if _FORK_RANK[fork] < _FORK_RANK[introduced]:
        return "NOT_ACTIVE_IN_FORK"
    return "ACTIVE"


def _dynamic_spec(byte: int) -> dict[str, Any] | None:
    if 0x60 <= byte <= 0x7F:
        depth = byte - 0x5F
        return {"byte": byte, "mnemonic": f"PUSH{depth}", "pops": 0, "pushes": 1,
                "introduced_fork": "frontier", "category": "stack",
                "immediate_bytes": depth, "status": "ACTIVE"}
    if 0x80 <= byte <= 0x8F:
        depth = byte - 0x7F
        return {"byte": byte, "mnemonic": f"DUP{depth}", "pops": depth,
                "pushes": depth + 1, "introduced_fork": "frontier",
                "category": "stack", "immediate_bytes": 0, "status": "ACTIVE"}
    if 0x90 <= byte <= 0x9F:
        depth = byte - 0x8F
        return {"byte": byte, "mnemonic": f"SWAP{depth}", "pops": depth + 1,
                "pushes": depth + 1, "introduced_fork": "frontier",
                "category": "stack", "immediate_bytes": 0, "status": "ACTIVE"}
    if 0xA0 <= byte <= 0xA4:
        topics = byte - 0xA0
        return {"byte": byte, "mnemonic": f"LOG{topics}", "pops": topics + 2,
                "pushes": 0, "introduced_fork": "frontier",
                "category": "logging", "immediate_bytes": 0, "status": "ACTIVE"}
    return None


def opcode_spec(opcode: int | str, *, fork: str = "osaka") -> dict[str, Any]:
    """Return a deterministic opcode description without assuming unknown bytes."""
    selected_fork = _normalize_fork(fork)
    if isinstance(opcode, bool):
        raise ValueError("opcode must be a byte value or mnemonic")
    if isinstance(opcode, int):
        if not 0 <= opcode <= 255:
            raise ValueError("opcode byte must be between 0 and 255")
        byte = opcode
    elif isinstance(opcode, str):
        raw = opcode.strip().upper()
        if re.fullmatch(r"0X[0-9A-F]{1,2}", raw):
            byte = int(raw[2:], 16)
        else:
            raw = _NAME_ALIASES.get(raw, raw)
            # PUSH0 is its own Shanghai opcode, not PUSH followed by a depth.
            # Handle it before the generic PUSHn parser so it cannot be rejected
            # by the PUSH1..PUSH32 bounds below.
            if raw == "PUSH0":
                byte = 0x5F
                dynamic = None
            else:
                dynamic = re.fullmatch(r"(PUSH|DUP|SWAP|LOG)([0-9]{1,2})", raw)
            if dynamic:
                kind, number = dynamic.group(1), int(dynamic.group(2))
                valid = (
                    (kind == "PUSH" and 1 <= number <= 32)
                    or (kind == "DUP" and 1 <= number <= 16)
                    or (kind == "SWAP" and 1 <= number <= 16)
                    or (kind == "LOG" and 0 <= number <= 4)
                )
                if not valid:
                    raise ValueError(f"Unknown opcode mnemonic: {opcode}")
                byte = (
                    0x5F + number if kind == "PUSH"
                    else 0x7F + number if kind == "DUP"
                    else 0x8F + number if kind == "SWAP"
                    else 0xA0 + number
                )
            else:
                byte = next((key for key, item in _BASE.items() if item[0] == raw), -1)
                if raw == "CLZ":
                    byte = 0x1E
                if raw == "PREVRANDAO":
                    byte = 0x44
                if raw in {"SLOTNUM", "DUPN", "SWAPN", "EXCHANGE"}:
                    byte = {"SLOTNUM": 0x4B, "DUPN": 0xE6, "SWAPN": 0xE7, "EXCHANGE": 0xE8}[raw]
                if byte < 0:
                    raise ValueError(f"Unknown opcode mnemonic: {opcode}")
    else:
        raise ValueError("opcode must be a byte value or mnemonic")

    dynamic = _dynamic_spec(byte)
    if dynamic is not None:
        item = dynamic
        item["status"] = "ACTIVE"
    elif byte == 0x5F:
        item = {"byte": byte, "mnemonic": "PUSH0", "pops": 0, "pushes": 1,
                "introduced_fork": "shanghai", "category": "stack",
                "immediate_bytes": 0, "status": _status_for("shanghai", selected_fork)}
    elif byte == 0x1E:
        item = {"byte": byte, "mnemonic": "CLZ", "pops": 1, "pushes": 1,
                "introduced_fork": "osaka", "category": "bitwise",
                "immediate_bytes": 0, "status": _status_for("osaka", selected_fork)}
    elif byte in _BASE:
        name, pops, pushes, introduced, category = _BASE[byte]
        if byte == 0x44 and selected_fork in _FORK_RANK and _FORK_RANK[selected_fork] >= _FORK_RANK["paris"]:
            name = "PREVRANDAO"
            introduced = "paris"
        item = {"byte": byte, "mnemonic": name, "pops": pops, "pushes": pushes,
                "introduced_fork": introduced, "category": category,
                "immediate_bytes": 0, "status": _status_for(introduced, selected_fork)}
    elif byte in _PREVIEW and selected_fork == "glamsterdam-preview":
        name, pops, pushes, category, immediate = _PREVIEW[byte]
        item = {"byte": byte, "mnemonic": name, "pops": pops, "pushes": pushes,
                "introduced_fork": "glamsterdam-preview", "category": category,
                "immediate_bytes": immediate, "status": "PREVIEW_ONLY"}
    else:
        return {"byte": byte, "mnemonic": None, "pops": None, "pushes": None,
                "introduced_fork": None, "category": "unknown",
                "immediate_bytes": 0, "status": "UNRECOGNIZED"}
    item["fork"] = selected_fork
    return dict(item)


def _quantity(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a non-negative integer quantity")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        raw = value.strip()
        try:
            result = int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
        except ValueError as exc:
            raise ValueError(f"{label} is not a valid integer quantity") from exc
    else:
        raise ValueError(f"{label} must be a non-negative integer quantity")
    if result < 0:
        raise ValueError(f"{label} cannot be negative")
    return result


def _word(value: Any, label: str) -> str:
    raw = str(value or "").strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not re.fullmatch(r"[0-9a-f]{1,64}", raw):
        raise ValueError(f"{label} must be a 1-32 byte hex word")
    return "0x" + raw.zfill(64)


def _decode_single(value: int) -> int:
    if not (0 <= value <= 90 or 128 <= value <= 255):
        raise ValueError("invalid DUPN/SWAPN immediate byte")
    return (value + 145) % 256


def _decode_pair(value: int) -> tuple[int, int]:
    if not (0 <= value <= 81 or 128 <= value <= 255):
        raise ValueError("invalid EXCHANGE immediate byte")
    k = value ^ 143
    q, r = divmod(k, 16)
    if q < r:
        return q + 1, r + 1
    return r + 1, 29 - q


def _decode_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not value.startswith("0x") or not _HEX_RE.fullmatch(value):
        raise ValueError("bytecode must be 0x-prefixed even-length hex")
    raw = value[2:]
    if len(raw) // 2 > MAX_BYTECODE_BYTES:
        raise ValueError(f"bytecode exceeds safety limit ({MAX_BYTECODE_BYTES} bytes)")
    return bytes.fromhex(raw)


def decode_bytecode(bytecode: str, *, fork: str = "osaka") -> dict[str, Any]:
    """Decode instruction boundaries and PUSH immediates without treating data as opcodes."""
    selected_fork = _normalize_fork(fork)
    try:
        code = _decode_bytes(bytecode)
    except ValueError as exc:
        return {"supported": False, "schema_version": OPCODE_SCHEMA_VERSION,
                "fork": selected_fork, "reason": str(exc), "instructions": []}

    instructions: list[dict[str, Any]] = []
    pc = 0
    while pc < len(code):
        byte = code[pc]
        spec = opcode_spec(byte, fork=selected_fork)
        mnemonic = spec.get("mnemonic")
        row = {
            "pc": pc,
            "byte": byte,
            "opcode": mnemonic or f"UNKNOWN_0x{byte:02x}",
            "status": spec["status"],
            "category": spec["category"],
            "pops": spec["pops"],
            "pushes": spec["pushes"],
            "introduced_fork": spec["introduced_fork"],
            "instruction_bytes": 1,
        }

        if mnemonic and mnemonic.startswith("PUSH") and mnemonic[4:].isdigit():
            width = int(mnemonic[4:])
            raw_immediate = code[pc + 1:pc + 1 + width]
            complete = len(raw_immediate) == width
            row.update({
                "immediate_bytes": width,
                "immediate_data": "0x" + raw_immediate.hex(),
                "immediate_complete": complete,
                "instruction_bytes": 1 + width,
            })
            if complete:
                row["immediate_value"] = int.from_bytes(raw_immediate, "big")
            else:
                row["status"] = "TRUNCATED_IMMEDIATE"
            instructions.append(row)
            pc += 1 + width
            continue

        if mnemonic in {"DUPN", "SWAPN", "EXCHANGE"} and selected_fork == "glamsterdam-preview":
            immediate_available = pc + 1 < len(code)
            immediate = code[pc + 1] if immediate_available else 0
            row.update({
                "immediate_bytes": 1,
                "immediate_byte": immediate,
                "immediate_from_padding": not immediate_available,
            })
            try:
                if mnemonic in {"DUPN", "SWAPN"}:
                    depth = _decode_single(immediate)
                    row["stack_depth_operand"] = depth
                    row["pops"] = depth if mnemonic == "DUPN" else depth + 1
                    row["pushes"] = depth + 1 if mnemonic == "DUPN" else depth + 1
                else:
                    first, second = _decode_pair(immediate)
                    row["stack_depth_operands"] = [first, second]
                    row["pops"] = second + 1
                    row["pushes"] = second + 1
                row["instruction_bytes"] = 2
            except ValueError:
                # EIP-8024 preserves jump-destination analysis: a disassembler
                # must not mask an invalid immediate that is itself JUMPDEST/PUSH.
                row["status"] = "INVALID_IMMEDIATE"
                row["instruction_bytes"] = 1
            instructions.append(row)
            pc += row["instruction_bytes"]
            continue

        instructions.append(row)
        pc += 1

    jumpdests = [row["pc"] for row in instructions if row["opcode"] == "JUMPDEST"]
    statuses: dict[str, int] = {}
    for row in instructions:
        statuses[row["status"]] = statuses.get(row["status"], 0) + 1
    return {
        "supported": True,
        "schema_version": OPCODE_SCHEMA_VERSION,
        "schema": "BytecodeInstruction",
        "fork": selected_fork,
        "bytecode_bytes": len(code),
        "instruction_count": len(instructions),
        "jumpdest_positions": jumpdests,
        "status_counts": statuses,
        "instructions": instructions,
    }


def _name_for_trace(raw: str, fork: str) -> str:
    name = str(raw or "").strip().upper()
    if name == "SHA3":
        return "KECCAK256"
    if name == "DIFFICULTY" and fork in _FORK_RANK and _FORK_RANK[fork] >= _FORK_RANK["paris"]:
        return "PREVRANDAO"
    return name


def normalize_struct_logs(
    struct_logs: Sequence[Mapping[str, Any]],
    *,
    fork: str = "osaka",
    bytecode: str | None = None,
    backend: str = "anvil-structlog",
    include_stack: bool = False,
    include_memory: bool = False,
    max_steps: int = MAX_TRACE_STEPS,
) -> dict[str, Any]:
    """Normalize backend structLogs into OpcodeTrace v1; never populate missing fields."""
    try:
        selected_fork = _normalize_fork(fork)
    except ValueError as exc:
        return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                "fork": str(fork), "backend": backend, "reason": str(exc), "steps": []}
    if not isinstance(backend, str) or not backend.strip():
        return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                "fork": selected_fork, "backend": backend, "reason": "backend is required", "steps": []}
    if not isinstance(struct_logs, Sequence) or isinstance(struct_logs, (str, bytes)):
        return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                "fork": selected_fork, "backend": backend, "reason": "structLogs must be an array", "steps": []}
    if type(max_steps) is not int or max_steps < 1:
        return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                "fork": selected_fork, "backend": backend, "reason": "max_steps must be a positive integer", "steps": []}
    if len(struct_logs) > max_steps:
        return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                "fork": selected_fork, "backend": backend,
                "reason": f"structLogs exceeded safety limit ({max_steps} steps)",
                "step_count": len(struct_logs), "steps": []}

    decoded_by_pc: dict[int, dict[str, Any]] = {}
    if bytecode is not None:
        decoded = decode_bytecode(bytecode, fork=selected_fork)
        if not decoded.get("supported"):
            return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                    "fork": selected_fork, "backend": backend,
                    "reason": "bytecode validation failed: " + str(decoded.get("reason")), "steps": []}
        decoded_by_pc = {row["pc"]: row for row in decoded["instructions"]}

    steps: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for index, raw in enumerate(struct_logs):
        if not isinstance(raw, Mapping):
            return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                    "fork": selected_fork, "backend": backend,
                    "reason": f"structLogs[{index}] is not an object", "steps": []}
        try:
            pc = _quantity(raw.get("pc"), f"structLogs[{index}].pc")
            depth = _quantity(raw.get("depth"), f"structLogs[{index}].depth")
            if depth > MAX_STACK_DEPTH:
                raise ValueError(f"structLogs[{index}].depth exceeds EVM call-depth bound")
            gas = _quantity(raw.get("gas"), f"structLogs[{index}].gas") if raw.get("gas") is not None else None
            gas_cost = _quantity(raw.get("gasCost"), f"structLogs[{index}].gasCost") if raw.get("gasCost") is not None else None
        except ValueError as exc:
            return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                    "fork": selected_fork, "backend": backend,
                    "reason": str(exc), "failed_step": index, "steps": []}

        trace_name = str(raw.get("op") or "").strip().upper()
        if not trace_name:
            return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                    "fork": selected_fork, "backend": backend,
                    "reason": f"structLogs[{index}].op is missing", "failed_step": index, "steps": []}
        normalized_name = _name_for_trace(trace_name, selected_fork)
        try:
            spec = opcode_spec(normalized_name, fork=selected_fork)
        except ValueError:
            spec = {"byte": None, "mnemonic": None, "pops": None, "pushes": None,
                    "category": "unknown", "status": "UNRECOGNIZED", "introduced_fork": None}
        status = spec["status"]
        opcode_byte = spec.get("byte")
        if bytecode is not None:
            instruction = decoded_by_pc.get(pc)
            if instruction is None:
                status = "PC_NOT_INSTRUCTION_BOUNDARY"
                warnings.append({"step": index, "pc": pc, "reason": status})
            else:
                opcode_byte = instruction["byte"]
                expected_name = instruction["opcode"]
                if expected_name != normalized_name:
                    status = "BYTECODE_MISMATCH"
                    warnings.append({
                        "step": index, "pc": pc, "reason": status,
                        "trace_opcode": trace_name, "bytecode_opcode": expected_name,
                    })
                else:
                    status = instruction["status"]
        if status in {"UNRECOGNIZED", "NOT_ACTIVE_IN_FORK", "PREVIEW_ONLY"}:
            warnings.append({"step": index, "pc": pc, "reason": status, "opcode": trace_name})
        counts[status] = counts.get(status, 0) + 1

        stack_value = raw.get("stack")
        stack_available = isinstance(stack_value, list)
        stack_depth = len(stack_value) if stack_available else None
        stack_words = None
        stack_error = None
        if stack_available:
            if stack_depth > MAX_STACK_DEPTH:
                return {"supported": False, "schema": "OpcodeTrace", "schema_version": OPCODE_SCHEMA_VERSION,
                        "fork": selected_fork, "backend": backend,
                        "reason": f"structLogs[{index}].stack exceeds EVM stack bound",
                        "failed_step": index, "steps": []}
            try:
                normalized_words = [_word(value, f"structLogs[{index}].stack[{position}]")
                                    for position, value in enumerate(stack_value)]
                stack_words = normalized_words if include_stack else None
            except ValueError as exc:
                stack_available = False
                stack_depth = None
                stack_words = None
                stack_error = str(exc)
                warnings.append({"step": index, "pc": pc, "reason": "MALFORMED_STACK", "detail": stack_error})

        memory_value = raw.get("memory")
        memory_available = isinstance(memory_value, list)
        memory_words = len(memory_value) if memory_available else None
        memory_snapshot = None
        memory_capture_status = "NOT_REQUESTED"
        if include_memory:
            if not memory_available:
                memory_capture_status = "UNAVAILABLE"
            elif memory_words > MAX_CAPTURE_MEMORY_WORDS:
                memory_capture_status = "LIMIT_EXCEEDED"
            else:
                try:
                    memory_snapshot = [_word(value, f"structLogs[{index}].memory[{position}]")
                                       for position, value in enumerate(memory_value)]
                    memory_capture_status = "CAPTURED"
                except ValueError:
                    memory_available = False
                    memory_words = None
                    memory_capture_status = "MALFORMED"

        storage_value = raw.get("storage")
        storage_available = isinstance(storage_value, Mapping)
        storage_slot_count = len(storage_value) if storage_available else None
        error_value = raw.get("error")
        step = {
            "schema": "OpcodeStep",
            "schema_version": OPCODE_SCHEMA_VERSION,
            "index": index,
            "pc": pc,
            "opcode_byte": opcode_byte,
            "opcode": normalized_name,
            "opcode_status": status,
            "fork": selected_fork,
            "backend": backend,
            "depth": depth,
            "gas_remaining": gas,
            "gas_cost": gas_cost,
            "stack_available": stack_available,
            "stack_depth": stack_depth,
            "stack_words": stack_words,
            "stack_error": stack_error,
            "memory_available": memory_available,
            "memory_words": memory_words,
            "memory_snapshot": memory_snapshot,
            "memory_capture_status": memory_capture_status,
            "storage_available": storage_available,
            "storage_slot_count": storage_slot_count,
            "call_frame_seq": None,
            "error": str(error_value) if error_value is not None else None,
        }
        steps.append(step)

    return {
        "supported": True,
        "schema": "OpcodeTrace",
        "schema_version": OPCODE_SCHEMA_VERSION,
        "backend": backend,
        "fork": selected_fork,
        "step_count": len(steps),
        "status_counts": counts,
        "warning_count": len(warnings),
        "warnings": warnings,
        "steps": steps,
        "evidence_limit": (
            "OpcodeStep records interpreter-level observations. Missing stack, memory, storage, "
            "or frame-attribution data remains unavailable; this schema is separate from call-frame TraceEvent v2."
        ),
    }
