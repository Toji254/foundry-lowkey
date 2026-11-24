"""Exact Anvil storage-access extraction from opcode-level structLogs.

This adapter records SLOAD/SSTORE slot accesses and attributes them to the
executing call frame. It refuses exact status when frame identity or stack
evidence is incomplete. Values are included only when the trace exposes them.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_HEX_WORD_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{1,64}\Z")
_CALL_OPS = {
    "CALL": "CALL",
    "STATICCALL": "STATICCALL",
    "DELEGATECALL": "DELEGATECALL",
    "CALLCODE": "CALLCODE",
    "CREATE": "CREATE",
    "CREATE2": "CREATE2",
}


def _quantity(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be an integer quantity.")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{label} cannot be negative.")
        return value
    if isinstance(value, str):
        try:
            parsed = int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError as exc:
            raise ValueError(f"{label} must be an integer quantity.") from exc
        if parsed < 0:
            raise ValueError(f"{label} cannot be negative.")
        return parsed
    raise ValueError(f"{label} must be an integer quantity.")


def _word(value: Any, label: str) -> str:
    raw = str(value or "").lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if not re.fullmatch(r"[0-9a-f]{1,64}", raw):
        raise ValueError(f"{label} must be a 1-32 byte hex word.")
    return "0x" + raw.zfill(64)


def _address(value: Any) -> str | None:
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        return None
    return value.lower()


def _node_type(node: Mapping[str, Any]) -> str:
    return str(node.get("type") or "").upper()


def _target_from_step(step: Mapping[str, Any], op: str) -> str | None:
    if op in {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"}:
        stack = step.get("stack")
        if not isinstance(stack, list) or len(stack) < 2:
            return None
        try:
            return "0x" + _word(stack[-2], "call target")[-40:]
        except ValueError:
            return None
    return None


def _flatten_call_tree(root: Mapping[str, Any], max_frames: int) -> tuple[list[dict[str, Any]], dict[int, list[int]]]:
    nodes: list[dict[str, Any]] = []
    children: dict[int, list[int]] = {}

    def visit(node: Mapping[str, Any], parent: int | None, depth: int) -> None:
        if len(nodes) >= max_frames:
            raise ValueError(f"callTracer frame count exceeded safety limit ({max_frames}).")
        if not isinstance(node, Mapping):
            raise ValueError("callTracer contains a non-object call frame.")
        seq = len(nodes)
        nodes.append({"seq": seq, "parent": parent, "depth": depth, "node": node})
        if parent is not None:
            children.setdefault(parent, []).append(seq)
        raw_children = node.get("calls") or []
        if not isinstance(raw_children, list):
            raise ValueError("callTracer frame calls must be an array.")
        for child in raw_children:
            if not isinstance(child, Mapping):
                raise ValueError("callTracer child frame must be an object.")
            visit(child, seq, depth + 1)

    visit(root, None, 0)
    return nodes, children


def _match_child(
    *,
    parent_seq: int,
    op: str,
    target: str | None,
    nodes: list[dict[str, Any]],
    children: dict[int, list[int]],
    cursors: dict[int, int],
) -> int | None:
    expected = _CALL_OPS.get(op)
    if expected is None:
        return None
    child_ids = children.get(parent_seq, [])
    start = cursors.get(parent_seq, 0)
    matches: list[tuple[int, int]] = []
    for position in range(start, len(child_ids)):
        child_seq = child_ids[position]
        child = nodes[child_seq]["node"]
        if _node_type(child) != expected:
            continue
        child_target = _address(child.get("to") or child.get("createdAddress") or child.get("created_address"))
        if target is not None and child_target != target:
            continue
        matches.append((position, child_seq))
    if not matches:
        return None
    if target is None and len(matches) != 1:
        return None
    position, child_seq = matches[0]
    cursors[parent_seq] = position + 1
    return child_seq


def _storage_context(node: Mapping[str, Any], parent_address: str | None) -> str | None:
    kind = _node_type(node)
    if kind in {"DELEGATECALL", "CALLCODE"}:
        return parent_address
    if kind in {"CREATE", "CREATE2"}:
        return _address(node.get("createdAddress") or node.get("created_address"))
    return _address(node.get("to"))


def _unsupported(reason: str, *, step_count: int = 0, access_count: int = 0,
                 unmapped_storage_accesses: int = 0, unmatched_frames: int = 0) -> dict[str, Any]:
    return {
        "supported": False,
        "backend": "anvil-structlog",
        "reason": reason[:500],
        "frame_storage": {},
        "step_count": step_count,
        "access_count": access_count,
        "unmapped_storage_accesses": unmapped_storage_accesses,
        "unmatched_frames": unmatched_frames,
    }


def normalize_struct_logs(
    call_trace: Mapping[str, Any],
    struct_logs: Sequence[Mapping[str, Any]],
    *,
    max_steps: int = 250_000,
    max_frames: int = 16_384,
) -> dict[str, Any]:
    """Return exact per-frame SLOAD/SSTORE observations when trace data is complete.

    The callTracer tree supplies frame identity; structLogs supplies ordered
    opcodes and stack operands. CALL/STATICCALL use the callee's storage context,
    while DELEGATECALL/CALLCODE retain the caller's storage context.

    Exact means that every observed SLOAD/SSTORE has a validated slot and a
    uniquely matched call frame. Slot values remain null when the client does
    not expose them; null is never replaced with zero.
    """
    if not isinstance(call_trace, Mapping):
        return _unsupported("callTracer result must be an object.")
    if not isinstance(struct_logs, Sequence) or isinstance(struct_logs, (str, bytes)):
        return _unsupported("structLogs must be an array.")
    if not struct_logs:
        return _unsupported("structLogs is empty.")
    if type(max_steps) is not int or max_steps < 1 or type(max_frames) is not int or max_frames < 1:
        return _unsupported("Trace safety limits must be positive integers.")
    if len(struct_logs) > max_steps:
        return _unsupported(f"structLogs exceeded safety limit ({max_steps} steps).", step_count=len(struct_logs))

    try:
        nodes, children = _flatten_call_tree(call_trace, max_frames)
    except ValueError as exc:
        return _unsupported(str(exc), step_count=len(struct_logs))
    if not nodes:
        return _unsupported("callTracer returned no root frame.", step_count=len(struct_logs))

    root_node = nodes[0]["node"]
    root_address = _storage_context(root_node, None)
    if root_address is None:
        return _unsupported("callTracer root has no usable execution-context address.", step_count=len(struct_logs))

    try:
        root_depth = _quantity(struct_logs[0].get("depth"), "structLogs depth")
    except (AttributeError, ValueError) as exc:
        return _unsupported(str(exc), step_count=len(struct_logs))

    cursors: dict[int, int] = {}
    frame_storage: dict[int, list[dict[str, Any]]] = {0: []}
    active = [{
        "depth": root_depth,
        "trace_seq": 0,
        "address": root_address,
        "ancestor_reverted": bool(root_node.get("error")),
    }]
    unmapped_storage = 0
    unmatched_frames = 0
    access_count = 0
    read_count = 0
    write_count = 0
    last_depth = root_depth

    for index, raw_step in enumerate(struct_logs):
        if not isinstance(raw_step, Mapping):
            return _unsupported(
                f"structLogs[{index}] is not an object.",
                step_count=len(struct_logs), access_count=access_count,
                unmapped_storage_accesses=unmapped_storage, unmatched_frames=unmatched_frames,
            )
        try:
            depth = _quantity(raw_step.get("depth"), f"structLogs[{index}].depth")
        except ValueError as exc:
            return _unsupported(
                str(exc), step_count=len(struct_logs), access_count=access_count,
                unmapped_storage_accesses=unmapped_storage, unmatched_frames=unmatched_frames,
            )
        while active and active[-1]["depth"] > depth:
            active.pop()
        if not active:
            return _unsupported(
                f"structLogs depth escaped the root frame at step {index}.",
                step_count=len(struct_logs), access_count=access_count,
                unmapped_storage_accesses=unmapped_storage, unmatched_frames=unmatched_frames,
            )

        if depth > active[-1]["depth"]:
            parent = active[-1]
            previous = struct_logs[index - 1] if index > 0 else {}
            previous_op = str(previous.get("op") or "").upper() if isinstance(previous, Mapping) else ""
            if depth != parent["depth"] + 1 or previous_op not in _CALL_OPS:
                unmatched_frames += 1
                child_seq = None
            else:
                target = _target_from_step(previous, previous_op)
                child_seq = _match_child(
                    parent_seq=parent["trace_seq"], op=previous_op, target=target,
                    nodes=nodes, children=children, cursors=cursors,
                ) if parent["trace_seq"] is not None else None
                if child_seq is None:
                    unmatched_frames += 1
            child_node = nodes[child_seq]["node"] if child_seq is not None else {}
            child_address = (
                _storage_context(child_node, parent["address"])
                if child_seq is not None else (
                    parent["address"] if previous_op in {"DELEGATECALL", "CALLCODE"}
                    else _target_from_step(previous, previous_op)
                )
            )
            child_reverted = bool(parent["ancestor_reverted"] or child_node.get("error"))
            active.append({
                "depth": depth,
                "trace_seq": child_seq,
                "address": child_address,
                "ancestor_reverted": child_reverted,
            })
            if child_seq is not None:
                frame_storage[child_seq] = []
        elif depth < root_depth:
            return _unsupported(
                f"structLogs depth {depth} is shallower than root depth {root_depth}.",
                step_count=len(struct_logs), access_count=access_count,
                unmapped_storage_accesses=unmapped_storage, unmatched_frames=unmatched_frames,
            )

        last_depth = depth
        op = str(raw_step.get("op") or "").upper()
        if op not in {"SLOAD", "SSTORE"}:
            continue
        access_count += 1
        stack = raw_step.get("stack")
        required_words = 1 if op == "SLOAD" else 2
        if not isinstance(stack, list) or len(stack) < required_words or active[-1]["address"] is None:
            unmapped_storage += 1
            continue
        try:
            slot = _word(stack[-1], f"structLogs[{index}] storage slot")
            new_value = _word(stack[-2], f"structLogs[{index}] SSTORE value") if op == "SSTORE" else None
        except ValueError:
            unmapped_storage += 1
            continue

        frame_seq = active[-1]["trace_seq"]
        if frame_seq is None:
            unmapped_storage += 1
            continue

        previous_value = None
        if op == "SLOAD":
            next_step = struct_logs[index + 1] if index + 1 < len(struct_logs) else None
            if isinstance(next_step, Mapping):
                try:
                    if _quantity(next_step.get("depth"), "next structLogs depth") == depth:
                        next_stack = next_step.get("stack")
                        if isinstance(next_stack, list) and next_stack:
                            previous_value = _word(next_stack[-1], "SLOAD result")
                            new_value = previous_value
                except ValueError:
                    pass
            read_count += 1
        else:
            raw_storage = raw_step.get("storage")
            if isinstance(raw_storage, Mapping):
                for raw_slot, raw_value in raw_storage.items():
                    try:
                        if _word(raw_slot, "storage snapshot slot") == slot:
                            previous_value = _word(raw_value, "storage snapshot value")
                            break
                    except ValueError:
                        continue
            write_count += 1

        frame_storage[frame_seq].append({
            "account": active[-1]["address"],
            "slot": slot,
            "previous_value": previous_value,
            "new_value": new_value,
            "is_write": op == "SSTORE",
            "reverted": bool(active[-1]["ancestor_reverted"]),
        })

    mapped_accesses = sum(len(rows) for rows in frame_storage.values())
    # Invalid accesses were already counted when their stack/frame was checked.
    # Reconcile against the mapped rows instead of adding the same misses twice.
    unmapped_storage = access_count - mapped_accesses
    if unmapped_storage:
        return _unsupported(
            "One or more SLOAD/SSTORE operations lacked a validated frame or stack slot; exact storage evidence refused.",
            step_count=len(struct_logs), access_count=access_count,
            unmapped_storage_accesses=unmapped_storage, unmatched_frames=unmatched_frames,
        )

    return {
        "supported": True,
        "backend": "anvil-structlog",
        "reason": None,
        "frame_storage": {str(key): value for key, value in sorted(frame_storage.items())},
        "step_count": len(struct_logs),
        "access_count": access_count,
        "read_count": read_count,
        "write_count": write_count,
        "unmapped_storage_accesses": 0,
        "unmatched_frames": unmatched_frames,
        "storage_scope": "ordered SLOAD/SSTORE slot accesses attributed to matched callTracer frames; slot values remain null when the client does not expose them",
    }
