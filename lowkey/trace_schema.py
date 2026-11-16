"""Canonical, backend-neutral trace event contract for Lowkey P2.

The canonical TraceEvent deliberately contains only the fields in the P2
contract. Legacy trace objects are adapted at the boundary; they are never
silently treated as canonical evidence.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

TRACE_SCHEMA_VERSION = 2
TRACE_KINDS = frozenset({"Call", "DelegateCall", "StaticCall", "Create", "Create2"})
STORAGE_SUPPORT = frozenset({"exact", "partial", "declared_only"})
TRACE_FIELDS = (
    "seq", "backend", "kind", "accessor", "account", "depth", "value",
    "selector", "calldata", "reverted", "storage", "storage_support",
)
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_BYTES_RE = re.compile(r"0x(?:[0-9a-fA-F]{2})*\Z")
_WORD_RE = re.compile(r"0x[0-9a-fA-F]{64}\Z")

_KIND_ALIASES = {
    "CALL": "Call",
    "DELEGATECALL": "DelegateCall",
    "STATICCALL": "StaticCall",
    "CREATE": "Create",
    "CREATE2": "Create2",
}


def _quantity(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"TraceEvent {label} must be an integer quantity or null.")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"TraceEvent {label} cannot be negative.")
        return value
    if isinstance(value, str):
        try:
            result = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        except ValueError as exc:
            raise ValueError(f"TraceEvent {label} must be an integer quantity or hex quantity.") from exc
        if result < 0:
            raise ValueError(f"TraceEvent {label} cannot be negative.")
        return result
    raise ValueError(f"TraceEvent {label} must be an integer quantity or null.")


def _address(value: Any, label: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not _ADDRESS_RE.fullmatch(value):
        raise ValueError(f"TraceEvent {label} must be a 20-byte address or null.")
    return value.lower()


def _calldata(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _BYTES_RE.fullmatch(value):
        raise ValueError("TraceEvent calldata must be 0x-prefixed, whole-byte hex or null.")
    return value.lower()


def _kind(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("TraceEvent kind must be one of: " + ", ".join(sorted(TRACE_KINDS)))
    result = _KIND_ALIASES.get(value.upper(), value)
    if result not in TRACE_KINDS:
        raise ValueError(
            f"Unsupported trace kind '{value}'. P2 accepts: " + ", ".join(sorted(TRACE_KINDS))
        )
    return result


def _storage_rows(value: Any, label: str) -> list[dict[str, Any]] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise ValueError(f"TraceEvent {label} must be an array or null.")
    rows: list[dict[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, Mapping):
            raise ValueError(f"TraceEvent {label}[{index}] must be an object.")
        address = _address(row.get("account", row.get("address")), f"{label}[{index}].account")
        slot = row.get("slot")
        if not isinstance(slot, str) or not _WORD_RE.fullmatch(slot):
            raise ValueError(f"TraceEvent {label}[{index}].slot must be a bytes32 hex word.")
        previous = row.get("previous_value", row.get("value"))
        updated = row.get("new_value", row.get("post_value"))
        normalized = {
            "account": address,
            "slot": slot.lower(),
            "previous_value": None,
            "new_value": None,
            "is_write": None,
            "reverted": None,
        }
        for field, raw in (("previous_value", previous), ("new_value", updated)):
            if raw is not None:
                if isinstance(raw, int):
                    if raw < 0 or raw >= 1 << 256:
                        raise ValueError(f"TraceEvent {label}[{index}].{field} must fit uint256.")
                    normalized[field] = "0x" + format(raw, "064x")
                elif isinstance(raw, str) and _WORD_RE.fullmatch(raw):
                    normalized[field] = raw.lower()
                else:
                    raise ValueError(f"TraceEvent {label}[{index}].{field} must be bytes32 or null.")
        for field in ("is_write", "reverted"):
            raw = row.get(field)
            if raw is not None and not isinstance(raw, bool):
                raise ValueError(f"TraceEvent {label}[{index}].{field} must be boolean or null.")
            normalized[field] = raw
        optional_values = {
            "access_type": ({"read", "write"}, str),
            "storage_kind": ({"persistent", "transient"}, str),
        }
        for field, (allowed, expected_type) in optional_values.items():
            raw = row.get(field)
            if raw is not None:
                if not isinstance(raw, expected_type) or raw not in allowed:
                    raise ValueError(
                        f"TraceEvent {label}[{index}].{field} must be one of: "
                        + ", ".join(sorted(allowed)) + "."
                    )
                normalized[field] = raw
        frame_id = row.get("frame_id")
        if frame_id is not None:
            if not isinstance(frame_id, str) or not frame_id or len(frame_id) > 120:
                raise ValueError(f"TraceEvent {label}[{index}].frame_id must be a non-empty string up to 120 characters.")
            normalized["frame_id"] = frame_id
        opcode = row.get("opcode")
        if opcode is not None:
            if not isinstance(opcode, str) or not re.fullmatch(r"[A-Z0-9]{2,16}", opcode):
                raise ValueError(f"TraceEvent {label}[{index}].opcode must be an uppercase EVM opcode name.")
            normalized["opcode"] = opcode
        for field in ("access_seq", "opcode_index", "pc"):
            raw = row.get(field)
            if raw is not None:
                parsed = _quantity(raw, f"{label}[{index}].{field}")
                if parsed is None:
                    raise ValueError(f"TraceEvent {label}[{index}].{field} cannot be null when supplied.")
                normalized[field] = parsed
        code_address = row.get("code_address")
        if code_address is not None:
            normalized["code_address"] = _address(code_address, f"{label}[{index}].code_address")
        read_value = row.get("read_value")
        if read_value is not None:
            normalized["read_value"] = _storage_word(read_value, f"{label}[{index}].read_value")
        rows.append(normalized)
    return rows


def build_trace_event(
    *,
    seq: int,
    backend: str,
    kind: Any,
    accessor: Any = None,
    account: Any = None,
    depth: Any = None,
    value: Any = None,
    selector: Any = None,
    calldata: Any = None,
    reverted: bool | None = None,
    storage: list[dict[str, Any]] | None = None,
    storage_support: str,
) -> dict[str, Any]:
    """Validate and build one canonical TraceEvent with explicit capability."""
    if type(seq) is not int or seq < 0:
        raise ValueError("TraceEvent seq must be a nonnegative integer.")
    if not isinstance(backend, str) or not backend.strip():
        raise ValueError("TraceEvent backend is required.")
    backend = backend.strip().lower()
    if backend not in {"anvil-calltracer", "anvil-structlog", "anvil-prestate-diff", "forge-state-diff"}:
        raise ValueError(f"Unsupported TraceEvent backend '{backend}'.")
    if storage_support not in STORAGE_SUPPORT:
        raise ValueError("TraceEvent storage_support must be exact, partial or declared_only.")
    if reverted is not None and not isinstance(reverted, bool):
        raise ValueError("TraceEvent reverted must be boolean or null.")

    raw_calldata = _calldata(calldata)
    derived_selector = (
        raw_calldata[:10]
        if raw_calldata is not None and len(raw_calldata) >= 10
        else None
    )
    if selector is not None:
        if not isinstance(selector, str) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", selector):
            raise ValueError("TraceEvent selector must be a 4-byte hex selector or null.")
        selector = selector.lower()
        if derived_selector is not None and selector != derived_selector:
            raise ValueError("TraceEvent selector does not match calldata.")
    else:
        selector = derived_selector

    rows = _storage_rows(storage, "storage")
    if storage_support == "exact" and rows is None:
        raise ValueError("Exact storage support requires an explicit per-access storage array.")
    if storage_support == "partial" and rows is None:
        raise ValueError("Partial storage support requires an explicit observed storage array.")
    return {
        "seq": seq,
        "backend": backend,
        "kind": _kind(kind),
        "accessor": _address(accessor, "accessor"),
        "account": _address(account, "account"),
        "depth": _quantity(depth, "depth"),
        "value": _quantity(value, "value"),
        "selector": selector,
        "calldata": raw_calldata,
        "reverted": reverted,
        "storage": rows,
        "storage_support": storage_support,
    }


def from_legacy_event(event: Mapping[str, Any], *, seq: int | None = None) -> dict[str, Any]:
    """Adapt the existing v1 trace event without filling absent evidence."""
    if not isinstance(event, Mapping):
        raise ValueError("Legacy trace event must be an object.")
    backend = str(event.get("source_backend") or event.get("backend") or "")
    support = (
        "exact" if backend == "forge-state-diff"
        else ("partial" if backend == "anvil-prestate-diff" else "declared_only")
    )
    storage = event.get("storage")
    if support == "declared_only":
        storage = None
    return build_trace_event(
        seq=event.get("index", 0) if seq is None else seq,
        backend=backend,
        kind=event.get("kind"),
        accessor=event.get("accessor"),
        account=event.get("account"),
        depth=event.get("depth"),
        value=event.get("value"),
        selector=event.get("selector"),
        calldata=event.get("input", event.get("calldata")),
        reverted=event.get("reverted"),
        storage=storage,
        storage_support=support,
    )


def flatten_calltracer(root: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Flatten a nested debug_trace* callTracer tree into ordered pre-order rows."""
    if not isinstance(root, Mapping):
        raise ValueError("callTracer root must be an object.")
    flattened: list[dict[str, Any]] = []

    def visit(
        node: Mapping[str, Any],
        depth: int,
        inherited_msg_sender: str | None = None,
    ) -> None:
        if not isinstance(node, Mapping):
            raise ValueError("callTracer child must be an object.")
        kind = str(node.get("type") or node.get("callType") or "CALL").upper()
        opcode_from = node.get("from")
        # callTracer.from is the opcode caller. For DELEGATECALL/CALLCODE,
        # Solidity msg.sender is inherited from the parent frame instead.
        # Forge AccountAccess.accessor records that inherited message sender.
        accessor = (
            inherited_msg_sender
            if depth > 0 and kind in {"DELEGATECALL", "CALLCODE"}
            else opcode_from
        )
        row = {
            "type": kind,
            "from": opcode_from,
            "accessor": accessor,
            "to": node.get("to"),
            "created_address": node.get("created_address", node.get("createdAddress")),
            "depth": depth,
            "value": node.get("value"),
            "input": node.get("input", node.get("data")),
            "error": node.get("error"),
            "reverted": bool(node.get("error")) if node.get("error") is not None else bool(node.get("reverted", False)),
        }
        flattened.append(row)
        children = node.get("calls") or []
        if not isinstance(children, list):
            raise ValueError("callTracer nested calls must be an array.")
        # For the child opcode, the caller contract address is the current
        # execution context (node.to), but delegatecall preserves this frame's
        # msg.sender for its own context. A normal child CALL's opcode sender
        # is supplied by child.from and its msg.sender is that contract.
        current_msg_sender = accessor
        for child in children:
            visit(child, depth + 1, current_msg_sender)

    visit(root, 0)
    return flattened


def _storage_word(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,64}", value):
        raise ValueError(f"{label} must be a 1-32 byte 0x-prefixed storage value or null.")
    return "0x" + value[2:].lower().zfill(64)


def normalize_prestate_diff(diff: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Normalize prestateTracer diffMode changes as transaction-level partial storage.

    The result contains only slots whose before/after values are exposed by the
    RPC. It cannot identify which nested frame accessed the slot, nor can it
    report read-only slots.
    """
    if not isinstance(diff, Mapping):
        raise ValueError("prestateTracer diff must be an object.")
    pre = diff.get("pre")
    post = diff.get("post")
    if not isinstance(pre, Mapping) or not isinstance(post, Mapping):
        raise ValueError("prestateTracer diffMode must contain pre and post account maps.")

    rows: list[dict[str, Any]] = []
    for raw_address in sorted(set(pre) | set(post), key=str.lower):
        address = _address(raw_address, "prestateTracer address")
        if address is None:
            continue
        before_account = pre.get(raw_address) or {}
        after_account = post.get(raw_address) or {}
        if not isinstance(before_account, Mapping) or not isinstance(after_account, Mapping):
            raise ValueError("prestateTracer account entries must be objects.")
        before_storage = before_account.get("storage") or {}
        after_storage = after_account.get("storage") or {}
        if not isinstance(before_storage, Mapping) or not isinstance(after_storage, Mapping):
            raise ValueError("prestateTracer storage entries must be maps.")
        for raw_slot in sorted(set(before_storage) | set(after_storage), key=str.lower):
            slot = str(raw_slot).lower()
            if not _WORD_RE.fullmatch(slot):
                raise ValueError("prestateTracer slot must be a 32-byte hex word.")
            previous_value = _storage_word(before_storage.get(raw_slot), "prestateTracer previous value")
            new_value = _storage_word(after_storage.get(raw_slot), "prestateTracer new value")
            rows.append({
                "account": address,
                "slot": slot,
                "previous_value": previous_value,
                "new_value": new_value,
                "is_write": (
                    None if previous_value is None or new_value is None
                    else previous_value != new_value
                ),
                "reverted": None,
            })
    return rows


def normalize_calltracer(
    calls: Sequence[Mapping[str, Any]],
    *,
    storage_support: str = "declared_only",
    partial_storage: Mapping[int, list[dict[str, Any]]] | None = None,
    exact_storage: Mapping[int, list[dict[str, Any]]] | None = None,
    per_access_storage: Mapping[int, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Normalize callTracer rows with declared, transaction-partial or opcode-exact storage.

    prestateTracer rows remain transaction-level partial evidence. Exact mode
    requires an explicit per-frame array for every call frame, including empty
    arrays for frames in which no storage opcode was observed.
    """
    if isinstance(calls, Mapping):
        calls = flatten_calltracer(calls)
    if not isinstance(calls, Sequence) or isinstance(calls, (str, bytes)):
        raise ValueError("callTracer calls must be a sequence or a nested callTracer root object.")
    if storage_support not in {"declared_only", "partial", "exact"}:
        raise ValueError("callTracer storage_support must be declared_only, partial or exact.")
    rows = []
    partial_storage = partial_storage or {}
    exact_storage = exact_storage or {}
    structlog_storage = per_access_storage is not None
    per_access_storage = per_access_storage or {}
    if structlog_storage:
        expected_indices = set(range(len(calls)))
        if set(per_access_storage) != expected_indices:
            raise ValueError("Exact Anvil structLogs storage requires an explicit per-frame array for every call frame.")
        if any(not isinstance(per_access_storage[index], list) for index in expected_indices):
            raise ValueError("Anvil structLogs storage values must be per-frame arrays.")
    if storage_support == "exact":
        expected_indices = set(range(len(calls)))
        if set(exact_storage) != expected_indices:
            raise ValueError("Exact callTracer storage requires an explicit per-frame array for every call frame.")
        if any(not isinstance(exact_storage[index], list) for index in expected_indices):
            raise ValueError("Exact callTracer storage values must be per-frame arrays.")
    for index, call in enumerate(calls):
        if not isinstance(call, Mapping):
            raise ValueError(f"callTracer event #{index} must be an object.")
        error = call.get("error")
        if structlog_storage:
            event_support = "exact"
            event_storage = per_access_storage[index]
        elif storage_support == "exact":
            event_support = "exact"
            event_storage = exact_storage[index]
        elif storage_support == "partial" and index in partial_storage:
            event_support = "partial"
            event_storage = partial_storage[index]
        else:
            event_support = "declared_only"
            event_storage = None
        rows.append(build_trace_event(
            seq=index,
            backend="anvil-structlog" if structlog_storage else "anvil-calltracer",
            kind=call.get("type"),
            accessor=call.get("accessor", call.get("from")),
            account=call.get("to") or call.get("created_address") or call.get("createdAddress"),
            depth=call.get("depth"),
            value=call.get("value"),
            calldata=call.get("input", call.get("data")),
            reverted=bool(error) if error is not None else bool(call.get("reverted", False)),
            storage=event_storage,
            storage_support=event_support,
        ))
    return rows


def normalize_opcode_storage(
    opcode_trace: Mapping[str, Any],
    call_trace: Mapping[str, Any],
    *,
    max_steps: int = 200_000,
) -> dict[str, Any]:
    """Attribute Anvil/Geth struct-logger storage opcodes to callTracer frames.

    The opcode logger exposes execution depth and stack. callTracer supplies the
    ordered frame tree and CALL target/type. If any frame transition or target
    cannot be reconciled, the result is unsupported rather than guessed.
    """
    def unsupported(reason: str, *, steps: int = 0, accesses: int = 0) -> dict[str, Any]:
        return {
            "supported": False,
            "complete": False,
            "mode": "opcode-struct-logger",
            "reason": reason,
            "steps": steps,
            "access_count": accesses,
            "by_frame_index": {},
        }

    if not isinstance(opcode_trace, Mapping):
        return unsupported("Opcode trace must be an object.")
    if not isinstance(call_trace, Mapping):
        return unsupported("A nested callTracer tree is required for frame attribution.")
    if type(max_steps) is not int or max_steps < 1:
        return unsupported("max_steps must be a positive integer.")
    struct_logs = opcode_trace.get("structLogs")
    if not isinstance(struct_logs, list) or not struct_logs:
        return unsupported("Opcode trace has no structLogs array.")
    if len(struct_logs) >= max_steps:
        return unsupported("Opcode trace reached the configured step limit; completeness is unknown.", steps=len(struct_logs))

    frames: list[dict[str, Any]] = []

    def add_frame(node: Mapping[str, Any], parent: dict[str, Any] | None, path: str) -> dict[str, Any]:
        if not isinstance(node, Mapping):
            raise ValueError("callTracer child is not an object.")
        kind = str(node.get("type") or node.get("callType") or "CALL").upper()
        allowed = {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE", "CREATE", "CREATE2"}
        if kind not in allowed:
            raise ValueError(f"Unsupported callTracer frame type {kind!r}.")
        raw_code_address = node.get("to") or node.get("created_address", node.get("createdAddress"))
        code_address = _address(raw_code_address, "callTracer frame code address") if raw_code_address else None
        if parent is not None and kind in {"DELEGATECALL", "CALLCODE"}:
            storage_account = parent["storage_account"]
        else:
            storage_account = code_address
        parent_reverted = bool(parent and parent["reverted"])
        frame = {
            "index": len(frames),
            "frame_id": path,
            "type": kind,
            "code_address": code_address,
            "storage_account": storage_account,
            "reverted": parent_reverted or bool(node.get("error")) or bool(node.get("reverted", False)),
            "children": [],
            "child_cursor": 0,
        }
        frames.append(frame)
        children = node.get("calls") or []
        if not isinstance(children, list):
            raise ValueError("callTracer calls must be an array.")
        for child_index, child in enumerate(children):
            frame["children"].append(add_frame(child, frame, f"{path}.{child_index}"))
        return frame

    try:
        root = add_frame(call_trace, None, "0")
    except (TypeError, ValueError) as exc:
        return unsupported(str(exc))

    by_frame_index: dict[int, list[dict[str, Any]]] = {
        frame["index"]: [] for frame in frames
    }
    active = [root]
    previous_depth: int | None = None
    pending_child: dict[str, Any] | None = None
    access_seq = 0
    call_ops = {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE", "CREATE", "CREATE2"}
    storage_ops = {"SLOAD", "SSTORE", "TLOAD", "TSTORE"}

    def stack_word(raw: Any, label: str) -> str:
        if isinstance(raw, bool):
            raise ValueError(f"{label} cannot be boolean.")
        if isinstance(raw, int):
            if raw < 0 or raw >= 1 << 256:
                raise ValueError(f"{label} is outside uint256.")
            return "0x" + format(raw, "064x")
        if not isinstance(raw, str):
            raise ValueError(f"{label} must be a 32-byte stack word.")
        value = raw.lower().removeprefix("0x")
        if not re.fullmatch(r"[0-9a-f]{1,64}", value):
            raise ValueError(f"{label} must be a 1-32 byte hex stack word.")
        return "0x" + value.zfill(64)

    for step_index, step in enumerate(struct_logs):
        if not isinstance(step, Mapping):
            return unsupported(f"structLogs[{step_index}] is not an object.", steps=len(struct_logs), accesses=access_seq)
        try:
            depth = _quantity(step.get("depth"), f"structLogs[{step_index}].depth")
            if depth is None or depth < 1:
                raise ValueError("Opcode logger depth must be a positive integer.")
            if previous_depth is None:
                if depth != 1:
                    raise ValueError("Opcode logger root depth must be 1.")
            elif depth > previous_depth:
                if depth != previous_depth + 1 or pending_child is None:
                    raise ValueError("Opcode logger entered a frame without a matched CALL/CREATE child.")
                active.append(pending_child)
            elif depth < previous_depth:
                while len(active) > depth:
                    active.pop()
                if len(active) != depth:
                    raise ValueError("Opcode logger frame depth cannot be reconciled with callTracer.")
                pending_child = None
            else:
                pending_child = None
            if len(active) != depth:
                raise ValueError("Opcode logger depth and active call frame stack disagree.")

            current = active[-1]
            opcode = str(step.get("op") or "").upper()
            stack = step.get("stack")
            if opcode in call_ops:
                if not isinstance(stack, list):
                    raise ValueError(f"{opcode} opcode is missing its stack.")
                target = None
                if opcode in {"CALL", "STATICCALL", "DELEGATECALL", "CALLCODE"}:
                    if len(stack) < 2:
                        raise ValueError(f"{opcode} opcode stack is too short to identify its target.")
                    target_word = stack_word(stack[-2], f"{opcode} target")
                    target = "0x" + target_word[-40:]
                if current["child_cursor"] >= len(current["children"]):
                    raise ValueError(f"{opcode} has no corresponding callTracer child.")
                child = current["children"][current["child_cursor"]]
                current["child_cursor"] += 1
                if child["type"] != opcode:
                    raise ValueError(
                        f"{opcode} does not match next callTracer child type {child['type']}."
                    )
                if target is not None and child["code_address"] != target:
                    raise ValueError(
                        f"{opcode} target {target} does not match callTracer child {child['code_address']}."
                    )
                pending_child = child
            else:
                pending_child = None

            if opcode in storage_ops:
                if not isinstance(stack, list):
                    raise ValueError(f"{opcode} opcode is missing its stack.")
                minimum = 2 if opcode in {"SSTORE", "TSTORE"} else 1
                if len(stack) < minimum:
                    raise ValueError(f"{opcode} opcode stack is too short.")
                if not current["storage_account"]:
                    raise ValueError(f"{opcode} frame has no verified storage-context address.")
                slot = stack_word(stack[-1], f"{opcode} slot")
                is_write = opcode in {"SSTORE", "TSTORE"}
                storage_kind = "transient" if opcode in {"TLOAD", "TSTORE"} else "persistent"
                read_value = None
                previous_value = None
                new_value = stack_word(stack[-2], f"{opcode} value") if is_write else None
                if not is_write and step_index + 1 < len(struct_logs):
                    next_step = struct_logs[step_index + 1]
                    if isinstance(next_step, Mapping) and next_step.get("depth") == depth:
                        next_stack = next_step.get("stack")
                        if isinstance(next_stack, list) and next_stack:
                            read_value = stack_word(next_stack[-1], f"{opcode} result")
                if is_write:
                    state_storage = step.get("storage")
                    if isinstance(state_storage, Mapping):
                        for raw_slot, raw_value in state_storage.items():
                            if stack_word(raw_slot, f"{opcode} observed storage slot") == slot:
                                previous_value = stack_word(raw_value, f"{opcode} previous value")
                                break
                row = {
                    "account": current["storage_account"],
                    "slot": slot,
                    "previous_value": previous_value,
                    "new_value": new_value,
                    "is_write": is_write,
                    "reverted": current["reverted"],
                    "access_type": "write" if is_write else "read",
                    "storage_kind": storage_kind,
                    "frame_id": current["frame_id"],
                    "access_seq": access_seq,
                    "opcode_index": step_index,
                    "pc": _quantity(step.get("pc"), f"structLogs[{step_index}].pc"),
                    "opcode": opcode,
                    "code_address": current["code_address"],
                }
                if read_value is not None:
                    row["read_value"] = read_value
                by_frame_index[current["index"]].append(row)
                access_seq += 1
            previous_depth = depth
        except (TypeError, ValueError) as exc:
            return unsupported(str(exc), steps=len(struct_logs), accesses=access_seq)

    if len(active) != 1:
        return unsupported("Opcode trace ended with unclosed call frames.", steps=len(struct_logs), accesses=access_seq)
    for frame in frames:
        if frame["child_cursor"] != len(frame["children"]):
            return unsupported(
                f"Opcode trace did not account for every child call in frame {frame['frame_id']}.",
                steps=len(struct_logs), accesses=access_seq,
            )
    return {
        "supported": True,
        "complete": True,
        "mode": "opcode-struct-logger",
        "steps": len(struct_logs),
        "frame_count": len(frames),
        "access_count": access_seq,
        "by_frame_index": by_frame_index,
        "storage_scope": "ordered SLOAD/SSTORE/TLOAD/TSTORE accesses attributed to callTracer frames; DELEGATECALL/CALLCODE use the inherited storage context",
    }


def normalize_forge_events(events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalize Forge's ordered per-account call contexts with exact slot observations."""
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        raise ValueError("Forge trace events must be a sequence.")
    normalized = []
    raw_events = []
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise ValueError(f"Forge trace event #{index} must be an object.")
        legacy = dict(event)
        legacy.setdefault("source_backend", "forge-state-diff")
        legacy.setdefault("storage", [])
        raw_events.append(legacy)
    # Forge reports EVM call depth relative to the test runner; Anvil's
    # callTracer starts at root depth 0. Normalize the minimum observed depth
    # to zero so parity compares equivalent tree positions, not harness frame
    # bookkeeping.
    observed_depths = [
        _quantity(event.get("depth"), "depth")
        for event in raw_events
        if event.get("depth") is not None
    ]
    depth_base = min(observed_depths) if observed_depths else 0
    for index, legacy in enumerate(raw_events):
        raw_depth = _quantity(legacy.get("depth"), "depth")
        normalized.append(build_trace_event(
            seq=index,
            backend="forge-state-diff",
            kind=legacy.get("kind"),
            accessor=legacy.get("accessor"),
            account=legacy.get("account"),
            depth=None if raw_depth is None else raw_depth - depth_base,
            value=legacy.get("value"),
            selector=legacy.get("selector"),
            calldata=legacy.get("input", legacy.get("calldata")),
            reverted=legacy.get("reverted"),
            storage=legacy.get("storage", []),
            storage_support="exact",
        ))
    return normalized
