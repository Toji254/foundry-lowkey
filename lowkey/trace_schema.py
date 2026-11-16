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
    if backend not in {"anvil-calltracer", "anvil-prestate-diff", "forge-state-diff"}:
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


def normalize_calltracer(
    calls: Sequence[Mapping[str, Any]],
    *,
    storage_support: str = "declared_only",
    partial_storage: Mapping[int, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    """Normalize flattened callTracer rows, optionally attaching transaction-level partial storage.

    prestateTracer has no call-frame attribution. A slot may be attached only
    to the root transaction event and is explicitly marked partial.
    """
    if isinstance(calls, Mapping):
        calls = flatten_calltracer(calls)
    if not isinstance(calls, Sequence) or isinstance(calls, (str, bytes)):
        raise ValueError("callTracer calls must be a sequence or a nested callTracer root object.")
    if storage_support not in {"declared_only", "partial"}:
        raise ValueError("callTracer storage_support must be declared_only or partial.")
    rows = []
    partial_storage = partial_storage or {}
    for index, call in enumerate(calls):
        if not isinstance(call, Mapping):
            raise ValueError(f"callTracer event #{index} must be an object.")
        error = call.get("error")
        has_partial_observation = storage_support == "partial" and index in partial_storage
        event_support = "partial" if has_partial_observation else "declared_only"
        event_storage = partial_storage[index] if has_partial_observation else None
        rows.append(build_trace_event(
            seq=index,
            backend="anvil-calltracer",
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
