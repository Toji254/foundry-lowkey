"""Backend-neutral trace event schema shared by Anvil and Forge evidence."""
from __future__ import annotations
import re
from typing import Any

TRACE_SCHEMA_VERSION = 1
_KIND_NAMES = {
    "CALL": "Call", "DELEGATECALL": "DelegateCall", "STATICCALL": "StaticCall",
    "CALLCODE": "CallCode", "CREATE": "Create", "CREATE2": "Create2",
}

def _quantity(value: Any, label: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"Trace event {label} must be an integer quantity.")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"Trace event {label} cannot be negative.")
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError as exc:
            raise ValueError(f"Trace event {label} must be an integer or hex quantity.") from exc
    raise ValueError(f"Trace event {label} must be an integer quantity.")

def _address(value: Any, label: str) -> str | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise ValueError(f"Trace event {label} must be a 20-byte address or null.")
    return value.lower()

def _calldata(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("Trace event calldata must be hex bytes or null.")
    raw = value.lower()
    if not re.fullmatch(r"0x(?:[0-9a-f]{2})*", raw):
        raise ValueError("Trace event calldata must be 0x-prefixed, whole-byte hex.")
    return raw

def _kind(value: Any) -> str | None:
    if value is None or value == "":
        return None
    raw = str(value)
    return _KIND_NAMES.get(raw.upper(), raw)

def build_trace_event(*, index: int, kind: Any, accessor: Any, account: Any,
                      depth: Any, value: Any, reverted: bool | None,
                      input_data: Any, storage: list[dict[str, Any]] | None,
                      source_backend: str, error: str | None = None) -> dict[str, Any]:
    """Build a stable event; null means the backend did not expose a field."""
    if not isinstance(index, int) or index < 0:
        raise ValueError("Trace event index must be a nonnegative integer.")
    if not isinstance(source_backend, str) or not source_backend.strip():
        raise ValueError("Trace event source_backend is required.")
    if reverted is not None and not isinstance(reverted, bool):
        raise ValueError("Trace event reverted must be boolean or null.")
    if storage is not None and (not isinstance(storage, list) or
                                not all(isinstance(row, dict) for row in storage)):
        raise ValueError("Trace event storage must be an array of objects or null.")
    calldata = _calldata(input_data)
    selector = calldata[:10] if calldata is not None and len(calldata) >= 10 else None
    return {
        "index": index, "kind": _kind(kind),
        "accessor": _address(accessor, "accessor"),
        "account": _address(account, "account"),
        "depth": _quantity(depth, "depth"), "value": _quantity(value, "value"),
        "reverted": reverted, "selector": selector, "input": calldata,
        "storage": [dict(row) for row in storage] if storage is not None else None,
        "error": str(error) if error else None, "source_backend": source_backend,
    }

def normalize_rpc_trace_events(calls: list[dict[str, Any]], *,
                               backend: str = "anvil-calltracer") -> list[dict[str, Any]]:
    """Convert flattened callTracer rows. callTracer does not expose storage."""
    if not isinstance(calls, list):
        raise ValueError("RPC trace calls must be an array.")
    events = []
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            raise ValueError(f"RPC trace call #{index} must be an object.")
        error = call.get("error")
        events.append(build_trace_event(
            index=index, kind=call.get("type"), accessor=call.get("from"),
            account=call.get("to") or call.get("created_address"),
            depth=call.get("depth"), value=call.get("value"),
            reverted=bool(error), input_data=call.get("input"), storage=None,
            source_backend=backend, error=str(error) if error else None,
        ))
    return events
