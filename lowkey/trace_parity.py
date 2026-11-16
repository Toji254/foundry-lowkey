"""Evidence-aware comparison for canonical Forge and Anvil TraceEvent streams."""
from __future__ import annotations

from typing import Any, Mapping, Sequence

try:
    from .trace_schema import TRACE_SCHEMA_VERSION, TRACE_FIELDS, STORAGE_SUPPORT, build_trace_event
except ImportError:
    try:
        from lowkey.trace_schema import TRACE_SCHEMA_VERSION, TRACE_FIELDS, STORAGE_SUPPORT, build_trace_event
    except ImportError:
        # The installer places sibling modules directly in ~/.lowkey rather
        # than creating an importable lowkey package.
        from trace_schema import TRACE_SCHEMA_VERSION, TRACE_FIELDS, STORAGE_SUPPORT, build_trace_event

_COMPARE_FIELDS = (
    "kind", "accessor", "account", "depth", "value", "selector",
    "calldata", "reverted",
)


def _validate_events(
    events: Sequence[Mapping[str, Any]], label: str, expected_backend: str
) -> list[dict[str, Any]]:
    if not isinstance(events, Sequence) or isinstance(events, (str, bytes)):
        raise ValueError(f"{label} trace must be an array.")
    normalized = []
    for index, event in enumerate(events):
        if not isinstance(event, Mapping):
            raise ValueError(f"{label} trace event #{index} must be an object.")
        missing = [field for field in TRACE_FIELDS if field not in event]
        if missing:
            raise ValueError(f"{label} trace event #{index} is missing canonical fields: {', '.join(missing)}")
        backend = event.get("backend")
        backend_ok = (
            backend in {"anvil-calltracer", "anvil-structlog"}
            if expected_backend == "anvil" else backend == expected_backend
        )
        if not backend_ok:
            raise ValueError(
                f"{label} trace event #{index} must come from {expected_backend}; "
                f"received {backend!r}."
            )
        normalized.append(build_trace_event(
            seq=event["seq"],
            backend=event["backend"],
            kind=event["kind"],
            accessor=event["accessor"],
            account=event["account"],
            depth=event["depth"],
            value=event["value"],
            selector=event["selector"],
            calldata=event["calldata"],
            reverted=event["reverted"],
            storage=event["storage"],
            storage_support=event["storage_support"],
        ))
    return normalized


def compare_trace_events(
    forge_events: Sequence[Mapping[str, Any]],
    anvil_events: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Compare common observable call semantics and report storage capability separately.

    Null is unknown, never equal evidence. Different storage capability is
    surfaced as a degradation, not silently treated as a full parity match.
    """
    forge = _validate_events(forge_events, "Forge", "forge-state-diff")
    anvil = _validate_events(anvil_events, "Anvil", "anvil")
    mismatches: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []
    if not forge or not anvil:
        unknowns.append({
            "dimension": "event_stream",
            "forge_count": len(forge),
            "anvil_count": len(anvil),
            "reason": "Parity cannot be accepted when either normalized trace is empty.",
        })
    if len(forge) != len(anvil):
        mismatches.append({
            "dimension": "event_count",
            "forge": len(forge),
            "anvil": len(anvil),
        })
    for index in range(min(len(forge), len(anvil))):
        left, right = forge[index], anvil[index]
        if left["seq"] != index or right["seq"] != index:
            mismatches.append({
                "seq": index,
                "dimension": "sequence",
                "forge": left["seq"],
                "anvil": right["seq"],
            })
        for field in _COMPARE_FIELDS:
            a, b = left[field], right[field]
            if a is None or b is None:
                unknowns.append({
                    "seq": index,
                    "dimension": field,
                    "forge": a,
                    "anvil": b,
                    "reason": "A backend did not expose this field; null is not a match.",
                })
            elif a != b:
                mismatches.append({
                    "seq": index,
                    "dimension": field,
                    "forge": a,
                    "anvil": b,
                })

    forge_support = sorted({event["storage_support"] for event in forge})
    anvil_support = sorted({event["storage_support"] for event in anvil})
    forge_exact = bool(forge) and all(x == "exact" for x in forge_support)
    anvil_exact = bool(anvil) and all(x == "exact" for x in anvil_support)
    storage_access_mismatches: list[dict[str, Any]] = []
    storage_value_mismatches: list[dict[str, Any]] = []
    storage_value_unknowns: list[dict[str, Any]] = []

    if forge_exact and anvil_exact:
        for frame_index, (left_event, right_event) in enumerate(zip(forge, anvil)):
            left_rows = left_event.get("storage")
            right_rows = right_event.get("storage")
            if not isinstance(left_rows, list) or not isinstance(right_rows, list):
                storage_access_mismatches.append({
                    "frame": frame_index,
                    "dimension": "storage_rows",
                    "reason": "Exact storage evidence must contain an array for every frame.",
                })
                continue
            if len(left_rows) != len(right_rows):
                storage_access_mismatches.append({
                    "frame": frame_index,
                    "dimension": "access_count",
                    "forge": len(left_rows),
                    "anvil": len(right_rows),
                })
            for access_index, (left_row, right_row) in enumerate(zip(left_rows, right_rows)):
                for field in ("account", "slot", "is_write"):
                    left_value = left_row.get(field)
                    right_value = right_row.get(field)
                    if left_value is None or right_value is None:
                        storage_access_mismatches.append({
                            "frame": frame_index, "access": access_index,
                            "dimension": field, "forge": left_value, "anvil": right_value,
                            "reason": "Exact access parity requires this field on both backends.",
                        })
                    elif left_value != right_value:
                        storage_access_mismatches.append({
                            "frame": frame_index, "access": access_index,
                            "dimension": field, "forge": left_value, "anvil": right_value,
                        })
                left_kind = left_row.get("storage_kind", "persistent")
                right_kind = right_row.get("storage_kind", "persistent")
                if left_kind != right_kind:
                    storage_access_mismatches.append({
                        "frame": frame_index, "access": access_index,
                        "dimension": "storage_kind", "forge": left_kind, "anvil": right_kind,
                    })

                if left_row.get("is_write") is False and right_row.get("is_write") is False:
                    left_read = (
                        left_row.get("read_value")
                        or left_row.get("previous_value")
                        or left_row.get("new_value")
                    )
                    right_read = (
                        right_row.get("read_value")
                        or right_row.get("previous_value")
                        or right_row.get("new_value")
                    )
                    if left_read is None or right_read is None:
                        storage_value_unknowns.append({
                            "frame": frame_index, "access": access_index,
                            "dimension": "read_value", "forge": left_read, "anvil": right_read,
                        })
                    elif left_read != right_read:
                        storage_value_mismatches.append({
                            "frame": frame_index, "access": access_index,
                            "dimension": "read_value", "forge": left_read, "anvil": right_read,
                        })
                elif left_row.get("is_write") is True and right_row.get("is_write") is True:
                    for field in ("previous_value", "new_value"):
                        left_value = left_row.get(field)
                        right_value = right_row.get(field)
                        if left_value is None or right_value is None:
                            storage_value_unknowns.append({
                                "frame": frame_index, "access": access_index,
                                "dimension": field, "forge": left_value, "anvil": right_value,
                            })
                        elif left_value != right_value:
                            storage_value_mismatches.append({
                                "frame": frame_index, "access": access_index,
                                "dimension": field, "forge": left_value, "anvil": right_value,
                            })

        storage_parity = "mismatch" if (storage_access_mismatches or storage_value_mismatches) else "exact_comparable"
        storage_value_parity = (
            "mismatch" if storage_value_mismatches
            else "incomplete" if storage_value_unknowns
            else "matched"
        )
    else:
        storage_parity = "degraded"
        storage_value_parity = "not_comparable"

    status = "MISMATCH" if (mismatches or storage_access_mismatches or storage_value_mismatches) else ("INCOMPLETE" if (unknowns or (forge_exact and anvil_exact and storage_value_unknowns)) else "MATCHED")
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "status": status,
        "call_tree_matched": not mismatches,
        "storage_accesses_matched": forge_exact and anvil_exact and not storage_access_mismatches,
        "events_compared": min(len(forge), len(anvil)),
        "forge_event_count": len(forge),
        "anvil_event_count": len(anvil),
        "compared_fields": list(_COMPARE_FIELDS),
        "mismatches": mismatches,
        "unknowns": unknowns,
        "storage_parity": storage_parity,
        "storage_value_parity": storage_value_parity,
        "storage_access_mismatches": storage_access_mismatches,
        "storage_value_mismatches": storage_value_mismatches,
        "storage_value_unknowns": storage_value_unknowns,
        "storage_support": {
            "forge": forge_support,
            "anvil": anvil_support,
        },
        "limitations": [
            "Forge state-diff exposes ordered per-account-access storage observations.",
            "Anvil opcode tracing attributes SLOAD/SSTORE/TLOAD/TSTORE steps to callTracer frames when every frame transition and call target reconciles.",
            "Storage value parity is reported separately where a backend does not expose before/after values.",
            "Transaction-level prestateTracer changes remain partial and are never promoted to per-frame exact evidence.",
        ],
    }