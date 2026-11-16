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
        if event.get("backend") != expected_backend:
            raise ValueError(
                f"{label} trace event #{index} must come from {expected_backend}; "
                f"received {event.get('backend')!r}."
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
    anvil = _validate_events(anvil_events, "Anvil", "anvil-calltracer")
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
    storage_parity = "exact_comparable" if forge_exact and anvil_exact else (
        "degraded" if forge_support != anvil_support or not anvil_exact else "comparable"
    )

    status = "MISMATCH" if mismatches else ("INCOMPLETE" if unknowns else "MATCHED")
    return {
        "schema_version": TRACE_SCHEMA_VERSION,
        "status": status,
        "call_tree_matched": not mismatches,
        "events_compared": min(len(forge), len(anvil)),
        "forge_event_count": len(forge),
        "anvil_event_count": len(anvil),
        "compared_fields": list(_COMPARE_FIELDS),
        "mismatches": mismatches,
        "unknowns": unknowns,
        "storage_parity": storage_parity,
        "storage_support": {
            "forge": forge_support,
            "anvil": anvil_support,
        },
        "limitations": [
            "Forge state-diff provides ordered per-access storage observations.",
            "Anvil prestateTracer provides transaction-level changed slots and cannot attribute them to individual call frames.",
            "A MATCHED call-tree result does not upgrade partial or declared-only storage evidence.",
        ],
    }
