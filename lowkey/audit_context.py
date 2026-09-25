#!/usr/bin/env python3
"""Shared project-scoped audit context and append-only evidence bus for Lowkey."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote
import os


SCHEMA_VERSION = 1
AUDIT_DIR_NAME = ".audit"
CONTEXT_FILE_NAME = "context.json"
EVENTS_FILE_NAME = "events.jsonl"


def source_link(
    file: str | None,
    line: int | None = None,
    column: int | None = None,
    root: Path | None = None,
    display: str | None = None,
) -> str:
    """Return a clean source label with an optional clickable VS Code target."""
    project_root = foundry_project_root(root)
    if not file:
        return "unknown location"

    path = Path(str(file))
    absolute = (project_root / path).resolve() if not path.is_absolute() else path.resolve()

    if display:
        label = display
    else:
        try:
            label = absolute.relative_to(project_root).as_posix()
        except ValueError:
            label = path.as_posix()

        if line:
            label += f":{int(line)}"
        if column:
            label += f":{int(column)}"

    if os.environ.get("TERM_PROGRAM", "").lower() != "vscode":
        return label

    target = f"vscode://file/{quote(str(absolute), safe='/')}"
    if line:
        target += f":{int(line)}"
        if column:
            target += f":{int(column)}"

    return f"\x1b]8;;{target}\x1b\\{label}\x1b]8;;\x1b\\"




def foundry_project_root(start: Path | None = None) -> Path:
    path = (start or Path.cwd()).expanduser().resolve()
    if path.is_file():
        path = path.parent
    for parent in (path, *path.parents):
        if (parent / "foundry.toml").is_file():
            return parent
    return path


def audit_dir(root: Path | None = None) -> Path:
    path = foundry_project_root(root) / AUDIT_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def context_path(root: Path | None = None) -> Path:
    return audit_dir(root) / CONTEXT_FILE_NAME


def events_path(root: Path | None = None) -> Path:
    return audit_dir(root) / EVENTS_FILE_NAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _default_context(root: Path) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "project": {
            "root": str(root),
            "name": root.name,
        },
        "target": {
            "address": None,
            "contract": None,
            "artifact": None,
        },
        "actor": None,
        "rpc": None,
        "focus": None,
        "latest": {
            "tx_hash": None,
            "function": None,
            "value": None,
            "calldata": None,
            "trace": None,
            "state_diff": None,
        },
        "tools": {},
        "signals": [],
        "updated_at": _now(),
    }


def load(root: Path | None = None) -> dict[str, Any]:
    project_root = foundry_project_root(root)
    path = context_path(project_root)
    if not path.exists():
        return _default_context(project_root)

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}

    context = _default_context(project_root)
    if isinstance(data, dict):
        for key, value in data.items():
            if key in context and isinstance(value, dict) and isinstance(context[key], dict):
                context[key].update(value)
            else:
                context[key] = value
    context["project"]["root"] = str(project_root)
    context["project"]["name"] = project_root.name
    context["schema_version"] = SCHEMA_VERSION
    return context


def save(data: dict[str, Any], root: Path | None = None) -> Path:
    project_root = foundry_project_root(root)
    data = dict(data)
    data["schema_version"] = SCHEMA_VERSION
    data.setdefault("project", {})
    data["project"]["root"] = str(project_root)
    data["project"]["name"] = project_root.name
    data["updated_at"] = _now()

    path = context_path(project_root)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    return path


def update(root: Path | None = None, **changes: Any) -> dict[str, Any]:
    data = load(root)

    for key, value in changes.items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key].update(value)
        else:
            data[key] = value

    save(data, root)
    return data


def emit(
    event_type: str,
    root: Path | None = None,
    *,
    tool: str = "lowkey",
    status: str = "completed",
    summary: str | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    record = {
        "timestamp": _now(),
        "tool": tool,
        "type": event_type,
        "status": status,
    }
    if summary:
        record["summary"] = summary
    if data:
        record["data"] = data

    path = events_path(root)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def record_tool(
    tool: str,
    root: Path | None = None,
    *,
    status: str = "completed",
    summary: str | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = load(root)
    tool_state = context.setdefault("tools", {}).setdefault(tool, {})
    tool_state.update({
        "status": status,
        "updated_at": _now(),
    })
    if summary is not None:
        tool_state["summary"] = summary
    if data:
        tool_state.update(data)
    save(context, root)
    emit("tool-run", root, tool=tool, status=status, summary=summary, data=data)
    return context


def _signal_id(signal: dict[str, Any]) -> str:
    identity = "|".join(
        str(signal.get(key) or "")
        for key in ("tool", "check", "file", "line", "column", "title")
    )
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10].upper()
    return f"{str(signal.get('tool') or 'LOWKEY').upper()}-{digest}"


def add_signal(signal: dict[str, Any], root: Path | None = None) -> dict[str, Any]:
    context = load(root)
    signal = dict(signal)
    signal.setdefault("status", "open")
    signal.setdefault("first_seen", _now())
    signal.setdefault("last_seen", _now())
    signal.setdefault("id", _signal_id(signal))

    signals = context.setdefault("signals", [])
    existing = next((item for item in signals if item.get("id") == signal["id"]), None)

    if existing is None:
        signals.append(signal)
        action = "signal-added"
    else:
        preserved = existing.get("status", signal["status"])
        existing.update(signal)
        existing["status"] = preserved
        existing["last_seen"] = _now()
        signal = existing
        action = "signal-updated"

    save(context, root)
    emit(
        action,
        root,
        tool=str(signal.get("tool") or "lowkey"),
        summary=str(signal.get("title") or signal.get("check") or "Audit signal"),
        data=signal,
    )
    return signal


def update_signal_status(
    signal_id: str,
    status: str,
    root: Path | None = None,
    *,
    note: str | None = None,
) -> dict[str, Any] | None:
    allowed = {"open", "investigating", "proven", "dismissed"}
    if status not in allowed:
        raise ValueError(f"invalid signal status: {status}")

    context = load(root)
    for signal in context.setdefault("signals", []):
        if signal.get("id") != signal_id:
            continue
        previous = signal.get("status", "open")
        signal["status"] = status
        signal["updated_at"] = _now()
        if note:
            signal["triage_note"] = note
        save(context, root)
        emit(
            "signal-status",
            root,
            tool=str(signal.get("tool") or "lowkey"),
            summary=f"{signal_id}: {previous} -> {status}",
            data={
                "signal_id": signal_id,
                "previous": previous,
                "status": status,
                "note": note,
            },
        )
        return signal
    return None


def signals(root: Path | None = None, status: str | None = None) -> list[dict[str, Any]]:
    found = list(load(root).get("signals", []))
    if status is None:
        return found
    return [item for item in found if item.get("status") == status]


def set_focus(signal_id: str, root: Path | None = None) -> dict[str, Any] | None:
    context = load(root)
    for signal in context.setdefault("signals", []):
        if signal.get("id") != signal_id:
            continue
        focus = {
            "signal_id": signal_id,
            "title": signal.get("title"),
            "tool": signal.get("tool"),
            "file": signal.get("file"),
            "line": signal.get("line"),
            "column": signal.get("column"),
            "function": signal.get("function"),
            "updated_at": _now(),
        }
        signal["status"] = "investigating"
        signal["updated_at"] = _now()
        context["focus"] = focus
        save(context, root)
        emit(
            "focus-changed",
            root,
            tool="lowkey",
            summary=f"investigation focus: {signal_id}",
            data=focus,
        )
        return signal
    return None


def attach_signal_evidence(
    signal_id: str,
    evidence: dict[str, Any],
    root: Path | None = None,
) -> dict[str, Any] | None:
    """Attach structured investigation evidence to an existing audit signal.

    Evidence is kept on the signal so ``lk findings`` and ``lk focus`` can show
    the concrete observations produced while investigating that signal.
    Re-running the same evidence payload updates it instead of duplicating it.
    """
    context = load(root)
    for signal in context.setdefault("signals", []):
        if signal.get("id") != signal_id:
            continue

        evidence = dict(evidence)
        evidence.setdefault("captured_at", _now())
        kind = str(evidence.get("kind") or "evidence")
        identity = {
            key: value
            for key, value in evidence.items()
            if key not in {"id", "captured_at"}
        }
        digest = hashlib.sha1(
            json.dumps(identity, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:12].upper()
        evidence.setdefault("id", f"{kind.upper()}-{digest}")

        records = signal.setdefault("evidence", [])
        if not isinstance(records, list):
            records = []
            signal["evidence"] = records

        existing = next(
            (item for item in records if isinstance(item, dict) and item.get("id") == evidence["id"]),
            None,
        )
        if existing is None:
            records.append(evidence)
            action = "signal-evidence-added"
        else:
            existing.update(evidence)
            evidence = existing
            action = "signal-evidence-updated"

        signal["updated_at"] = _now()
        save(context, root)
        emit(
            action,
            root,
            tool=str(signal.get("tool") or "lowkey"),
            summary=f"{signal_id}: {kind}",
            data={"signal_id": signal_id, "evidence": evidence},
        )
        return signal
    return None

def set_target(
    root: Path | None = None,
    *,
    address: str | None = None,
    contract: str | None = None,
    artifact: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    target = {
        "address": address,
        "contract": contract,
        "artifact": artifact,
    }
    if source:
        target["source"] = source
    return update(root, target=target)


def set_latest(
    root: Path | None = None,
    *,
    tx_hash: str | None = None,
    function: str | None = None,
    value: str | None = None,
    calldata: str | None = None,
    trace: str | None = None,
    state_diff: str | None = None,
) -> dict[str, Any]:
    latest = {}
    for key, value_ in {
        "tx_hash": tx_hash,
        "function": function,
        "value": value,
        "calldata": calldata,
        "trace": trace,
        "state_diff": state_diff,
    }.items():
        if value_ is not None:
            latest[key] = value_
    return update(root, latest=latest)


def human_snapshot(root: Path | None = None) -> str:
    data = load(root)
    target = data.get("target", {})
    latest = data.get("latest", {})
    tools = data.get("tools", {})
    open_signals = len(signals(root, "open"))

    lines = [
        f"Project : {data['project']['root']}",
        f"Target  : {target.get('contract') or 'none'}"
        + (f" ({target.get('address')})" if target.get("address") else ""),
        f"Actor   : {data.get('actor') or 'none'}",
        f"RPC     : {data.get('rpc') or 'none'}",
        f"Focus   : {(data.get('focus') or {}).get('signal_id') if isinstance(data.get('focus'), dict) and (data.get('focus') or {}).get('signal_id') else 'none'}",
        f"Latest  : {latest.get('function') or 'none'}"
        + (f" [{latest.get('tx_hash')}]" if latest.get("tx_hash") else ""),
        f"Signals : {open_signals} open",
    ]

    for name, state in sorted(tools.items()):
        if isinstance(state, dict):
            lines.append(
                f"{name:<8}: {state.get('status', 'unknown')}"
                + (f" — {state.get('summary')}" if state.get("summary") else "")
            )
    return "\n".join(lines)
