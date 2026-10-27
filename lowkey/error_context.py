"""Private last-error capture shared by Lowkey command routers.

Only bounded, redacted diagnostic text and command metadata are saved. Raw argv,
environment variables, prompts, credentials, source files and command outputs are
never stored as part of the error context.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


_SECRET_ASSIGNMENT = re.compile(
    r"""(?im)(\b[\w]*(?:api[_-]?key|secret|password|private[_-]?key|mnemonic|seed[_-]?phrase|access[_-]?token|bearer[_-]?token|authorization)\b\s*[:=]\s*)(?:"[^"\n]*"|'[^'\n]*'|[^;\n,]+)"""
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}")
_OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b")
_GEMINI_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b")
_URL_QUERY = re.compile(r"(?i)(https?://[^\s?#]+)\?[^\s#]+")


def state_dir() -> Path:
    value = os.environ.get("XDG_STATE_HOME")
    base = Path(value).expanduser() if value else Path.home() / ".local" / "state"
    return base / "lowkey"


def last_error_path() -> Path:
    return state_dir() / "last-error.json"


def redact(text: Any, *, limit: int = 6000) -> str:
    value = str(text or "")
    value = _SECRET_ASSIGNMENT.sub(r'\1"[REDACTED]"', value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _OPENAI_KEY.sub("[REDACTED API KEY]", value)
    value = _GEMINI_KEY.sub("[REDACTED API KEY]", value)
    value = _URL_QUERY.sub(r"\1?[REDACTED QUERY]", value)
    value = value.replace("\x00", "")
    return value[:limit]


def _safe_command(command: Any) -> str:
    if isinstance(command, (list, tuple)):
        parts = [str(item) for item in command[:2]]
    else:
        parts = str(command or "").strip().split()[:2]
    safe = [re.sub(r"[^A-Za-z0-9_.-]", "", item)[:80] for item in parts]
    return " ".join(item for item in safe if item)


def record_last_error(
    *,
    command: Any,
    error: Any,
    exit_code: int | None = None,
    project_root: str | None = None,
    source: str = "lowkey",
) -> dict[str, Any]:
    path = last_error_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    record = {
        "schema_version": 1,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": _safe_command(command),
        "exit_code": exit_code if isinstance(exit_code, int) else None,
        "source": str(source or "lowkey")[:40],
        "project_label": Path(project_root).name if project_root else None,
        "project_root": str(Path(project_root).expanduser().resolve()) if project_root else None,
        "error": redact(error),
        "redaction_note": "Diagnostic text is redacted and truncated; no raw argv or credentials are stored.",
    }
    fd, temp_name = tempfile.mkstemp(prefix=".last-error.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return record


def read_last_error() -> dict[str, Any]:
    path = last_error_path()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError("No saved Lowkey error exists yet. Run a failing lk command or use --text.") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read saved Lowkey error at {path}; preserve a copy before recovery.") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1 or not value.get("error"):
        raise RuntimeError("Saved Lowkey error record is malformed.")
    value["error"] = redact(value["error"])
    return value


def auto_error_explain_enabled() -> bool:
    config_path = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")).expanduser() / "lowkey" / "ai.json"
    try:
        value = json.loads(config_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return False
    return isinstance(value, dict) and value.get("auto_explain_errors") is True


def _project_context_path(project_root: str | os.PathLike[str]) -> tuple[Path, Path]:
    """Return private shared command-history path and canonical project root."""
    root = Path(project_root).expanduser().resolve()
    import hashlib

    digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:32]
    return state_dir() / "projects" / digest / "command-context.json", root


def _redact_diagnostic_output(value: Any, limit: int = 24000) -> str:
    """Redact secrets before selecting bounded, useful command observations."""
    text = redact(value, limit=limit)
    text = re.sub(
        r"(?i)(--(?:private-key|mnemonic|seed(?:-phrase)?|password|api-key|token|secret|authorization|bearer-token)(?:=|\\s+))\\S+",
        r"\\1[REDACTED]",
        text,
    )
    text = re.sub(r"\\b0x[0-9a-fA-F]{64}\\b", "[REDACTED PRIVATE KEY OR HASH]", text)
    return text


def _diagnostic_excerpt(output: Any, limit: int = 6000) -> str:
    """Keep warnings, errors, source locations, and deployment clues—not full output."""
    text = _redact_diagnostic_output(output)
    lines = text.splitlines()
    if not lines:
        return ""

    signal = re.compile(
        r"warning\\s*\\(\\d+\\)|\\bwarning:|\\berror\\s*\\(\\d+\\)|\\berror:|"
        r"compiler run|build diagnostics|build failure|reason\\s*:|"
        r"unnamed return|unused local|return variable|"
        r"could not identify|no .*target|target discovery|deployment|deployed to|"
        r"contract address|broadcast|script/[^\\s]+\\.sol|src/[^\\s]+\\.sol|"
        r"\\.sol:\\d+|lowkey local audit lab|lowkey build|"
        r"result: review needed|failed|reverted|connection refused|chain id",
        re.IGNORECASE,
    )
    selected = set()
    for index, line in enumerate(lines):
        if signal.search(line):
            selected.update(range(max(0, index - 2), min(len(lines), index + 5)))

    if not selected:
        selected.update(range(max(0, len(lines) - 8), len(lines)))

    parts = []
    size = 0
    for index in sorted(selected):
        line = lines[index].rstrip()
        if not line:
            continue
        line = line[:600]
        addition = line + "\\n"
        if size + len(addition) > limit:
            break
        parts.append(line)
        size += len(addition)
    return "\\n".join(parts)[-limit:]


def _event_signals(output: Any) -> list[str]:
    """Convert command output into compact, redacted evidence labels."""
    text = _redact_diagnostic_output(output)
    lines = text.splitlines()
    signals: list[str] = []

    for index, line in enumerate(lines):
        stripped = line.strip()
        if re.search(r"warning\\s*\\(\\d+\\)|\\bwarning:", stripped, re.IGNORECASE):
            location = ""
            for follow in lines[index + 1:index + 5]:
                match = re.search(r"([A-Za-z0-9_./-]+\\.sol:\\d+(?::\\d+)?)", follow)
                if match:
                    location = match.group(1)
                    break
            signals.append(("Compiler warning: " + stripped + (f" ({location})" if location else ""))[:500])
        elif re.search(r"error\\s*\\(\\d+\\)|\\berror:", stripped, re.IGNORECASE):
            signals.append(("Compiler/runtime error: " + stripped)[:500])
        if len(signals) >= 10:
            break

    lowered = text.lower()
    if "could not identify a deployed application target" in lowered or "no deployed application target" in lowered:
        signals.append("Deployment target discovery failed after a project-native deployment attempt.")
    if "unnamed return variable can remain unassigned" in lowered:
        signals.append("Solidity warning: a declared return value may remain unassigned.")
    if "unused local variable" in lowered:
        signals.append("Solidity warning: a local variable is unused.")
    if "failed to retrieve chain id" in lowered or "connection refused" in lowered:
        signals.append("RPC connectivity or chain-ID lookup failed.")
    return list(dict.fromkeys(item[:500] for item in signals))[:12]


def record_command_event(
    *,
    project_root: str | os.PathLike[str] | None,
    command: Any,
    exit_code: int | None,
    output: Any = "",
    source: str = "dispatcher",
) -> dict[str, Any] | None:
    """Persist a bounded event so later Lowkey commands can reuse prior findings.

    History is keyed to the canonical project path and stored under the user's
    private Lowkey state directory, never in the audited repository. Raw argv,
    environment variables, full output and source files are not persisted.
    """
    if not project_root:
        return None
    try:
        path, root = _project_context_path(project_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass

        excerpt = _diagnostic_excerpt(output)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "command": _safe_command(command)[:160],
            "exit_code": exit_code if isinstance(exit_code, int) else None,
            "status": "failed" if isinstance(exit_code, int) and exit_code != 0 else "completed",
            "source": re.sub(r"[^A-Za-z0-9_.-]", "", str(source or "dispatcher"))[:40],
            "signals": _event_signals(output),
            "diagnostic_excerpt": excerpt,
        }

        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or payload.get("schema_version") != 1:
                payload = {}
        except (OSError, json.JSONDecodeError):
            payload = {}

        # Do not let a hashed path collision mix two project histories.
        if payload.get("project_identity") not in (None, str(root)):
            payload = {}
        events = payload.get("events")
        if not isinstance(events, list):
            events = []
        events.append(event)
        payload = {
            "schema_version": 1,
            "project_identity": str(root),
            "project_label": root.name or "project",
            "updated_at": event["timestamp"],
            "events": events[-30:],
        }

        import tempfile
        fd, temp_name = tempfile.mkstemp(prefix=".command-context.", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
            os.chmod(path, 0o600)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise
        return event
    except (OSError, TypeError, ValueError):
        # Context capture is advisory and must never break the native command.
        return None


def read_project_context(
    project_root: str | os.PathLike[str] | None,
    *,
    max_events: int = 8,
) -> dict[str, Any]:
    """Read recent project knowledge without returning the private absolute path."""
    if not project_root:
        return {"project_label": None, "events": []}
    try:
        path, root = _project_context_path(project_root)
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {"project_label": Path(project_root).name if project_root else None, "events": []}

    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return {"project_label": root.name, "events": []}
    if payload.get("project_identity") != str(root):
        return {"project_label": root.name, "events": []}

    raw_events = payload.get("events")
    if not isinstance(raw_events, list):
        raw_events = []
    limit = max(1, min(int(max_events), 12))
    events = []
    for item in raw_events[-limit:]:
        if not isinstance(item, dict):
            continue
        signals = item.get("signals")
        events.append({
            "timestamp": str(item.get("timestamp") or "")[:40],
            "command": str(item.get("command") or "")[:160],
            "exit_code": item.get("exit_code") if isinstance(item.get("exit_code"), int) else None,
            "status": "failed" if item.get("status") == "failed" else "completed",
            "signals": [redact(value, limit=500) for value in signals[:12] if isinstance(value, str)] if isinstance(signals, list) else [],
            "diagnostic_excerpt": redact(item.get("diagnostic_excerpt"), limit=2200),
        })
    return {"project_label": str(payload.get("project_label") or root.name)[:160], "events": events}
