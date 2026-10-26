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
