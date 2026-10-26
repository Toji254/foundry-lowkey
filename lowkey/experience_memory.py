"""Native validated experience memory for Lowkey.

Lessons are structured data, never executable code. Proposed lessons are excluded
from AI context until a human explicitly approves them with recorded evidence.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = 1
LESSON_KINDS = {"protocol-pattern", "test-procedure", "tool-configuration", "project-fact", "false-positive-rule"}
FEEDBACK_KINDS = {"confirmed-finding", "false-positive", "missed-finding", "useful-test", "tool-failure", "corrected-assumption"}
VALIDATION_KINDS = {"test", "reproduction", "manual-review"}
MAX_LESSONS = 500
MAX_FEEDBACK = 5000
MAX_LESSON_CONTEXT_BYTES = 6000


class MemoryError(RuntimeError):
    """Actionable error from Lowkey experience memory."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _user_data_dir() -> Path:
    override = os.environ.get("XDG_DATA_HOME")
    base = Path(override).expanduser() if override else Path.home() / ".local" / "share"
    return base / "lowkey"


def _project_root(start: str | Path | None = None, *, required: bool = True) -> Path | None:
    path = Path(start).expanduser().resolve() if start else Path.cwd().resolve()
    try:
        try:
            import audit_context
        except ImportError:
            from lowkey import audit_context
        resolved = Path(audit_context.foundry_project_root(path)).expanduser().resolve()
        if not resolved.is_dir():
            raise MemoryError(f"Project root is not a directory: {resolved}")
        if not audit_context.is_audit_project(resolved):
            if required:
                raise MemoryError("No Lowkey-supported project was detected. Run this command inside the project you are auditing.")
            return None
        return resolved
    except MemoryError:
        raise
    except (ImportError, OSError, TypeError, ValueError) as exc:
        if required:
            raise MemoryError(f"Could not resolve the current Lowkey project: {exc}") from exc
        return None


def _secure_mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
        os.chmod(path.parent, 0o700)
    except OSError:
        pass


def _read_json(path: Path, missing: Any) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return missing
    except OSError as exc:
        raise MemoryError(f"Cannot read {path}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MemoryError(f"Invalid memory JSON in {path}; preserve a backup before editing it.") from exc


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    _secure_mkdir(path.parent)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(dict(value), handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def _load_store(path: Path, *, project_label: str | None = None) -> dict[str, Any]:
    default: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "lessons": []}
    if project_label is not None:
        default["project_label"] = project_label
    value = _read_json(path, default)
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise MemoryError(f"Unsupported memory format in {path}. Back it up before migrating.")
    lessons = value.get("lessons")
    if not isinstance(lessons, list) or len(lessons) > MAX_LESSONS:
        raise MemoryError(f"Memory file has an invalid or excessive lesson list: {path}")
    if any(not isinstance(item, dict) or not isinstance(item.get("id"), str) for item in lessons):
        raise MemoryError(f"Memory file contains a malformed lesson record: {path}")
    return value


def _save_lessons(path: Path, store: Mapping[str, Any]) -> None:
    lessons = store.get("lessons")
    if not isinstance(lessons, list) or len(lessons) > MAX_LESSONS:
        raise MemoryError("Lesson store reached its supported size limit.")
    _atomic_json(path, store)


def _project_store(root: str | Path | None = None, *, create: bool = False) -> tuple[Path, dict[str, Any]]:
    project = _project_root(root)
    assert project is not None
    directory = project / ".audit" / "experience"
    if create:
        _secure_mkdir(directory)
    path = directory / "lessons.json"
    store = _load_store(path, project_label=project.name)
    store.setdefault("project_label", project.name)
    return path, store


def _global_store(*, create: bool = False) -> tuple[Path, dict[str, Any]]:
    path = _user_data_dir() / "skills.json"
    if create:
        _secure_mkdir(path.parent)
    return path, _load_store(path)


def _bounded(value: str, label: str, limit: int, *, required: bool = True) -> str:
    clean = str(value or "").strip()
    if required and not clean:
        raise MemoryError(f"{label} is required.")
    if len(clean) > limit:
        raise MemoryError(f"{label} must be at most {limit} characters.")
    return clean


def _normalize_tags(raw: list[str] | None) -> list[str]:
    tags: list[str] = []
    for value in raw or []:
        clean = str(value).strip().lower().replace(" ", "-")
        if not clean:
            continue
        if len(clean) > 48 or not all(ch.isalnum() or ch in "-_" for ch in clean):
            raise MemoryError(f"Invalid lesson tag: {value!r}")
        if clean not in tags:
            tags.append(clean)
    if len(tags) > 12:
        raise MemoryError("Use at most 12 tags per lesson.")
    return tags


def project_memory_dir(root: str | Path | None = None, *, create: bool = False) -> Path:
    project = _project_root(root)
    assert project is not None
    path = project / ".audit" / "experience"
    if create:
        _secure_mkdir(path)
    return path


def record_feedback(
    *, kind: str, summary: str, evidence: str = "", finding_id: str = "",
    root: str | Path | None = None,
) -> dict[str, Any]:
    if kind not in FEEDBACK_KINDS:
        raise MemoryError(f"Feedback kind must be one of: {', '.join(sorted(FEEDBACK_KINDS))}.")
    project = _project_root(root)
    assert project is not None
    path = project_memory_dir(project, create=True) / "feedback.jsonl"
    try:
        count = sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    except FileNotFoundError:
        count = 0
    except OSError as exc:
        raise MemoryError(f"Cannot inspect feedback history: {exc}") from exc
    if count >= MAX_FEEDBACK:
        raise MemoryError("Feedback history reached its size limit; archive it before adding more.")
    record = {
        "id": uuid.uuid4().hex[:12], "schema_version": SCHEMA_VERSION,
        "created_at": _now(), "project_label": project.name, "kind": kind,
        "summary": _bounded(summary, "Feedback summary", 1200),
        "evidence": _bounded(evidence, "Evidence note", 1800, required=False),
        "finding_id": _bounded(finding_id, "Finding ID", 160, required=False),
        "status": "recorded",
    }
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    return record


def read_feedback(root: str | Path | None = None) -> list[dict[str, Any]]:
    project = _project_root(root)
    assert project is not None
    path = project_memory_dir(project) / "feedback.jsonl"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise MemoryError(f"Cannot read feedback history: {exc}") from exc
    records = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise MemoryError(f"Feedback history has invalid JSON at line {number}; preserve the file for recovery.") from exc
        if isinstance(value, dict):
            records.append(value)
    return records


def propose_lesson(
    *, kind: str, title: str, lesson: str, when_relevant: str = "",
    rationale: str = "", evidence: str = "", tags: list[str] | None = None,
    based_on_feedback: str = "", root: str | Path | None = None,
) -> dict[str, Any]:
    if kind not in LESSON_KINDS:
        raise MemoryError(f"Lesson type must be one of: {', '.join(sorted(LESSON_KINDS))}.")
    project = _project_root(root)
    assert project is not None
    path, store = _project_store(project, create=True)
    if len(store["lessons"]) >= MAX_LESSONS:
        raise MemoryError("Project lesson store reached its size limit.")
    now = _now()
    record = {
        "id": uuid.uuid4().hex[:12], "schema_version": SCHEMA_VERSION,
        "created_at": now, "updated_at": now, "project_label": project.name,
        "scope": "project", "kind": kind,
        "title": _bounded(title, "Lesson title", 160),
        "lesson": _bounded(lesson, "Lesson", 3000),
        "when_relevant": _bounded(when_relevant, "When relevant", 1000, required=False),
        "rationale": _bounded(rationale, "Rationale", 1600, required=False),
        "evidence": _bounded(evidence, "Evidence", 1800, required=False),
        "tags": _normalize_tags(tags),
        "based_on_feedback": _bounded(based_on_feedback, "Feedback ID", 80, required=False),
        "status": "proposed", "validation": None,
    }
    store["lessons"].append(record)
    _save_lessons(path, store)
    return record


def _find_lesson(lesson_id: str, root: str | Path | None = None) -> tuple[str, dict[str, Any], Path, dict[str, Any]]:
    clean_id = _bounded(lesson_id, "Lesson ID", 80)
    project = _project_root(root, required=False)
    candidates: list[tuple[str, Path, dict[str, Any]]] = []
    if project is not None:
        path = project / ".audit" / "experience" / "lessons.json"
        candidates.append(("project", path, _load_store(path, project_label=project.name)))
    global_path, global_store = _global_store()
    candidates.append(("global", global_path, global_store))
    for scope, path, store in candidates:
        for record in store["lessons"]:
            if record.get("id") == clean_id:
                return scope, record, path, store
    raise MemoryError(f"No lesson with ID {clean_id!r} exists in this project or global memory.")


def approve_lesson(
    lesson_id: str, *, validation_kind: str, validation: str,
    global_scope: bool = False, root: str | Path | None = None,
) -> dict[str, Any]:
    if validation_kind not in VALIDATION_KINDS:
        raise MemoryError(f"Validation kind must be one of: {', '.join(sorted(VALIDATION_KINDS))}.")
    note = _bounded(validation, "Validation evidence", 1800)
    if len(note) < 8:
        raise MemoryError("Validation evidence must be specific enough to audit (at least 8 characters).")
    scope, item, path, store = _find_lesson(lesson_id, root)
    if scope != "project" or item.get("status") != "proposed":
        raise MemoryError("Only proposed project lessons can be approved. Global memory is already an approved store.")
    record = dict(item)
    record["status"] = "approved"
    record["updated_at"] = _now()
    record["validation"] = {"kind": validation_kind, "note": note, "validated_at": _now()}
    if global_scope:
        global_path, global_store = _global_store(create=True)
        if any(existing.get("id") == record["id"] for existing in global_store["lessons"]):
            raise MemoryError("A global lesson with this ID already exists; no change was made.")
        global_record = dict(record)
        global_record["scope"] = "global"
        global_record["source_project"] = record.get("project_label")
        global_store["lessons"].append(global_record)
        _save_lessons(global_path, global_store)
    for index, existing in enumerate(store["lessons"]):
        if existing.get("id") == lesson_id:
            store["lessons"][index] = record
            break
    _save_lessons(path, store)
    return record


def reject_lesson(lesson_id: str, *, reason: str, root: str | Path | None = None) -> dict[str, Any]:
    scope, item, path, store = _find_lesson(lesson_id, root)
    if scope != "project" or item.get("status") != "proposed":
        raise MemoryError("Only proposed project lessons can be rejected.")
    record = dict(item)
    record["status"] = "rejected"
    record["updated_at"] = _now()
    record["rejection_reason"] = _bounded(reason, "Rejection reason", 1200)
    for index, existing in enumerate(store["lessons"]):
        if existing.get("id") == lesson_id:
            store["lessons"][index] = record
            break
    _save_lessons(path, store)
    return record


def list_lessons(*, status: str = "all", scope: str = "project", root: str | Path | None = None) -> list[dict[str, Any]]:
    if status not in {"all", "proposed", "approved", "rejected"}:
        raise MemoryError("Status must be all, proposed, approved, or rejected.")
    if scope not in {"project", "global", "both"}:
        raise MemoryError("Scope must be project, global, or both.")
    result: list[dict[str, Any]] = []
    if scope in {"project", "both"}:
        try:
            _, store = _project_store(root)
            result.extend(dict(item) for item in store["lessons"] if status == "all" or item.get("status") == status)
        except MemoryError:
            if scope == "project":
                raise
    if scope in {"global", "both"}:
        _, store = _global_store()
        result.extend(dict(item) for item in store["lessons"] if status == "all" or item.get("status") == status)
    return sorted(result, key=lambda item: (item.get("created_at", ""), item.get("id", "")), reverse=True)


def memory_status(root: str | Path | None = None) -> dict[str, Any]:
    project = _project_root(root, required=False)
    global_path, global_store = _global_store()
    result: dict[str, Any] = {
        "project": None, "global_memory": str(global_path),
        "global_approved": sum(1 for item in global_store["lessons"] if item.get("status") == "approved"),
        "project_approved": 0, "project_proposed": 0, "feedback_records": 0,
    }
    if project is not None:
        path, store = _project_store(project)
        result.update({
            "project": str(project), "project_memory": str(path),
            "project_approved": sum(1 for item in store["lessons"] if item.get("status") == "approved"),
            "project_proposed": sum(1 for item in store["lessons"] if item.get("status") == "proposed"),
            "feedback_records": len(read_feedback(project)),
        })
    return result


def lessons_for_context(root: str | Path | None = None, *, project_limit: int = 5, global_limit: int = 3) -> list[dict[str, Any]]:
    """Return a compact set of approved lessons for explicit AI tasks only."""
    try:
        project_lessons = list_lessons(status="approved", scope="project", root=root)
    except MemoryError:
        project_lessons = []
    global_lessons = list_lessons(status="approved", scope="global", root=root)
    picked: list[dict[str, Any]] = []
    for scope, records, limit in (
        ("project", project_lessons, project_limit),
        ("global", global_lessons, global_limit),
    ):
        for record in records[:max(0, limit)]:
            picked.append({
                "id": record.get("id"), "scope": scope, "kind": record.get("kind"),
                "title": record.get("title"), "lesson": record.get("lesson"),
                "when_relevant": record.get("when_relevant", ""),
                "rationale": record.get("rationale", ""), "tags": record.get("tags", []),
                "validation": record.get("validation"),
            })
            if len(json.dumps(picked, ensure_ascii=False).encode("utf-8")) > MAX_LESSON_CONTEXT_BYTES:
                picked.pop()
                return picked
    return picked


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lk memory", description="Native experience memory; lessons are inert data, never code.")
    sub = parser.add_subparsers(dest="action")
    sub.add_parser("status", help="show project/global memory counts")
    feedback = sub.add_parser("feedback", help="record a correction or audit outcome")
    feedback.add_argument("--kind", choices=sorted(FEEDBACK_KINDS), required=True)
    feedback.add_argument("--summary", required=True)
    feedback.add_argument("--evidence", default="")
    feedback.add_argument("--finding-id", default="")
    proposal = sub.add_parser("propose", help="propose a reusable lesson for review")
    proposal.add_argument("--kind", choices=sorted(LESSON_KINDS), required=True)
    proposal.add_argument("--title", required=True)
    proposal.add_argument("--lesson", required=True)
    proposal.add_argument("--when", dest="when_relevant", default="")
    proposal.add_argument("--rationale", default="")
    proposal.add_argument("--evidence", default="")
    proposal.add_argument("--tag", action="append", default=[])
    proposal.add_argument("--based-on-feedback", default="")
    listing = sub.add_parser("list", help="list lessons")
    listing.add_argument("--status", choices=("all", "proposed", "approved", "rejected"), default="all")
    listing.add_argument("--scope", choices=("project", "global", "both"), default="project")
    show = sub.add_parser("show", help="show a lesson")
    show.add_argument("lesson_id")
    show.add_argument("--scope", choices=("project", "global", "both"), default="both")
    approve = sub.add_parser("approve", help="promote a lesson only after validation")
    approve.add_argument("lesson_id")
    approve.add_argument("--validation-kind", choices=sorted(VALIDATION_KINDS), required=True)
    approve.add_argument("--validation", required=True, help="reproducible test, proof, or review evidence")
    approve.add_argument("--global", dest="global_scope", action="store_true", help="explicitly share a validated lesson across projects")
    reject = sub.add_parser("reject", help="reject a proposed lesson")
    reject.add_argument("lesson_id")
    reject.add_argument("--reason", required=True)
    feedback_list = sub.add_parser("feedback-list", help="show captured audit feedback")
    feedback_list.add_argument("--limit", type=int, default=20)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    args = ["--help" if value in {"--h", "help"} else value for value in args]
    parser = _parser()
    if not args or args[0] in {"-h", "--help"}:
        parser.print_help()
        return 0
    try:
        parsed = parser.parse_args(args)
        if parsed.action == "status":
            print(json.dumps(memory_status(), indent=2, sort_keys=True))
            return 0
        if parsed.action == "feedback":
            item = record_feedback(
                kind=parsed.kind, summary=parsed.summary, evidence=parsed.evidence,
                finding_id=parsed.finding_id,
            )
            print(f"Recorded feedback {item['id']} ({item['kind']}) in project memory.")
            return 0
        if parsed.action == "propose":
            item = propose_lesson(
                kind=parsed.kind, title=parsed.title, lesson=parsed.lesson,
                when_relevant=parsed.when_relevant, rationale=parsed.rationale,
                evidence=parsed.evidence, tags=parsed.tag, based_on_feedback=parsed.based_on_feedback,
            )
            print(f"Proposed lesson {item['id']}: {item['title']}")
            print("Status: proposed; inactive until explicitly approved with validation evidence.")
            return 0
        if parsed.action == "list":
            items = list_lessons(status=parsed.status, scope=parsed.scope)
            if not items:
                print("No lessons matched. Proposed lessons stay inactive until approved.")
                return 0
            for item in items:
                safe_title = json.dumps(str(item.get("title", "")), ensure_ascii=True)
                print(f"{item['id']}  [{item.get('scope', 'project')}/{item.get('status', 'unknown')}]  {item.get('kind')}: {safe_title}")
            return 0
        if parsed.action == "show":
            for item in list_lessons(status="all", scope=parsed.scope):
                if item.get("id") == parsed.lesson_id:
                    print(json.dumps(item, indent=2, sort_keys=True, ensure_ascii=False))
                    return 0
            raise MemoryError(f"No lesson with ID {parsed.lesson_id!r} found.")
        if parsed.action == "approve":
            item = approve_lesson(
                parsed.lesson_id, validation_kind=parsed.validation_kind,
                validation=parsed.validation, global_scope=parsed.global_scope,
            )
            print(f"Approved lesson {item['id']}: {item['title']}")
            print(f"Scope: {'project + global' if parsed.global_scope else 'project only'}")
            print("Available as reference context for explicit AI tasks; native security rules are unchanged.")
            return 0
        if parsed.action == "reject":
            item = reject_lesson(parsed.lesson_id, reason=parsed.reason)
            print(f"Rejected lesson {item['id']}: {item['title']}")
            return 0
        if parsed.action == "feedback-list":
            if not 1 <= parsed.limit <= 200:
                raise MemoryError("--limit must be between 1 and 200.")
            items = read_feedback()
            for item in items[-parsed.limit:]:
                safe_summary = json.dumps(str(item.get("summary", "")), ensure_ascii=True)
                print(f"{item.get('id')}  [{item.get('kind')}] {safe_summary}")
            if not items:
                print("No project feedback recorded.")
            return 0
        parser.print_help()
        return 2
    except (MemoryError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
