"""Append-only evidence ledger for AI review hypotheses and native verification.

Model output creates candidates only. A test run is recorded separately and never
automatically changes a finding into a confirmed vulnerability. Final dispositions
are explicit human decisions tied to a recorded test-run event.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


class EvidenceLedgerError(RuntimeError):
    """Invalid or inconsistent audit evidence operation."""


SCHEMA_VERSION = 1
MAX_LEDGER_RECORD_BYTES = 48_000
DISPOSITIONS = {"confirmed", "rejected", "needs-review"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _root(value: str | Path) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise EvidenceLedgerError(f"Project root is not a directory: {path}")
    return path


def review_dir(root: str | Path) -> Path:
    return _root(root) / ".audit" / "ai-review"


def ledger_path(root: str | Path) -> Path:
    return review_dir(root) / "ledger.jsonl"


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(dict(value), handle, indent=2, sort_keys=True, ensure_ascii=False)
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


def append_event(root: str | Path, event_type: str, details: Mapping[str, Any]) -> dict[str, Any]:
    path = ledger_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    event = {
        "schema_version": SCHEMA_VERSION,
        "event_id": uuid.uuid4().hex[:16],
        "timestamp": _now(),
        "event_type": str(event_type),
        "details": dict(details),
    }
    encoded = (json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    if len(encoded) > MAX_LEDGER_RECORD_BYTES:
        raise EvidenceLedgerError("Evidence record exceeds the ledger size limit.")
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "ab") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    return event


def read_events(root: str | Path) -> list[dict[str, Any]]:
    path = ledger_path(root)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise EvidenceLedgerError(f"Cannot read the evidence ledger: {exc}") from exc
    events = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EvidenceLedgerError(f"Evidence ledger JSON is corrupt at line {number}; preserve a copy before recovery.") from exc
        if not isinstance(value, dict) or not isinstance(value.get("event_id"), str):
            raise EvidenceLedgerError(f"Evidence ledger record {number} is malformed.")
        events.append(value)
    return events


def _project_revision(root: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True,
            text=True, timeout=2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = (proc.stdout or "").strip()
    return value if proc.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40,64}", value) else None


def record_review(root: str | Path, report: Mapping[str, Any]) -> dict[str, Any]:
    project = _root(root)
    findings = report.get("candidate_findings")
    if not isinstance(findings, list):
        raise EvidenceLedgerError("Security review did not provide a candidate_findings list.")
    review_id = uuid.uuid4().hex[:12]
    metadata = report.get("_lowkey_meta") if isinstance(report.get("_lowkey_meta"), dict) else {}
    stored = dict(report)
    stored.update({
        "schema_version": SCHEMA_VERSION,
        "review_id": review_id,
        "created_at": _now(),
        "project_root": str(project),
        "project_revision": _project_revision(project),
        "conclusion_policy": "AI items remain unverified candidates until explicit native evidence and human disposition.",
    })
    report_path = review_dir(project) / "reviews" / f"{review_id}.json"
    _atomic_json(report_path, stored)
    append_event(project, "review_created", {
        "review_id": review_id,
        "report_path": report_path.relative_to(project).as_posix(),
        "source_context_sha256": metadata.get("context_sha256"),
        "source_files_included": metadata.get("source_files_included"),
        "provider": metadata.get("provider"),
        "model": metadata.get("model"),
        "project_revision": stored.get("project_revision"),
        "finding_count": len(findings),
    })
    for item in findings:
        if not isinstance(item, dict):
            continue
        append_event(project, "finding_candidate", {
            "finding_id": item.get("finding_id"),
            "review_id": review_id,
            "title": item.get("title"),
            "category": item.get("category"),
            "severity": item.get("severity"),
            "location": item.get("location"),
            "evidence_quote": item.get("evidence_quote"),
            "source_quote_status": item.get("source_quote_status", "unmatched"),
            "impact": item.get("impact"),
            "exploit_preconditions": item.get("exploit_preconditions"),
            "recommendation": item.get("recommendation"),
            "model_confidence": item.get("confidence"),
            "status": "candidate",
            "verified": False,
        })
    return {"review_id": review_id, "report_path": report_path.relative_to(project).as_posix(), "finding_count": len(findings)}


def record_native_test(root: str | Path, result: Mapping[str, Any]) -> dict[str, Any]:
    project = _root(root)
    finding_id = str(result.get("finding_id") or "")
    if not re.fullmatch(r"F-[0-9a-f]{12}", finding_id):
        raise EvidenceLedgerError("A valid candidate finding ID is required to attach native test evidence.")
    if not any(
        event.get("event_type") == "finding_candidate"
        and (event.get("details") or {}).get("finding_id") == finding_id
        for event in read_events(project)
    ):
        raise EvidenceLedgerError(f"Unknown finding ID: {finding_id}")
    outcome = str(result.get("status") or "")
    if outcome not in {"passed", "failed", "timeout", "tool_error"}:
        raise EvidenceLedgerError("Native test result has an invalid status.")
    summary_lines = result.get("summary_lines", [])
    if not isinstance(summary_lines, list):
        summary_lines = []
    details = {
        "finding_id": finding_id,
        "run_id": uuid.uuid4().hex[:12],
        "test_path": result.get("test_path"),
        "test_name": result.get("test_name"),
        "test_sha256": result.get("test_sha256"),
        "command": result.get("command"),
        "status": outcome,
        "exit_code": result.get("exit_code"),
        "elapsed_ms": result.get("elapsed_ms"),
        "output_sha256": result.get("output_sha256"),
        "summary_lines": [str(line)[:500] for line in summary_lines[:40]],
        "output_retained": False,
        "runtime_id": result.get("runtime_id"),
        "project_revision": _project_revision(project),
        "note": "A test result is execution evidence, not automatic proof that a model claim is correct.",
    }
    event = append_event(project, "native_test_run", details)
    details["event_id"] = event["event_id"]
    return details


def record_disposition(
    root: str | Path,
    finding_id: str,
    *,
    disposition: str,
    reviewer: str,
    reason: str,
    evidence_id: str | None = None,
) -> dict[str, Any]:
    project = _root(root)
    if disposition not in DISPOSITIONS:
        raise EvidenceLedgerError(f"Disposition must be one of: {', '.join(sorted(DISPOSITIONS))}.")
    reviewer = str(reviewer or "").strip()
    reason = str(reason or "").strip()
    if not reviewer or len(reviewer) > 160 or not reason or len(reason) > 2500:
        raise EvidenceLedgerError("A reviewer (up to 160 characters) and reason (up to 2500 characters) are required.")
    if not re.fullmatch(r"F-[0-9a-f]{12}", str(finding_id or "")):
        raise EvidenceLedgerError("Finding ID must look like F- followed by 12 lowercase hex characters.")
    events = read_events(project)
    if not any(
        event.get("event_type") == "finding_candidate"
        and (event.get("details") or {}).get("finding_id") == finding_id
        for event in events
    ):
        raise EvidenceLedgerError(f"Unknown finding ID: {finding_id}")
    test_event = None
    if disposition in {"confirmed", "rejected"}:
        if not evidence_id:
            raise EvidenceLedgerError("A confirmed/rejected disposition requires --evidence-id referencing a native test run.")
        test_event = next((
            event for event in events
            if event.get("event_type") == "native_test_run"
            and event.get("event_id") == evidence_id
            and (event.get("details") or {}).get("finding_id") == finding_id
        ), None)
        if not test_event:
            raise EvidenceLedgerError("Evidence ID must reference a native test run attached to this finding.")
        if disposition == "confirmed" and (test_event.get("details") or {}).get("status") != "passed":
            raise EvidenceLedgerError("Confirmation requires a passing native reproduction test plus human review.")
    elif evidence_id:
        test_event = next((
            event for event in events
            if event.get("event_type") == "native_test_run"
            and event.get("event_id") == evidence_id
            and (event.get("details") or {}).get("finding_id") == finding_id
        ), None)
        if not test_event:
            raise EvidenceLedgerError("Evidence ID must reference a native test run attached to this finding.")
    event = append_event(project, "human_disposition", {
        "finding_id": finding_id,
        "disposition": disposition,
        "reviewer": reviewer,
        "reason": reason,
        "evidence_id": test_event.get("event_id") if test_event else None,
        "explicit_human_decision": True,
        "verified_by_model": False,
    })
    feedback_id = None
    feedback_kind = {"confirmed": "confirmed-finding", "rejected": "false-positive"}.get(disposition)
    if feedback_kind:
        try:
            try:
                import experience_memory
            except ImportError:
                from lowkey import experience_memory
            memory_record = experience_memory.record_feedback(
                kind=feedback_kind,
                summary=f"{disposition.title()} review candidate {finding_id}: {reason[:500]}",
                evidence=f"Evidence ledger event {event['event_id']}; native test run {test_event.get('event_id') if test_event else 'none'}; reviewer {reviewer}. Re-check source and test evidence for future revisions.",
                finding_id=finding_id,
                root=project,
            )
            feedback_id = memory_record.get("id")
        except Exception:
            # Evidence disposition is authoritative; optional memory must not block it.
            feedback_id = None
    return {**event, "memory_feedback_id": feedback_id}


def summary(root: str | Path) -> dict[str, Any]:
    project = _root(root)
    events = read_events(project)
    findings: dict[str, dict[str, Any]] = {}
    for event in events:
        event_type = event.get("event_type")
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        finding_id = details.get("finding_id")
        if event_type == "finding_candidate" and isinstance(finding_id, str):
            findings.setdefault(finding_id, {
                "finding_id": finding_id,
                "title": details.get("title"),
                "category": details.get("category"),
                "severity": details.get("severity"),
                "location": details.get("location"),
                "source_quote_status": details.get("source_quote_status", "unmatched"),
                "status": "candidate",
                "verified": False,
                "test_runs": [],
                "disposition": None,
            })
            # Later reviews may update the descriptive candidate data, but never its status.
            findings[finding_id].update({
                key: details.get(key) for key in (
                    "title", "category", "severity", "location", "source_quote_status"
                )
            })
        elif finding_id in findings and event_type == "native_test_run":
            findings[finding_id]["test_runs"].append({
                "run_id": details.get("run_id"),
                "event_id": event.get("event_id"),
                "test_path": details.get("test_path"),
                "test_name": details.get("test_name"),
                "status": details.get("status"),
                "exit_code": details.get("exit_code"),
                "elapsed_ms": details.get("elapsed_ms"),
            })
            findings[finding_id]["status"] = "native-test-recorded"
        elif finding_id in findings and event_type == "human_disposition":
            findings[finding_id]["disposition"] = {
                "event_id": event.get("event_id"),
                "disposition": details.get("disposition"),
                "reviewer": details.get("reviewer"),
                "reason": details.get("reason"),
                "evidence_id": details.get("evidence_id"),
            }
            findings[finding_id]["status"] = {
                "confirmed": "human-confirmed",
                "rejected": "human-rejected",
                "needs-review": "needs-review",
            }.get(str(details.get("disposition")), "candidate")
    return {
        "schema_version": SCHEMA_VERSION,
        "project_root": str(project),
        "ledger_path": ledger_path(project).relative_to(project).as_posix(),
        "event_count": len(events),
        "findings": sorted(findings.values(), key=lambda item: item["finding_id"]),
        "principle": "Model confidence never sets verification status; native runs are evidence, final dispositions are human decisions.",
    }


def historical_feedback_context(root: str | Path, *, limit: int = 5) -> list[dict[str, Any]]:
    """Return short historic investigation notes clearly marked as non-proof."""
    project = _root(root)
    try:
        try:
            import experience_memory
        except ImportError:
            from lowkey import experience_memory
        values = experience_memory.read_feedback(project)
    except Exception:
        return []
    selected = []
    for item in values[-max(0, min(limit, 10)):]:
        if not isinstance(item, dict):
            continue
        selected.append({
            "feedback_id": str(item.get("id", ""))[:40],
            "kind": str(item.get("kind", ""))[:80],
            "summary": str(item.get("summary", ""))[:350],
            "evidence_note": str(item.get("evidence", ""))[:500],
            "finding_id": str(item.get("finding_id", ""))[:80],
            "created_at": str(item.get("created_at", ""))[:60],
            "trust_boundary": "historical feedback only; not proof about current source or current runtime state",
        })
    return selected
