"""Source-grounded AI test planning; output is a proposal, never executable authority."""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

try:
    import ai_harness
    import evidence_ledger
    import security_review
    from agent_runtime import AgentRuntime
except ImportError:
    from lowkey import ai_harness, evidence_ledger, security_review
    from lowkey.agent_runtime import AgentRuntime


class TestPlanError(RuntimeError):
    """Invalid or unsupported AI test plan."""


KINDS = {"unit", "fuzz", "invariant", "regression", "integration", "fork"}
PRIORITIES = {"critical", "high", "medium", "low"}


def _text(value: Any, field: str, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise TestPlanError(f"Test plan field '{field}' must be a string.")
    value = value.strip()
    if required and not value:
        raise TestPlanError(f"Test plan field '{field}' cannot be empty.")
    if len(value) > limit:
        raise TestPlanError(f"Test plan field '{field}' exceeds {limit} characters.")
    return value


def _string_list(value: Any, field: str, *, count: int = 12, length: int = 1000) -> list[str]:
    if not isinstance(value, list) or len(value) > count:
        raise TestPlanError(f"Test plan field '{field}' must be a list of at most {count} items.")
    result = []
    for index, entry in enumerate(value):
        result.append(_text(entry, f"{field}[{index + 1}]", length))
    return result


def validate_test_plan(result: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    summary = _text(result.get("summary"), "summary", 6000)
    limitations = _string_list(result.get("limitations"), "limitations", count=20, length=1000)
    cases = result.get("test_cases")
    if not isinstance(cases, list) or len(cases) > 30:
        raise TestPlanError("Test plan field 'test_cases' must be a list of at most 30 cases.")
    source_files = context.get("source_files", [])
    if not isinstance(source_files, list):
        raise TestPlanError("Selected source context is malformed.")
    normalized = []
    seen = set()
    for index, item in enumerate(cases):
        if not isinstance(item, dict):
            raise TestPlanError(f"Test case {index + 1} must be an object.")
        title = _text(item.get("title"), "test_cases[].title", 220)
        key = title.casefold()
        if key in seen:
            continue
        seen.add(key)
        kind = _text(item.get("kind"), "test_cases[].kind", 30).lower()
        if kind not in KINDS:
            kind = "unit"
        priority = _text(item.get("priority"), "test_cases[].priority", 20).lower()
        if priority not in PRIORITIES:
            priority = "medium"
        suggested_name = _text(item.get("suggested_test_name"), "test_cases[].suggested_test_name", 140)
        if not re.fullmatch(r"test[A-Za-z0-9_]{1,128}", suggested_name):
            raise TestPlanError(f"Test case {index + 1} needs a valid suggested function name beginning with 'test'.")
        source = item.get("source")
        if not isinstance(source, dict):
            raise TestPlanError(f"Test case {index + 1} needs a source object.")
        source_path = _text(source.get("path"), "test_cases[].source.path", 300)
        symbol = _text(source.get("symbol"), "test_cases[].source.symbol", 240)
        quote = _text(source.get("quote"), "test_cases[].source.quote", 1800)
        quote_status = "matched" if security_review.source_quote_matches(
            source_path, quote, source_files
        ) else "unmatched"
        normalized.append({
            "title": title,
            "kind": kind,
            "priority": priority,
            "suggested_test_name": suggested_name,
            "source": {"path": source_path, "symbol": symbol, "quote": quote},
            "source_quote_status": quote_status,
            "hypothesis": _text(item.get("hypothesis"), "test_cases[].hypothesis", 1800),
            "setup": _text(item.get("setup"), "test_cases[].setup", 1600),
            "steps": _string_list(item.get("steps"), "test_cases[].steps", count=12, length=1000),
            "assertions": _string_list(item.get("assertions"), "test_cases[].assertions", count=12, length=1000),
            "vulnerability_signal": _text(
                item.get("vulnerability_signal"), "test_cases[].vulnerability_signal", 1200, required=False
            ),
            "existing_coverage_note": _text(
                item.get("existing_coverage_note"), "test_cases[].existing_coverage_note", 1200, required=False
            ),
            "status": "proposed",
            "executed": False,
            "verified": False,
        })
    return {
        "summary": summary,
        "test_cases": normalized,
        "limitations": limitations,
        "status": "proposed",
        "verified": False,
        "execution_policy": "No test code was written and no test was run.",
    }


def _store_report(root: Path, report: Mapping[str, Any]) -> dict[str, Any]:
    plan_id = "TP-" + uuid.uuid4().hex[:12]
    path = root / ".audit" / "ai-review" / "test-plans" / f"{plan_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    stored_report = dict(report)
    stored_meta = dict(stored_report.get("_lowkey_meta") or {})
    stored_meta.update({"plan_id": plan_id, "report_path": path.relative_to(root).as_posix()})
    stored_report["_lowkey_meta"] = stored_meta
    fd, temporary = tempfile.mkstemp(prefix=f".{plan_id}.", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(stored_report, handle, indent=2, sort_keys=True, ensure_ascii=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    return {"plan_id": plan_id, "report_path": path.relative_to(root).as_posix()}


def create_test_plan(root: str | Path, contract_name: str | None = None) -> dict[str, Any]:
    project = Path(root).expanduser().resolve()
    runtime = AgentRuntime(project)
    grants = {"read_source", "provider_request", "source_quote_check", "write_evidence"}
    plan = runtime.plan("test-planner", ["read_source", "provider_request", "write_evidence"])
    context = runtime.run_action(
        plan, "read_source",
        lambda: ai_harness._protocol_review_context(project, contract_name),
        granted_permissions=grants,
    )
    task = (
        "Suggest a focused smart-contract test plan, not a security verdict and not Solidity code. Return JSON keys summary, "
        "test_cases, and limitations. Each test case needs title, kind (unit/fuzz/invariant/regression/integration/fork), "
        "priority, suggested_test_name beginning with test, source {path,symbol,quote}, hypothesis, setup, steps, assertions, "
        "vulnerability_signal, and existing_coverage_note. The source quote must be copied from the cited current source. "
        "Include positive, negative, boundary, and state-change tests only when justified. Assertions must say exactly what "
        "should happen. Explain an invariant in plain language and say how a test would check it. Mark tests needing a live "
        "network as requiring a reachable RPC. Never claim that a test exists, was written, or passed. The review context does "
        "not include test folders, so do not pretend to know existing test coverage. If no useful test follows from the source, "
        "return no test cases and explain why. Never write files, invoke tools, deploy, or run tests. Use simple, concise "
        "English for a developer who is still learning: avoid unexplained jargon, keep each setup, step, and assertion short."
    )
    raw = runtime.run_action(
        plan, "provider_request",
        lambda: ai_harness.request_structured(
            purpose="test_plan", task=task, context=context,
            required_fields=("summary", "test_cases", "limitations"),
        ),
        granted_permissions=grants,
    )
    normalized = runtime.delegate(
        plan, "source-evidence-checker", ["source_quote_check"],
        lambda: validate_test_plan(raw, context),
        granted_permissions=grants,
    )
    status = ai_harness.status()
    normalized["ai_generated"] = True
    normalized["origin"] = "configured-model"
    normalized["_lowkey_meta"] = {
        "ai_generated": True,
        "origin": "configured-model",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source_files_included": context.get("source_files_included", len(context.get("source_files", []))),
        "context_sha256": hashlib.sha256(json.dumps(context, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
        "provider": status.get("provider"),
        "model": status.get("model"),
        "runtime_id": runtime.runtime_id,
        "verified": False,
    }
    stored = runtime.run_action(
        plan, "write_evidence",
        lambda: _store_report(project, normalized),
        granted_permissions=grants,
    )
    normalized["_lowkey_meta"].update(stored)
    evidence_ledger.append_event(project, "test_plan_created", {
        "plan_id": stored["plan_id"],
        "report_path": stored["report_path"],
        "source_context_sha256": normalized["_lowkey_meta"]["context_sha256"],
        "source_files_included": normalized["_lowkey_meta"]["source_files_included"],
        "test_case_count": len(normalized["test_cases"]),
        "all_source_quotes_matched": all(item["source_quote_status"] == "matched" for item in normalized["test_cases"]),
        "status": "proposed",
        "verified": False,
    })
    return normalized


def render_test_plan(report: Mapping[str, Any]) -> str:
    meta = report.get("_lowkey_meta") if isinstance(report.get("_lowkey_meta"), dict) else {}
    cases = report.get("test_cases", [])
    if not isinstance(cases, list):
        cases = []
    lines = [
        "@ AI OUTPUT — TEST IDEAS (UNVERIFIED)",
        "======================================",
        f"Summary: {str(report.get('summary', '')).strip()}",
        f"Test ideas suggested: {len(cases)}",
        "",
        "Important: this is a plan, not test code. Lowkey has not written or run these tests.",
        "The source check only confirms whether a quoted snippet exists; it does not prove the test idea is correct.",
    ]
    if not cases:
        lines.extend([
            "",
            "No usable test idea was returned for the selected source.",
            "Check the saved limits below and review the contract and test files yourself.",
        ])
    priority_labels = {"critical": "Write first", "high": "Write first", "medium": "Next", "low": "Later"}
    kind_labels = {
        "unit": "One function or rule",
        "fuzz": "Many inputs",
        "invariant": "A rule that should always hold",
        "regression": "Prevent a bug from coming back",
        "integration": "How contracts work together",
        "fork": "Test against a live network",
    }
    for index, item in enumerate(cases, 1):
        if not isinstance(item, dict):
            continue
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        priority = str(item.get("priority", "medium")).lower()
        kind = str(item.get("kind", "unit")).lower()
        quote_status = item.get("source_quote_status")
        quote_label = "Found in the cited file (citation check only)" if quote_status == "matched" else "NOT FOUND in the selected source — check this before using the idea"
        lines.extend([
            "",
            f"IDEA {index}: {str(item.get('title', '')).strip()}",
            f"Write order: {priority_labels.get(priority, 'Next')}  |  Test type: {kind_labels.get(kind, kind)}",
            f"Suggested test function name: {item.get('suggested_test_name')}",
            f"Where to look: {source.get('path')} — {source.get('symbol')}",
            f"Source check: {quote_label}",
            f"Goal: {item.get('hypothesis')}",
            f"Prepare: {item.get('setup')}",
            "Steps:",
        ])
        steps = item.get("steps", [])
        if isinstance(steps, list) and steps:
            lines.extend(f"  {step_index}. {value}" for step_index, value in enumerate(steps, 1))
        else:
            lines.append("  No steps were supplied.")
        lines.append("A correct test should show:")
        assertions = item.get("assertions", [])
        if isinstance(assertions, list) and assertions:
            lines.extend(f"  - {value}" for value in assertions)
        else:
            lines.append("  No expected result was supplied; review this idea before implementing it.")
        if item.get("vulnerability_signal"):
            lines.append(f"What would indicate a problem: {item['vulnerability_signal']}")
    limitations = report.get("limitations", [])
    if isinstance(limitations, list) and limitations:
        lines.extend(["", "Important limits:"])
        lines.extend(f"  - {str(value)}" for value in limitations[:8])
        if len(limitations) > 8:
            lines.append(f"  - {len(limitations) - 8} more note(s) are saved in the report.")
    lines.extend([
        "",
        "Existing tests were not checked in this AI step. Review the test/ folder so you do not add duplicates.",
    ])
    if meta.get("plan_id"):
        lines.append(f"Plan ID: {meta['plan_id']}")
    if meta.get("report_path"):
        lines.append(f"Saved plan: {meta['report_path']}")
    lines.append("Next step: review an idea against the current code before writing a Solidity test.")
    return "\n".join(lines)
