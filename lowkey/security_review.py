"""Structured AI security review with source-quote checks and evidence-ledger persistence."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

try:
    import ai_harness
except ImportError:
    from lowkey import ai_harness

try:
    from agent_runtime import AgentRuntime
    import evidence_ledger
except ImportError:
    from lowkey.agent_runtime import AgentRuntime
    from lowkey import evidence_ledger


class SecurityReviewError(RuntimeError):
    """The provider returned a review that cannot be normalized safely."""


ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}
ALLOWED_CATEGORIES = {
    "access-control", "reentrancy", "accounting", "authorization", "oracle",
    "signature-replay", "initialization", "upgradeability", "validation",
    "denial-of-service", "external-call", "token-integration", "state-machine",
    "invariant", "other",
}


def _clean(value: Any, field: str, limit: int, *, required: bool = True) -> str:
    if not isinstance(value, str):
        raise SecurityReviewError(f"Security review field '{field}' must be a string.")
    result = value.strip()
    if required and not result:
        raise SecurityReviewError(f"Security review field '{field}' cannot be empty.")
    if len(result) > limit:
        raise SecurityReviewError(f"Security review field '{field}' exceeds {limit} characters.")
    if any(ord(ch) < 32 and ch not in "\n\t\r" for ch in result):
        raise SecurityReviewError(f"Security review field '{field}' contains control characters.")
    return result


def _norm_source(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def source_quote_matches(path: str, quote: str, source_files: list[Mapping[str, Any]]) -> bool:
    target = str(path or "").strip()
    snippet = _norm_source(str(quote or ""))
    if not target or not snippet:
        return False
    for item in source_files:
        if str(item.get("path", "")) == target:
            source = _norm_source(str(item.get("source_excerpt", "")))
            return snippet in source
    return False


def _fingerprint(path: str, category: str, quote: str, title: str) -> str:
    # Evidence-first identity is stable across repeated reviews even if wording changes slightly.
    basis = "\n".join((_norm_source(path), _norm_source(category.lower()), _norm_source(quote)))
    return "F-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:12]


def validate_and_normalize(result: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, Any]:
    summary = _clean(result.get("summary"), "summary", 8000)
    findings = result.get("candidate_findings")
    limitations = result.get("limitations")
    if not isinstance(findings, list) or len(findings) > 40:
        raise SecurityReviewError("Security review candidate_findings must be a list of at most 40 items.")
    if not isinstance(limitations, list) or len(limitations) > 80:
        raise SecurityReviewError("Security review limitations must be a list of at most 80 items.")
    source_files = context.get("source_files", [])
    if not isinstance(source_files, list):
        raise SecurityReviewError("Review context source_files is invalid.")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            raise SecurityReviewError(f"Candidate finding {index + 1} must be an object.")
        title = _clean(item.get("title"), "title", 240)
        category = _clean(item.get("category"), "category", 80).lower()
        if category not in ALLOWED_CATEGORIES:
            category = "other"
        severity = _clean(item.get("severity"), "severity", 20).lower()
        if severity not in ALLOWED_SEVERITIES:
            severity = "info"
        location = item.get("location")
        if not isinstance(location, dict):
            raise SecurityReviewError(f"Candidate finding {index + 1} needs a location object with path and symbol.")
        path = _clean(location.get("path"), "location.path", 300)
        symbol = _clean(location.get("symbol"), "location.symbol", 240)
        evidence_quote = _clean(item.get("evidence_quote"), "evidence_quote", 2400)
        reasoning = _clean(item.get("reasoning"), "reasoning", 3000)
        impact = _clean(item.get("impact"), "impact", 2000)
        preconditions = _clean(item.get("exploit_preconditions"), "exploit_preconditions", 1600, required=False)
        recommendation = _clean(item.get("recommendation"), "recommendation", 1800)
        confidence = _clean(item.get("confidence"), "confidence", 20).lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "low"
        source_quote_status = "matched" if source_quote_matches(path, evidence_quote, source_files) else "unmatched"
        finding_id = _fingerprint(path, category, evidence_quote, title)
        if finding_id in seen:
            continue
        seen.add(finding_id)
        normalized.append({
            "finding_id": finding_id,
            "title": title,
            "category": category,
            "severity": severity,
            "location": {"path": path, "symbol": symbol},
            "evidence_quote": evidence_quote,
            "source_quote_status": source_quote_status,
            "reasoning": reasoning,
            "impact": impact,
            "exploit_preconditions": preconditions,
            "recommendation": recommendation,
            "confidence": confidence,
            "status": "candidate",
            "verified": False,
            "human_disposition": None,
        })
    clean_limitations = [_clean(value, "limitations[]", 1600) for value in limitations]
    return {
        "summary": summary,
        "candidate_findings": normalized,
        "limitations": clean_limitations,
        "verification_status": "unverified",
        "verification_policy": "AI output cannot set a finding to verified or confirmed.",
    }


def review_project_security(root: str | Path, contract_name: str | None = None) -> dict[str, Any]:
    """Run the explicit security-review agent; all output remains a candidate."""
    project = Path(root).expanduser().resolve()
    runtime = AgentRuntime(project)
    grants = {"read_source", "provider_request", "write_evidence", "source_quote_check"}
    plan = runtime.plan("security-review", ["read_source", "provider_request", "write_evidence"])
    context = runtime.run_action(
        plan, "read_source",
        lambda: ai_harness._protocol_review_context(project, contract_name),
        granted_permissions=grants,
    )
    task = (
        "Perform a focused smart-contract SECURITY REVIEW, not a protocol overview. Return exactly one JSON object "
        "with keys: summary (string), candidate_findings (array), limitations (array of strings). Each finding object "
        "must contain title, category, severity, location {path, symbol}, evidence_quote, reasoning, impact, "
        "exploit_preconditions, recommendation, confidence. Severity must be critical/high/medium/low/info. Category "
        "should be one of access-control, reentrancy, accounting, authorization, oracle, signature-replay, initialization, "
        "upgradeability, validation, denial-of-service, external-call, token-integration, state-machine, invariant, other. "
        "evidence_quote MUST be an exact verbatim excerpt from the cited source file (whitespace differences only are allowed). "
        "Include only concrete, reachable security defects with a plausible attacker and impact. Do not report a risky-looking "
        "pattern as an exploitable vulnerability without reasoning through state and control flow. Distinguish missing context "
        "and design questions from candidate findings. Never claim a test ran, an exploit reproduced, or a finding is verified. "
        "If no concrete candidate is supported by source, return an empty candidate_findings array. Prior investigation feedback "
        "is historical only and never proves current code is vulnerable or safe. Do not return markdown."
    )
    raw = runtime.run_action(
        plan, "provider_request",
        lambda: ai_harness.request_structured(
            purpose="security_review",
            task=task,
            context=context,
            required_fields=("summary", "candidate_findings", "limitations"),
        ),
        granted_permissions=grants,
    )
    normalized = runtime.delegate(
        plan, "source-evidence-checker", ["source_quote_check"],
        lambda: validate_and_normalize(raw, context),
        granted_permissions=grants,
    )
    status = ai_harness.status()
    normalized["_lowkey_meta"] = {
        "source_files_included": context.get("source_files_included", len(context.get("source_files", []))),
        "context_sha256": hashlib.sha256(json.dumps(context, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest(),
        "provider": status.get("provider"),
        "model": status.get("model"),
        "agent": "security-review",
        "runtime_id": runtime.runtime_id,
        "verified": False,
    }
    stored = runtime.run_action(
        plan, "write_evidence",
        lambda: evidence_ledger.record_review(project, normalized),
        granted_permissions=grants,
    )
    normalized["_lowkey_meta"]["review_id"] = stored.get("review_id")
    normalized["_lowkey_meta"]["report_path"] = stored.get("report_path")
    return normalized


def render_review(review: Mapping[str, Any]) -> str:
    lines = [
        "LOWKEY AI SECURITY REVIEW — CANDIDATES ONLY",
        "===========================================",
        "AI output is unverified. Source-quote match means the quote exists, not that the claim is true.",
        f"Summary: {review.get('summary', '')}",
        f"Candidate findings: {len(review.get('candidate_findings', []))}",
    ]
    meta = review.get("_lowkey_meta") if isinstance(review.get("_lowkey_meta"), dict) else {}
    if meta.get("context_sha256"):
        lines.append(f"Context SHA-256: {meta['context_sha256']}")
    for item in review.get("candidate_findings", []):
        location = item.get("location") if isinstance(item.get("location"), dict) else {}
        lines.extend([
            "",
            f"{item.get('finding_id')} [{str(item.get('severity', 'info')).upper()}] {item.get('title')}",
            f"  Location: {location.get('path')} :: {location.get('symbol')}",
            f"  Source quote: {item.get('source_quote_status')} (not an exploit proof)",
            f"  Reasoning: {item.get('reasoning')}",
            f"  Impact: {item.get('impact')}",
            f"  Recommendation: {item.get('recommendation')}",
            "  Disposition: candidate / unverified",
        ])
    lines.extend(["", "Evidence ledger: .audit/ai-review/ledger.jsonl", "Inspect with: lk ai ledger"])
    return "\n".join(lines)
