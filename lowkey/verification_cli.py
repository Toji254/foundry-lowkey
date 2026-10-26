"""CLI integration for engine inventory and bounded verification campaigns."""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from verification_adapters import default_registry, inspect_project, TEST_KINDS
except ImportError:
    from lowkey.verification_adapters import default_registry, inspect_project, TEST_KINDS

try:
    import audit_context
except ImportError:
    try:
        from lowkey import audit_context
    except ImportError:
        audit_context = None


def _project_root() -> Path:
    try:
        import audit_context
        root = audit_context.foundry_project_root()
        if root:
            return Path(root).expanduser().resolve()
    except (ImportError, OSError):
        pass
    return Path.cwd().resolve()


def _help() -> None:
    print("""Lowkey verification engine orchestration

Usage:
  lk verification engines [--json]
  lk verification run <manifest.json> [--profile light|balanced|deep]
      [--output .audit/verification/campaign.json]
  lk verification correlate <campaign-report.json> [--signal SIGNAL_ID ...]
      [--output .audit/verification/correlation-report.json]

Campaign manifest:
  {
    "test_kind": "fuzz",
    "budget": {"timeout_seconds": 120, "max_memory_mb": 2048},
    "request": {
      "engine_config_by_engine": {
        "echidna": {"target": "test/EchidnaTarget.sol", "contract": "EchidnaTarget", "config": "echidna.yaml"},
        "medusa": {"config": "medusa.json", "target_contracts": ["EchidnaTarget"], "workers": 1},
        "halmos": {"function": "test"}
      },
      "argv_by_engine": {
        "forge": ["test", "--fuzz-runs", "64"]
      }
    }
  }

Native arguments are passed without a shell. Use engine_config_by_engine for different harness/config paths in one campaign, or argv_by_engine to override a tool with exact native arguments. Engine-specific configuration is explicit;
unsupported/missing arguments are reported, never silently replaced with guessed commands.
""")

def engine_inventory(root: Path | None = None) -> dict[str, Any]:
    project_root = (root or _project_root()).resolve()
    project = inspect_project(project_root)
    registry = default_registry()
    inventory = registry.inventory()
    matrix = registry.support_matrix(project)
    for engine in inventory:
        support = matrix[engine["name"]]
        engine["support_matrix"] = support["test_kinds"]
        engine["supported_test_kinds"] = [
            kind for kind, item in support["test_kinds"].items() if item["supported"]
        ]
    return {"project": project, "engines": inventory, "plugin_errors": registry.plugin_errors}


def run_campaign_manifest(
    manifest_path: str | Path,
    *,
    project_root: str | Path | None = None,
    profile_override: str | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(project_root).expanduser().resolve() if project_root else _project_root()
    path = Path(manifest_path).expanduser()
    if not path.is_absolute():
        path = root / path
    manifest_bytes = path.read_bytes()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("campaign manifest must be a JSON object")
    kind = str(manifest.get("test_kind") or "")
    if kind not in TEST_KINDS:
        raise ValueError(f"test_kind must be one of: {', '.join(TEST_KINDS)}")
    project_value = Path(str(manifest.get("project") or "."))
    if project_value.is_absolute() or ".." in project_value.parts:
        raise ValueError("manifest.project must be a safe relative path")
    selected_root = (root / project_value).resolve()
    if not selected_root.is_relative_to(root) or not selected_root.is_dir():
        raise ValueError("manifest.project is missing or escapes the workspace")
    project = inspect_project(selected_root)
    request = manifest.get("request") or {}
    budget = manifest.get("budget") or {}
    if not isinstance(request, dict) or not isinstance(budget, dict):
        raise ValueError("request and budget must be JSON objects")
    investigation = _normalize_investigation(manifest.get("investigation"))
    profile = profile_override or str(manifest.get("profile") or "balanced")
    campaign = default_registry().run_campaign(
        project, kind, request=request, budget=budget, profile=profile,
    )
    campaign.update({
        "manifest": str(path),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "project": project,
        "workspace_root": str(root),
        "investigation": investigation,
    })
    if output_path:
        destination = Path(output_path).expanduser()
        if not destination.is_absolute():
            destination = root / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        campaign["report_path"] = str(destination)
        destination.write_text(json.dumps(campaign, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return campaign



def _normalize_investigation(value: Any) -> dict[str, Any]:
    """Validate the optional, explicit link between a campaign and audit scope."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("investigation must be a JSON object")

    result: dict[str, Any] = {}
    signal_ids = value.get("signal_ids", value.get("signal_id", []))
    if isinstance(signal_ids, str):
        signal_ids = [signal_ids]
    if signal_ids is None:
        signal_ids = []
    if not isinstance(signal_ids, list) or not all(
        isinstance(item, str) and item.strip() for item in signal_ids
    ):
        raise ValueError("investigation.signal_ids must be a string or list of non-empty signal IDs")
    result["signal_ids"] = list(dict.fromkeys(item.strip() for item in signal_ids))

    for key in ("property_id", "function", "security_property", "description"):
        raw = value.get(key)
        if raw is not None:
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError(f"investigation.{key} must be a non-empty string")
            result[key] = raw.strip()

    source_file = value.get("source_file")
    if source_file is not None:
        if not isinstance(source_file, str) or not source_file.strip():
            raise ValueError("investigation.source_file must be a project-relative path")
        source_path = Path(source_file)
        if source_path.is_absolute() or ".." in source_path.parts:
            raise ValueError("investigation.source_file must not be absolute or escape the project")
        result["source_file"] = source_path.as_posix()

    source_line = value.get("source_line")
    if source_line is not None:
        if isinstance(source_line, bool):
            raise ValueError("investigation.source_line must be a positive integer")
        try:
            source_line = int(source_line)
        except (TypeError, ValueError):
            raise ValueError("investigation.source_line must be a positive integer")
        if source_line < 1:
            raise ValueError("investigation.source_line must be a positive integer")
        result["source_line"] = source_line
    return result


def _verification_interpretation(test_kind: str, result: dict[str, Any]) -> str:
    """Describe a native result without upgrading it into an automatic security verdict."""
    status = str(result.get("status") or "unknown").lower()
    if status == "failed":
        if test_kind in {"fuzz", "invariant", "exploit", "formal"}:
            return "property_or_counterexample_failure_requires_review"
        return "test_failure_requires_triage"
    if status == "passed":
        return "engine_completed_without_reported_failure_not_a_security_verdict"
    if status == "submitted":
        return "remote_or_deferred_job_submitted_not_completed"
    if status == "inconclusive":
        return "result_inconclusive"
    if status == "timeout":
        return "execution_timed_out"
    if status == "resource_limit":
        return "execution_stopped_by_resource_limit"
    if status == "unsupported":
        return "engine_or_project_combination_unsupported"
    if status == "error":
        return "engine_or_setup_error_no_security_result"
    return "unrecognized_result_status_requires_review"


def _resolve_investigation_signals(
    root: Path,
    investigation: dict[str, Any],
    requested_ids: list[str],
) -> tuple[list[str], list[str]]:
    """Use explicit IDs first; otherwise match only an unambiguous file+function scope."""
    ids = list(dict.fromkeys(
        [*investigation.get("signal_ids", []), *(requested_ids or [])]
    ))
    notes: list[str] = []
    if ids or not (investigation.get("source_file") and investigation.get("function")):
        return ids, notes
    if audit_context is None:
        return [], ["Audit context is unavailable; source-scope matching was not attempted."]

    source = (root / investigation["source_file"]).resolve()
    if not source.is_relative_to(root.resolve()):
        return [], ["Investigation source path escaped the active project and was ignored."]

    requested_function = str(investigation["function"]).strip().lower()
    matches = []
    for signal in audit_context.signals(root):
        if not isinstance(signal, dict) or not signal.get("file"):
            continue
        signal_path = Path(str(signal["file"]))
        if not signal_path.is_absolute():
            signal_path = root / signal_path
        try:
            if signal_path.resolve() != source:
                continue
        except OSError:
            continue
        observed_function = str(signal.get("function") or "").strip().lower()
        if not observed_function:
            continue
        if "(" in requested_function:
            if observed_function != requested_function:
                continue
        elif observed_function.split("(", 1)[0] != requested_function:
            continue
        matches.append(str(signal.get("id") or ""))

    matches = [item for item in dict.fromkeys(matches) if item]
    if len(matches) == 1:
        return matches, notes
    if len(matches) > 1:
        notes.append(
            "Source/function scope matched multiple signals; no automatic attachment was made. "
            "Pass --signal with the intended signal ID or specify an exact function signature."
        )
    else:
        notes.append(
            "No existing audit signal matched the explicit source_file + function scope; "
            "no signal was created automatically."
        )
    return [], notes


def correlate_campaign(
    report_path: str | Path,
    *,
    project_root: str | Path | None = None,
    signal_ids: list[str] | None = None,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    """Correlate native campaign outcomes and optionally attach evidence to existing signals.

    This is a conservative evidence-joining step. It never creates a vulnerability
    finding from a failed test and never marks a signal as proven.
    """
    root = Path(project_root).expanduser().resolve() if project_root else _project_root()
    path = Path(report_path).expanduser()
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    try:
        report_bytes = path.read_bytes()
        campaign = json.loads(report_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not read campaign report: {exc}") from exc
    if not isinstance(campaign, dict):
        raise ValueError("campaign report must be a JSON object")

    project = campaign.get("project")
    declared_root = project.get("root") if isinstance(project, dict) else None
    if not declared_root:
        raise ValueError("campaign report has no project.root; refusing to attach evidence without project provenance")
    try:
        declared_root_path = Path(str(declared_root)).expanduser().resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"campaign project root is invalid: {exc}") from exc
    if declared_root_path != root:
        raise ValueError(
            "campaign report belongs to a different project root; run correlation from that project "
            "or pass the correct project root"
        )

    test_kind = str(campaign.get("test_kind") or "unknown").lower()
    investigation = _normalize_investigation(campaign.get("investigation"))
    target_ids, notes = _resolve_investigation_signals(root, investigation, signal_ids or [])
    campaign_digest = hashlib.sha256(report_bytes).hexdigest()
    property_id = investigation.get("property_id")
    if property_id:
        correlation_id = "property:" + str(property_id)
    elif len(target_ids) == 1:
        correlation_id = "signal:" + target_ids[0]
    elif investigation.get("source_file") and investigation.get("function"):
        correlation_id = (
            "scope:" + investigation["source_file"] + ":" + investigation["function"]
        )
    else:
        correlation_id = "campaign:" + campaign_digest[:16]

    raw_results = campaign.get("results")
    if not isinstance(raw_results, list):
        raise ValueError("campaign report results must be an array")
    engine_results = []
    status_counts: dict[str, int] = {}
    for row in raw_results:
        if not isinstance(row, dict) or not isinstance(row.get("result"), dict):
            continue
        result = row["result"]
        selection = row.get("selection") if isinstance(row.get("selection"), dict) else {}
        engine = str(result.get("engine") or selection.get("engine") or "unknown")
        status = str(result.get("status") or "unknown").lower()
        metadata = result.get("metadata") if isinstance(result.get("metadata"), dict) else {}
        stdout = str(result.get("raw_stdout") or "")
        stderr = str(result.get("raw_stderr") or "")
        normalized = {
            "engine": engine,
            "status": status,
            "exit_code": result.get("exit_code"),
            "summary": str(result.get("summary") or ""),
            "result_semantics": metadata.get("result_semantics"),
            "failure_classification": metadata.get("failure_classification"),
            "interpretation": _verification_interpretation(test_kind, result),
            "duration_seconds": result.get("duration_seconds"),
            "artifacts": list(result.get("artifacts") or []),
            "stdout_sha256": hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            "stderr_sha256": hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
            "raw_evidence_preserved_in_campaign_report": True,
        }
        engine_results.append(normalized)
        status_counts[status] = status_counts.get(status, 0) + 1

    raw_selection = campaign.get("considered_engines")
    if not isinstance(raw_selection, list):
        raw_selection = []
    engine_selection = []
    for item in raw_selection:
        if not isinstance(item, dict):
            continue
        engine_selection.append({
            "engine": str(item.get("engine") or "unknown"),
            "status": str(item.get("status") or "unknown"),
            "test_kind": item.get("test_kind"),
            "memory_class": item.get("memory_class"),
            "reason": str(item.get("reason") or ""),
        })
    selection_summary = campaign.get("selection_summary")
    if not isinstance(selection_summary, dict):
        selection_summary = {}

    if not engine_results:
        notes.append(
            "No well-formed engine results were recorded. This is a coverage gap, not a passing verification result."
        )
    for item in engine_selection:
        if item["status"] != "selected":
            notes.append(
                f"Engine {item['engine']} was not run ({item['status']}): "
                f"{item['reason'] or 'no reason supplied'}"
            )

    failures = [
        item for item in engine_results
        if item["interpretation"] in {
            "property_or_counterexample_failure_requires_review",
            "test_failure_requires_triage",
        }
    ]
    payload: dict[str, Any] = {
        "schema_version": 1,
        "campaign_report": str(path),
        "campaign_report_sha256": campaign_digest,
        "manifest": campaign.get("manifest"),
        "manifest_sha256": campaign.get("manifest_sha256"),
        "project_root": str(root),
        "test_kind": test_kind,
        "profile": campaign.get("profile"),
        "correlation_id": correlation_id,
        "investigation": investigation,
        "target_signal_ids": target_ids,
        "engine_selection": engine_selection,
        "selection_summary": selection_summary,
        "engine_results": engine_results,
        "coverage_status": "engine_results_available" if engine_results else "no_engine_results",
        "summary": {
            "engines_with_results": len(engine_results),
            "no_engine_results": not bool(engine_results),
            "status_counts": status_counts,
            "reported_test_or_property_failures": len(failures),
            "passed_engines": status_counts.get("passed", 0),
            "execution_issues": sum(
                status_counts.get(key, 0)
                for key in ("error", "timeout", "resource_limit", "unsupported", "inconclusive", "submitted")
            ) + (1 if not engine_results else 0),
            "security_finding_confirmed": False,
        },
        "interpretation": (
            "This report joins engine evidence for an explicitly identified property/signal or one campaign. "
            "Engine failures are leads for review, not automatic vulnerability confirmations. A passed engine "
            "only reports its configured test/specification outcome and does not establish protocol-wide safety."
        ),
        "notes": notes,
    }

    attached_ids: list[str] = []
    missing_ids: list[str] = []
    if target_ids and audit_context is not None:
        evidence = {
            "kind": "verification-correlation",
            "campaign_report_sha256": campaign_digest,
            "campaign_report": str(path),
            "manifest_sha256": campaign.get("manifest_sha256"),
            "correlation_id": correlation_id,
            "test_kind": test_kind,
            "profile": campaign.get("profile"),
            "investigation": investigation,
            "engine_results": engine_results,
            "interpretation": payload["interpretation"],
            "security_finding_confirmed": False,
        }
        for signal_id in target_ids:
            attached = audit_context.attach_signal_evidence(signal_id, evidence, root)
            if attached is None:
                missing_ids.append(signal_id)
            else:
                attached_ids.append(signal_id)
    elif target_ids:
        missing_ids.extend(target_ids)
        notes.append("Audit context is unavailable; no signal evidence was written.")

    payload["attached_signal_ids"] = attached_ids
    payload["missing_signal_ids"] = missing_ids
    if missing_ids:
        payload["notes"].append(
            "Some requested signal IDs did not exist in this project's audit context; no replacement signals were created."
        )

    destination = Path(output_path).expanduser() if output_path else Path(".audit/verification/correlation-report.json")
    if not destination.is_absolute():
        destination = root / destination
    destination = destination.resolve()
    payload["correlation_report_path"] = str(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload

def run_cli(args: list[str]) -> int:
    if not args or any(str(arg).lower() in {"-h", "--help", "help"} for arg in args):
        _help()
        return 0 if args else 2
    command = args[0]
    if command == "engines":
        json_mode = "--json" in args[1:]
        if any(arg not in {"--json"} for arg in args[1:]):
            print("Error: usage: lk verification engines [--json]", file=sys.stderr)
            return 2
        payload = engine_inventory()
        if json_mode:
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
        print(f"Project: {payload['project']['root']}")
        print(f"Languages: {', '.join(payload['project']['languages']) or 'unknown'}")
        print(f"Build systems: {', '.join(payload['project']['build_systems']) or 'unknown'}")
        for error in payload.get("plugin_errors", []):
            print(f"  Plugin load error [{error['plugin']}]: {error['error']}")
        for engine in payload["engines"]:
            state = "available" if engine["available"] else "not installed"
            print(f"  {engine['name']}: {state}")
            print(f"    kinds: {', '.join(engine['test_kinds']) or 'not a test executor'}")
            if engine["supported_test_kinds"]:
                print(f"    compatible: {', '.join(engine['supported_test_kinds'])}")
            if engine["notes"]:
                print(f"    note: {engine['notes']}")
        return 0
    if command == "correlate":
        if len(args) < 2:
            print("Error: provide a saved campaign report to correlate", file=sys.stderr)
            return 2
        report_path = args[1]
        output = Path(".audit/verification/correlation-report.json")
        requested_signals: list[str] = []
        index = 2
        while index < len(args):
            value = args[index]
            if value in {"--signal", "--output"}:
                index += 1
                if index >= len(args):
                    print(f"Error: {value} requires a value", file=sys.stderr)
                    return 2
                if value == "--signal":
                    requested_signals.append(args[index])
                else:
                    output = Path(args[index]).expanduser()
            elif value.startswith("--signal="):
                requested_signals.append(value.split("=", 1)[1])
            elif value.startswith("--output="):
                output = Path(value.split("=", 1)[1]).expanduser()
            else:
                print(f"Error: unknown option: {value}", file=sys.stderr)
                return 2
            index += 1
        try:
            payload = correlate_campaign(
                report_path,
                signal_ids=requested_signals,
                output_path=output,
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Error: could not correlate verification campaign: {exc}", file=sys.stderr)
            return 2
        summary = payload["summary"]
        print("LOWKEY VERIFICATION CORRELATION")
        print("===============================")
        print(f"  Test kind         : {payload['test_kind']}")
        print(f"  Correlation       : {payload['correlation_id']}")
        print(f"  Engine results    : {summary['engines_with_results']}")
        print(f"  Failures to review: {summary['reported_test_or_property_failures']}")
        print(f"  Passed engines    : {summary['passed_engines']} (not a security verdict)")
        print(f"  Evidence attached : {len(payload['attached_signal_ids'])}")
        if payload["missing_signal_ids"]:
            print("  Missing signals   : " + ", ".join(payload["missing_signal_ids"]))
        for note in payload["notes"]:
            print(f"  Note              : {note}")
        print(f"  Report            : {payload['correlation_report_path']}")
        if not summary["engines_with_results"]:
            return 2
        return 1 if payload["missing_signal_ids"] else 0
    if command == "run":
        if len(args) < 2:
            print("Error: provide a campaign manifest", file=sys.stderr)
            return 2
        manifest = args[1]
        profile = None
        output = Path(".audit/verification/campaign.json")
        index = 2
        while index < len(args):
            value = args[index]
            if value in {"--profile", "--output"}:
                index += 1
                if index >= len(args):
                    print(f"Error: {value} requires a value", file=sys.stderr)
                    return 2
                if value == "--profile":
                    profile = args[index]
                else:
                    output = Path(args[index]).expanduser()
            elif value.startswith("--profile="):
                profile = value.split("=", 1)[1]
            elif value.startswith("--output="):
                output = Path(value.split("=", 1)[1]).expanduser()
            else:
                print(f"Error: unknown option: {value}", file=sys.stderr)
                return 2
            index += 1
        try:
            report = run_campaign_manifest(
                manifest, profile_override=profile, output_path=output,
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"Error: verification campaign failed: {exc}", file=sys.stderr)
            return 2
        print(f"Verification campaign: {report['test_kind']} ({report['profile']})")
        print(f"  Execution: {report['execution_mode']} (serial)")
        print(f"  Selected engines: {report['selected_count']}")
        selection = report.get("selection_summary", {})
        if selection:
            print(
                "  Selection outcomes: "
                + ", ".join(f"{key}={value}" for key, value in selection.items())
            )
        for item in report.get("considered_engines", []):
            if item.get("status") != "selected":
                print(f"  Not selected: {item['engine']} ({item['status']}) — {item['reason']}")
        for key, value in report["summary"].items():
            print(f"  {key}: {value}")
        print(f"  Report: {report.get('report_path', output)}")
        failure_statuses = {
            "failed", "timeout", "resource_limit", "error", "unsupported",
            "inconclusive", "submitted",
        }
        diagnostic_results = [
            item.get("result", {})
            for item in report.get("results", [])
            if isinstance(item, dict)
            and isinstance(item.get("result"), dict)
            and item["result"].get("status") in failure_statuses
        ]
        if diagnostic_results:
            print("  Engine diagnostics:")
            for result in diagnostic_results:
                print(
                    f"    {result.get('engine', 'unknown')}: "
                    f"{result.get('status', 'unknown')} — "
                    f"{result.get('summary') or 'no summary supplied'}"
                )
                for stream_name in ("raw_stderr", "raw_stdout"):
                    stream = str(result.get(stream_name) or "").strip()
                    if not stream:
                        continue
                    lines = stream.splitlines()
                    print(f"      {stream_name} (last {min(20, len(lines))} lines):")
                    for line in lines[-20:]:
                        print(f"        {line}")
        if report["selected_count"] == 0:
            return 2
        if any(report["summary"].get(key, 0) for key in ("failed", "timeout", "resource_limit", "error", "unsupported", "inconclusive", "submitted")):
            return 1
        return 0
    print("Error: expected 'engines', 'run', or 'correlate'. Use 'lk verification --h'.", file=sys.stderr)
    return 2
