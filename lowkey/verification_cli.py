"""CLI integration for engine inventory and bounded verification campaigns."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

try:
    from verification_adapters import default_registry, inspect_project, TEST_KINDS
except ImportError:
    from lowkey.verification_adapters import default_registry, inspect_project, TEST_KINDS


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

Campaign manifest:
  {
    "test_kind": "fuzz",
    "budget": {"timeout_seconds": 120},
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
    manifest = json.loads(path.read_text(encoding="utf-8"))
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
    profile = profile_override or str(manifest.get("profile") or "balanced")
    campaign = default_registry().run_campaign(
        project, kind, request=request, budget=budget, profile=profile,
    )
    campaign.update({
        "manifest": str(path),
        "project": project,
        "workspace_root": str(root),
    })
    if output_path:
        destination = Path(output_path).expanduser()
        if not destination.is_absolute():
            destination = root / destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        campaign["report_path"] = str(destination)
        destination.write_text(json.dumps(campaign, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return campaign


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
        if report["selected_count"] == 0:
            return 2
        if any(report["summary"][key] for key in ("failed", "timeout", "error", "unsupported", "inconclusive", "submitted")):
            return 1
        return 0
    print("Error: expected 'engines' or 'run'. Use 'lk verification --h'.", file=sys.stderr)
    return 2
