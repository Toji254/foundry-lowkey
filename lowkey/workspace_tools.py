#!/usr/bin/env python3
"""Workspace member selection and honest monorepo project overview for Lowkey."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import project_detection

try:
    import project_tools
except ImportError:
    project_tools = None


def _workspace(start: str | Path = ".") -> Path:
    path = Path(start).expanduser().resolve()
    return Path(project_detection.workspace_root(path)).resolve()


def _members(root: Path) -> list[dict[str, Any]]:
    return project_detection.discover_nested_projects(root)


def resolve_member(root: str | Path, selector: str | int) -> Path:
    """Resolve a stable 1-based index, member name, relative path, or absolute path."""
    workspace = _workspace(root)
    members = _members(workspace)
    value = str(selector).strip()
    if not value:
        raise ValueError("provide a member index, name, or path")

    if re.fullmatch(r"\d+", value):
        index = int(value)
        if index < 1 or index > len(members):
            raise ValueError(f"member index {index} is outside the available range 1–{len(members)}")
        return Path(members[index - 1]["root"]).resolve()

    candidate_path = Path(value).expanduser()
    if candidate_path.is_absolute():
        resolved = candidate_path.resolve()
    else:
        resolved = (workspace / candidate_path).resolve()
    path_matches = [
        Path(item["root"]).resolve()
        for item in members
        if Path(item["root"]).resolve() == resolved
    ]
    if path_matches:
        return path_matches[0]

    matches = [
        Path(item["root"]).resolve()
        for item in members
        if value in {
            str(item.get("name") or ""),
            str(item.get("relative") or ""),
            Path(str(item["root"])).name,
        }
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        paths = ", ".join(str(item.relative_to(workspace)) for item in matches)
        raise ValueError(f"member name '{value}' is ambiguous; use one of: {paths}")
    raise ValueError(f"no workspace member matches '{value}'")


def _foundry_config(root: Path) -> dict[str, Any]:
    path = root / "foundry.toml"
    if not path.is_file() or tomllib is None:
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError, ValueError):
        return {}
    profile_name = os.environ.get("FOUNDRY_PROFILE", "default")
    profiles = data.get("profile", {}) if isinstance(data, dict) else {}
    profile = profiles.get(profile_name, {}) if isinstance(profiles, dict) else {}
    if not isinstance(profile, dict):
        profile = {}
    return {**data, **profile}


def _count_files(root: Path, directory: str, suffixes: set[str]) -> int:
    candidate = (root / directory).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return 0
    if not candidate.is_dir():
        return 0
    ignored = {
        ".git", ".audit", ".venv", "venv", "node_modules", "lib", "vendor",
        "out", "cache", "artifacts", "broadcast", "build", "dist", "target",
    }
    count = 0
    for current, dirs, files in os.walk(candidate, followlinks=False):
        dirs[:] = sorted(
            name for name in dirs
            if name not in ignored and not (Path(current) / name).is_symlink()
        )
        count += sum(1 for name in files if Path(name).suffix.lower() in suffixes)
    return count


def _member_relationships(workspace: Path, members: list[dict[str, Any]]) -> dict[str, list[str]]:
    roots = {Path(item["root"]).resolve(): item for item in members}
    names: dict[str, Path] = {}
    for root, item in roots.items():
        package_path = root / "package.json"
        if package_path.is_file():
            try:
                package = json.loads(package_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                package = {}
            if isinstance(package, dict) and package.get("name"):
                names[str(package["name"])] = root

    used_by: dict[str, list[str]] = {str(root): [] for root in roots}
    for consumer in roots:
        package_path = consumer / "package.json"
        if package_path.is_file():
            try:
                package = json.loads(package_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                package = {}
            if isinstance(package, dict):
                for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    dependencies = package.get(section, {})
                    if not isinstance(dependencies, dict):
                        continue
                    for name, version in dependencies.items():
                        if str(version).startswith("workspace:") and str(name) in names:
                            provider = names[str(name)]
                            if provider != consumer:
                                used_by[str(provider)].append(consumer.relative_to(workspace).as_posix())

        config = _foundry_config(consumer)
        remappings = config.get("remappings", [])
        if not isinstance(remappings, list):
            remappings = []
        remappings_file = consumer / "remappings.txt"
        if remappings_file.is_file():
            try:
                remappings = list(remappings) + remappings_file.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                pass
        for entry in remappings:
            if not isinstance(entry, str) or "=" not in entry:
                continue
            _prefix, destination = entry.split("=", 1)
            target = (consumer / destination.strip()).resolve()
            for provider in roots:
                if provider == consumer:
                    continue
                try:
                    target.relative_to(provider)
                except ValueError:
                    continue
                used_by[str(provider)].append(consumer.relative_to(workspace).as_posix())
                break

    return {
        key: sorted(set(values))
        for key, values in used_by.items()
    }


def workspace_overview(root: str | Path = ".") -> dict[str, Any]:
    requested = Path(root).expanduser().resolve()
    workspace = _workspace(requested)
    if requested != workspace or not project_detection.is_workspace_root(workspace):
        raise ValueError("the current directory is not the workspace root")

    members = _members(workspace)
    relationships = _member_relationships(workspace, members)
    active = project_detection.workspace_selection(workspace)
    records: list[dict[str, Any]] = []
    config_markers = (
        "foundry.toml", "hardhat.config.ts", "hardhat.config.js",
        "Anchor.toml", "Scarb.toml", "Move.toml", "Cargo.toml",
        "go.mod", "pyproject.toml", "package.json",
    )
    for index, item in enumerate(members, 1):
        member_root = Path(item["root"]).resolve()
        config = _foundry_config(member_root)
        if (member_root / "foundry.toml").is_file():
            src = str(config.get("src") or "src")
            test = str(config.get("test") or "test")
            script = str(config.get("script") or "script")
            sources = _count_files(member_root, src, {".sol", ".vy", ".vyi"})
            tests = _count_files(member_root, test, {".sol", ".vy", ".vyi", ".t.sol"})
            scripts = _count_files(member_root, script, {".sol", ".vy", ".vyi"})
        else:
            try:
                from analysis_adapters import inspect_repository
                analysis = inspect_repository(member_root)
            except Exception:
                analysis = {}
            languages = dict(item.get("languages") or analysis.get("languages") or {})
            sources = sum(int(value or 0) for value in languages.values())
            tests = sum(
                _count_files(member_root, directory, {".sol", ".vy", ".vyi", ".rs", ".cairo", ".move"})
                for directory in ("test", "tests")
            )
            scripts = sum(
                _count_files(member_root, directory, {".sol", ".vy", ".vyi", ".rs", ".cairo", ".move"})
                for directory in ("script", "scripts")
            )
        configs = [name for name in config_markers if (member_root / name).is_file()]
        rel = member_root.relative_to(workspace).as_posix()
        consumers = relationships.get(str(member_root), [])
        role = "shared first-party package" if consumers else "workspace member"
        records.append({
            "index": index,
            "name": str(item.get("name") or member_root.name),
            "path": rel,
            "root": str(member_root),
            "backend": str(item.get("backend") or item.get("kind") or "unknown"),
            "languages": dict(item.get("languages") or {}),
            "source_files": sources,
            "test_files": tests,
            "script_files": scripts,
            "configs": configs,
            "role": role,
            "used_by": consumers,
            "active": bool(active and active.resolve() == member_root),
        })

    return {
        "workspace_root": str(workspace),
        "active_member": str(active.relative_to(workspace)) if active else None,
        "member_count": len(records),
        "members": records,
        "selection_file": ".audit/workspace.json",
        "scope_policy": "Workspace overview is aggregate metadata only. Build, test and audit operations must select one member and never silently combine sibling packages.",
    }


def _render_overview(data: dict[str, Any]) -> str:
    lines = [
        "LOWKEY WORKSPACE OVERVIEW",
        "=" * 72,
        f"Workspace : {data['workspace_root']}",
        f"Members   : {data['member_count']}",
        f"Active    : {data['active_member'] or 'none selected'}",
        "",
        "#  MEMBER                         BUILD SYSTEM        SOURCE  TEST  SCRIPT  CONFIG",
        "-" * 96,
    ]
    for item in data["members"]:
        name = f"{item['index']}. {item['path']}"
        config = ", ".join(item["configs"]) or "manifest not detected"
        lines.append(
            f"{name[:32]:32} {item['backend'][:18]:18} "
            f"{item['source_files']:>6} {item['test_files']:>5} "
            f"{item['script_files']:>7}  {config}"
        )
        if item["role"] == "shared first-party package":
            lines.append(f"    role: shared first-party package; used by: {', '.join(item['used_by'])}")
    lines += [
        "",
        "Selection is workspace-local (.audit/workspace.json). A real child package",
        "directory always takes precedence over a saved selection. Sibling packages",
        "are not merged into one audit target.",
        "Use: lk workspace select <index|name|path>",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lk workspace",
        description="Inspect and select one package in a multi-project workspace.",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    for action, help_text in (
        ("project", "show an aggregate project map when invoked at a workspace root"),
        ("list", "list workspace members and their independent build scopes"),
        ("status", "show the saved active member"),
    ):
        command = sub.add_parser(action, help=help_text)
        command.add_argument("--root", default=".", help="workspace root")
        command.add_argument("--json", action="store_true", help="print JSON")
    select = sub.add_parser("select", help="persist one workspace member as the active package")
    select.add_argument("selector", help="1-based index, name, relative path, or absolute path")
    select.add_argument("--root", default=".", help="workspace root")
    args = parser.parse_args(argv)

    try:
        workspace = _workspace(args.root)
        if args.action == "select":
            selected = resolve_member(workspace, args.selector)
            if not project_detection.set_workspace_selection(workspace, selected):
                raise ValueError(f"could not save selection for {selected}")
            print(f"Active workspace member: {selected.relative_to(workspace)}")
            print("Saved to .audit/workspace.json. Child package directories still override this selection.")
            return 0

        data = workspace_overview(workspace)
        if args.action == "status":
            if args.json:
                print(json.dumps({
                    "workspace_root": data["workspace_root"],
                    "active_member": data["active_member"],
                    "member_count": data["member_count"],
                }, indent=2))
            else:
                print(f"Workspace: {data['workspace_root']}")
                print(f"Active member: {data['active_member'] or 'none selected'}")
            return 0
        if args.json:
            print(json.dumps(data, indent=2, sort_keys=True))
            return 0
        print(_render_overview(data))
        if args.action == "project" and project_tools is not None:
            project_tools.render_project_map(workspace)
        return 0
    except ValueError as exc:
        if args.action == "project" and "not the workspace root" in str(exc):
            return 3
        print(f"Lowkey workspace: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Lowkey workspace: could not inspect workspace: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
