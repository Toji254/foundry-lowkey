#!/usr/bin/env python3
"""Project-aware, resource-conscious Foundry build planning and execution."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    tomllib = None
from typing import Any, Sequence

MODULE_DIR = Path(__file__).resolve().parent
if str(MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(MODULE_DIR))

import project_detection
import project_tools
import audit_context
import forge_tools
import bootstrap

GIB = 1024 ** 3
IGNORED = {
    ".git", ".audit", ".venv", "venv", "node_modules", "lib", "vendor",
    "out", "cache", "artifacts", "broadcast", "build", "dist", "target",
}


def _nearest_foundry(path: Path) -> Path | None:
    for parent in (path, *path.parents):
        if (parent / "foundry.toml").is_file():
            return parent.resolve()
    return None


def _resolve_project_root(
    requested: Path,
    *,
    member: str | None = None,
) -> tuple[Path | None, str | None]:
    requested = requested.expanduser().resolve()
    if requested.is_file():
        requested = requested.parent

    workspace = Path(project_detection.workspace_root(requested)).resolve()
    workspace_mode = project_detection.is_workspace_root(workspace)

    if member:
        try:
            import workspace_tools
            selected = workspace_tools.resolve_member(workspace, member)
        except (ImportError, ValueError) as exc:
            return None, str(exc)
        if not (selected / "foundry.toml").is_file():
            return None, f"selected workspace member has no foundry.toml: {selected}"
        if not project_detection.set_workspace_selection(workspace, selected):
            return None, f"could not persist workspace member selection: {selected}"
        return selected, None

    members = project_detection.discover_nested_projects(workspace) if workspace_mode else []
    member_roots = [Path(item["root"]).resolve() for item in members]
    foundry_members = [
        path for path in member_roots if (path / "foundry.toml").is_file()
    ]

    # At the workspace root, select a concrete Foundry member before considering
    # an umbrella foundry.toml. A workspace config must not silently combine
    # sibling packages or mask the package-local compiler settings.
    if workspace_mode and requested == workspace:
        active = project_detection.workspace_selection(workspace)
        if active is not None and active in member_roots:
            if active in foundry_members:
                return active, None
            # The explicitly selected member uses another build system. Let the
            # native project router handle it rather than inheriting root Forge.
            return None, None
        if len(foundry_members) == 1:
            return foundry_members[0], None
        if len(foundry_members) > 1:
            options = ", ".join(
                f"{index}. {path.relative_to(workspace).as_posix()}"
                for index, path in enumerate(foundry_members, 1)
            )
            return None, (
                "multiple Foundry members are available; Lowkey will not mix sibling packages. "
                f"Select one with 'lk workspace select <index|name|path>' or pass --root. Members: {options}"
            )
        if (workspace / "foundry.toml").is_file():
            return workspace, None
        return None, None

    # A real child package always wins over a stale workspace selection. If
    # that child has no Foundry config, do not fall back to the workspace's
    # umbrella config or to a different selected sibling.
    if workspace_mode:
        containing = [
            path for path in member_roots
            if requested == path or path in requested.parents
        ]
        if containing:
            nearest = _nearest_foundry(requested)
            if nearest is not None and nearest != workspace:
                return nearest, None
            return None, None

    nearest = _nearest_foundry(requested)
    if nearest is not None:
        return nearest, None

    if workspace_mode:
        active = project_detection.workspace_selection(workspace)
        if active is not None and active in foundry_members:
            return active, None
        if len(foundry_members) == 1:
            return foundry_members[0], None
        if len(foundry_members) > 1:
            options = ", ".join(
                f"{index}. {path.relative_to(workspace).as_posix()}"
                for index, path in enumerate(foundry_members, 1)
            )
            return None, (
                "multiple Foundry members are available; Lowkey will not mix sibling packages. "
                f"Select one with 'lk workspace select <index|name|path>' or pass --root. Members: {options}"
            )
    return None, None

def _profile_from_args(args: Sequence[str]) -> str:
    for index, value in enumerate(args):
        if value == "--profile" and index + 1 < len(args):
            return str(args[index + 1])
        if value.startswith("--profile="):
            return value.split("=", 1)[1]
    return os.environ.get("FOUNDRY_PROFILE", "default")


def _explicit_threads(args: Sequence[str]) -> int | None:
    for index, value in enumerate(args):
        if value == "--threads" and index + 1 < len(args):
            try:
                return max(1, int(args[index + 1]))
            except (TypeError, ValueError):
                return None
        if value.startswith("--threads="):
            try:
                return max(1, int(value.split("=", 1)[1]))
            except (TypeError, ValueError):
                return None
    return None


def _active_config_path(
    root: Path,
    forge_args: Sequence[str] = (),
) -> Path:
    """Resolve Foundry's selected config file, including CLI and environment overrides."""
    configured = ""
    values = list(forge_args)
    for index, value in enumerate(values):
        if value == "--config-path":
            if index + 1 >= len(values) or values[index + 1].startswith("--"):
                raise ValueError("--config-path requires a config file path")
            configured = values[index + 1]
        elif value.startswith("--config-path="):
            configured = value.split("=", 1)[1]
    if not configured:
        configured = os.environ.get("FOUNDRY_CONFIG", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        return candidate.resolve()
    return (root / "foundry.toml").resolve()


def _toml_config(
    root: Path,
    profile: str,
    config_path: Path | None = None,
) -> dict[str, Any]:
    if tomllib is None:
        return {}
    path = config_path or _active_config_path(root)
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, tomllib.TOMLDecodeError, ValueError):
        return {}
    profiles = data.get("profile", {})
    selected = profiles.get(profile, {}) if isinstance(profiles, dict) else {}
    if not isinstance(selected, dict):
        selected = {}
    default = profiles.get("default", {}) if isinstance(profiles, dict) else {}
    if not isinstance(default, dict):
        default = {}
    return {**data, **default, **selected}


def load_foundry_config(
    root: Path,
    profile: str,
    config_path: Path | None = None,
) -> tuple[dict[str, Any], str]:
    """Prefer Forge's effective config and report the actual selected config path."""
    config_path = config_path or _active_config_path(root)
    binary = forge_tools.forge_path()
    if binary:
        command = [
            binary, "config", "--json", "--root", str(root),
            "--profile", profile, "--config-path", str(config_path),
        ]
        try:
            result = subprocess.run(
                command, cwd=root, capture_output=True, text=True, timeout=12,
                stdin=subprocess.DEVNULL, check=False,
            )
            if result.returncode == 0:
                value = json.loads(result.stdout or "{}")
                if isinstance(value, dict) and value:
                    return value, (
                        f"forge config --json (effective configuration; active file {config_path})"
                    )
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
            pass
    return _toml_config(root, profile, config_path), (
        f"{config_path} [profile.{profile}] "
        "(manifest fallback; CLI/environment overrides may not be reflected)"
    )

def _config_dirs(config: dict[str, Any], key: str, default: str) -> list[str]:
    value = config.get(key, default)
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return [default]


def _safe_scope_path(root: Path, value: str) -> tuple[str, Path]:
    candidate = Path(value).expanduser()
    resolved = (root / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    try:
        relative = resolved.relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"Foundry {value!r} resolves outside the selected package; select that package separately") from exc
    return relative, resolved


def _resolve_target(root: Path, target: str, config: dict[str, Any]) -> str:
    candidate = Path(target).expanduser()
    if candidate.is_absolute():
        resolved = candidate.resolve()
    else:
        resolved = (root / candidate).resolve()
    if resolved.exists():
        try:
            return resolved.relative_to(root.resolve()).as_posix()
        except ValueError as exc:
            raise ValueError("target must be inside the selected Foundry package; do not mix sibling packages") from exc

    search_roots: list[Path] = []
    for value in _config_dirs(config, "src", "src"):
        _relative, path = _safe_scope_path(root, value)
        if path.is_dir():
            search_roots.append(path)
    matches: list[str] = []
    declaration = re.compile(
        r"\b(?:contract|interface|library)\s+" + re.escape(target) + r"\b"
    )
    for search_root in search_roots:
        for current, dirs, files in os.walk(search_root, followlinks=False):
            dirs[:] = sorted(name for name in dirs if name not in IGNORED)
            for filename in files:
                if not filename.endswith(".sol"):
                    continue
                path = Path(current) / filename
                try:
                    if declaration.search(path.read_text(encoding="utf-8", errors="replace")):
                        matches.append(path.relative_to(root).as_posix())
                except OSError:
                    continue
    matches = sorted(set(matches))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(f"contract name '{target}' is ambiguous: {', '.join(matches[:8])}")
    raise ValueError(f"no source file or contract named '{target}' was found under the configured src directory")


def _count_sources(root: Path, directory: str) -> int:
    try:
        relative, path = _safe_scope_path(root, directory)
    except ValueError:
        return 0
    if not path.is_dir():
        return 0
    count = 0
    for current, dirs, files in os.walk(path, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in IGNORED)
        count += sum(1 for name in files if Path(name).suffix.lower() in {".sol", ".vy", ".vyi"})
    return count


def _meminfo(proc_root: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    try:
        lines = (proc_root / "meminfo").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return values
    for line in lines:
        match = re.match(r"^([A-Za-z_()]+):\s+(\d+)\s+kB", line)
        if match:
            values[match.group(1)] = int(match.group(2)) * 1024
    return values


def _swap_info(proc_root: Path) -> dict[str, int]:
    total = used = 0
    try:
        lines = (proc_root / "swaps").read_text(encoding="utf-8", errors="replace").splitlines()[1:]
    except OSError:
        return {"swap_total_bytes": 0, "swap_used_bytes": 0}
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        try:
            total += int(fields[2]) * 1024
            used += int(fields[3]) * 1024
        except ValueError:
            continue
    return {"swap_total_bytes": total, "swap_used_bytes": used}


def _zram_used(sys_root: Path) -> int:
    total = 0
    for path in sys_root.glob("block/zram*/mm_stat"):
        try:
            fields = path.read_text(encoding="utf-8", errors="replace").split()
            if len(fields) >= 3:
                total += int(fields[2])
        except (OSError, ValueError):
            continue
    return total


def _memory_pressure(proc_root: Path) -> dict[str, float | None]:
    result: dict[str, float | None] = {"memory_psi_some_avg10": None, "memory_psi_full_avg10": None}
    try:
        lines = (proc_root / "pressure" / "memory").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return result
    for line in lines:
        kind = line.split(" ", 1)[0]
        match = re.search(r"avg10=([0-9.]+)", line)
        if not match:
            continue
        key = "memory_psi_some_avg10" if kind == "some" else "memory_psi_full_avg10" if kind == "full" else None
        if key:
            try:
                result[key] = float(match.group(1))
            except ValueError:
                pass
    return result


def _cgroup_memory_limit(sys_root: Path) -> tuple[int | None, int | None]:
    candidates = (
        (sys_root / "fs" / "cgroup" / "memory.max", sys_root / "fs" / "cgroup" / "memory.current"),
        (sys_root / "fs" / "cgroup" / "memory" / "memory.limit_in_bytes",
         sys_root / "fs" / "cgroup" / "memory" / "memory.usage_in_bytes"),
    )
    for limit_path, current_path in candidates:
        try:
            raw_limit = limit_path.read_text(encoding="utf-8").strip()
            raw_current = current_path.read_text(encoding="utf-8").strip()
            if raw_limit == "max":
                continue
            limit = int(raw_limit)
            current = int(raw_current)
            if 0 < limit < (1 << 60):
                return limit, max(0, limit - current)
        except (OSError, ValueError):
            continue
    return None, None


def collect_resources(
    proc_root: Path | str = "/proc",
    sys_root: Path | str = "/sys",
    *,
    cpu_count: int | None = None,
) -> dict[str, Any]:
    """Read host/container memory, swap/zram, CPU availability and memory PSI."""
    proc = Path(proc_root)
    sysfs = Path(sys_root)
    memory = _meminfo(proc)
    swap = _swap_info(proc)
    pressure = _memory_pressure(proc)
    total = memory.get("MemTotal")
    available = memory.get("MemAvailable")
    limit, cgroup_available = _cgroup_memory_limit(sysfs)
    if cgroup_available is not None:
        available = min(available, cgroup_available) if available is not None else cgroup_available
        total = min(total, limit) if total is not None and limit is not None else limit
    detected_cpu = cpu_count if cpu_count is not None else (os.cpu_count() or 1)
    try:
        affinity = len(os.sched_getaffinity(0))
        detected_cpu = min(detected_cpu, affinity)
    except (AttributeError, OSError):
        pass
    return {
        "memory_total_bytes": total,
        "memory_available_bytes": available,
        "swap_total_bytes": swap["swap_total_bytes"],
        "swap_used_bytes": swap["swap_used_bytes"],
        "zram_used_bytes": _zram_used(sysfs),
        "cpu_count": max(1, int(detected_cpu or 1)),
        "cgroup_memory_limit_bytes": limit,
        **pressure,
        "inspection": "procfs/sysfs where available; unavailable fields are null or zero",
    }


def select_threads(
    resources: dict[str, Any],
    *,
    explicit: int | None = None,
    low_memory: bool = False,
) -> tuple[int, str, list[str]]:
    warnings: list[str] = []
    available = resources.get("memory_available_bytes")
    total = resources.get("memory_total_bytes")
    cpus = max(1, int(resources.get("cpu_count") or 1))
    psi_full = resources.get("memory_psi_full_avg10")
    swap_total = int(resources.get("swap_total_bytes") or 0)
    swap_used = int(resources.get("swap_used_bytes") or 0)

    if explicit is not None:
        chosen = max(1, explicit)
        reason = f"explicit user override ({chosen})"
        if available is None and chosen > 1:
            warnings.append("The explicit thread override exceeds the conservative fallback because memory could not be measured.")
        elif chosen > 1:
            conservative = 1 if (total is not None and total <= 8 * GIB) or available < 4 * GIB else min(
                cpus, max(1, int((available - 3 * GIB) // (1.5 * GIB))), 4
            )
            if chosen > conservative:
                warnings.append(
                    f"The explicit {chosen}-thread override exceeds Lowkey's current conservative bound of {conservative}; "
                    "the user override is preserved, but memory exhaustion is more likely."
                )
        return chosen, reason, warnings
    if low_memory:
        return 1, "low-memory mode forces one compiler worker", warnings
    if available is None:
        warnings.append("Memory availability could not be measured; using one conservative compiler worker.")
        return 1, "resource data unavailable", warnings

    # This is a conservative concurrency guardrail, not a per-contract memory
    # estimate. Small hosts stay serial even when swap/zram is large.
    if (total is not None and total <= 8 * GIB) or available < 4 * GIB:
        chosen = 1
        reason = "small memory budget; serial compilation is the conservative default"
    else:
        pressure_high = psi_full is not None and psi_full >= 1.0
        swap_high = swap_total > 0 and swap_used / swap_total >= 0.75
        if pressure_high or swap_high:
            chosen = 1
            reason = "current memory pressure or swap use is elevated"
        else:
            budget_workers = max(1, int((available - 3 * GIB) // (1.5 * GIB)))
            chosen = min(cpus, budget_workers, 4)
            reason = "bounded by available memory, CPU availability and a conservative reserve"
    if available < 1.5 * GIB:
        warnings.append("Available memory may be too low even for one compiler process; narrow the scope before compiling.")
    elif available < 2 * GIB:
        warnings.append(
            "Available memory is below 2 GiB. Even one compiler process may be terminated; "
            "prefer --scope production or --target and inspect host memory pressure."
        )
    if psi_full is not None and psi_full >= 1.0:
        warnings.append("Memory PSI reports active full stalls; the host is already under memory pressure.")
    if swap_total > 0 and swap_used / swap_total >= 0.75:
        warnings.append("Swap is at least 75% used. Lowkey will not alter swap or retry a failed build.")
    return chosen, reason, warnings


def classify_build_failure(output: str, returncode: int, timed_out: bool = False) -> dict[str, Any]:
    lowered = str(output or "").lower()
    if timed_out:
        return {
            "category": "timeout",
            "reason": "Forge exceeded its bounded timeout. No source or security conclusion follows.",
        }
    oom_markers = (
        "out of memory", "oom-kill", "oom killer", "cannot allocate memory",
        "memory allocation failed", "killed process", "compiler killed",
        "resource temporarily unavailable",
    )
    if any(marker in lowered for marker in oom_markers):
        return {
            "category": "resource_exhaustion",
            "reason": "Compiler output contains a memory/resource exhaustion signal.",
        }
    if returncode in {-9, 137}:
        return {
            "category": "process_terminated",
            "reason": "The compiler process received SIGKILL (or exit 137). This may be OOM or an external kill; the exit code alone does not prove which.",
        }
    return {
        "category": "compiler_or_source_error",
        "reason": "Forge returned a build error without a recognized OOM/termination marker.",
    }


def build_plan(
    root: Path,
    *,
    scope: str = "full",
    target: str | None = None,
    forge_args: Sequence[str] = (),
    low_memory: bool = False,
) -> dict[str, Any]:
    profile = _profile_from_args(forge_args)
    config_path = _active_config_path(root, forge_args)
    config, config_source = load_foundry_config(root, profile, config_path)
    src_dirs = _config_dirs(config, "src", "src")
    test_dirs = _config_dirs(config, "test", "test")
    script_dirs = _config_dirs(config, "script", "script")
    scope_paths: list[str] = []
    if scope == "production":
        scope_paths = src_dirs
    elif scope == "tests":
        scope_paths = test_dirs
    elif scope == "scripts":
        scope_paths = script_dirs
    elif scope == "target":
        if not target:
            raise ValueError("--scope target requires --target <file|contract-name>")
        scope_paths = [_resolve_target(root, target, config)]
    elif scope != "full":
        raise ValueError(f"unsupported build scope: {scope}")

    checked_paths: list[str] = []
    for value in scope_paths:
        relative, path = _safe_scope_path(root, value)
        if not path.exists():
            raise ValueError(f"configured Foundry {scope} path does not exist: {value}")
        checked_paths.append(relative)

    resources = collect_resources()
    explicit_threads = _explicit_threads(forge_args)
    threads, thread_reason, warnings = select_threads(
        resources, explicit=explicit_threads, low_memory=low_memory
    )
    source_count = sum(_count_sources(root, item) for item in src_dirs)
    test_count = sum(_count_sources(root, item) for item in test_dirs)
    script_count = sum(_count_sources(root, item) for item in script_dirs)
    selected_scope_count = (
        sum(_count_sources(root, item) for item in checked_paths)
        if checked_paths else source_count + test_count + script_count
    )
    if selected_scope_count > 180:
        warnings.append(
            f"Selected scope inventories {selected_scope_count} source file(s) "
            f"({source_count} production, {test_count} test, {script_count} script in the package). "
            "Forge still resolves the transitive import closure, including remapped dependencies."
        )
        available = resources.get("memory_available_bytes")
        total = resources.get("memory_total_bytes")
        if available is None or available < 6 * GIB or (total is not None and total <= 8 * GIB):
            warnings.append(
                "This large scope may exceed available memory even with one compiler worker. "
                "Lowkey has no validated per-compiler memory estimate; narrow to --scope production "
                "or a focused --target if memory is tight."
            )
    if scope == "target":
        warnings.append(
            "Target file count excludes its transitive imports. Forge resolves that closure; "
            "Lowkey does not claim to estimate its total compiler memory."
        )

    forge_args_final = ["build", "--root", str(root)]
    forge_args_final.extend(checked_paths)
    if explicit_threads is None:
        forge_args_final.extend(["--threads", str(threads)])
    forge_args_final.extend(str(item) for item in forge_args)

    compiler = config.get("solc") or config.get("solc_version") or config.get("solc-version")
    cache_path = config.get("cache_path") or config.get("cache-path") or "cache"
    output_path = config.get("out") or "out"
    return {
        "project_root": str(root),
        "config_file": str(config_path),
        "config_source": config_source,
        "profile": profile,
        "compiler": str(compiler) if compiler is not None else "Foundry default / unresolved",
        "optimizer": config.get("optimizer", "Foundry default / unresolved"),
        "optimizer_runs": config.get("optimizer_runs", config.get("optimizer-runs", "Foundry default / unresolved")),
        "via_ir": config.get("via_ir", config.get("via-ir", "Foundry default / unresolved")),
        "src": src_dirs,
        "test": test_dirs,
        "script": script_dirs,
        "source_file_count": source_count,
        "test_file_count": test_count,
        "script_file_count": script_count,
        "scope": scope,
        "scope_paths": checked_paths,
        "remapping_count": len(config.get("remappings") or []),
        "out": str(output_path),
        "cache": str(cache_path),
        "cache_policy": "reuse existing Foundry cache and artifacts; no clean or cache deletion",
        "resources": resources,
        "threads": threads,
        "thread_reason": thread_reason,
        "warnings": warnings,
        "forge_args": forge_args_final,
        "side_effects": {
            "compile": True,
            "deploy": False,
            "transactions": False,
            "provider_upload": False,
            "cache_delete": False,
            "host_swap_change": False,
            "unrelated_process_kill": False,
        },
    }


def render_plan(plan: dict[str, Any]) -> str:
    resources = plan["resources"]
    def gib(value: Any) -> str:
        return "unknown" if value is None else f"{int(value) / GIB:.2f} GiB"
    lines = [
        "LOWKEY FOUNDRY BUILD PLAN",
        "=" * 72,
        f"Package root : {plan['project_root']}",
        f"Config       : {plan['config_file']}",
        f"Config read  : {plan['config_source']}",
        f"Profile      : {plan['profile']}",
        f"Compiler     : {plan['compiler']}",
        f"Optimizer    : {plan['optimizer']} (runs: {plan['optimizer_runs']})",
        f"via_ir       : {plan['via_ir']}",
        f"Source dirs  : {', '.join(plan['src'])}",
        f"Test dirs    : {', '.join(plan['test'])}",
        f"Script dirs  : {', '.join(plan['script'])}",
        f"Inventory    : {plan['source_file_count']} source / {plan['test_file_count']} test / {plan['script_file_count']} script files",
        f"Scope        : {plan['scope']}" + (f" -> {', '.join(plan['scope_paths'])}" if plan["scope_paths"] else " -> full project"),
        f"Cache        : reuse {plan['cache']} and {plan['out']}; no clean",
        "",
        "RESOURCE SNAPSHOT",
        "-----------------",
        f"RAM available: {gib(resources.get('memory_available_bytes'))} / {gib(resources.get('memory_total_bytes'))}",
        f"Swap used    : {gib(resources.get('swap_used_bytes'))} / {gib(resources.get('swap_total_bytes'))}",
        f"zram used    : {gib(resources.get('zram_used_bytes'))}",
        f"CPU workers  : {resources.get('cpu_count')}",
        f"Memory PSI   : some={resources.get('memory_psi_some_avg10')} full={resources.get('memory_psi_full_avg10')}",
        f"Forge threads: {plan['threads']} ({plan['thread_reason']})",
        "",
        "COMMAND",
        "-------",
        "forge " + " ".join(plan["forge_args"][1:]),
        "",
        "No compiler setting is changed. No deployment, transaction, provider upload, cache deletion, host swap change or unrelated process kill is planned.",
    ]
    if plan["warnings"]:
        lines += ["", "WARNINGS"] + [f"- {warning}" for warning in plan["warnings"]]
    return "\n".join(lines)


def _run_native_fallback(argv: Sequence[str]) -> int:
    script = Path(__file__).resolve().with_name("lk.py")
    if not script.is_file():
        print("Lowkey build: this is not a Foundry package and the native project router is unavailable.", file=sys.stderr)
        return 2
    return subprocess.run(
        [sys.executable, str(script), "build", *argv],
        cwd=Path.cwd(), check=False,
    ).returncode


def run_build(
    argv: Sequence[str],
    *,
    root: Path | None = None,
    fallback_to_native: bool = False,
) -> int:
    parser = argparse.ArgumentParser(
        prog="lk build",
        description="Plan and run a project-scoped Foundry build with conservative compiler concurrency.",
        epilog=(
            "Examples:\n"
            "  lk build --scope production\n"
            "  lk build --scope tests --plan\n"
            "  lk build --target TrancheVault --plan\n"
            "  lk build --scope full --low-memory\n"
            "  lk build --root packages/perps --scope production"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--root", help="project/package root; nested package config takes precedence over workspace selection")
    parser.add_argument("--member", help="explicit workspace member index, name, or path; saves the workspace-local selection")
    parser.add_argument("--scope", choices=("full", "production", "tests", "scripts", "target"), default="full")
    parser.add_argument("--target", help="source file path or unique contract name for --scope target")
    parser.add_argument("--low-memory", action="store_true", help="force one compiler worker")
    parser.add_argument("--plan", action="store_true", help="show the exact plan without compiling")
    parser.add_argument("--json", action="store_true", help="print the build plan as JSON")
    args, forge_args = parser.parse_known_args(list(argv))

    requested = Path(args.root).expanduser().resolve() if args.root else (root or Path.cwd()).expanduser().resolve()
    project, selection_error = _resolve_project_root(requested, member=args.member)
    if selection_error:
        print(f"Lowkey build: {selection_error}", file=sys.stderr)
        return 2
    if project is None or not (project / "foundry.toml").is_file():
        if fallback_to_native:
            return _run_native_fallback(argv)
        return forge_tools.die(f"Forge build requires a selected package-local foundry.toml: {project or requested}")

    if args.target and args.scope not in {"full", "target"}:
        return forge_tools.die("--target cannot be combined with a different --scope.")
    scope = "target" if args.target else args.scope
    try:
        plan = build_plan(
            project, scope=scope, target=args.target,
            forge_args=forge_args, low_memory=args.low_memory,
        )
    except (OSError, ValueError) as exc:
        return forge_tools.die(str(exc))

    if args.json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print(render_plan(plan))
    if args.plan:
        print("\nPlan only: no compiler was started and no build artifacts were changed.")
        return 0

    binary = forge_tools.forge_path()
    if not binary:
        return forge_tools.die("forge was not found on PATH. Install Foundry first.")
    command = [binary, *plan["forge_args"]]
    timeout = forge_tools._forge_timeout(plan["forge_args"])
    print("\nStarting Forge. Existing cache/artifacts will be reused; no automatic retry is performed.")
    try:
        completed, timed_out = forge_tools._run_bounded_process(
            command, project, capture_output=True, timeout=timeout,
        )
    except OSError as exc:
        return forge_tools.die(f"could not execute Forge: {exc}", 1)

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if stdout:
        print(stdout, end="" if stdout.endswith("\n") else "\n")
    if stderr:
        print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)

    returncode = 124 if timed_out else int(completed.returncode or 0)
    diagnostics = "\n".join(part for part in (stdout, stderr) if part)
    failure = classify_build_failure(diagnostics, returncode, timed_out)
    try:
        native_failure = bootstrap.classify_build_failure(diagnostics, command)
    except Exception:
        native_failure = {}
    status = "completed" if returncode == 0 else "failed"
    evidence = {
        "command": command,
        "exit_code": returncode,
        "scope": scope,
        "scope_paths": plan["scope_paths"],
        "profile": plan["profile"],
        "compiler": plan["compiler"],
        "threads": plan["threads"],
        "resource_snapshot": plan["resources"],
        "classification": failure,
        "native_build_classification": native_failure,
        "timeout": timed_out,
        "retry_performed": False,
        "cache_cleared": False,
    }
    audit_context.emit(
        "forge-build", project, tool="forge", status=status,
        summary=f"forge build ({scope})",
        data=evidence,
    )
    audit_context.record_tool(
        "forge-build", project, status=status,
        summary=f"forge build ({scope})",
        data=evidence,
    )
    if returncode == 0:
        print(f"\nBUILD PASSED: {scope} scope compiled. This is not a test run or an audit-completeness claim.")
        return 0
    print(f"\nBUILD FAILED: {failure['category']} — {failure['reason']}", file=sys.stderr)
    if failure["category"] in {"resource_exhaustion", "process_terminated"}:
        print(
            "Lowkey did not retry, clear caches, change compiler settings, alter swap or kill other processes. "
            "Narrow the scope and inspect kernel/cgroup logs if OOM is suspected.",
            file=sys.stderr,
        )
    return returncode if returncode > 0 else 1


def main(argv: list[str] | None = None) -> int:
    return run_build(list(sys.argv[1:] if argv is None else argv), fallback_to_native=True)


if __name__ == "__main__":
    raise SystemExit(main())
