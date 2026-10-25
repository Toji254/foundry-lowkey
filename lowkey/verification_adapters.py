"""Capability registry and common contract for Lowkey verification-tool adapters.

This module deliberately does not execute engines. It describes what is available,
what a project can support, and the evidence shape an adapter must return. Execution
and project-specific generation remain owned by their native engines.
"""
from __future__ import annotations

import shutil
import subprocess
import os
from importlib.metadata import entry_points
import signal
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


TEST_KINDS = (
    "unit", "integration", "invariant", "exploit", "regression", "fuzz", "formal"
)


@dataclass(frozen=True)
class EngineCapability:
    """Declarative capabilities of one engine/adapter."""

    name: str
    command: str
    test_kinds: tuple[str, ...]
    languages: tuple[str, ...] = ()
    build_systems: tuple[str, ...] = ()
    project_markers: tuple[str, ...] = ()
    requires_rpc: bool = False
    memory_class: str = "medium"
    notes: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("engine capability name must be a non-empty string")
        if not isinstance(self.command, str) or not self.command.strip():
            raise ValueError("engine capability command must be a non-empty string")
        if not isinstance(self.test_kinds, (tuple, list)):
            raise ValueError("engine capability test_kinds must be a tuple or list")
        if self.memory_class not in {"low", "medium", "high"}:
            raise ValueError(
                "engine capability memory_class must be one of: low, medium, high"
            )
        unknown_kinds = [
            kind for kind in self.test_kinds
            if not isinstance(kind, str) or kind not in TEST_KINDS
        ]
        if unknown_kinds:
            raise ValueError(
                "engine capability test_kinds contain unknown or non-string kinds: "
                + ", ".join(repr(kind) for kind in unknown_kinds)
            )


@dataclass
class EngineResult:
    """Normalized result with original evidence retained verbatim."""

    engine: str
    status: str
    exit_code: int | None = None
    summary: str = ""
    artifacts: list[str] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    raw_evidence: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)
    duration_seconds: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class ToolAdapter(Protocol):
    """Plugin contract. Implementations must not silently discard raw evidence."""

    capability: EngineCapability

    def available(self) -> bool:
        """Whether the required executable/runtime is available."""

    def supports(self, project: dict[str, Any], test_kind: str) -> tuple[bool, str]:
        """Return support decision and a human-readable reason."""

    def run(
        self, project: dict[str, Any], request: dict[str, Any], *,
        budget: dict[str, Any],
    ) -> EngineResult:
        """Run one bounded campaign and preserve native output/evidence."""


class ExecutableAdapter:
    """Minimal adapter base for tools whose availability is executable-based."""

    def __init__(self, capability: EngineCapability) -> None:
        self.capability = capability

    def available(self) -> bool:
        return shutil.which(self.capability.command) is not None

    def supports(self, project: dict[str, Any], test_kind: str) -> tuple[bool, str]:
        if test_kind not in self.capability.test_kinds:
            return False, f"{self.capability.name} does not implement {test_kind} tests"
        languages = {str(value).lower() for value in (project.get("languages") or [])}
        if project.get("language"):
            languages.add(str(project["language"]).lower())
        if self.capability.languages and not languages.intersection(self.capability.languages):
            return False, f"languages {', '.join(sorted(languages)) or 'unknown'} are unsupported"
        build_systems = {str(value).lower() for value in (project.get("build_systems") or [])}
        if project.get("build_system"):
            build_systems.add(str(project["build_system"]).lower())
        if self.capability.build_systems and not build_systems.intersection(self.capability.build_systems):
            return False, f"build systems {', '.join(sorted(build_systems)) or 'unknown'} are unsupported"
        markers = set(project.get("markers") or [])
        if self.capability.project_markers and not markers.intersection(self.capability.project_markers):
            return False, "required project markers were not detected"
        if not self.available():
            return False, f"required executable '{self.capability.command}' is unavailable"
        return True, "supported by detected project/tool capabilities"

    def run(
        self, project: dict[str, Any], request: dict[str, Any], *,
        budget: dict[str, Any],
    ) -> EngineResult:
        """Run a bounded native command without a shell.

        Native argument construction is explicit: the registry never guesses
        an engine's target/harness syntax or silently claims a proof.
        """
        root_value = project.get("root")
        if not root_value:
            return EngineResult(self.capability.name, "unsupported", summary="project root is required")
        root = Path(str(root_value)).expanduser().resolve()
        if not root.is_dir():
            return EngineResult(self.capability.name, "unsupported", summary=f"project root is not a directory: {root}")
        test_kind = str(request.get("test_kind") or "")
        available, reason = self.supports(project, test_kind)
        if not available:
            return EngineResult(self.capability.name, "unsupported", summary=reason)
        raw_args = request.get("argv")
        if raw_args is None and self.capability.name == "forge":
            raw_args = ["test"]
        if not isinstance(raw_args, list) or not all(isinstance(arg, str) for arg in raw_args):
            return EngineResult(
                self.capability.name, "unsupported",
                summary="request.argv must be a list of native CLI arguments; no shell is used",
            )
        try:
            timeout = max(1, min(int(budget.get("timeout_seconds", 120)), 7200))
        except (TypeError, ValueError):
            timeout = 120
        command = [self.capability.command, *raw_args]
        started_at = time.monotonic()
        try:
            output_limit = max(1024, min(int(budget.get("max_output_bytes", 262144)), 4194304))
        except (TypeError, ValueError):
            output_limit = 262144

        captured = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = {"stdout": False, "stderr": False}
        orphan_process_group_terminated = False
        reader_threads_stuck = False

        def drain(pipe: Any, name: str) -> None:
            # Drain continuously to avoid child-process deadlock, but retain only
            # a bounded prefix so noisy fuzzers/solvers cannot exhaust RAM.
            while True:
                chunk = pipe.read(65536)
                if not chunk:
                    break
                remaining = output_limit - len(captured[name])
                if remaining > 0:
                    captured[name].extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    truncated[name] = True
            pipe.close()

        try:
            process = subprocess.Popen(
                command, cwd=root, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False,
                bufsize=0, start_new_session=(os.name == "posix"),
            )
            readers = [
                threading.Thread(target=drain, args=(process.stdout, "stdout"), daemon=True),
                threading.Thread(target=drain, args=(process.stderr, "stderr"), daemon=True),
            ]
            for reader in readers:
                reader.start()
            try:
                process.wait(timeout=timeout)
                code = process.returncode
                status = "passed" if code == 0 else "failed"
            except subprocess.TimeoutExpired:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGTERM)
                    else:
                        process.kill()
                except OSError:
                    pass
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        if os.name == "posix":
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                    except OSError:
                        pass
                    process.wait()
                code, status = 124, "timeout"
            # A tool may exit while a child it spawned still holds inherited
            # stdout/stderr pipes open. Do not leave daemon drain threads or
            # background descendants behind after a campaign.
            for reader in readers:
                reader.join(timeout=0.25)
            if any(reader.is_alive() for reader in readers):
                reader_threads_stuck = True
                if os.name == "posix":
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        orphan_process_group_terminated = True
                    except OSError:
                        pass
                    for reader in readers:
                        reader.join(timeout=1)
                    if any(reader.is_alive() for reader in readers):
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                            orphan_process_group_terminated = True
                        except OSError:
                            pass
                for reader in readers:
                    reader.join(timeout=1)
            stdout = bytes(captured["stdout"]).decode("utf-8", errors="replace")
            stderr = bytes(captured["stderr"]).decode("utf-8", errors="replace")
            marker = "\n[LOWKEY_OUTPUT_TRUNCATED; retained at most output_limit_bytes]"
            if truncated["stdout"]:
                stdout += marker
            if truncated["stderr"]:
                stderr += marker
            if status == "timeout":
                stderr += f"\nLOWKEY_TIMEOUT_SECONDS={timeout}"
        except OSError as exc:
            return EngineResult(self.capability.name, "error", exit_code=127, summary=str(exc))
        return EngineResult(
            engine=self.capability.name, status=status, exit_code=code,
            summary=f"{' '.join(command)} exited with {code}",
            duration_seconds=round(time.monotonic() - started_at, 6),
            raw_stdout=stdout, raw_stderr=stderr,
            raw_evidence={
                "argv": command, "cwd": str(root), "timeout_seconds": timeout,
                "output_limit_bytes": output_limit,
                "stdout_truncated": truncated["stdout"],
                "stderr_truncated": truncated["stderr"],
                "orphan_process_group_terminated": orphan_process_group_terminated,
                "reader_threads_stuck_after_cleanup": any(reader.is_alive() for reader in readers),
            },
            metadata={"test_kind": test_kind, "project": str(root)},
        )


class NativeConfiguredAdapter(ExecutableAdapter):
    """Adapter with a conservative native command builder for a known engine."""

    def request_configuration(
        self, project: dict[str, Any], request: dict[str, Any],
    ) -> tuple[list[str] | None, str]:
        explicit = request.get("argv")
        if isinstance(explicit, list) and all(isinstance(arg, str) for arg in explicit):
            return explicit, "explicit native argv supplied"
        if explicit is not None:
            return None, "request.argv must be a list of native CLI argument strings"
        return None, "engine-specific configuration is required"

    def request_ready(self, project: dict[str, Any], request: dict[str, Any]) -> tuple[bool, str]:
        argv, reason = self.request_configuration(project, request)
        return argv is not None, reason

    def run(
        self, project: dict[str, Any], request: dict[str, Any], *,
        budget: dict[str, Any],
    ) -> EngineResult:
        prepared = dict(request)
        if "argv" not in prepared:
            argv, reason = self.request_configuration(project, prepared)
            if argv is None:
                return EngineResult(self.capability.name, "unsupported", summary=reason)
            prepared["argv"] = argv
        return super().run(project, prepared, budget=budget)


def _project_file(root_value: Any, value: Any, *, suffix: str | None = None) -> tuple[str | None, str]:
    """Resolve an existing project-relative config/target without path traversal."""
    if not isinstance(root_value, (str, Path)) or not root_value:
        return None, "project root is required"
    if not isinstance(value, str) or not value.strip():
        return None, "a project-relative file path is required"
    raw = Path(value)
    if raw.is_absolute() or ".." in raw.parts:
        return None, "file path must be relative to the project root and must not contain '..'"
    root = Path(root_value).expanduser().resolve()
    resolved = (root / raw).resolve()
    if not resolved.is_relative_to(root):
        return None, "file path escapes the project root"
    if not resolved.is_file():
        return None, f"file does not exist: {value}"
    if suffix and resolved.suffix.lower() != suffix:
        return None, f"file must use the {suffix} suffix: {value}"
    return str(raw), ""


class EchidnaAdapter(NativeConfiguredAdapter):
    def request_configuration(self, project: dict[str, Any], request: dict[str, Any]) -> tuple[list[str] | None, str]:
        explicit, reason = super().request_configuration(project, request)
        if explicit is not None or request.get("argv") is not None:
            return explicit, reason
        target, reason = _project_file(project.get("root"), request.get("target"))
        if target is None:
            return None, "Echidna requires request.target pointing to a Solidity harness file; " + reason
        argv = [target]
        contract = request.get("contract")
        if contract:
            if not isinstance(contract, str) or not contract.strip():
                return None, "request.contract must be a non-empty contract name"
            argv.extend(["--contract", contract])
        config = request.get("config")
        if config:
            config_path, reason = _project_file(project.get("root"), config, suffix=".yaml")
            if config_path is None:
                config_path, reason = _project_file(project.get("root"), config, suffix=".yml")
            if config_path is None:
                return None, "Echidna config is invalid: " + reason
            argv.extend(["--config", config_path])
        return argv, "Echidna harness and optional config validated"


class MedusaAdapter(NativeConfiguredAdapter):
    def request_configuration(self, project: dict[str, Any], request: dict[str, Any]) -> tuple[list[str] | None, str]:
        explicit, reason = super().request_configuration(project, request)
        if explicit is not None or request.get("argv") is not None:
            return explicit, reason
        config = request.get("config") or "medusa.json"
        config_path, reason = _project_file(project.get("root"), config, suffix=".json")
        if config_path is None:
            return None, "Medusa requires a valid medusa.json-style config; " + reason
        argv = ["fuzz", "--config", config_path]
        target_contracts = request.get("target_contracts")
        if target_contracts:
            if isinstance(target_contracts, str):
                target_contracts = [target_contracts]
            if not isinstance(target_contracts, list) or not all(
                isinstance(item, str) and item.strip() for item in target_contracts
            ):
                return None, "request.target_contracts must be a string or list of contract names"
            argv.extend(["--target-contracts", ", ".join(target_contracts)])
        timeout = request.get("engine_timeout_seconds")
        if timeout is not None:
            try:
                timeout = int(timeout)
            except (TypeError, ValueError):
                return None, "request.engine_timeout_seconds must be an integer"
            if timeout < 1:
                return None, "request.engine_timeout_seconds must be positive"
            argv.extend(["--timeout", str(timeout)])
        return argv, "Medusa config and optional target overrides validated"


class HalmosAdapter(NativeConfiguredAdapter):
    def request_configuration(self, project: dict[str, Any], request: dict[str, Any]) -> tuple[list[str] | None, str]:
        explicit, reason = super().request_configuration(project, request)
        if explicit is not None or request.get("argv") is not None:
            return explicit, reason
        function = request.get("function", "test")
        if not isinstance(function, str) or not function.strip():
            return None, "request.function must be a non-empty function filter"
        return ["--function", function], "Foundry/Halmos function filter selected"


class CertoraAdapter(NativeConfiguredAdapter):
    def request_configuration(self, project: dict[str, Any], request: dict[str, Any]) -> tuple[list[str] | None, str]:
        explicit, reason = super().request_configuration(project, request)
        if explicit is not None or request.get("argv") is not None:
            return explicit, reason
        config_path, reason = _project_file(project.get("root"), request.get("config"), suffix=".conf")
        if config_path is None:
            return None, "Certora requires an existing JSON5 .conf file; " + reason
        return [config_path], "Certora configuration file validated"

    def run(
        self, project: dict[str, Any], request: dict[str, Any], *,
        budget: dict[str, Any],
    ) -> EngineResult:
        result = super().run(project, request, budget=budget)
        if result.status == "passed":
            # A zero CLI exit may only mean that a remote verification job was
            # submitted; do not misreport it as a proven property.
            result.status = "submitted"
            result.summary = "Certora CLI exited successfully; proof outcome is not established by this exit code"
            result.metadata["result_semantics"] = "cli_success_is_not_proof_success"
        return result


class CapabilityRegistry:
    """Registry for adapters; selection is capability- and budget-driven."""

    def __init__(self, adapters: list[ToolAdapter] | None = None) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        self.plugin_errors: list[dict[str, str]] = []
        for adapter in adapters or []:
            self.register(adapter)

    def _request_ready(
        self, name: str, adapter: ToolAdapter, project: dict[str, Any],
        request: dict[str, Any],
    ) -> tuple[bool, str]:
        checker = getattr(adapter, "request_ready", None)
        if not callable(checker):
            raw_args = request.get("argv")
            if name == "forge" or (
                isinstance(raw_args, list) and all(isinstance(arg, str) for arg in raw_args)
            ):
                return True, "explicit native argv supplied"
            return False, "explicit native argv/harness configuration is required for this engine"
        try:
            decision = checker(project, request)
            if not isinstance(decision, tuple) or len(decision) != 2 or not isinstance(decision[0], bool):
                raise TypeError("request_ready() must return (bool, reason)")
            return decision[0], str(decision[1])
        except Exception as exc:
            self._record_adapter_error(name, "request_ready()", exc)
            return False, f"adapter configuration check failed: {type(exc).__name__}: {exc}"

    def register(self, adapter: ToolAdapter) -> None:
        name = adapter.capability.name.strip().lower()
        if not name:
            raise ValueError("adapter capability name must not be empty")
        if name in self._adapters:
            raise ValueError(f"adapter already registered: {name}")
        self._adapters[name] = adapter

    def _record_adapter_error(self, name: str, phase: str, exc: Exception) -> None:
        entry = {
            "plugin": name,
            "error": f"{phase} raised {type(exc).__name__}: {exc}",
        }
        if entry not in self.plugin_errors:
            self.plugin_errors.append(entry)

    def _safe_available(self, name: str, adapter: ToolAdapter) -> bool:
        try:
            return bool(adapter.available())
        except Exception as exc:
            self._record_adapter_error(name, "available()", exc)
            return False

    def _safe_supports(
        self, name: str, adapter: ToolAdapter, project: dict[str, Any],
        test_kind: str,
    ) -> tuple[bool, str, bool]:
        try:
            decision = adapter.supports(project, test_kind)
            if (
                not isinstance(decision, tuple) or len(decision) != 2
                or not isinstance(decision[0], bool)
            ):
                raise TypeError("supports() must return (bool, reason)")
            return decision[0], str(decision[1]), False
        except Exception as exc:
            self._record_adapter_error(name, "supports()", exc)
            return False, f"adapter capability check failed: {type(exc).__name__}: {exc}", True

    def inventory(self) -> list[dict[str, Any]]:
        rows = []
        for name in sorted(self._adapters):
            adapter = self._adapters[name]
            cap = adapter.capability
            rows.append({
                **asdict(cap),
                "available": self._safe_available(name, adapter),
            })
        return rows

    def support_matrix(self, project: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """Return availability and explicit per-kind compatibility reasons."""
        matrix: dict[str, dict[str, Any]] = {}
        for name, adapter in sorted(self._adapters.items()):
            kinds: dict[str, dict[str, Any]] = {}
            for kind in adapter.capability.test_kinds:
                supported, reason, _ = self._safe_supports(name, adapter, project, kind)
                kinds[kind] = {"supported": supported, "reason": reason}
            matrix[name] = {
                "available": self._safe_available(name, adapter),
                "test_kinds": kinds,
                "notes": adapter.capability.notes,
            }
        return matrix

    def plan(
        self, project: dict[str, Any], test_kind: str, *,
        profile: str = "balanced",
        request: dict[str, Any] | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Explain all selected and rejected engines for one bounded campaign."""
        if test_kind not in TEST_KINDS:
            raise ValueError(f"unknown test kind: {test_kind}")
        profiles = {
            "light": {"low"},
            "balanced": {"low", "medium"},
            "deep": {"low", "medium", "high"},
        }
        if profile not in profiles:
            raise ValueError(f"unknown resource profile: {profile}")
        selected: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        order = {"low": 0, "medium": 1, "high": 2}
        for name, adapter in self._adapters.items():
            cap = adapter.capability
            ok, reason, adapter_error = self._safe_supports(name, adapter, project, test_kind)
            if not ok:
                rejected.append({
                    "engine": name, "test_kind": test_kind,
                    "memory_class": cap.memory_class,
                    "status": "adapter_error" if adapter_error else "unsupported",
                    "reason": reason,
                })
                continue
            if request is not None and name != "forge":
                per_engine = request.get("argv_by_engine") or {}
                engine_request = dict(request)
                engine_request.pop("argv_by_engine", None)
                if isinstance(per_engine, dict) and name in per_engine:
                    engine_request["argv"] = per_engine[name]
                configured, config_reason = self._request_ready(name, adapter, project, engine_request)
                if not configured:
                    rejected.append({
                        "engine": name, "test_kind": test_kind,
                        "memory_class": cap.memory_class, "status": "missing_configuration",
                        "reason": config_reason,
                    })
                    continue
            if cap.memory_class not in profiles[profile]:
                rejected.append({
                    "engine": name, "test_kind": test_kind,
                    "memory_class": cap.memory_class, "status": "profile_excluded",
                    "reason": f"{cap.memory_class}-memory engine excluded by {profile} profile",
                })
                continue
            selected.append({
                "engine": name, "test_kind": test_kind,
                "memory_class": cap.memory_class, "status": "selected",
                "reason": reason,
            })
        key = lambda row: (order.get(row["memory_class"], 3), row["engine"])
        return {
            "selected": sorted(selected, key=key),
            "rejected": sorted(rejected, key=key),
        }

    def select(
        self, project: dict[str, Any], test_kind: str, *,
        profile: str = "balanced",
    ) -> list[dict[str, Any]]:
        return self.plan(project, test_kind, profile=profile)["selected"]


    def run_campaign(
        self, project: dict[str, Any], test_kind: str, *,
        request: dict[str, Any] | None = None,
        budget: dict[str, Any] | None = None,
        profile: str = "balanced",
    ) -> dict[str, Any]:
        """Execute compatible engines serially and preserve every native result.

        Per-engine native CLI arguments may be supplied in request.argv_by_engine.
        Missing arguments never trigger guessed Echidna/Medusa/solver configuration.
        """
        campaign_started_at = time.monotonic()
        request = dict(request or {})
        budget = dict(budget or {})
        plan = self.plan(project, test_kind, profile=profile, request=request)
        selected = plan["selected"]
        profile_limits = {
            "light": {"timeout_seconds": 60, "fuzz_runs": 32, "invariant_runs": 16, "invariant_depth": 10},
            "balanced": {"timeout_seconds": 300, "fuzz_runs": 256, "invariant_runs": 64, "invariant_depth": 20},
            "deep": {"timeout_seconds": 900, "fuzz_runs": 1024, "invariant_runs": 256, "invariant_depth": 50},
        }
        limits = profile_limits[profile]
        budget.setdefault("timeout_seconds", limits["timeout_seconds"])
        by_name = {name: adapter for name, adapter in self._adapters.items()}
        results: list[dict[str, Any]] = []
        argv_by_engine = request.get("argv_by_engine") or {}
        if not isinstance(argv_by_engine, dict):
            raise ValueError("request.argv_by_engine must be a mapping of engine name to argv list")
        for candidate in selected:
            name = candidate["engine"]
            engine_request = dict(request)
            engine_request.pop("argv_by_engine", None)
            engine_request["test_kind"] = test_kind
            if name in argv_by_engine:
                engine_request["argv"] = argv_by_engine[name]
            elif "argv" not in engine_request and name == "forge":
                if test_kind == "fuzz":
                    engine_request["argv"] = ["test", "--fuzz-runs", str(limits["fuzz_runs"])]
                elif test_kind == "invariant":
                    engine_request["argv"] = [
                        "test", "--invariant-runs", str(limits["invariant_runs"]),
                        "--invariant-depth", str(limits["invariant_depth"]),
                    ]
            engine_started_at = time.monotonic()
            try:
                result = by_name[name].run(project, engine_request, budget=budget)
                if result.duration_seconds is None:
                    result.duration_seconds = round(time.monotonic() - engine_started_at, 6)
            except Exception as exc:
                # One broken adapter must not erase evidence from the rest of a campaign.
                result = EngineResult(
                    engine=name,
                    status="error",
                    summary=f"adapter raised {type(exc).__name__}: {exc}",
                    raw_evidence={"exception_type": type(exc).__name__},
                    duration_seconds=round(time.monotonic() - engine_started_at, 6),
                )
            results.append({
                "selection": candidate,
                "result": result.to_dict(),
            })
        return {
            "profile": profile,
            "test_kind": test_kind,
            "execution_mode": "serial",
            "duration_seconds": round(time.monotonic() - campaign_started_at, 6),
            "engine_duration_seconds": round(sum(
                row["result"].get("duration_seconds") or 0 for row in results
            ), 6),
            "selected_count": len(selected),
            "considered_engines": plan["selected"] + plan["rejected"],
            "plugin_errors": list(self.plugin_errors),
            "results": results,
            "summary": {
                "passed": sum(row["result"]["status"] == "passed" for row in results),
                "submitted": sum(row["result"]["status"] == "submitted" for row in results),
                "failed": sum(row["result"]["status"] == "failed" for row in results),
                "timeout": sum(row["result"]["status"] == "timeout" for row in results),
                "unsupported": sum(row["result"]["status"] == "unsupported" for row in results),
                "error": sum(row["result"]["status"] == "error" for row in results),
            },
        }


def inspect_project(root: str | Path) -> dict[str, Any]:
    """Detect project markers, languages, and build systems without network access."""
    project_root = Path(root).expanduser().resolve()
    if not project_root.is_dir():
        raise ValueError(f"project root is not a directory: {project_root}")
    marker_names = {
        "foundry.toml", "brownie-config.yaml", "brownie-config.yml",
        "Cargo.toml", "go.mod", "pyproject.toml", "requirements.txt",
        "pom.xml", "build.gradle", "build.gradle.kts", "package.json",
        "hardhat.config.js", "hardhat.config.cjs", "hardhat.config.ts",
        "hardhat.config.mjs", "truffle-config.js", "ape-config.yaml",
        "Move.toml", "Scarb.toml", "soroban",
    }
    markers = sorted(
        name for name in marker_names
        if (project_root / name).exists()
    )
    if any(project_root.glob("hardhat.config.*")):
        markers.extend(name for name in ["hardhat.config"] if name not in markers)
    build_systems: list[str] = []
    if "foundry.toml" in markers:
        build_systems.append("foundry")
    if any(name.startswith("hardhat.config") for name in markers) or "hardhat.config" in markers:
        build_systems.append("hardhat")
    if any(name.startswith("brownie-config") for name in markers):
        build_systems.append("brownie")
    if "package.json" in markers:
        build_systems.append("npm")
    if "Cargo.toml" in markers:
        build_systems.append("cargo")
    if "go.mod" in markers:
        build_systems.append("go")
    if "pyproject.toml" in markers or "requirements.txt" in markers:
        build_systems.append("python")
    if "pom.xml" in markers or "build.gradle" in markers or "build.gradle.kts" in markers:
        build_systems.append("jvm")
    if "Move.toml" in markers:
        build_systems.append("move")
    if "Scarb.toml" in markers:
        build_systems.append("scarb")
    ignored = {
        ".git", ".venv", "venv", "node_modules", "vendor", "lib", "target",
        "build", "dist", "out", "cache", ".audit", "__pycache__", ".pytest_cache",
    }
    suffix_languages = {
        ".sol": "solidity", ".vy": "vyper", ".rs": "rust", ".go": "go",
        ".py": "python", ".ts": "typescript", ".tsx": "typescript",
        ".js": "javascript", ".jsx": "javascript", ".java": "java",
        ".move": "move", ".cairo": "cairo",
    }
    languages: set[str] = set()
    for directory, dirnames, filenames in os.walk(project_root):
        dirnames[:] = [name for name in dirnames if name not in ignored]
        for filename in filenames:
            suffix = Path(filename).suffix.lower()
            if suffix in suffix_languages:
                languages.add(suffix_languages[suffix])
    if "foundry" in build_systems or "hardhat" in build_systems or "brownie" in build_systems:
        if any(language == "solidity" for language in languages):
            languages.add("solidity")
    return {
        "root": str(project_root),
        "markers": sorted(set(markers)),
        "languages": sorted(languages),
        "language": sorted(languages)[0] if languages else "",
        "build_systems": sorted(set(build_systems)),
        "build_system": build_systems[0] if build_systems else "",
    }


def default_registry(*, load_plugins: bool = True) -> CapabilityRegistry:
    """Build builtin adapters and load optional Python entry-point plugins.

    Third-party packages register factories in the lowkey.verification_adapters
    entry-point group. A factory returns one ToolAdapter or a list/tuple of
    adapters. Plugin failures are retained for inspection.
    """
    adapters: list[ToolAdapter] = [
        ExecutableAdapter(EngineCapability("forge", "forge", ("unit", "integration", "invariant", "exploit", "regression", "fuzz"), ("solidity",), ("foundry",), ("foundry.toml",), memory_class="low", notes="Native Forge tests/fuzz/invariant; formal proof is not implied.")),
        EchidnaAdapter(EngineCapability("echidna", "echidna", ("invariant", "fuzz"), ("solidity",), ("foundry", "hardhat"), memory_class="medium", notes="Requires an explicit harness source; config is optional.")),
        MedusaAdapter(EngineCapability("medusa", "medusa", ("invariant", "fuzz"), ("solidity",), ("foundry", "hardhat"), memory_class="medium", notes="Uses medusa.json and native medusa fuzz command.")),
        HalmosAdapter(EngineCapability("halmos", "halmos", ("formal", "unit", "regression"), ("solidity",), ("foundry",), memory_class="high", notes="Symbolic testing; bounded by solver/model assumptions.")),
        CertoraAdapter(EngineCapability("certora", "certoraRun", ("formal",), ("solidity",), memory_class="high", notes="Requires an explicit .conf; successful CLI exit is not proof success.")),
        ExecutableAdapter(EngineCapability("slither", "slither", (), ("solidity",), ("foundry", "hardhat", "brownie"), memory_class="low", notes="Static analysis, not a test executor or formal proof engine.")),
    ]
    registry = CapabilityRegistry(adapters)
    if load_plugins:
        try:
            points = entry_points().select(group="lowkey.verification_adapters")
        except Exception as exc:
            registry.plugin_errors.append({
                "plugin": "entry-point-discovery",
                "error": f"{type(exc).__name__}: {exc}",
            })
            points = ()
        for point in points:
            try:
                factory = point.load()
                provided = factory()
                candidates = list(provided) if isinstance(provided, (list, tuple)) else [provided]
                for adapter in candidates:
                    if not hasattr(adapter, "capability") or not all(
                        callable(getattr(adapter, method, None))
                        for method in ("available", "supports", "run")
                    ):
                        raise TypeError("plugin factory must return objects implementing ToolAdapter")
                    registry.register(adapter)
            except Exception as exc:
                registry.plugin_errors.append({
                    "plugin": point.name,
                    "error": f"{type(exc).__name__}: {exc}",
                })
    return registry
