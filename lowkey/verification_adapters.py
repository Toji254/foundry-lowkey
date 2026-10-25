"""Capability registry and common contract for Lowkey verification-tool adapters.

This module deliberately does not execute engines. It describes what is available,
what a project can support, and the evidence shape an adapter must return. Execution
and project-specific generation remain owned by their native engines.
"""
from __future__ import annotations

import shutil
import subprocess
import os
import signal
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
        language = str(project.get("language") or "").lower()
        if self.capability.languages and language not in self.capability.languages:
            return False, f"language {language or 'unknown'} is unsupported"
        build = str(project.get("build_system") or "").lower()
        if self.capability.build_systems and build not in self.capability.build_systems:
            return False, f"build system {build or 'unknown'} is unsupported"
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
        try:
            process = subprocess.Popen(
                command, cwd=root, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                start_new_session=(os.name == "posix"),
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
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
                    stdout, stderr = process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        if os.name == "posix":
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                    except OSError:
                        pass
                    stdout, stderr = process.communicate()
                code, status = 124, "timeout"
                stderr = (stderr or "") + f"\nLOWKEY_TIMEOUT_SECONDS={timeout}"
        except OSError as exc:
            return EngineResult(self.capability.name, "error", exit_code=127, summary=str(exc))
        return EngineResult(
            engine=self.capability.name, status=status, exit_code=code,
            summary=f"{' '.join(command)} exited with {code}",
            raw_stdout=stdout or "", raw_stderr=stderr or "",
            raw_evidence={"argv": command, "cwd": str(root), "timeout_seconds": timeout},
            metadata={"test_kind": test_kind, "project": str(root)},
        )


class CapabilityRegistry:
    """Registry for adapters; selection is capability- and budget-driven."""

    def __init__(self, adapters: list[ToolAdapter] | None = None) -> None:
        self._adapters: dict[str, ToolAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: ToolAdapter) -> None:
        name = adapter.capability.name.strip().lower()
        if not name:
            raise ValueError("adapter capability name must not be empty")
        if name in self._adapters:
            raise ValueError(f"adapter already registered: {name}")
        self._adapters[name] = adapter

    def inventory(self) -> list[dict[str, Any]]:
        rows = []
        for name in sorted(self._adapters):
            adapter = self._adapters[name]
            cap = adapter.capability
            rows.append({
                **asdict(cap),
                "available": bool(adapter.available()),
            })
        return rows

    def select(
        self, project: dict[str, Any], test_kind: str, *,
        profile: str = "balanced",
    ) -> list[dict[str, Any]]:
        """Return eligible engines, preferring lightweight tools on constrained runs."""
        if test_kind not in TEST_KINDS:
            raise ValueError(f"unknown test kind: {test_kind}")
        profiles = {
            "light": {"low"},
            "balanced": {"low", "medium"},
            "deep": {"low", "medium", "high"},
        }
        if profile not in profiles:
            raise ValueError(f"unknown resource profile: {profile}")
        allowed = profiles[profile]
        candidates = []
        for name, adapter in self._adapters.items():
            cap = adapter.capability
            ok, reason = adapter.supports(project, test_kind)
            if not ok:
                continue
            if cap.memory_class not in allowed:
                continue
            candidates.append({
                "engine": name,
                "test_kind": test_kind,
                "memory_class": cap.memory_class,
                "reason": reason,
            })
        order = {"low": 0, "medium": 1, "high": 2}
        return sorted(candidates, key=lambda row: (order.get(row["memory_class"], 3), row["engine"]))


def default_registry() -> CapabilityRegistry:
    """Describe common engines without claiming they are installed or runnable."""
    specs = [
        EngineCapability("forge", "forge", ("unit", "integration", "invariant", "exploit", "regression", "fuzz"), ("solidity",), ("foundry",), ("foundry.toml",), memory_class="low", notes="Native Forge tests/fuzz/invariant; formal proof is not implied."),
        EngineCapability("echidna", "echidna", ("invariant", "fuzz"), ("solidity",), ("foundry", "hardhat"), memory_class="medium", notes="Property-based smart-contract fuzzing."),
        EngineCapability("medusa", "medusa", ("invariant", "fuzz"), ("solidity",), ("foundry", "hardhat"), memory_class="medium", notes="Coverage-guided EVM fuzzing."),
        EngineCapability("halmos", "halmos", ("formal", "unit", "regression"), ("solidity",), ("foundry",), memory_class="high", notes="Symbolic testing; bounded by solver/model assumptions."),
        EngineCapability("certora", "certoraRun", ("formal",), ("solidity",), memory_class="high", notes="Requires configured rules/specifications and external service/tool setup."),
        EngineCapability("slither", "slither", (), ("solidity",), ("foundry", "hardhat", "brownie"), memory_class="low", notes="Static analysis, not a test executor or formal proof engine."),
    ]
    adapters: list[ToolAdapter] = [ExecutableAdapter(spec) for spec in specs]
    return CapabilityRegistry(adapters)
