"""Pluggable stateful walkthrough benchmark adapters.

The walkthrough core owns project modeling, transaction execution, evidence,
snapshot isolation, and rendering. Protocol-specific benchmark adapters are
registered by the caller; Lowkey ships no project-specific benchmark logic.
"""

from __future__ import annotations

from typing import Any, Protocol

try:
    from . import walkthrough as core
except ImportError:
    import walkthrough as core


class WalkthroughBenchmarkAdapter(Protocol):
    adapter_id: str
    display_name: str

    def matches(
        self,
        model: core.ContractModel,
        models: list[core.ContractModel],
        config: dict[str, Any],
    ) -> bool: ...

    def prepare(
        self,
        root: Any,
        config: dict[str, Any],
        host: Any,
        rpc: str,
        actors: list[core.Actor],
        model: core.ContractModel,
        models: list[core.ContractModel],
    ) -> tuple[dict[str, Any] | None, str | None]: ...

    def build_stories(
        self,
        config: dict[str, Any],
        actors: list[core.Actor],
        target: dict[str, Any],
    ) -> list[core.WalkthroughStory]: ...

    def warmup_steps(
        self,
        config: dict[str, Any],
        actors: list[core.Actor],
        model: core.ContractModel,
        now: int,
    ) -> list[core.Step]: ...

    def workflow_steps(
        self,
        config: dict[str, Any],
        actors: list[core.Actor],
        model: core.ContractModel,
        target: str,
        now: int,
    ) -> list[core.Step]: ...

    def manages_child_prerequisites(self, model: core.ContractModel) -> bool: ...

    def observe_step(
        self,
        story: core.WalkthroughStory,
        step: core.Step,
        rpc: str,
        target: dict[str, Any],
        actors: list[core.Actor],
    ) -> None: ...

    def assess(
        self,
        story: core.WalkthroughStory,
        story_steps: list[core.Step],
        rpc: str,
        target: dict[str, Any],
        actors: list[core.Actor],
    ) -> None: ...


_REGISTERED_BENCHMARK_ADAPTERS: list[type] = []


def register_benchmark_adapter(adapter_type: type) -> type:
    """Register a caller-provided benchmark adapter."""
    if adapter_type not in _REGISTERED_BENCHMARK_ADAPTERS:
        _REGISTERED_BENCHMARK_ADAPTERS.append(adapter_type)
    return adapter_type


def get_benchmark_adapter(
    model: core.ContractModel,
    models: list[core.ContractModel],
    config: dict[str, Any],
) -> WalkthroughBenchmarkAdapter | None:
    """Return the first caller-registered adapter matching the project."""
    for adapter_type in _REGISTERED_BENCHMARK_ADAPTERS:
        try:
            adapter = adapter_type()
        except TypeError:
            continue
        if adapter.matches(model, models, config):
            return adapter
    return None
