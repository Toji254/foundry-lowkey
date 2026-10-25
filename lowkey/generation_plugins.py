"""Plugin contract and routing for project-specific test artifact generators.

Generator plugins produce reviewable drafts and must describe the properties they
actually encoded. A generated file is never assumed to be a valid test or proof.
"""
from __future__ import annotations

import contextlib
import io
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class GenerationCapability:
    name: str
    languages: tuple[str, ...]
    build_systems: tuple[str, ...]
    artifact_kinds: tuple[str, ...]
    notes: str = ""


@dataclass
class GeneratedArtifact:
    kind: str
    path: str
    status: str
    intended_property: str | None = None
    expected_behavior: str | None = None
    assumptions: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GenerationRun:
    generator: str
    status: str
    artifacts: list[GeneratedArtifact] = field(default_factory=list)
    report_path: str | None = None
    stdout: str = ""
    stderr: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class GenerationAdapter(Protocol):
    capability: GenerationCapability

    def supports(self, project: dict[str, Any]) -> tuple[bool, str]:
        """Explain whether this generator supports the detected project."""

    def generate(self, project: dict[str, Any], request: dict[str, Any]) -> GenerationRun:
        """Generate artifacts and report what each artifact actually asserts."""


class GenerationRegistry:
    def __init__(self, adapters: list[GenerationAdapter] | None = None) -> None:
        self._adapters: dict[str, GenerationAdapter] = {}
        for adapter in adapters or []:
            self.register(adapter)

    def register(self, adapter: GenerationAdapter) -> None:
        name = adapter.capability.name.strip().lower()
        if not name:
            raise ValueError("generator name must not be empty")
        if name in self._adapters:
            raise ValueError(f"generator already registered: {name}")
        self._adapters[name] = adapter

    def inventory(self) -> list[dict[str, Any]]:
        return [asdict(self._adapters[name].capability) for name in sorted(self._adapters)]

    def select(self, project: dict[str, Any]) -> list[dict[str, Any]]:
        selected = []
        for name, adapter in sorted(self._adapters.items()):
            supported, reason = adapter.supports(project)
            if supported:
                selected.append({"generator": name, "reason": reason})
        return selected

    def generate(self, project: dict[str, Any], request: dict[str, Any]) -> list[GenerationRun]:
        runs = []
        for selected in self.select(project):
            adapter = self._adapters[selected["generator"]]
            runs.append(adapter.generate(project, request))
        return runs


class SolidityFoundryGenerationAdapter:
    """Adapter for Lowkey's current Solidity/Foundry project-aware generator."""

    capability = GenerationCapability(
        name="solidity-foundry",
        languages=("solidity",),
        build_systems=("foundry",),
        artifact_kinds=("unit", "integration", "invariant", "exploit", "regression", "fuzz", "formal"),
        notes="Conservative Solidity source analysis; unsupported setup is skipped, and drafts are not proof.",
    )

    def supports(self, project: dict[str, Any]) -> tuple[bool, str]:
        languages = {str(value).lower() for value in (project.get("languages") or [])}
        if project.get("language"):
            languages.add(str(project["language"]).lower())
        builds = {str(value).lower() for value in (project.get("build_systems") or [])}
        if project.get("build_system"):
            builds.add(str(project["build_system"]).lower())
        if "solidity" not in languages:
            return False, "no Solidity source detected"
        if "foundry" not in builds:
            return False, "Foundry project marker not detected"
        root = project.get("root")
        if not root or not (Path(str(root)).expanduser() / "foundry.toml").is_file():
            return False, "foundry.toml is missing from the project root"
        return True, "Solidity source and Foundry build configuration detected"

    def generate(self, project: dict[str, Any], request: dict[str, Any]) -> GenerationRun:
        supported, reason = self.supports(project)
        if not supported:
            return GenerationRun(self.capability.name, "unsupported", stderr=reason)
        try:
            try:
                import test_generation
            except ImportError:
                from lowkey import test_generation
        except ImportError as exc:
            return GenerationRun(self.capability.name, "error", stderr=f"test generator unavailable: {exc}")

        contract = str(request.get("contract") or "").strip()
        if not contract:
            return GenerationRun(self.capability.name, "unsupported", stderr="request.contract is required")
        types = request.get("types", list(self.capability.artifact_kinds))
        if isinstance(types, str):
            types_arg = types
        elif isinstance(types, (list, tuple)) and all(isinstance(value, str) for value in types):
            types_arg = ",".join(types)
        else:
            return GenerationRun(self.capability.name, "unsupported", stderr="request.types must be a string or list of strings")
        args = [contract, "--types", types_arg]
        output_dir = request.get("output_dir")
        if output_dir:
            args.extend(["--output-dir", str(output_dir)])
        if request.get("force"):
            args.append("--force")
        stdout = io.StringIO()
        stderr = io.StringIO()
        config = {"target_contract": contract, "target": project.get("target")}
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = test_generation.run_test_gen(config, args, project_root=project["root"])
        root = Path(str(project["root"])).expanduser().resolve()
        relative_output = Path(str(output_dir or ".audit/test-gen"))
        output_root = relative_output if relative_output.is_absolute() else root / relative_output
        safe_contract = test_generation._solidity_name(contract)
        output_root = output_root / safe_contract
        report_path = output_root / "report.json"
        if not report_path.is_file() and (output_root / "report.latest.json").is_file():
            report_path = output_root / "report.latest.json"
        if exit_code != 0 or not report_path.is_file():
            return GenerationRun(
                self.capability.name, "failed", report_path=str(report_path),
                stdout=stdout.getvalue(), stderr=stderr.getvalue(),
                metadata={"exit_code": exit_code, "reason": "generator failed or report was not written"},
            )
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return GenerationRun(
                self.capability.name, "failed", report_path=str(report_path),
                stdout=stdout.getvalue(), stderr=stderr.getvalue(),
                metadata={"exit_code": exit_code, "reason": f"invalid generation report: {exc}"},
            )

        property_info = report.get("fuzz_property") or {}
        property_description = None
        if property_info:
            property_description = (
                f"{property_info.get('state')} equals the value passed to "
                f"{property_info.get('setter')} ({property_info.get('type')})"
            )
        artifacts = []
        for artifact_path in report.get("generated", []):
            path = Path(artifact_path)
            kind = next(
                (value for value in self.capability.artifact_kinds
                 if path.name.lower().startswith(f"lowkeygenerated{value}".lower())),
                "unknown",
            )
            encoded_property = property_description if kind in {"unit", "fuzz", "invariant", "formal"} else None
            status = "property-draft" if encoded_property else "scaffold"
            artifacts.append(GeneratedArtifact(
                kind=kind,
                path=str(path if path.is_absolute() else root / path),
                status=status,
                intended_property=encoded_property,
                expected_behavior=(
                    "The public getter equals the last successful direct setter input."
                    if property_info and kind in {"unit", "fuzz", "invariant", "formal"}
                    else None
                ),
                assumptions=[
                    "Generated constructor placeholder values may not represent valid protocol setup.",
                    "Review and compile the artifact before relying on it.",
                ],
                provenance={
                    "contract": report.get("contract"),
                    "source": report.get("source"),
                    "fuzz_property": property_info or None,
                },
                metadata={"generator_report": str(report_path), "review_required": True},
            ))
        skipped = report.get("skipped") or []
        return GenerationRun(
            generator=self.capability.name,
            status="drafted" if artifacts else ("partial" if skipped else "empty"),
            artifacts=artifacts,
            report_path=str(report_path),
            stdout=stdout.getvalue(),
            stderr=stderr.getvalue(),
            metadata={
                "requested_types": report.get("requested_types", []),
                "skipped": skipped,
                "warning": report.get("warning"),
            },
        )


def default_generation_registry() -> GenerationRegistry:
    return GenerationRegistry([SolidityFoundryGenerationAdapter()])
