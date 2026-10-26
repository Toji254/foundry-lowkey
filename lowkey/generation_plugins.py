"""Plugin contract and routing for project-specific test artifact generators.

Generator plugins produce reviewable drafts and must describe the properties they
actually encoded. A generated file is never assumed to be a valid test or proof.
"""
from __future__ import annotations

import ast
import contextlib
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
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
        selected = self.select(project)
        requested_language = str(request.get("language") or "").strip().lower()
        if requested_language:
            selected = [
                item for item in selected
                if requested_language in self._adapters[item["generator"]].capability.languages
            ]

        # A mixed-language repository can have multiple capable adapters. Route
        # to the adapter(s) that actually contain the requested contract/source,
        # instead of failing because another language backend cannot find it.
        contract = str(request.get("contract") or "").strip()
        if contract:
            matched = []
            for item in selected:
                adapter = self._adapters[item["generator"]]
                matcher = getattr(adapter, "matches_request", None)
                if not callable(matcher):
                    matched.append(item)
                    continue
                try:
                    matches, _reason = matcher(project, request)
                except (AttributeError, ImportError, OSError, ValueError, RuntimeError):
                    matches = False
                if matches:
                    matched.append(item)
            if matched:
                selected = matched

        return [
            self._adapters[item["generator"]].generate(project, request)
            for item in selected
        ]


class SolidityFoundryGenerationAdapter:
    """Adapter for Lowkey's current Solidity/Foundry project-aware generator."""

    capability = GenerationCapability(
        name="solidity-foundry",
        languages=("solidity",),
        build_systems=("foundry",),
        artifact_kinds=("unit", "integration", "invariant", "exploit", "regression", "fuzz", "formal", "fork", "poc"),
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

    def matches_request(self, project: dict[str, Any], request: dict[str, Any]) -> tuple[bool, str]:
        contract = str(request.get("contract") or "").strip()
        if not contract:
            return False, "request.contract is required"
        root = Path(str(project.get("root") or "")).expanduser()
        try:
            try:
                import test_generation
            except ImportError:
                from lowkey import test_generation
            matched = test_generation._contract_source(root, contract) is not None
        except (AttributeError, ImportError, OSError, ValueError, RuntimeError):
            matched = False
        return matched, "matching Solidity contract source" if matched else "no matching Solidity source"

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
        if request.get("validate"):
            args.append("--validate")
        if request.get("strict"):
            args.append("--strict")
        constructor_args = request.get("constructor_args")
        if constructor_args is not None:
            if not isinstance(constructor_args, (list, tuple)) or not all(
                isinstance(value, str) and value.strip() for value in constructor_args
            ):
                return GenerationRun(
                    self.capability.name, "unsupported",
                    stderr="request.constructor_args must be a list of non-empty Solidity expression strings",
                )
            args.extend(["--constructor-args", json.dumps(list(constructor_args))])

        # Resolve report candidates before execution. When --force is absent,
        # test_generation.py writes a fresh report.latest.json instead of replacing
        # report.json. Never let an older report stand in for this invocation.
        root = Path(str(project["root"])).expanduser().resolve()
        relative_output = Path(str(output_dir or ".audit/test-gen"))
        output_root = relative_output if relative_output.is_absolute() else root / relative_output
        safe_contract = test_generation._solidity_name(contract)
        output_root = output_root / safe_contract
        report_candidates = (output_root / "report.json", output_root / "report.latest.json")
        previous_report_state = {}
        for candidate in report_candidates:
            try:
                previous_report_state[candidate] = (
                    candidate.stat().st_mtime_ns,
                    candidate.read_bytes(),
                )
            except OSError:
                previous_report_state[candidate] = None

        stdout = io.StringIO()
        stderr = io.StringIO()
        config = {"target_contract": contract, "target": project.get("target")}
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = test_generation.run_test_gen(config, args, project_root=project["root"])

        fresh_reports = []
        for candidate in report_candidates:
            try:
                current_state = (candidate.stat().st_mtime_ns, candidate.read_bytes())
            except OSError:
                continue
            if current_state != previous_report_state[candidate]:
                fresh_reports.append(candidate)
        if not fresh_reports:
            report_path = max(
                (candidate for candidate in report_candidates if candidate.is_file()),
                key=lambda candidate: candidate.stat().st_mtime_ns,
                default=report_candidates[0],
            )
            return GenerationRun(
                self.capability.name, "failed", report_path=str(report_path),
                stdout=stdout.getvalue(), stderr=stderr.getvalue(),
                metadata={
                    "exit_code": exit_code,
                    "reason": "generator did not write a fresh report for this invocation",
                },
            )
        report_path = max(fresh_reports, key=lambda candidate: candidate.stat().st_mtime_ns)
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
        validation = report.get("validation") or {}
        validation_status = validation.get("status", "not-requested")
        # Solidity validation executes uniquely renamed temporary copies, so the
        # executed basename includes a LowkeyValidation_<token>_ prefix rather
        # than matching the original generated artifact's basename exactly.
        execution_paths = {
            Path(str(item.get("path", ""))).name
            for item in validation.get("test_executions", [])
            if isinstance(item, dict) and item.get("exit_code") == 0
        }
        artifacts = []
        for artifact_path in report.get("generated", []):
            path = Path(artifact_path)
            kind = next(
                (value for value in self.capability.artifact_kinds
                 if path.name.lower().startswith(f"lowkeygenerated{value}".lower())),
                "unknown",
            )
            has_property = bool(property_description) and kind in {"unit", "fuzz", "invariant"}
            executed_successfully = any(
                executed_name == path.name or executed_name.endswith("_" + path.name)
                for executed_name in execution_paths
            )
            artifact_status = "behaviorally-validated" if executed_successfully else "generated-unvalidated"
            artifacts.append(GeneratedArtifact(
                kind=kind,
                path=str(path if path.is_absolute() else root / path),
                status=artifact_status,
                intended_property=property_description if has_property else None,
                expected_behavior=(
                    "The public getter equals the last successful direct setter input."
                    if has_property else None
                ),
                assumptions=[
                    "This artifact encodes only the reported property and configured setup.",
                    "Protocol-wide security is not established by artifact generation.",
                ],
                provenance={
                    "contract": report.get("contract"),
                    "source": report.get("source"),
                    "source_sha256": report.get("source_sha256"),
                    "fuzz_property": property_info or None,
                },
                metadata={
                    "generator_report": str(report_path),
                    "review_required": True,
                    "validation_status": validation_status,
                },
            ))
        skipped = report.get("skipped") or []
        has_skips = bool(skipped)
        validation_requested = bool(validation.get("requested"))
        validation_failed = validation_requested and validation_status != "passed"
        if validation_failed:
            run_status = "failed"
        elif has_skips:
            run_status = "partial" if artifacts else "failed"
        elif artifacts and exit_code == 0:
            run_status = "generated"
        elif artifacts:
            run_status = "failed"
        else:
            run_status = "empty"
        return GenerationRun(
            generator=self.capability.name,
            status=run_status,
            artifacts=artifacts,
            report_path=str(report_path),
            stdout=stdout.getvalue(),
            stderr=stderr.getvalue(),
            metadata={
                "exit_code": exit_code,
                "requested_types": report.get("requested_types", []),
                "generated_types": sorted({artifact.kind for artifact in artifacts}),
                "skipped": skipped,
                "validation": validation,
                "warning": report.get("warning"),
            },
        )




class VyperTitanoboaGenerationAdapter:
    """Generate and execute narrow, assertion-backed Vyper tests with Titanoboa.

    Only an explicitly recognized public-integer getter plus a one-statement
    direct setter is inferred automatically. More complex protocol properties
    are refused until a concrete property and test oracle are supplied.
    """

    capability = GenerationCapability(
        name="vyper-titanoboa",
        languages=("vyper",),
        build_systems=(),
        artifact_kinds=("unit", "fuzz", "invariant"),
        notes="Executes narrow Vyper setter/getter properties through Titanoboa; unsupported scenarios are rejected.",
    )

    _ALL_KINDS = ("unit", "fuzz", "invariant", "integration", "exploit", "fork", "poc", "regression", "formal")

    def supports(self, project: dict[str, Any]) -> tuple[bool, str]:
        languages = {str(value).lower() for value in (project.get("languages") or [])}
        if project.get("language"):
            languages.add(str(project["language"]).lower())
        if "vyper" not in languages:
            return False, "no Vyper source detected"
        root = Path(str(project.get("root") or "")).expanduser()
        if not root.is_dir() or not any(self._source_files(root)):
            return False, "no Vyper source file found in the project"
        return True, "Vyper source detected; Titanoboa test generation is available for recognized simple properties"

    @staticmethod
    def _source_files(root: Path) -> list[Path]:
        ignored = {
            ".git", ".audit", ".venv", "venv", "node_modules", "vendor",
            "lib", "target", "build", "dist", "out", "cache", "__pycache__",
            ".pytest_cache", "test", "tests", "script", "scripts",
        }
        return sorted(
            path for path in root.rglob("*.vy")
            if path.is_file() and not any(part in ignored for part in path.relative_to(root).parts)
        )

    @staticmethod
    def _requested_kinds(raw: Any) -> list[str]:
        if raw is None:
            return ["unit", "fuzz", "invariant"]
        if isinstance(raw, (list, tuple)):
            values = [str(value).strip().lower() for value in raw]
        else:
            text = str(raw).strip().lower()
            values = list(VyperTitanoboaGenerationAdapter._ALL_KINDS) if text == "all" else [
                value.strip() for value in text.split(",") if value.strip()
            ]
        unknown = sorted(set(values) - set(VyperTitanoboaGenerationAdapter._ALL_KINDS))
        if unknown:
            raise ValueError("unknown test type(s): " + ", ".join(unknown))
        return list(dict.fromkeys(values))

    def matches_request(self, project: dict[str, Any], request: dict[str, Any]) -> tuple[bool, str]:
        root = Path(str(project.get("root") or "")).expanduser()
        requested = str(request.get("contract") or "").strip().lower()
        if not requested or not root.is_dir():
            return False, "request.contract and an existing project root are required"
        matches = [
            path for path in self._source_files(root)
            if path.stem.lower() == requested
            or path.relative_to(root).as_posix().lower() == requested
            or path.relative_to(root).with_suffix("").as_posix().lower() == requested
        ]
        return bool(matches), (
            "matching Vyper source" if matches else "no matching Vyper source"
        )

    @staticmethod
    def _clean_source(source: str) -> str:
        # Only structural, line-anchored declarations are considered. This
        # masks Vyper comments so documentation cannot manufacture a property.
        return re.sub(r"(?m)#.*$", "", source)

    @classmethod
    def _simple_property(cls, source: str) -> dict[str, str] | None:
        clean = cls._clean_source(source)
        states: dict[str, str] = {}
        for match in re.finditer(
            r"(?m)^([A-Za-z_]\w*)\s*:\s*public\(\s*((?:uint|int)\d*)\s*\)\s*$",
            clean,
        ):
            states[match.group(1)] = match.group(2)

        function_pattern = re.compile(
            r"(?m)^(?P<decorators>(?:@[^\n]+\n)*)"
            r"def\s+(?P<setter>[A-Za-z_]\w*)\s*"
            r"\(\s*(?P<parameter>[A-Za-z_]\w*)\s*:\s*(?P<type>(?:uint|int)\d*)\s*\)"
            r"\s*:\s*\n"
            r"(?P<body>(?:[ \t]+[^\n]*(?:\n|$))+)"
        )
        for match in function_pattern.finditer(clean):
            if not re.search(r"(?m)^@external\s*$", match.group("decorators")):
                continue
            body_lines = [
                line.strip()
                for line in match.group("body").splitlines()
                if line.strip()
            ]
            if len(body_lines) != 1:
                continue
            parameter = match.group("parameter")
            setter_type = match.group("type")
            for state, state_type in states.items():
                if setter_type != state_type:
                    continue
                if body_lines[0] == f"self.{state} = {parameter}":
                    width = int(re.search(r"\d+", setter_type).group(0)) if re.search(r"\d+", setter_type) else (
                        256 if setter_type == "uint" else 128
                    )
                    signed = setter_type.startswith("int")
                    return {
                        "setter": match.group("setter"),
                        "parameter": parameter,
                        "type": setter_type,
                        "state": state,
                        "minimum": str(-(2 ** (width - 1)) if signed else 0),
                        "maximum": str((2 ** (width - (1 if signed else 0))) - 1),
                    }
        return None

    @staticmethod
    def _constructor(source: str) -> tuple[bool, int]:
        clean = VyperTitanoboaGenerationAdapter._clean_source(source)
        match = re.search(r"(?ms)^(?:@[^\n]+\n)*def\s+__init__\s*\((.*?)\)\s*:", clean)
        if not match:
            return False, 0
        params = [part.strip() for part in match.group(1).split(",") if part.strip()]
        return True, len(params)

    @staticmethod
    def _literal_constructor_args(raw: Any, count: int) -> list[str] | None:
        if count == 0:
            return [] if raw in (None, [], ()) else None
        if not isinstance(raw, (list, tuple)) or len(raw) != count:
            return None
        rendered: list[str] = []
        for item in raw:
            if not isinstance(item, str) or not item.strip():
                return None
            try:
                literal = ast.literal_eval(item)
            except (ValueError, SyntaxError):
                # Accept only literal Python values: no function calls, names,
                # attribute access, comprehensions, or injected statements.
                return None
            if not isinstance(literal, (str, int, bool, bytes, type(None))):
                return None
            rendered.append(repr(literal))
        return rendered

    @staticmethod
    def _render_test(
        *,
        kind: str,
        source_rel: str,
        source_sha256: str,
        property_info: dict[str, str],
        constructor_args: list[str],
    ) -> str:
        setter = property_info["setter"]
        parameter = property_info["parameter"]
        solidity_type = property_info["type"]
        state = property_info["state"]
        minimum = property_info["minimum"]
        maximum = property_info["maximum"]
        source_literal = repr(source_rel)
        args_literal = ", ".join(constructor_args)
        deploy_args = f", {args_literal}" if args_literal else ""
        lines = [
            '"""Lowkey-generated executable Vyper property test."""',
            "from pathlib import Path",
            "import boa",
            "from hypothesis import given, strategies as st",
            "",
            f"SOURCE_RELATIVE = Path({source_literal})",
            f"SOURCE_SHA256 = {source_sha256!r}",
            "",
            "def _project_root():",
            "    for candidate in Path(__file__).resolve().parents:",
            "        source = candidate / SOURCE_RELATIVE",
            "        if source.is_file():",
            "            return candidate",
            "    raise AssertionError(f'Cannot locate source file: {SOURCE_RELATIVE}')",
            "",
            "def _deploy():",
            f"    return boa.load(str(_project_root() / SOURCE_RELATIVE){deploy_args})",
            "",
        ]
        if kind == "unit":
            lines += [
                f"def test_{setter}_writes_value_to_public_getter():",
                "    target = _deploy()",
                f"    expected = {1 if minimum == '0' else -1}",
                f"    target.{setter}(expected)",
                f"    assert target.{state}() == expected",
                "",
            ]
        elif kind == "fuzz":
            lines += [
                f"@given(next_value=st.integers(min_value={minimum}, max_value={maximum}))",
                f"def test_fuzz_{setter}_round_trip(next_value):",
                "    target = _deploy()",
                "    target." + setter + "(next_value)",
                f"    assert target.{state}() == next_value",
                "",
            ]
        elif kind == "invariant":
            lines += [
                f"@given(values=st.lists(st.integers(min_value={minimum}, max_value={maximum}), min_size=1, max_size=24))",
                f"def test_sequence_property_{state}_matches_last_setter(values):",
                "    target = _deploy()",
                "    for value in values:",
                f"        target.{setter}(value)",
                f"        assert target.{state}() == value",
                "",
            ]
        return "\n".join(lines)

    def generate(self, project: dict[str, Any], request: dict[str, Any]) -> GenerationRun:
        supported, reason = self.supports(project)
        if not supported:
            return GenerationRun(self.capability.name, "unsupported", stderr=reason)
        root = Path(str(project["root"])).expanduser().resolve()
        try:
            kinds = self._requested_kinds(request.get("types"))
        except ValueError as exc:
            return GenerationRun(self.capability.name, "unsupported", stderr=str(exc))
        source_files = self._source_files(root)
        requested_contract = str(request.get("contract") or "").strip()
        matches = [
            path for path in source_files
            if path.stem.lower() == requested_contract.lower()
            or path.relative_to(root).as_posix().lower() == requested_contract.lower()
            or path.relative_to(root).with_suffix("").as_posix().lower() == requested_contract.lower()
        ]
        if len(matches) != 1:
            reason = (
                f"contract/source '{requested_contract}' is ambiguous; candidates: "
                + ", ".join(path.relative_to(root).as_posix() for path in matches)
                if matches else
                f"no Vyper source matched '{requested_contract}'; available: "
                + ", ".join(path.relative_to(root).as_posix() for path in source_files)
            )
            return GenerationRun(self.capability.name, "unsupported", stderr=reason)

        source_path = matches[0]
        source_rel = source_path.relative_to(root).as_posix()
        source = source_path.read_text(encoding="utf-8")
        source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
        property_info = self._simple_property(source)
        has_constructor, constructor_count = self._constructor(source)
        constructor_args = self._literal_constructor_args(request.get("constructor_args"), constructor_count)
        output_dir_raw = Path(str(request.get("output_dir") or ".audit/test-gen")).expanduser()
        output_dir = output_dir_raw if output_dir_raw.is_absolute() else root / output_dir_raw
        # Keep Vyper reports/artifacts separate from Solidity when one repository
        # contains both backends and a contract happens to share the same name.
        output_dir = (
            output_dir.resolve() / "vyper" /
            re.sub(r"[^A-Za-z0-9_]", "_", source_path.stem)
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        report_path = output_dir / "report.json"
        generated: list[Path] = []
        skipped: list[dict[str, str]] = []
        validation: dict[str, Any] = {"requested": bool(request.get("validate")), "status": "not-requested"}
        if not shutil.which("vyper"):
            return GenerationRun(
                self.capability.name, "failed", report_path=str(report_path),
                stderr="Vyper CLI is not installed; refusing to create unvalidated tests.",
                metadata={"reason": "vyper-unavailable"},
            )
        try:
            import boa  # noqa: F401
            import pytest  # noqa: F401
            import hypothesis  # noqa: F401
        except ImportError as exc:
            return GenerationRun(
                self.capability.name, "failed", report_path=str(report_path),
                stderr=f"Vyper generation requires Titanoboa, pytest, and Hypothesis ({exc}).",
                metadata={"reason": "test-runtime-unavailable"},
            )

        init_present, init_count = self._constructor(source)
        if init_present and constructor_count and constructor_args is None:
            constructor_reason = (
                f"constructor requires {constructor_count} argument(s); pass --constructor-args "
                "as a JSON array of Python literals, e.g. '[\"100\", \"\\\"TOKEN\\\"\"]'."
            )
        elif constructor_args is None:
            constructor_reason = "constructor argument list is invalid for this contract; no test files were written."
        else:
            constructor_reason = ""

        effective_types: list[str] = []
        for kind in kinds:
            if kind not in self.capability.artifact_kinds:
                skipped.append({"type": kind, "reason": f"{self.capability.name} does not implement {kind} generation."})
                continue
            if not property_info:
                skipped.append({"type": kind, "reason": "No public integer getter with a one-statement direct setter was recognized."})
                continue
            if constructor_reason:
                skipped.append({"type": kind, "reason": constructor_reason})
                continue
            effective_types.append(kind)

        for kind in effective_types:
            filename = output_dir / f"test_lowkey_{kind}_{source_path.stem.lower()}.py"
            if filename.exists() and not request.get("force"):
                skipped.append({"type": kind, "reason": f"{filename.relative_to(root) if filename.is_relative_to(root) else filename} already exists; pass --force to replace."})
                continue
            content = self._render_test(
                kind=kind,
                source_rel=source_rel,
                source_sha256=source_sha256,
                property_info=property_info,
                constructor_args=constructor_args or [],
            )
            if re.search(r"(?i)\bTODO\b|\bstarter\b|\bscaffold\b", content) or "assert " not in content:
                skipped.append({"type": kind, "reason": "Generated test failed the completeness gate; no file was written."})
                continue
            filename.write_text(content, encoding="utf-8")
            generated.append(filename)

        if request.get("validate"):
            if not generated:
                validation = {"requested": True, "status": "not-applicable", "detail": "No complete generated test files were available to execute."}
            else:
                try:
                    compile_run = subprocess.run(
                        [shutil.which("vyper"), "-f", "bytecode", str(source_path)],
                        cwd=root, capture_output=True, text=True, timeout=180, check=False,
                    )
                except (OSError, subprocess.TimeoutExpired) as exc:
                    compile_run = None
                    validation = {"requested": True, "status": "failed", "detail": f"Could not compile source: {exc}"}
                if compile_run is not None and compile_run.returncode != 0:
                    validation = {
                        "requested": True, "status": "baseline-failed",
                        "detail": "The untouched Vyper source did not compile before generated tests were evaluated.",
                        "stdout_tail": (compile_run.stdout or "")[-4000:],
                        "stderr_tail": (compile_run.stderr or "")[-4000:],
                    }
                elif compile_run is not None:
                    executions = []
                    for generated_path in generated:
                        try:
                            executed = subprocess.run(
                                [sys.executable, "-m", "pytest", "-q", str(generated_path)],
                                cwd=root, capture_output=True, text=True, timeout=300, check=False,
                            )
                            executions.append({
                                "path": generated_path.relative_to(root).as_posix(),
                                "exit_code": executed.returncode,
                                "stdout_tail": (executed.stdout or "")[-4000:],
                                "stderr_tail": (executed.stderr or "")[-4000:],
                            })
                        except (OSError, subprocess.TimeoutExpired) as exc:
                            executions.append({"path": str(generated_path), "exit_code": None, "error": str(exc)})
                    validation = {
                        "requested": True,
                        "status": "passed" if executions and all(item.get("exit_code") == 0 for item in executions) else "failed",
                        "test_executions": executions,
                    }

        status = "failed" if (request.get("validate") and validation.get("status") != "passed") else (
            "partial" if skipped else "generated"
        )
        report = {
            "generator": self.capability.name,
            "contract": source_path.stem,
            "source": source_rel,
            "source_sha256": source_sha256,
            "requested_types": kinds,
            "generated": [path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path) for path in generated],
            "skipped": skipped,
            "recognized_property": property_info,
            "constructor_requires_arguments": constructor_count if has_constructor else 0,
            "validation": validation,
            "protocol_security_established": False,
            "status": status,
        }
        report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        artifacts = []
        validation_status = validation.get("status", "not-requested")
        for path in generated:
            artifacts.append(GeneratedArtifact(
                kind=next((kind for kind in effective_types if path.name.startswith(f"test_lowkey_{kind}_")), "unknown"),
                path=str(path),
                status="behaviorally-validated" if validation_status == "passed" else "generated-unvalidated",
                intended_property=(
                    f"{property_info['state']} equals the value passed to {property_info['setter']} ({property_info['type']})"
                    if property_info else None
                ),
                expected_behavior=f"The public getter {property_info['state']} equals the last setter input." if property_info else None,
                assumptions=["This checks only the inferred direct setter/getter relation, not protocol-wide security."],
                provenance={"contract": source_path.stem, "source": source_rel, "source_sha256": source_sha256},
                metadata={"generator_report": str(report_path), "validation_status": validation_status},
            ))
        return GenerationRun(
            generator=self.capability.name,
            status=status,
            artifacts=artifacts,
            report_path=str(report_path),
            stdout=(
                f"Vyper test generation for {source_path.stem}\n"
                f"Generated: {len(generated)} complete executable test(s)\n"
                f"Skipped: {len(skipped)} requested type(s)\n"
                f"Validation: {validation_status}\n"
                f"Report: {report_path}\n"
            ),
            stderr="\n".join(f"{item['type']}: {item['reason']}" for item in skipped),
            metadata={"requested_types": kinds, "skipped": skipped, "validation": validation},
        )


def run_generation_command(config: dict[str, Any], args: list[str]) -> int:
    """CLI bridge that routes project-aware generation through the plugin registry."""
    try:
        try:
            import test_generation
        except ImportError:
            from lowkey import test_generation
        try:
            from verification_adapters import inspect_project
        except ImportError:
            from lowkey.verification_adapters import inspect_project
    except ImportError as exc:
        print(f"Error: generation runtime unavailable: {exc}")
        return 2

    if any(str(arg).lower() in {"-h", "--help", "help"} for arg in args):
        print("""Lowkey project-aware test generation

Usage:
  lk test-gen <ContractName> [--language solidity|vyper]
      [--types unit,fuzz,invariant,...] [--output-dir DIR]
      [--constructor-args '<JSON array>'] [--force] [--validate] [--strict]

Native backends:
  solidity + Foundry     Unit, fuzz, and invariant candidates for a safely
                         recognized public-integer getter/direct setter.
  vyper + Titanoboa      Python unit, Hypothesis fuzz, and setter-sequence
                         candidates for the equivalent simple Vyper property.

Routing:
  A request is routed to the backend(s) that contain the requested contract.
  Use --language to choose a backend explicitly. Vyper reports and artifacts
  live under .audit/test-gen/vyper/<ContractName>/ so they never overwrite
  Solidity reports for a same-named contract.

Only complete artifacts with executable assertions are written. Unsupported
categories are recorded as skipped and return nonzero. --validate compiles the
untouched source and executes eligible generated tests. A passing narrow test
does not establish protocol-wide security.
""")
        return 0

    contract = str(config.get("target_contract") or "").strip()
    types: str | list[str] = ["unit", "fuzz", "invariant"]
    output_dir = ".audit/test-gen"
    force = False
    validate = False
    strict = False
    constructor_args: list[str] | None = None
    language: str | None = None
    positionals: list[str] = []
    index = 0
    while index < len(args):
        value = str(args[index])
        if value == "--types":
            index += 1
            if index >= len(args):
                print("Error: --types needs a comma-separated list or 'all'")
                return 2
            types = str(args[index])
        elif value.startswith("--types="):
            types = value.split("=", 1)[1]
        elif value == "--output-dir":
            index += 1
            if index >= len(args):
                print("Error: --output-dir needs a path")
                return 2
            output_dir = str(args[index])
        elif value.startswith("--output-dir="):
            output_dir = value.split("=", 1)[1]
        elif value == "--language":
            index += 1
            if index >= len(args):
                print("Error: --language needs 'solidity' or 'vyper'")
                return 2
            language = str(args[index]).strip().lower()
            if language not in {"solidity", "vyper"}:
                print("Error: --language must be 'solidity' or 'vyper'")
                return 2
        elif value.startswith("--language="):
            language = value.split("=", 1)[1].strip().lower()
            if language not in {"solidity", "vyper"}:
                print("Error: --language must be 'solidity' or 'vyper'")
                return 2
        elif value == "--force":
            force = True
        elif value == "--validate":
            validate = True
        elif value == "--strict":
            strict = True
        elif value == "--constructor-args":
            index += 1
            if index >= len(args):
                print("Error: --constructor-args needs a JSON array")
                return 2
            try:
                parsed_args = json.loads(args[index])
            except json.JSONDecodeError as exc:
                print(f"Error: invalid --constructor-args JSON: {exc}")
                return 2
            if not isinstance(parsed_args, list) or not all(
                isinstance(item, str) and item.strip() for item in parsed_args
            ):
                print("Error: --constructor-args must be a JSON array of non-empty Solidity expressions")
                return 2
            constructor_args = [item.strip() for item in parsed_args]
        elif value.startswith("--constructor-args="):
            try:
                parsed_args = json.loads(value.split("=", 1)[1])
            except json.JSONDecodeError as exc:
                print(f"Error: invalid --constructor-args JSON: {exc}")
                return 2
            if not isinstance(parsed_args, list) or not all(
                isinstance(item, str) and item.strip() for item in parsed_args
            ):
                print("Error: --constructor-args must be a JSON array of non-empty Solidity expressions")
                return 2
            constructor_args = [item.strip() for item in parsed_args]
        elif value.startswith("-"):
            print(f"Error: unknown option: {value}")
            return 2
        else:
            positionals.append(value)
        index += 1
    if positionals:
        contract = positionals[0]
    if not contract:
        print("Error: provide <ContractName> or set the active project target first.")
        return 2

    try:
        project_root = Path(str(project_root_from_config(config) or Path.cwd())).expanduser().resolve()
        project = inspect_project(project_root)
    except (ValueError, OSError) as exc:
        print(f"Error: project inspection failed: {exc}")
        return 2
    request = {
        "contract": contract,
        "types": types,
        "output_dir": output_dir,
        "force": force,
        "validate": validate,
        "strict": strict,
        "constructor_args": constructor_args,
        "language": language,
    }
    runs = default_generation_registry().generate(project, request)
    if not runs:
        language_note = f" for language '{language}'" if language else ""
        print(f"Error: no installed generation plugin supports this project{language_note}.")
        return 2

    total_artifacts = 0
    all_complete = True
    any_artifact = False
    for run in runs:
        if run.stdout:
            print(run.stdout, end="" if run.stdout.endswith("\n") else "\n")
        if run.stderr:
            print(run.stderr, end="" if run.stderr.endswith("\n") else "\n")
        total_artifacts += len(run.artifacts)
        any_artifact = any_artifact or bool(run.artifacts)
        print(f"Generation plugin: {run.generator}")
        print(f"Generation status: {run.status}")
        if run.report_path:
            print(f"Report: {run.report_path}")
        for artifact in run.artifacts:
            print(f"  {artifact.kind}: {artifact.status} — {artifact.path}")
            if artifact.intended_property:
                print(f"    property: {artifact.intended_property}")
        for item in run.metadata.get("skipped", []):
            print(f"  not generated {item.get('type')}: {item.get('reason')}")
        if run.status != "generated":
            all_complete = False

    print(f"Structured artifacts: {total_artifacts}")
    if all_complete and total_artifacts:
        return 0
    if not any_artifact and all(run.status == "unsupported" for run in runs):
        print("No matching contract source was found in the selected language backend(s).")
        return 2
    print("Generation incomplete or validation failed; this command will not return success.")
    return 1


def project_root_from_config(config: dict[str, Any]) -> str | None:
    """Resolve project root from the existing Lowkey context without guessing a target."""
    try:
        import audit_context
        root = audit_context.foundry_project_root()
        return str(root) if root else None
    except (ImportError, OSError):
        return None


def default_generation_registry() -> GenerationRegistry:
    return GenerationRegistry([
        SolidityFoundryGenerationAdapter(),
        VyperTitanoboaGenerationAdapter(),
    ])
