"""Invocation-aware target scoping for local lab discovery.

Builds and dependency resolution remain project-wide. This module only
constrains which first-party source file may become the primary lab target.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


_SUPPORT_DIRS = frozenset({
    "test", "tests", "script", "scripts", "deploy", "deployment",
    "migrations", "fixture", "fixtures", "mock", "mocks",
    "harness", "harnesses", "benchmark", "benchmarks",
    "audit", "audits", "certora", "docs", "doc",
})


@dataclass(frozen=True)
class LabTargetScope:
    project_root: Path
    invocation_dir: Path
    target_scope: Path
    source_file: Path | None
    mode: str

    @property
    def dependency_scope(self) -> Path:
        return self.project_root


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def parse_scope_options(arguments: Iterable[str] | None):
    """Remove --scope/--source options without consuming a contract selector."""
    remaining: list[str] = []
    scope = None
    source = None
    values = list(arguments or [])
    index = 0

    while index < len(values):
        token = str(values[index])
        option = None
        value = None
        if token in {"--scope", "--source"}:
            option = token
            index += 1
            if index >= len(values) or str(values[index]).startswith("--"):
                raise ValueError(f"{option} requires a value.")
            value = str(values[index]).strip()
        elif token.startswith("--scope="):
            option, value = "--scope", token.split("=", 1)[1].strip()
        elif token.startswith("--source="):
            option, value = "--source", token.split("=", 1)[1].strip()
        else:
            remaining.append(token)
            index += 1
            continue

        if not value:
            raise ValueError(f"{option} requires a non-empty value.")
        if option == "--scope":
            if scope is not None:
                raise ValueError("--scope may be supplied only once.")
            scope = value
        else:
            if source is not None:
                raise ValueError("--source may be supplied only once.")
            source = value
        index += 1

    return remaining, scope, source


def _resolve_existing(path: Path, description: str) -> Path:
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{description} does not exist or cannot be resolved: {path}") from exc


def resolve_target_scope(
    project_root: str | Path,
    *,
    invocation_dir: str | Path | None = None,
    scope: str | Path | None = None,
    source: str | Path | None = None,
) -> LabTargetScope:
    """Resolve a target scope, refusing support-folder guesses and path escape."""
    root = _resolve_existing(Path(project_root).expanduser(), "project root")
    if not root.is_dir():
        raise ValueError(f"project root is not a directory: {root}")

    invoked = Path(invocation_dir if invocation_dir is not None else Path.cwd()).expanduser()
    invoked = _resolve_existing(invoked, "invocation directory")
    if not invoked.is_dir():
        raise ValueError(f"invocation directory is not a directory: {invoked}")

    # A selected workspace package can differ from the caller's workspace root.
    # In that case, default to the selected package, never to an outside path.
    effective_invocation = invoked if _is_within(invoked, root) else root

    source_path = None
    if source is not None:
        raw_source = Path(source).expanduser()
        source_candidate = raw_source if raw_source.is_absolute() else effective_invocation / raw_source
        source_path = _resolve_existing(source_candidate, "source file")
        if not source_path.is_file():
            raise ValueError(f"source is not a file: {source_path}")
        if source_path.suffix.lower() not in {".sol", ".vy"}:
            raise ValueError("lab source selection supports .sol and .vy files only.")
        if not _is_within(source_path, root):
            raise ValueError("source path resolves outside the selected project; refusing path traversal or an external symlink.")

    if scope is None:
        if source_path is not None:
            target_scope = source_path.parent
            mode = "source"
        else:
            target_scope = effective_invocation
            if target_scope != root:
                relative_parts = target_scope.relative_to(root).parts
                support_segment = next(
                    (part for part in relative_parts if part.casefold() in _SUPPORT_DIRS),
                    None,
                )
                if support_segment:
                    raise ValueError(
                        f"current directory is inside the '{support_segment}' support area. "
                        "Use --scope project or select an application file with --source <file>."
                    )
                mode = "invocation"
            else:
                mode = "project"
    else:
        scope_text = str(scope).strip()
        if not scope_text:
            raise ValueError("--scope requires a non-empty value.")
        if scope_text.casefold() == "project":
            target_scope = root
        else:
            raw_scope = Path(scope_text).expanduser()
            scope_candidate = raw_scope if raw_scope.is_absolute() else effective_invocation / raw_scope
            target_scope = _resolve_existing(scope_candidate, "target scope")
        if not target_scope.is_dir():
            raise ValueError(f"target scope is not a directory: {target_scope}")
        if not _is_within(target_scope, root):
            raise ValueError("target scope resolves outside the selected project; refusing path traversal or an external symlink.")
        mode = "explicit"

    if not _is_within(target_scope, root):
        raise ValueError("target scope resolves outside the selected project.")
    if source_path is not None and not _is_within(source_path, target_scope):
        raise ValueError("--source must be inside the selected --scope.")

    return LabTargetScope(
        project_root=root,
        invocation_dir=invoked,
        target_scope=target_scope.resolve(),
        source_file=source_path,
        mode=mode,
    )


def artifact_source_in_scope(
    project_root: str | Path,
    source_name: str | Path | None,
    *,
    target_scope: str | Path | None = None,
    source_file: str | Path | None = None,
) -> bool:
    """Check compiler source provenance against the selected project and scope."""
    if not source_name:
        return False
    root = Path(project_root).expanduser().resolve()
    raw_source = Path(str(source_name)).expanduser()
    candidate = (raw_source if raw_source.is_absolute() else root / raw_source).resolve()
    if not _is_within(candidate, root) or not candidate.is_file():
        return False

    if target_scope is not None:
        scope_path = Path(target_scope).expanduser().resolve()
        if not _is_within(scope_path, root) or not scope_path.is_dir():
            return False
        if not _is_within(candidate, scope_path):
            return False

    if source_file is not None:
        requested_source = Path(source_file).expanduser().resolve()
        if candidate != requested_source:
            return False

    return True
