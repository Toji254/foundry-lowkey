"""Permissioned, observable runtime for bounded Lowkey agents.

Plans are data, not authority. Every action is checked by code against the agent
capabilities and caller-granted permissions. Model output never calls a tool
directly. No generic shell, signing, broadcast, or deployment tool is registered.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping


class AgentRuntimeError(RuntimeError):
    """An action was invalid or outside the runtime's explicit permissions."""


KNOWN_ACTIONS = frozenset({
    "read_source", "provider_request", "source_quote_check", "write_evidence", "run_native_test"
})


def _json_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _append_private_jsonl(path: Path, record: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    encoded = (json.dumps(dict(record), sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


@dataclass(frozen=True)
class AgentSpec:
    name: str
    actions: frozenset[str]
    delegates_to: tuple[str, ...] = ()


class AgentRegistry:
    def __init__(self) -> None:
        self._agents: dict[str, AgentSpec] = {}

    def register(self, spec: AgentSpec, *, replace: bool = False) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", spec.name):
            raise AgentRuntimeError("Agent name must be a lowercase identifier.")
        if not spec.actions or not spec.actions <= KNOWN_ACTIONS:
            raise AgentRuntimeError("Agent has an empty or unknown action capability set.")
        if spec.name in self._agents and not replace:
            raise AgentRuntimeError(f"Agent already registered: {spec.name}")
        self._agents[spec.name] = spec

    def get(self, name: str) -> AgentSpec:
        try:
            return self._agents[name]
        except KeyError as exc:
            raise AgentRuntimeError(f"Agent is not registered: {name}") from exc

    def describe(self) -> list[dict[str, Any]]:
        return [
            {"name": item.name, "actions": sorted(item.actions), "delegates_to": list(item.delegates_to)}
            for item in sorted(self._agents.values(), key=lambda value: value.name)
        ]


DEFAULT_AGENTS = AgentRegistry()
DEFAULT_AGENTS.register(AgentSpec(
    "security-review",
    frozenset({"read_source", "provider_request", "write_evidence"}),
    ("source-evidence-checker",),
))
DEFAULT_AGENTS.register(AgentSpec("source-evidence-checker", frozenset({"source_quote_check"})))
DEFAULT_AGENTS.register(AgentSpec("native-test-verifier", frozenset({"run_native_test"})))


@dataclass(frozen=True)
class AgentPlan:
    plan_id: str
    agent: str
    project_root: str
    actions: tuple[str, ...]
    created_at: str
    delegate_depth: int = 0


@dataclass(frozen=True)
class ToolSpec:
    name: str
    permission: str
    handler: Callable[..., Mapping[str, Any]]
    requires_explicit_approval: bool = False


class ToolRegistry:
    """Only application-registered functions can execute; models cannot register tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(self, spec: ToolSpec, *, replace: bool = False) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", spec.name):
            raise AgentRuntimeError("Tool name must be a lowercase identifier.")
        if spec.name in self._tools and not replace:
            raise AgentRuntimeError(f"Tool already registered: {spec.name}")
        if not callable(spec.handler):
            raise AgentRuntimeError("Tool handler must be callable.")
        self._tools[spec.name] = spec

    def get(self, name: str) -> ToolSpec:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise AgentRuntimeError(f"Tool is not registered: {name}") from exc

    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "name": item.name,
                "permission": item.permission,
                "requires_explicit_approval": item.requires_explicit_approval,
            }
            for item in sorted(self._tools.values(), key=lambda value: value.name)
        ]

    def invoke(
        self,
        name: str,
        *,
        root: Path,
        arguments: Mapping[str, Any],
        granted_permissions: Iterable[str],
        approved: bool,
        runtime: "AgentRuntime",
    ) -> dict[str, Any]:
        tool = self.get(name)
        grants = frozenset(granted_permissions)
        if tool.permission not in grants:
            runtime.emit("tool:" + name, "denied", {"reason": "permission_missing"})
            raise AgentRuntimeError(f"Permission '{tool.permission}' is required for tool '{name}'.")
        if tool.requires_explicit_approval and not approved:
            runtime.emit("tool:" + name, "denied", {"reason": "explicit_approval_missing"})
            raise AgentRuntimeError(f"Tool '{name}' requires an explicit user-approved execution flag.")
        runtime.emit("tool:" + name, "started", {"arguments_sha256": _json_digest(arguments)})
        started = time.monotonic()
        try:
            result = dict(tool.handler(root=root, **dict(arguments)))
        except Exception as exc:
            runtime.emit("tool:" + name, "failed", {"error_type": type(exc).__name__})
            raise
        runtime.emit(
            "tool:" + name,
            "completed" if result.get("status") in {"passed", "failed"} else "finished",
            {
                "result_status": result.get("status"),
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "result_sha256": _json_digest(result),
            },
        )
        return result


class AgentRuntime:
    def __init__(self, root: str | Path, *, registry: AgentRegistry | None = None):
        self.root = Path(root).expanduser().resolve()
        if not self.root.is_dir():
            raise AgentRuntimeError(f"Project path is not a directory: {self.root}")
        self.registry = registry or DEFAULT_AGENTS
        self.runtime_id = uuid.uuid4().hex[:12]
        self.event_path = self.root / ".audit" / "ai-review" / "runtime-events.jsonl"

    def emit(self, action: str, status: str, data: Mapping[str, Any] | None = None) -> dict[str, Any]:
        details = dict(data or {})
        record = {
            "schema_version": 1,
            "event_id": uuid.uuid4().hex[:12],
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "runtime_id": self.runtime_id,
            "agent": getattr(self, "_active_agent", None),
            "action": str(action),
            "status": str(status),
            "project_root_sha256": hashlib.sha256(str(self.root).encode("utf-8")).hexdigest(),
            "details_sha256": _json_digest(details),
            "details": details,
        }
        _append_private_jsonl(self.event_path, record)
        return record

    def plan(self, agent: str, actions: Iterable[str], *, _delegate_depth: int = 0) -> AgentPlan:
        spec = self.registry.get(agent)
        chosen = tuple(dict.fromkeys(str(action) for action in actions))
        if not chosen:
            raise AgentRuntimeError("A plan must contain at least one action.")
        if _delegate_depth > 1:
            raise AgentRuntimeError("Delegation depth is limited to one child agent.")
        disallowed = set(chosen) - set(spec.actions)
        if disallowed:
            raise AgentRuntimeError(f"Agent '{agent}' cannot plan action(s): {', '.join(sorted(disallowed))}.")
        plan = AgentPlan(
            plan_id=uuid.uuid4().hex[:12],
            agent=agent,
            project_root=str(self.root),
            actions=chosen,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            delegate_depth=_delegate_depth,
        )
        previous = getattr(self, "_active_agent", None)
        self._active_agent = agent
        try:
            self.emit("plan-created", "planned", {
                "plan_id": plan.plan_id, "actions": list(chosen), "delegate_depth": _delegate_depth,
            })
        finally:
            self._active_agent = previous
        return plan

    def run_action(
        self,
        plan: AgentPlan,
        action: str,
        operation: Callable[[], Any],
        *,
        granted_permissions: Iterable[str],
        approved: bool = False,
    ) -> Any:
        if Path(plan.project_root).resolve() != self.root:
            raise AgentRuntimeError("Plan project scope does not match the active project.")
        if action not in plan.actions:
            raise AgentRuntimeError(f"Action '{action}' was not included in plan {plan.plan_id}.")
        if action not in self.registry.get(plan.agent).actions:
            raise AgentRuntimeError(f"Agent '{plan.agent}' is not allowed to perform '{action}'.")
        grants = frozenset(granted_permissions)
        if action not in grants:
            self.emit(action, "denied", {"reason": "permission_missing", "plan_id": plan.plan_id})
            raise AgentRuntimeError(f"Permission '{action}' was not granted for this invocation.")
        if action == "run_native_test" and not approved:
            self.emit(action, "denied", {"reason": "explicit_approval_missing", "plan_id": plan.plan_id})
            raise AgentRuntimeError("Native test execution requires an explicit user-approved --run flag.")
        previous = getattr(self, "_active_agent", None)
        self._active_agent = plan.agent
        self.emit(action, "started", {"plan_id": plan.plan_id})
        started = time.monotonic()
        try:
            result = operation()
            self.emit(action, "completed", {
                "plan_id": plan.plan_id,
                "elapsed_ms": int((time.monotonic() - started) * 1000),
                "result_sha256": _json_digest(result),
            })
            return result
        except Exception as exc:
            self.emit(action, "failed", {
                "plan_id": plan.plan_id, "error_type": type(exc).__name__,
            })
            raise
        finally:
            self._active_agent = previous

    def delegate(
        self,
        parent_plan: AgentPlan,
        child_agent: str,
        child_actions: Iterable[str],
        operation: Callable[[], Any],
        *,
        granted_permissions: Iterable[str],
    ) -> Any:
        parent = self.registry.get(parent_plan.agent)
        if child_agent not in parent.delegates_to:
            self.emit("delegate", "denied", {"parent": parent_plan.agent, "child": child_agent})
            raise AgentRuntimeError(f"Agent '{parent_plan.agent}' cannot delegate to '{child_agent}'.")
        if parent_plan.delegate_depth >= 1:
            raise AgentRuntimeError("Nested delegation is disabled; maximum depth is one.")
        child = self.registry.get(child_agent)
        actions = tuple(dict.fromkeys(str(action) for action in child_actions))
        if not actions or not set(actions) <= set(child.actions):
            raise AgentRuntimeError("Delegated actions exceed the child agent's capabilities.")
        self.emit("delegate", "started", {
            "parent": parent_plan.agent, "child": child_agent, "actions": list(actions),
        })
        child_plan = self.plan(child_agent, actions, _delegate_depth=parent_plan.delegate_depth + 1)
        result = None
        for action in actions:
            result = self.run_action(
                child_plan, action, operation,
                granted_permissions=granted_permissions,
            )
        self.emit("delegate", "completed", {"parent": parent_plan.agent, "child": child_agent})
        return result

    def status(self) -> dict[str, Any]:
        return {
            "runtime_id": self.runtime_id,
            "project_root": str(self.root),
            "event_log": str(self.event_path),
            "agents": self.registry.describe(),
            "delegation_max_depth": 1,
            "tool_execution": "registered tools only; model output cannot invoke tools directly",
            "forbidden_builtin_tools": ["arbitrary-shell", "sign-transaction", "broadcast-transaction", "deploy-contract"],
        }


def _validate_forge_test_target(root: Path, test_path: str, match_test: str) -> tuple[Path, str]:
    if not (root / "foundry.toml").is_file():
        raise AgentRuntimeError("Native test verification currently requires a Foundry project (foundry.toml).")
    relative = PurePosixPath(str(test_path).replace("\\", "/"))
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise AgentRuntimeError("Test path must be a relative path inside test/ or tests/.")
    if relative.parts[0] not in {"test", "tests"} or relative.suffix.lower() != ".sol":
        raise AgentRuntimeError("Only Solidity test files under test/ or tests/ may be selected.")
    if any(part.lower() == "fork" for part in relative.parts):
        raise AgentRuntimeError("Fork tests are excluded from this local verification tool; run them manually.")
    if not re.fullmatch(r"test[A-Za-z0-9_]{1,120}", str(match_test)):
        raise AgentRuntimeError("Test function must be an exact identifier beginning with 'test'.")
    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root.resolve())
    except (OSError, ValueError) as exc:
        raise AgentRuntimeError("Test path does not resolve to a file inside the project.") from exc
    if candidate.is_symlink() or not resolved.is_file():
        raise AgentRuntimeError("Selected test must be a regular, non-symlink file.")
    return resolved, relative.as_posix()


def plan_native_test(root: str | Path, *, test_path: str, match_test: str) -> dict[str, Any]:
    project = Path(root).expanduser().resolve()
    _, relative = _validate_forge_test_target(project, test_path, match_test)
    command = ["forge", "test", "--match-path", relative, "--match-test", f"^{match_test}$", "-vv"]
    runtime = AgentRuntime(project)
    plan = runtime.plan("native-test-verifier", ["run_native_test"])
    runtime.emit("native-test-plan", "planned", {
        "plan_id": plan.plan_id, "command": command,
        "note": "No command executed; add --run to explicitly execute this selected local test.",
    })
    return {"status": "planned", "command": command, "runtime_event_log": str(runtime.event_path)}


def _forge_test_tool(*, root: Path, test_path: str, match_test: str, timeout_seconds: int = 180) -> Mapping[str, Any]:
    resolved, relative = _validate_forge_test_target(root, test_path, match_test)
    if not 5 <= int(timeout_seconds) <= 300:
        raise AgentRuntimeError("Test timeout must be between 5 and 300 seconds.")
    command = ["forge", "test", "--match-path", relative, "--match-test", f"^{match_test}$", "-vv"]
    test_hash = hashlib.sha256(resolved.read_bytes()).hexdigest()
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command, cwd=str(root), capture_output=True, text=True,
            timeout=int(timeout_seconds), check=False,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        summary = [
            line.strip()[:500] for line in output.splitlines()
            if "[PASS]" in line or "[FAIL]" in line or "Suite result:" in line
            or re.search(r"\bRan \d+ test", line)
        ][:40]
        return {
            "status": "passed" if proc.returncode == 0 and any("[PASS]" in item for item in summary) else "failed",
            "exit_code": proc.returncode,
            "command": command,
            "test_path": relative,
            "test_name": match_test,
            "test_sha256": test_hash,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "output_sha256": hashlib.sha256(output.encode("utf-8", errors="replace")).hexdigest(),
            "summary_lines": summary,
            "output_retained": False,
            "timeout_seconds": int(timeout_seconds),
        }
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or b"") + (b"\n" if exc.stdout else b"") + (exc.stderr or b"")
        if isinstance(output, bytes):
            output_bytes = output
        else:
            output_bytes = str(output).encode("utf-8", errors="replace")
        return {
            "status": "timeout", "exit_code": None, "command": command,
            "test_path": relative, "test_name": match_test, "test_sha256": test_hash,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
            "summary_lines": [], "output_retained": False, "timeout_seconds": int(timeout_seconds),
        }
    except OSError as exc:
        return {
            "status": "tool_error", "exit_code": None, "command": command,
            "test_path": relative, "test_name": match_test, "test_sha256": test_hash,
            "elapsed_ms": int((time.monotonic() - started) * 1000),
            "output_sha256": hashlib.sha256(str(exc).encode()).hexdigest(),
            "summary_lines": [], "output_retained": False, "error_type": type(exc).__name__,
        }


BUILTIN_TOOLS = ToolRegistry()
BUILTIN_TOOLS.register(ToolSpec(
    "forge-test", "run_native_test", _forge_test_tool, requires_explicit_approval=True,
))


def execute_native_test(
    root: str | Path, *, test_path: str, match_test: str, finding_id: str,
    approved: bool, timeout_seconds: int = 180,
) -> dict[str, Any]:
    project = Path(root).expanduser().resolve()
    # Validate before recording or starting a process, including in preview wrappers.
    _validate_forge_test_target(project, test_path, match_test)
    runtime = AgentRuntime(project)
    plan = runtime.plan("native-test-verifier", ["run_native_test"])
    result = runtime.run_action(
        plan,
        "run_native_test",
        lambda: BUILTIN_TOOLS.invoke(
            "forge-test", root=project,
            arguments={"test_path": test_path, "match_test": match_test, "timeout_seconds": timeout_seconds},
            granted_permissions={"run_native_test"}, approved=approved, runtime=runtime,
        ),
        granted_permissions={"run_native_test"},
        approved=approved,
    )
    result["finding_id"] = finding_id
    result["runtime_id"] = runtime.runtime_id
    result["runtime_event_log"] = str(runtime.event_path)
    return result


def runtime_status() -> dict[str, Any]:
    return {
        "agents": DEFAULT_AGENTS.describe(),
        "tools": BUILTIN_TOOLS.describe(),
        "provider_tool_boundary": "structured provider requests only; model responses cannot invoke registered tools",
        "forbidden_builtin_tools": ["arbitrary-shell", "sign-transaction", "broadcast-transaction", "deploy-contract"],
    }
