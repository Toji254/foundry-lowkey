"""Jev capability orchestrator.

The Jevos/Jev typed decision engine remains unchanged. This module adds a separate
operator layer that routes requests to registered capability handlers.
Natural-language input is never executed as shell syntax or used as a tool name.
"""
from __future__ import annotations

import fnmatch, json, os, re, select, shlex, shutil, subprocess, sys, time, uuid
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

SCHEMA_VERSION = 1
MAX_FILE_BYTES = 256_000
MAX_SCAN_FILES = 2_000
MAX_OUTPUT_CHARS = 14_000
DEFAULT_MCP_COMMAND = "npx -y brave-mcp@latest --autoConnect"
_EXCLUDED_DIRS = {".git", ".venv", "venv", "node_modules", ".tox", "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache"}
_SENSITIVE_NAMES = {".env", ".env.local", ".env.production", "id_rsa", "id_ed25519", "credentials.json", "secrets.json", "jev-credentials.json", "ai-credentials.json", "wallet.json"}
_SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".keystore"}


class JevOrchestratorError(RuntimeError):
    """Actionable, user-safe orchestration error."""


def _config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME")
    return (Path(base).expanduser() if base else Path.home() / ".config") / "lowkey" / "jev-orchestrator.json"


def _default_config() -> dict[str, Any]:
    return {"schema_version": SCHEMA_VERSION, "autonomy_enabled": False, "browser_capability_enabled": True}


def _read_config() -> dict[str, Any]:
    path = _config_path()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _default_config()
    except (OSError, json.JSONDecodeError) as exc:
        raise JevOrchestratorError(f"Cannot read Jev settings at {path}. Preserve a backup before repairing it.") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise JevOrchestratorError("Jev orchestrator settings have an unsupported format.")
    config = _default_config()
    config.update(raw)
    for key in ("autonomy_enabled", "browser_capability_enabled"):
        if not isinstance(config.get(key), bool):
            raise JevOrchestratorError(f"Jev setting {key!r} must be true or false.")
    return config


def _write_config(config: Mapping[str, Any]) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({**dict(config), "schema_version": SCHEMA_VERSION}, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


_CAPABILITIES: dict[str, dict[str, str]] = {
    "browser.tabs": {"risk": "read-only", "description": "List tabs in the user's normal Brave browser through Brave DevTools MCP."},
    "browser.page": {"risk": "read-only", "description": "Read the current browser page through an available DevTools tool."},
    "browser.navigate": {"risk": "changes browser state", "description": "Navigate a browser tab to an explicit HTTP(S) URL."},
    "browser.click": {"risk": "changes browser state", "description": "Click a page control when a compatible DevTools tool is available."},
    "browser.scroll": {"risk": "changes browser view", "description": "Scroll the current browser page."},
    "workspace.list": {"risk": "read-only", "description": "List files and folders in the current workspace."},
    "workspace.find": {"risk": "read-only", "description": "Find workspace files by name or glob."},
    "workspace.search": {"risk": "read-only", "description": "Search text in source and documentation files."},
    "workspace.read": {"risk": "read-only", "description": "Read non-sensitive text files inside the current workspace."},
    "lowkey.read": {"risk": "read-only", "description": "Run a fixed allowlist of read-oriented Lowkey commands."},
    "lowkey.workflow": {"risk": "local project operation", "description": "Run allowlisted Lowkey workflows with approval or autonomy enabled."},
}


def capability_registry() -> list[dict[str, str]]:
    return [{"name": name, **metadata} for name, metadata in sorted(_CAPABILITIES.items())]


def _normalize_request(value: str) -> str:
    text = " ".join(str(value or "").strip().split())
    while text.startswith("/"):
        text = text[1:].lstrip()
    return text


def _safe_project_root() -> Path:
    return Path.cwd().resolve()


def _blocked_file(path: Path) -> bool:
    name = path.name.lower()
    return (name in _SENSITIVE_NAMES or name.startswith(".env")
            or path.suffix.lower() in _SENSITIVE_SUFFIXES
            or any(part.lower() in {".ssh", ".gnupg", ".aws", ".kube", "wallets", "secrets", "credentials"} for part in path.parts))


def _resolve_workspace_file(root: Path, raw_path: str) -> Path:
    relative = Path(raw_path.strip().strip("\"'"))
    if not str(relative).strip() or relative.is_absolute():
        raise JevOrchestratorError("Give a relative file path inside the current project.")
    candidate = root / relative
    if candidate.is_symlink():
        raise JevOrchestratorError("Jev will not read symlinked files for this request.")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise JevOrchestratorError("That path does not resolve to an existing file inside the current project.") from exc
    if not resolved.is_file():
        raise JevOrchestratorError("That workspace path is not a regular file.")
    if _blocked_file(resolved):
        raise JevOrchestratorError("Jev blocked that file because its name or location looks sensitive.")
    if resolved.stat().st_size > MAX_FILE_BYTES:
        raise JevOrchestratorError(f"That file is larger than Jev's {MAX_FILE_BYTES:,}-byte read limit.")
    return resolved


def _walk_workspace(root: Path):
    count = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in _EXCLUDED_DIRS and not (Path(current) / name).is_symlink()]
        for name in files:
            path = Path(current) / name
            count += 1
            if count > MAX_SCAN_FILES:
                return
            if not path.is_symlink() and not _blocked_file(path):
                yield path


def _extract_quoted_or_tail(text: str, prefixes: tuple[str, ...]) -> str:
    for prefix in prefixes:
        match = re.search(re.escape(prefix) + r"\s+([\"'])(.+?)\1", text, re.IGNORECASE)
        if match:
            return match.group(2).strip()
        match = re.search(re.escape(prefix) + r"\s+(.+)$", text, re.IGNORECASE)
        if match:
            candidate = re.sub(r"^(?:the|a|an)\s+", "", match.group(1).strip().rstrip("?."), flags=re.IGNORECASE)
            return candidate
    return ""


def _workspace_action(request: str, intent: str) -> str:
    root = _safe_project_root()
    if intent == "workspace.list":
        entries: list[tuple[str, bool]] = []
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(
                name for name in dirs
                if name not in _EXCLUDED_DIRS and not (Path(current) / name).is_symlink()
                and not _blocked_file(Path(current) / name)
            )
            current_path = Path(current)
            if current_path != root:
                entries.append((current_path.relative_to(root).as_posix() + "/", True))
            for name in sorted(files, key=str.casefold):
                path = current_path / name
                if path.is_symlink() or _blocked_file(path):
                    continue
                entries.append((path.relative_to(root).as_posix(), False))
                if len(entries) >= 81:
                    break
            if len(entries) >= 81:
                break
        lines = [f"{'DIR ' if is_dir else 'FILE'}  {name}" for name, is_dir in entries[:80]]
        suffix = "\nShowing the first 80 entries; excluded generated, dependency, and sensitive locations." if len(entries) > 80 else ""
        return f"Workspace: {root}\n" + ("\n".join(lines) if lines else "No visible project files were found.") + suffix
    if intent == "workspace.find":
        pattern = _extract_quoted_or_tail(request, ("find file", "find files named", "find files", "locate file"))
        if not pattern:
            return "Give me a filename or glob, for example: jev ask find files named '*Test.sol'."
        matches = [p.relative_to(root).as_posix() for p in _walk_workspace(root) if fnmatch.fnmatch(p.name, pattern) or fnmatch.fnmatch(p.relative_to(root).as_posix(), pattern)]
        return "\n".join(matches[:100]) if matches else f"No files matched {pattern!r} in {root}."
    if intent == "workspace.search":
        pattern = _extract_quoted_or_tail(request, ("search files for", "search for", "find text", "look for text"))
        if not pattern:
            return "Quote the text to search for, for example: jev ask search files for 'onlyOwner'."
        hits: list[str] = []
        scanned = 0
        extensions = {".sol", ".py", ".toml", ".json", ".md", ".txt", ".yml", ".yaml", ".sh", ".js", ".ts", ".rs", ".go", ".html", ".css"}
        for path in _walk_workspace(root):
            if path.suffix.lower() not in extensions:
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            for line_no, line in enumerate(source.splitlines(), 1):
                if pattern.casefold() in line.casefold():
                    hits.append(f"{path.relative_to(root).as_posix()}:{line_no}: {line.strip()[:220]}")
                    if len(hits) >= 80:
                        break
            if len(hits) >= 80:
                break
        return f"Search: {pattern!r}\nFiles checked: {scanned}\n" + ("\n".join(hits) if hits else "No matches found.")
    if intent == "workspace.read":
        relative = _extract_quoted_or_tail(request, ("read file", "show file", "open file", "cat file"))
        if not relative:
            return "Give me a relative path, for example: jev ask read file src/Vault.sol."
        path = _resolve_workspace_file(root, relative)
        content = path.read_text(encoding="utf-8", errors="replace")
        if len(content) > MAX_OUTPUT_CHARS:
            content = content[:MAX_OUTPUT_CHARS] + "\n… output truncated by Jev."
        return f"File: {path.relative_to(root).as_posix()}\n{content}"
    raise JevOrchestratorError(f"Unknown workspace capability: {intent}")


def _approval_required(config: Mapping[str, Any], *, explicit_yes: bool, mutating: bool) -> bool:
    return bool(mutating and not explicit_yes and not config.get("autonomy_enabled", False))


def _run_lowkey(command: list[str], *, requires_approval: bool, explicit_yes: bool) -> str:
    config = _read_config()
    if _approval_required(config, explicit_yes=explicit_yes, mutating=requires_approval):
        return ("I prepared the Lowkey operation but did not run it.\n"
                f"Requested operation: {' '.join(command)}\n"
                "Approve explicitly with 'jev ask --yes ...', or enable bounded autonomy using 'jev autonomy on'.")
    executable = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not (Path(executable).is_file() and os.access(executable, os.X_OK)):
        raise JevOrchestratorError("I could not find Lowkey (lk) on PATH or in ~/.foundry/bin.")
    timeout = 240 if any(part in {"test", "build", "scan", "audit", "fuzz", "invariant"} for part in command) else 45
    try:
        proc = subprocess.run([executable, *command], cwd=str(_safe_project_root()), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        captured = exc.stdout or ""
        if isinstance(captured, bytes):
            captured = captured.decode("utf-8", errors="replace")
        return f"Lowkey did not finish within {timeout} seconds.\n{captured[-MAX_OUTPUT_CHARS:]}"
    except OSError as exc:
        raise JevOrchestratorError(f"Could not run Lowkey: {exc}") from exc
    output = (proc.stdout or "").strip()
    if len(output) > MAX_OUTPUT_CHARS:
        output = "… earlier output omitted …\n" + output[-MAX_OUTPUT_CHARS:]
    heading = "Lowkey finished successfully." if proc.returncode == 0 else f"Lowkey finished with exit code {proc.returncode}."
    return heading + (f"\n\n{output}" if output else "\n(No command output.)")


def _native_intent(request: str) -> tuple[str, list[str], bool] | None:
    text = request.casefold()
    if re.search(r"\b(deploy|broadcast|sign transaction|send transaction|transfer funds|withdraw funds|delete files|rm -rf)\b", text):
        raise JevOrchestratorError("That request is outside Jev's registered capabilities. It will not sign/broadcast transactions, deploy contracts, or run destructive shell commands.")
    if re.search(r"\b(run|execute|start)\b.*\b(tests?|test suite|forge test)\b", text):
        return "lowkey.workflow", ["test"], True
    if re.search(r"\b(run|execute|compile|build)\b.*\b(build|compile|project|contracts?)\b", text) or text.strip() in {"build", "compile"}:
        return "lowkey.workflow", ["build"], True
    if re.search(r"\b(run|execute|start)\b.*\b(scan|security scan)\b", text) or text.strip() in {"scan", "security scan"}:
        return "lowkey.workflow", ["scan"], True
    if re.search(r"\b(run|execute|start)\b.*\b(audit|security audit)\b", text) or text.strip() in {"audit", "security audit"}:
        return "lowkey.workflow", ["audit"], True
    if "verification engines" in text or "available verification engines" in text:
        return "lowkey.read", ["verification", "engines"], False
    if re.search(r"\b(check|show|run)\b.*\b(doctor|health|installation)\b", text) or text.strip() in {"doctor", "health check"}:
        return "lowkey.read", ["doctor"], False
    if re.search(r"\b(show|check|get)\b.*\b(status|system status)\b", text) or text.strip() in {"status", "system status"}:
        return "lowkey.read", ["status"], False
    if re.search(r"\b(show|map|inspect|summari[sz]e)\b.*\b(project|workspace)\b", text) or text.strip() in {"project", "workspace"}:
        return "lowkey.read", ["project"], False
    return None


def _mcp_response_text(result: Mapping[str, Any]) -> str:
    structured = result.get("structuredContent")
    if structured is not None:
        return json.dumps(structured, indent=2, ensure_ascii=False)[:MAX_OUTPUT_CHARS]
    chunks = [item["text"] for item in result.get("content", []) if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str)]
    if chunks:
        joined = "\n".join(chunks)
        try:
            joined = json.dumps(json.loads(joined), indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            pass
        return joined[:MAX_OUTPUT_CHARS]
    return json.dumps(dict(result), indent=2, ensure_ascii=False)[:MAX_OUTPUT_CHARS]


class _MCPStdioClient:
    """Minimal MCP stdio client; Jev selects every tool it invokes."""
    def __init__(self, command: list[str], timeout: float = 12.0):
        self.command = command
        self.timeout = timeout
        self.process: subprocess.Popen[str] | None = None
        self._next_id = 1

    def __enter__(self):
        if not self.command or not shutil.which(self.command[0]):
            name = self.command[0] if self.command else "(empty)"
            raise JevOrchestratorError(f"Browser MCP launcher {name} was not found. Install Node.js/npm or set JEV_BRAVE_MCP_COMMAND.")
        try:
            self.process = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding="utf-8", bufsize=1)
            initialized = self._rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "jev-orchestrator", "version": "1.0.0"}})
            if not isinstance(initialized, dict) or "protocolVersion" not in initialized:
                raise JevOrchestratorError("Brave DevTools MCP returned an invalid initialize response.")
            self._notify("notifications/initialized", {})
            return self
        except Exception:
            # __exit__ is not called when __enter__ fails; reap the MCP process here.
            self._stop()
            raise

    def _stop(self):
        process = self.process
        if process is None:
            return
        try:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        finally:
            self.process = None

    def __exit__(self, exc_type, exc, traceback):
        self._stop()
        return False

    def _send(self, payload: Mapping[str, Any]) -> None:
        if not self.process or not self.process.stdin:
            raise JevOrchestratorError("Brave DevTools MCP is not running.")
        self.process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def _read_response(self, request_id: int) -> dict[str, Any]:
        if not self.process or not self.process.stdout:
            raise JevOrchestratorError("Brave DevTools MCP is not running.")
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.process.stdout], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            line = self.process.stdout.readline()
            if not line:
                break
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(message, dict) or message.get("id") != request_id:
                continue
            if "error" in message:
                error = message["error"]
                raise JevOrchestratorError(f"Brave DevTools MCP request failed: {str(error.get('message', error))[:500]}")
            result = message.get("result")
            if not isinstance(result, dict):
                raise JevOrchestratorError("Brave DevTools MCP returned an invalid response.")
            return result
        raise JevOrchestratorError(f"Brave DevTools MCP did not answer within {self.timeout:g} seconds. Check ordinary Brave's DevTools connection.")

    def _rpc(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)})
        return self._read_response(request_id)

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def tools(self) -> list[dict[str, Any]]:
        tools = self._rpc("tools/list", {}).get("tools")
        if not isinstance(tools, list) or not all(isinstance(item, dict) for item in tools):
            raise JevOrchestratorError("Brave DevTools MCP did not provide a valid tool registry.")
        return tools

    def call(self, name: str, args: Mapping[str, Any]) -> dict[str, Any]:
        result = self._rpc("tools/call", {"name": name, "arguments": dict(args)})
        if result.get("isError"):
            raise JevOrchestratorError(_mcp_response_text(result))
        return result


def _browser_intent(request: str) -> str | None:
    text = request.casefold()
    if re.search(r"\b(tabs?|open pages|browser windows)\b", text) and re.search(r"\b(list|show|get|currently|open|what|which)\b", text):
        return "browser.tabs"
    if re.search(r"\bscroll\b", text):
        return "browser.scroll"
    if re.search(r"\b(click|press)\b", text):
        return "browser.click"
    if re.search(r"\b(navigate|go to|visit|open)\b", text) and re.search(r"https?://", text):
        return "browser.navigate"
    if re.search(r"\b(read|inspect|show|summari[sz]e)\b", text) and re.search(r"\b(current|this|active)\s+(page|tab)\b|page content|current url", text):
        return "browser.page"
    return None


def _browser_tool_score(tool: Mapping[str, Any], intent: str) -> int:
    name = str(tool.get("name", "")).casefold().replace("_", " ").replace("-", " ")
    desc = str(tool.get("description", "")).casefold()
    if intent == "browser.tabs":
        return (12 if "tab" in name or "page" in name else 0) + (8 if "list" in name or "get" in name else 0) + (3 if "tab" in desc or "page" in desc else 0) - (10 if any(word in name for word in ("screenshot", "click", "navigate", "scroll", "close")) else 0)
    if intent == "browser.navigate":
        return (12 if "navigat" in name else 0) + (7 if "url" in name or "open page" in name else 0) + (3 if "url" in desc else 0) - (10 if "close" in name else 0)
    if intent == "browser.click":
        return (12 if "click" in name else 0) + (6 if "element" in name or "selector" in name else 0) + (2 if "click" in desc else 0)
    if intent == "browser.scroll":
        return (12 if "scroll" in name else 0) + (2 if "scroll" in desc else 0)
    if intent == "browser.page":
        return (9 if "evaluate" in name or "script" in name else 0) + (6 if "page" in name or "content" in name else 0) + (2 if "evaluate" in desc or "content" in desc else 0)
    return 0


def _extract_url(request: str) -> str | None:
    match = re.search(r"https?://[^\s\"'<>]+", request)
    if not match:
        return None
    candidate = match.group(0).rstrip(".,)")
    parsed = urlparse(candidate)
    return candidate if parsed.scheme in {"http", "https"} and parsed.netloc and not parsed.username and not parsed.password else None


def _tool_arguments(tool: Mapping[str, Any], request: str, intent: str) -> dict[str, Any]:
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    required = schema.get("required", []) if isinstance(schema, dict) else []
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise JevOrchestratorError("The selected browser tool has an unsupported argument schema.")
    args: dict[str, Any] = {}
    url = _extract_url(request)
    lower = request.casefold()
    target = _extract_quoted_or_tail(request, ("click", "press"))
    for raw_name in required:
        name = str(raw_name)
        key = name.casefold().replace("_", "").replace("-", "")
        prop = properties.get(name, {})
        prop = prop if isinstance(prop, dict) else {}
        if key in {"url", "uri", "href"} and url:
            args[name] = url
        elif key in {"script", "expression", "javascript", "code"} and intent == "browser.page":
            args[name] = "({title: document.title, url: location.href, text: document.body ? document.body.innerText.slice(0, 12000) : ''})"
        elif key in {"direction", "scrolldirection"} and intent == "browser.scroll":
            args[name] = "up" if re.search(r"\b(up|upward|towards the top)\b", lower) else "down"
        elif key in {"amount", "pixels", "distance", "y"} and intent == "browser.scroll":
            amount = re.search(r"\b(\d{2,4})\s*(?:px|pixels)?\b", lower)
            args[name] = int(amount.group(1)) if amount else 600
        elif key in {"selector", "text", "label", "element", "target", "query"} and intent == "browser.click" and target:
            args[name] = target
        else:
            enum = prop.get("enum")
            if isinstance(enum, list) and enum:
                args[name] = enum[0]
            else:
                raise JevOrchestratorError(f"The browser tool {tool.get('name')!r} needs {name!r}, but Jev could not infer it safely. Nothing was executed; provide that detail explicitly.")
    return args


def _call_browser(request: str, intent: str, explicit_yes: bool) -> str:
    config = _read_config()
    if not config.get("browser_capability_enabled", True):
        raise JevOrchestratorError("The Brave browser capability is turned off.")
    mutating = intent in {"browser.navigate", "browser.click", "browser.scroll"}
    if _approval_required(config, explicit_yes=explicit_yes, mutating=mutating):
        return ("I understood the browser request but did not change your browser.\n"
                "Enable bounded autonomous execution with 'jev autonomy on', or approve with 'jev ask --yes ...'.")
    custom = os.environ.get("JEV_BRAVE_MCP_COMMAND", "").strip()
    try:
        command = shlex.split(custom) if custom else shlex.split(DEFAULT_MCP_COMMAND)
    except ValueError as exc:
        raise JevOrchestratorError("JEV_BRAVE_MCP_COMMAND has invalid quoting.") from exc
    with _MCPStdioClient(command) as client:
        tools = client.tools()
        ranked = sorted(((_browser_tool_score(tool, intent), tool) for tool in tools), key=lambda pair: pair[0], reverse=True)
        if not ranked or ranked[0][0] < 7:
            available = ", ".join(str(tool.get("name", "?")) for tool in tools[:32])
            raise JevOrchestratorError(f"Brave DevTools MCP connected, but no registered tool matched. Available tools include: {available}")
        _, tool = ranked[0]
        result = client.call(str(tool["name"]), _tool_arguments(tool, request, intent))
        return f"Jev {'read from' if not mutating else 'performed'} Brave DevTools MCP tool {tool['name']!r}.\n\n{_mcp_response_text(result)}"


def _route_request(request: str, explicit_yes: bool) -> str:
    if not request:
        return help_text()
    browser = _browser_intent(request)
    if browser:
        return _call_browser(request, browser, explicit_yes)
    text = request.casefold()
    workspace = None
    if re.search(r"\b(list|show)\b.*\b(files|file tree|directory|directories|folder contents)\b", text):
        workspace = "workspace.list"
    elif re.search(r"\b(find|locate)\b.*\b(files? named|files? matching|file|files)\b", text):
        workspace = "workspace.find"
    elif re.search(r"\b(search|look)\b.*\b(files?|source|text)\b", text):
        workspace = "workspace.search"
    elif re.search(r"\b(read|show|open|cat)\b.*\bfile\b", text):
        workspace = "workspace.read"
    if workspace:
        return _workspace_action(request, workspace)
    native = _native_intent(request)
    if native:
        _, command, approval = native
        return _run_lowkey(command, requires_approval=approval, explicit_yes=explicit_yes)
    raise JevOrchestratorError(
        "Jev didn't execute anything because no registered capability matched this request.\n"
        "Use 'jev capabilities' to inspect supported operations or 'jev help' for examples. "
        "Signing/broadcasting, deployment, arbitrary shell commands, and destructive file actions are excluded."
    )


def help_text() -> str:
    return """JEV — operator and capability orchestrator
===========================================
Jev routes requests to registered tools and reports what they actually did.
The existing Jevos/Jev typed decision engine remains a separate capability.

EXAMPLES
  jev ask list my open Brave tabs
  jev ask /read the current page
  jev ask navigate to https://example.com
  jev ask run the project tests
  jev ask show project status
  jev ask list files
  jev ask find files named '*Test.sol'
  jev ask search files for 'onlyOwner'
  jev ask read file src/Vault.sol
  jev-ask list my open Brave tabs

CONTROL
  jev capabilities            Show registered capability types
  jev status                  Show local orchestrator settings
  jev autonomy on|off|status   Control autonomous execution
  jev ask --yes <request>      Explicitly approve a state-changing operation

Slash prefixes are optional. Arbitrary shell, signing, broadcasting, deployment
and destructive file operations are not registered. Autonomy is OFF by default;
read-only tasks remain available while it is off.
"""


def status_text() -> str:
    config = _read_config()
    npx = shutil.which("npx")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    ready = Path(lk).is_file() and os.access(lk, os.X_OK)
    return ("JEV ORCHESTRATOR STATUS\n"
            f"Autonomy: {'ON' if config['autonomy_enabled'] else 'OFF (safe default)'}\n"
            f"Brave capability: {'enabled' if config.get('browser_capability_enabled', True) else 'disabled'}\n"
            f"Brave MCP launcher: {'available' if npx else 'npx not found'} (browser connection not tested)\n"
            f"Lowkey CLI: {'available' if ready else 'not found'}\n"
            f"Settings: {_config_path()}\n"
            "Jevos decision provider and request budget remain managed by lk ai jev status.")


def _set_autonomy(value: str) -> int:
    config = _read_config()
    if value == "status":
        print(f"Jev autonomous execution is {'ON' if config['autonomy_enabled'] else 'OFF'}.")
        print("This switch affects registered operations that change local or browser state.")
        return 0
    if value not in {"on", "off"}:
        print("Usage: jev autonomy on|off|status", file=sys.stderr)
        return 2
    config["autonomy_enabled"] = value == "on"
    _write_config(config)
    if value == "on":
        print("Jev autonomous execution is ON. Registered local workflows and browser actions may run without per-action approval.")
        print("Signing/broadcasting transactions, deployments, arbitrary shell and destructive file commands remain unavailable.")
    else:
        print("Jev autonomous execution is OFF. Read-only tasks remain available; state-changing requests need --yes.")
    return 0


def _extract_cli_flags(args: list[str]) -> tuple[bool, list[str]]:
    yes = False
    cleaned = []
    for arg in args:
        if arg == "--yes":
            yes = True
        else:
            cleaned.append(arg)
    return yes, cleaned


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    command = args[0].casefold() if args else "help"
    if command in {"help", "--help", "-h", "--h"}:
        print(help_text())
        return 0
    if command == "status":
        print(status_text())
        return 0
    if command in {"capabilities", "tools"}:
        print("JEV REGISTERED CAPABILITIES")
        for item in capability_registry():
            print(f"  {item['name']:<20} [{item['risk']}] — {item['description']}")
        print("\nBrowser tools are discovered from Brave DevTools MCP only when a browser request runs.")
        return 0
    if command in {"autonomy", "auto"}:
        return _set_autonomy(args[1].casefold() if len(args) > 1 else "status")
    if command in {"ask", "run"}:
        explicit_yes, cleaned = _extract_cli_flags(args[1:])
        request = _normalize_request(" ".join(cleaned))
    else:
        explicit_yes, cleaned = _extract_cli_flags(args)
        request = _normalize_request(" ".join(cleaned))
    if not request:
        print(help_text())
        return 0
    try:
        print(_route_request(request, explicit_yes))
        return 0
    except JevOrchestratorError as exc:
        print(f"Jev did not complete the request: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Jev operation cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
