"""Project-scoped managed Anvil sessions.

This module deliberately stores sessions in Lowkey's established
``.audit/anvil.json`` state file.  It is not a second network registry.

Only processes launched by this manager and whose Linux process identity still
matches the recorded identity may be stopped.  Unmanaged Anvil processes are
never adopted or terminated.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


SCHEMA_VERSION = 2
DEFAULT_CHAIN_ID = 31337
PORT_RANGE = range(8545, 8566)


class NetworkError(RuntimeError):
    """A network session operation could not be completed safely."""


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _project_id(root: Path) -> str:
    return hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()


def _rpc_quantity(value: Any) -> int | None:
    """Decode an Ethereum JSON-RPC quantity without accepting bools or malformed data."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str):
        return None
    try:
        result = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None
    return result if result >= 0 else None


def _rpc_request(url: str, method: str, params: list[Any] | None = None, timeout: float = 1.5) -> Any:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        raise NetworkError(f"RPC {method} failed: {exc}") from exc
    if not isinstance(data, dict) or data.get("error"):
        detail = data.get("error") if isinstance(data, dict) else "invalid JSON-RPC response"
        raise NetworkError(f"RPC {method} returned an error: {detail}")
    return data.get("result")


def _proc_identity(pid: int) -> dict[str, Any] | None:
    """Return a stable-enough Linux identity for a process, or None."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        return None
    base = Path("/proc") / str(pid)
    try:
        raw_stat = (base / "stat").read_text(encoding="utf-8")
        close = raw_stat.rfind(")")
        if close < 0:
            return None
        # Fields following comm start with field 3 (state); starttime is 22.
        tail = raw_stat[close + 2:].split()
        start_ticks = int(tail[19])
        uid = (base / "status").read_text(encoding="utf-8")
        uid_match = re.search(r"^Uid:\s+(\d+)", uid, re.MULTILINE)
        executable = str((base / "exe").resolve())
        argv = (base / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        return {
            "pid": pid,
            "start_ticks": start_ticks,
            "uid": int(uid_match.group(1)) if uid_match else None,
            "executable": executable,
            "argv": argv,
        }
    except (OSError, ValueError, IndexError):
        return None


def _safe_process_match(record: dict[str, Any], identity: dict[str, Any] | None) -> bool:
    if not identity:
        return False
    try:
        return (
            int(record.get("pid")) == identity.get("pid")
            and int(record.get("process_start_ticks")) == identity.get("start_ticks")
            and int(record.get("process_uid")) == identity.get("uid") == os.getuid()
            and str(record.get("process_executable") or "") == identity.get("executable")
            and str(record.get("process_executable") or "").endswith("/anvil")
            and f"--port {int(record.get('port'))}" in str(identity.get("argv") or "")
        )
    except (TypeError, ValueError):
        return False


def _sanitize_origin(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.hostname}{port}"
    except ValueError:
        return None


class NetworkManager:
    """Manage several independently-owned Anvil processes for one project."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        anvil_binary: str | os.PathLike[str] = "anvil",
        *,
        popen: Callable[..., Any] = subprocess.Popen,
        rpc_call: Callable[..., Any] = _rpc_request,
        process_identity: Callable[[int], dict[str, Any] | None] = _proc_identity,
        sleep: Callable[[float], None] = time.sleep,
        port_range=PORT_RANGE,
        startup_attempts: int = 50,
    ):
        self.root = Path(root).expanduser().resolve()
        self.audit_dir = self.root / ".audit"
        self.state_path = self.audit_dir / "anvil.json"
        self.binary = str(anvil_binary)
        self._popen = popen
        self._rpc = rpc_call
        self._identity = process_identity
        self._sleep = sleep
        self._port_range = port_range
        self._startup_attempts = startup_attempts

    @property
    def project_id(self) -> str:
        return _project_id(self.root)

    def _read(self) -> dict[str, Any]:
        try:
            raw = self.state_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            data = {}
        except OSError as exc:
            raise NetworkError(
                f"Cannot read the project's managed network registry {self.state_path}: {exc}. "
                "Lowkey will not fall back to another RPC while network identity is unavailable."
            ) from exc
        else:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise NetworkError(
                    f"The project's managed network registry {self.state_path} is invalid JSON "
                    f"at line {exc.lineno}, column {exc.colno}. Repair or restore that file before using RPC commands."
                ) from exc
            if not isinstance(data, dict):
                raise NetworkError(
                    f"The project's managed network registry {self.state_path} must contain a JSON object. "
                    "Lowkey will not silently replace it or select another RPC."
                )
        # Preserve legacy fixture fields at the top level. Managed sessions
        # are an additive schema migration within the existing state file.
        sessions = data.get("managed_sessions")
        if not isinstance(sessions, dict):
            sessions = {}
        data["managed_sessions"] = sessions
        data.setdefault("schema_version", SCHEMA_VERSION)
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        data["schema_version"] = SCHEMA_VERSION
        fd, temp_name = tempfile.mkstemp(prefix="anvil.", suffix=".tmp", dir=self.audit_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.state_path)
            try:
                os.chmod(self.state_path, 0o600)
            except OSError:
                pass
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

    def _find(self, sessions: dict[str, Any], name: str) -> tuple[str, dict[str, Any]] | None:
        matches = [
            (sid, session) for sid, session in sessions.items()
            if isinstance(session, dict) and session.get("name") == name
        ]
        if len(matches) > 1:
            raise NetworkError(f"Network name {name!r} is ambiguous in the project registry.")
        return matches[0] if matches else None

    def _free_port(self) -> int:
        for port in self._port_range:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.bind(("127.0.0.1", int(port)))
                except OSError:
                    continue
                return int(port)
        raise NetworkError("No free local port is available in the configured Anvil range.")

    def create(
        self,
        name: str,
        *,
        chain_id: int = DEFAULT_CHAIN_ID,
        fork_url: str | None = None,
        fork_block: int | None = None,
    ) -> dict[str, Any]:
        name = str(name or "").strip()
        if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
            raise NetworkError("Network name must be 1-64 characters: letters, digits, dot, underscore or dash.")
        if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id < 1:
            raise NetworkError("Chain ID must be a positive integer.")
        if fork_block is not None and (isinstance(fork_block, bool) or not isinstance(fork_block, int) or fork_block < 0):
            raise NetworkError("Fork block must be a non-negative integer.")
        if fork_url and not _sanitize_origin(fork_url):
            raise NetworkError("Fork URL must be a valid HTTP(S) URL.")
        state = self._read()
        sessions = state["managed_sessions"]
        if self._find(sessions, name):
            raise NetworkError(f"A managed network named {name!r} already exists. Stop it before creating a replacement.")

        port = self._free_port()
        rpc_url = f"http://127.0.0.1:{port}"
        session_id = str(uuid.uuid4())
        log_path = self.audit_dir / "networks" / f"{session_id}.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        command = [self.binary, "--host", "127.0.0.1", "--port", str(port), "--chain-id", str(chain_id), "--mnemonic-random", "12", "--silent"]
        if fork_url:
            command.extend(["--fork-url", fork_url])
        if fork_block is not None:
            if not fork_url:
                raise NetworkError("--fork-block requires --fork-url.")
            command.extend(["--fork-block-number", str(fork_block)])
        try:
            with open(log_path, "a", encoding="utf-8") as log:
                process = self._popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, close_fds=True)
        except (OSError, ValueError) as exc:
            raise NetworkError(f"Could not start Anvil: {exc}") from exc

        try:
            rpc_data = None
            for _ in range(self._startup_attempts):
                if process.poll() is not None:
                    raise NetworkError(f"Anvil exited during startup (code {process.returncode}); inspect {log_path}.")
                try:
                    client = self._rpc(rpc_url, "web3_clientVersion", [])
                    reported_chain = self._rpc(rpc_url, "eth_chainId", [])
                    genesis = self._rpc(rpc_url, "eth_getBlockByNumber", ["earliest", False])
                    accounts = self._rpc(rpc_url, "eth_accounts", [])
                    if "anvil" not in str(client).lower():
                        raise NetworkError("The selected endpoint did not identify itself as Anvil.")
                    if int(str(reported_chain), 16) != chain_id:
                        raise NetworkError("Anvil returned an unexpected chain ID.")
                    genesis_number = _rpc_quantity(genesis.get("number")) if isinstance(genesis, dict) else None
                    if (
                        not isinstance(genesis, dict)
                        or not re.fullmatch(r"0x[0-9a-fA-F]{64}", str(genesis.get("hash") or ""))
                        or genesis_number is None
                    ):
                        raise NetworkError("Anvil did not return a valid identity block (number and hash).")
                    if not isinstance(accounts, list) or not accounts or any(not re.fullmatch(r"0x[0-9a-fA-F]{40}", str(a)) for a in accounts):
                        raise NetworkError("Anvil did not return a valid account list.")
                    rpc_data = {
                        "client_version": str(client),
                        "chain_id": chain_id,
                        "genesis_hash": str(genesis["hash"]).lower(),
                        "identity_block_hash": str(genesis["hash"]).lower(),
                        "identity_block_number": genesis_number,
                        "accounts": [str(a).lower() for a in accounts],
                    }
                    break
                except NetworkError:
                    self._sleep(0.1)
            if rpc_data is None:
                raise NetworkError(f"Anvil did not become healthy after {self._startup_attempts} checks; inspect {log_path}.")
            identity = self._identity(process.pid)
            if not identity or identity.get("uid") != os.getuid():
                raise NetworkError("Could not establish the launched Anvil process identity; refusing to register it.")
            session = {
                "id": session_id,
                "project_id": self.project_id,
                "name": name,
                "chain_id": chain_id,
                "rpc": rpc_url,
                "port": port,
                "genesis_hash": rpc_data["genesis_hash"],
                "identity_block_hash": rpc_data["identity_block_hash"],
                "identity_block_number": rpc_data["identity_block_number"],
                "client_version": rpc_data["client_version"],
                "pid": int(process.pid),
                "process_start_ticks": identity.get("start_ticks"),
                "process_uid": identity.get("uid"),
                "process_executable": identity.get("executable"),
                "process_group_id": int(process.pid),
                "log_path": str(log_path),
                "started_at": _now(),
                "status": "running",
                "fork_origin": _sanitize_origin(fork_url),
                "fork_block": fork_block,
                "actors": {
                    **({"lab-deployer": rpc_data["accounts"][0]} if rpc_data["accounts"] else {}),
                    **{f"anvil-{i}": address for i, address in enumerate(rpc_data["accounts"]) if i > 0},
                },
                "active_actor": "lab-deployer" if rpc_data["accounts"] else None,
                "deployments": {},
            }
            # Do not expose private keys or the original fork URL in persisted state.
            sessions[session_id] = session
            state["managed_sessions"] = sessions
            state["active_session_id"] = session_id
            # Keep the old single-node fields available to legacy readers. They
            # describe only the selected Lowkey-owned session.
            state.update({"auto_started": True, "pid": int(process.pid), "rpc": rpc_url, "started": session["started_at"], "managed_session_id": session_id})
            self._write(state)
            return dict(session)
        except Exception:
            # This process object was created by this exact call. It is safe to
            # ask it to terminate; never signal a PID obtained from stale state.
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                pass
            raise

    def list(self) -> list[dict[str, Any]]:
        state = self._read()
        result = []
        for session_id, item in state["managed_sessions"].items():
            if not isinstance(item, dict) or item.get("project_id") != self.project_id:
                continue
            session = dict(item)
            session["id"] = session_id
            ident = self._identity(int(session.get("pid") or 0))
            session["process_owned"] = _safe_process_match(session, ident)
            if not session["process_owned"] and session.get("status") != "stopped":
                session["status"] = "stale-or-unowned"
            result.append(session)
        return sorted(result, key=lambda x: (x.get("name") or "", x.get("id") or ""))

    def status(self, name: str | None = None) -> dict[str, Any] | None:
        sessions = self.list()
        state = self._read()
        if name:
            match = self._find(state["managed_sessions"], name)
            if not match:
                return None
            session_id, _ = match
            session = next((x for x in sessions if x.get("id") == session_id), None)
        else:
            active_id = state.get("active_session_id")
            session = next((x for x in sessions if x.get("id") == active_id), None)
        if not session:
            return None
        try:
            chain = self._rpc(session["rpc"], "eth_chainId", [])
            anchor_number = _rpc_quantity(session.get("identity_block_number"))
            block_tag = hex(anchor_number) if anchor_number is not None else "earliest"
            identity_block = self._rpc(session["rpc"], "eth_getBlockByNumber", [block_tag, False])
            expected_hash = str(
                session.get("identity_block_hash") or session.get("genesis_hash") or ""
            ).lower()
            actual_hash = (
                str(identity_block.get("hash") or "").lower()
                if isinstance(identity_block, dict) else ""
            )
            actual_number = (
                _rpc_quantity(identity_block.get("number"))
                if isinstance(identity_block, dict) else None
            )
            number_matches = anchor_number is None or actual_number == anchor_number
            session["rpc_healthy"] = _rpc_quantity(chain) == _rpc_quantity(session["chain_id"])
            session["identity_block_matches"] = bool(
                re.fullmatch(r"0x[0-9a-f]{64}", actual_hash)
                and expected_hash
                and actual_hash == expected_hash
                and number_matches
            )
            # Keep the established field for existing callers.
            session["genesis_matches"] = session["identity_block_matches"]
        except Exception:
            session["rpc_healthy"] = False
            session["identity_block_matches"] = False
            session["genesis_matches"] = False
        return session

    def use(self, name: str) -> dict[str, Any]:
        state = self._read()
        match = self._find(state["managed_sessions"], name)
        if not match:
            raise NetworkError(f"No managed network named {name!r} exists for this project.")
        session_id, session = match
        listed = self.status(name)
        if not listed or not listed.get("process_owned") or not listed.get("rpc_healthy") or not listed.get("genesis_matches"):
            raise NetworkError(f"Network {name!r} is not a healthy, identity-verified Lowkey-owned session; it cannot be selected.")
        state["active_session_id"] = session_id
        state.update({"auto_started": True, "pid": session["pid"], "rpc": session["rpc"], "started": session["started_at"], "managed_session_id": session_id})
        self._write(state)
        return listed

    def active(self) -> dict[str, Any] | None:
        state = self._read()
        sessions = self.list()
        active_id = state.get("active_session_id")
        if active_id:
            selected = next((s for s in sessions if s.get("id") == active_id), None)
            if selected and selected.get("process_owned") and selected.get("status") == "running":
                return selected
            if selected:
                raise NetworkError(
                    f"The selected managed network {selected.get('name')!r} is stale or no longer owned by Lowkey. "
                    "Select another healthy session with `lk lab network use <name>`; no RPC fallback was attempted."
                )
        running = [s for s in sessions if s.get("status") == "running" and s.get("process_owned")]
        if len(running) == 1:
            return self.use(str(running[0]["name"]))
        if len(running) > 1:
            raise NetworkError("Multiple managed Anvil networks are running and none is selected. Run `lk lab network use <name>`; Lowkey will not guess.")
        return None

    def get_by_id(self, session_id: str) -> dict[str, Any]:
        """Return one identity-verified session without changing active selection.

        Special-purpose project fixtures use this to select their own actor and
        deployment scope while an unrelated development network remains active.
        """
        state = self._read()
        record = state["managed_sessions"].get(str(session_id))
        if not isinstance(record, dict) or record.get("project_id") != self.project_id:
            raise NetworkError("Managed session ID does not belong to this project.")
        listed = next((item for item in self.list() if item.get("id") == str(session_id)), None)
        if not listed or not listed.get("process_owned") or listed.get("status") != "running":
            raise NetworkError("The requested managed session is stale or no longer owned by Lowkey.")
        verified = self.status(str(record.get("name") or ""))
        if (
            not verified or not verified.get("process_owned")
            or not verified.get("rpc_healthy") or not verified.get("genesis_matches")
        ):
            raise NetworkError("The requested managed session failed its RPC/genesis identity check.")
        return verified

    def stop(self, name: str) -> dict[str, Any]:
        state = self._read()
        match = self._find(state["managed_sessions"], name)
        if not match:
            raise NetworkError(f"No managed network named {name!r} exists for this project.")
        session_id, session = match
        pid = int(session.get("pid") or 0)
        identity = self._identity(pid)
        if not _safe_process_match(session, identity):
            session["status"] = "stale-or-unowned"
            self._write(state)
            raise NetworkError("Refusing to stop this session: PID ownership/identity no longer matches its recorded process. No process was signalled.")
        # Linux pidfds bind the signal to the process instance, avoiding the
        # PID-reuse race between /proc inspection and kill(pid, SIGTERM).
        pidfd_open = getattr(os, "pidfd_open", None)
        pidfd_signal = getattr(signal, "pidfd_send_signal", None)
        if pidfd_open is None or pidfd_signal is None:
            raise NetworkError("This platform cannot safely signal a verified process via pidfd; no process was signalled.")
        try:
            pidfd = pidfd_open(pid, 0)
        except ProcessLookupError:
            session["status"] = "stopped"
        except OSError as exc:
            raise NetworkError(f"Could not open a process handle safely: {exc}; no signal was sent.") from exc
        else:
            try:
                identity_after_open = self._identity(pid)
                if not _safe_process_match(session, identity_after_open):
                    raise NetworkError("Process identity changed while acquiring its handle; no signal was sent.")
                try:
                    pidfd_signal(pidfd, signal.SIGTERM)
                except ProcessLookupError:
                    session["status"] = "stopped"
                except PermissionError as exc:
                    raise NetworkError("Permission denied while stopping the verified Anvil process.") from exc
                else:
                    stopped = False
                    for _ in range(30):
                        if self._identity(pid) is None:
                            stopped = True
                            break
                        self._sleep(0.1)
                    if not stopped:
                        session["status"] = "stop-requested"
                        self._write(state)
                        raise NetworkError("Anvil did not exit after SIGTERM. It was not force-killed; inspect the recorded log and stop it manually.")
                    session["status"] = "stopped"
            finally:
                os.close(pidfd)
        if state.get("active_session_id") == session_id:
            state.pop("active_session_id", None)
        # Compatibility fields must not point at a stopped session.
        if state.get("managed_session_id") == session_id:
            for key in ("managed_session_id", "auto_started", "pid", "rpc", "started"):
                state.pop(key, None)
        self._write(state)
        return {"id": session_id, "name": name, "status": "stopped"}

    def register_existing_process(
        self,
        name: str,
        rpc_url: str,
        pid: int,
        *,
        purpose: str,
        fork_origin: str | None = None,
        fork_block: int | None = None,
        log_path: str | None = None,
        expected_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Register a process started by another Lowkey-owned workflow.

        This is used for special-purpose fixture Anvils so they participate in
        the same session identity and safe-stop rules as ordinary managed
        sessions. The process must already be live, owned by this UID, and
        demonstrably serving the RPC endpoint supplied by the caller. When a
        captured fixture context is supplied, registration pins its exact block
        number and verifies the timestamp, chain ID, base fee and gas limit.
        """
        name = str(name or "").strip()
        if not name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
            raise NetworkError("Managed process name is invalid.")
        parsed = urlsplit(str(rpc_url or ""))
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.port:
            raise NetworkError("Managed local process RPC must use an explicit loopback HTTP port.")
        identity = self._identity(int(pid))
        if not identity or identity.get("uid") != os.getuid():
            raise NetworkError("Could not establish process ownership; refusing to register the process.")
        record_for_match = {
            "pid": int(pid), "process_start_ticks": identity.get("start_ticks"),
            "process_uid": identity.get("uid"),
            "process_executable": identity.get("executable"), "port": parsed.port,
        }
        if not _safe_process_match(record_for_match, identity):
            raise NetworkError("The process identity does not match an Anvil executable listening on the expected port.")
        if expected_context is not None and not isinstance(expected_context, dict):
            raise NetworkError("Expected fixture block context must be an object.")
        expected_block_number = (
            _rpc_quantity(expected_context.get("blockNumber"))
            if expected_context is not None else None
        )
        if expected_context is not None and expected_block_number is None:
            raise NetworkError("Expected fixture block context has no valid blockNumber.")
        try:
            client = self._rpc(rpc_url, "web3_clientVersion", [])
            chain_value = self._rpc(rpc_url, "eth_chainId", [])
            chain_id = _rpc_quantity(chain_value)
            block_tag = hex(expected_block_number) if expected_block_number is not None else "latest"
            identity_block = self._rpc(rpc_url, "eth_getBlockByNumber", [block_tag, False])
            accounts = self._rpc(rpc_url, "eth_accounts", [])
        except Exception as exc:
            raise NetworkError(f"The process RPC could not be independently verified: {exc}") from exc

        if "anvil" not in str(client).lower():
            raise NetworkError("The process RPC endpoint did not identify itself as Anvil.")
        if chain_id is None or chain_id < 1:
            raise NetworkError("The process RPC returned an invalid chain ID.")
        if expected_context is not None:
            expected_chain_id = _rpc_quantity(expected_context.get("chainId"))
            if expected_chain_id is None or chain_id != expected_chain_id:
                raise NetworkError("The fixture RPC chain ID does not match the captured block context.")

        identity_block_hash = (
            str(identity_block.get("hash") or "").lower()
            if isinstance(identity_block, dict) else ""
        )
        identity_block_number = (
            _rpc_quantity(identity_block.get("number"))
            if isinstance(identity_block, dict) else None
        )
        if (
            not isinstance(identity_block, dict)
            or not re.fullmatch(r"0x[0-9a-f]{64}", identity_block_hash)
            or identity_block_number is None
        ):
            raise NetworkError(
                f"The process RPC returned no valid identity block at {block_tag}; "
                "the supplied process and RPC endpoint cannot be tied to a canonical header."
            )
        if expected_block_number is not None and identity_block_number != expected_block_number:
            raise NetworkError(
                "The fixture RPC returned a different block number than the captured Foundry context."
            )
        if expected_context is not None:
            for context_field, header_field in (
                ("timestamp", "timestamp"),
                ("baseFeePerGas", "baseFeePerGas"),
                ("gasLimit", "gasLimit"),
            ):
                expected_value = _rpc_quantity(expected_context.get(context_field))
                actual_value = _rpc_quantity(identity_block.get(header_field))
                if expected_value is None or actual_value != expected_value:
                    raise NetworkError(
                        f"The fixture RPC {header_field} does not match the captured Foundry block context."
                    )
        if (
            not isinstance(accounts, list)
            or not accounts
            or any(not re.fullmatch(r"0x[0-9a-fA-F]{40}", str(item)) for item in accounts)
        ):
            raise NetworkError("The process RPC returned an invalid account list.")
        # Compatibility alias: for fixture Anvils this is the captured context
        # block, not necessarily the special "earliest" block tag.
        genesis_hash = identity_block_hash
        state = self._read()
        if self._find(state["managed_sessions"], name):
            raise NetworkError(f"A managed network named {name!r} already exists.")
        session_id = str(uuid.uuid4())
        actors = {
            **({"lab-deployer": str(accounts[0]).lower()} if accounts else {}),
            **{f"anvil-{i}": str(address).lower() for i, address in enumerate(accounts) if i > 0},
        }
        session = {
            "id": session_id, "project_id": self.project_id, "name": name,
            "purpose": str(purpose), "chain_id": chain_id,
            "rpc": str(rpc_url), "port": parsed.port,
            "genesis_hash": genesis_hash,
            "identity_block_hash": identity_block_hash,
            "identity_block_number": identity_block_number,
            "client_version": str(client),
            "pid": int(pid), "process_start_ticks": identity.get("start_ticks"),
            "process_uid": identity.get("uid"),
            "process_executable": identity.get("executable"),
            "process_group_id": int(pid), "log_path": log_path,
            "started_at": _now(), "status": "running",
            "fork_origin": _sanitize_origin(fork_origin), "fork_block": fork_block,
            "actors": actors, "active_actor": "lab-deployer" if accounts else None,
            "deployments": {},
        }
        state["managed_sessions"][session_id] = session
        self._write(state)
        return dict(session)

    def stop_session(self, session_id: str) -> dict[str, Any]:
        """Stop an exact registered session without relying on a possibly reused name."""
        state = self._read()
        session = state["managed_sessions"].get(str(session_id))
        if not isinstance(session, dict) or session.get("project_id") != self.project_id:
            raise NetworkError("Managed session ID does not belong to this project.")
        return self.stop(str(session.get("name") or ""))

    def set_actor(self, session_id: str, actor: str | None) -> dict[str, Any]:
        state = self._read()
        session = state["managed_sessions"].get(session_id)
        if not isinstance(session, dict) or session.get("project_id") != self.project_id:
            raise NetworkError("Actor session does not belong to this project.")
        if actor is not None and actor not in (session.get("actors") or {}):
            raise NetworkError(f"Actor {actor!r} is not registered in this network session.")
        session["active_actor"] = actor
        self._write(state)
        return {
            "session_id": session_id,
            "actor": actor,
            "address": session.get("actors", {}).get(actor) if actor else None,
        }

    def register_actor(self, session_id: str, account_index: int, alias: str) -> dict[str, Any]:
        """Register a human-readable alias for an unlocked account in one session.

        Managed-session aliases are persisted inside that session only. Account
        zero remains reserved for Lowkey's internal deployer and no key material
        is ever copied into the actor registry.
        """
        if isinstance(account_index, bool) or not isinstance(account_index, int) or account_index < 1:
            raise NetworkError("Managed actor indices must be integers >= 1; account 0 is reserved for lab-deployer.")
        name = str(alias or "").strip()
        if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", name):
            raise NetworkError("Actor alias must start with a letter and contain only letters, digits, dot, underscore or dash.")
        if name.casefold() in {"lab-deployer", "anvil-0"}:
            raise NetworkError("That actor alias is reserved by Lowkey.")

        state = self._read()
        session = state["managed_sessions"].get(str(session_id))
        if not isinstance(session, dict) or session.get("project_id") != self.project_id:
            raise NetworkError("Actor session does not belong to this project.")
        actors = session.get("actors")
        if not isinstance(actors, dict):
            raise NetworkError("Managed network actor registry is invalid.")
        address = actors.get(f"anvil-{account_index}")
        if not isinstance(address, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
            raise NetworkError(f"Managed network account {account_index} is not available in this session.")
        existing = next((key for key in actors if str(key).casefold() == name.casefold()), None)
        if existing is not None:
            if str(actors[existing]).lower() == address.lower():
                return {"session_id": str(session_id), "actor": existing, "address": address, "created": False}
            raise NetworkError(f"Actor alias {name!r} already refers to a different account in this session.")
        actors[name] = address.lower()
        self._write(state)
        return {"session_id": str(session_id), "actor": name, "address": address.lower(), "created": True}

    def set_deployment(self, session_id: str, address: str, record: dict[str, Any]) -> None:
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", str(address)):
            raise NetworkError("Deployment address is invalid.")
        state = self._read()
        session = state["managed_sessions"].get(session_id)
        if not isinstance(session, dict) or session.get("project_id") != self.project_id:
            raise NetworkError("Deployment session does not belong to this project.")
        session.setdefault("deployments", {})[address.lower()] = dict(record)
        self._write(state)

    def record_deployment(
        self,
        session_id: str,
        record: dict[str, Any],
        *,
        operation_key: str,
    ) -> str:
        """Persist one supporting-deployment operation in its owning session.

        Unlike ``set_deployment``, this preserves separate operations for the
        same contract/address and also records a submitted transaction whose
        receipt did not yield an address. The session registry is authoritative
        for primary and supporting deployment evidence.
        """
        key = str(operation_key or "").strip()
        if not key or len(key) > 256 or any(ord(char) < 32 for char in key):
            raise NetworkError("Supporting deployment operation key is invalid.")
        if not isinstance(record, dict):
            raise NetworkError("Supporting deployment record must be an object.")
        address = record.get("address")
        if address is not None and not re.fullmatch(r"0x[0-9a-fA-F]{40}", str(address)):
            raise NetworkError("Supporting deployment address is invalid.")
        state = self._read()
        session = state["managed_sessions"].get(str(session_id))
        if not isinstance(session, dict) or session.get("project_id") != self.project_id:
            raise NetworkError("Supporting deployment session does not belong to this project.")
        deployments = session.setdefault("deployments", {})
        deployments[f"operation:{key}"] = dict(record)
        self._write(state)
        return f"operation:{key}"

    def get_deployments(self, session_id: str) -> dict[str, Any]:
        """Return deployment evidence owned by exactly one project session."""
        state = self._read()
        session = state["managed_sessions"].get(str(session_id))
        if not isinstance(session, dict) or session.get("project_id") != self.project_id:
            raise NetworkError("Deployment session does not belong to this project.")
        deployments = session.get("deployments")
        if not isinstance(deployments, dict):
            return {}
        return {
            str(key): dict(value)
            for key, value in deployments.items()
            if isinstance(value, dict)
        }
