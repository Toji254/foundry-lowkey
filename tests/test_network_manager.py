import json
import os
import signal

import pytest

from lowkey.network_manager import NetworkError, NetworkManager


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid
        self.returncode = None

    def poll(self):
        return self.returncode

    def terminate(self):
        self.returncode = -signal.SIGTERM

    def wait(self, timeout=None):
        self.returncode = -signal.SIGTERM
        return self.returncode


def make_manager(tmp_path, monkeypatch):
    processes = {}
    commands = []
    next_pid = iter(range(41001, 41020))
    genesis_by_port = {}
    account_by_port = {}

    def popen(command, **kwargs):
        commands.append(list(command))
        port = int(command[command.index("--port") + 1])
        pid = next(next_pid)
        processes[pid] = {"alive": True, "port": port}
        genesis_by_port[port] = "0x" + f"{port:064x}"
        account_by_port[port] = ["0x" + f"{(port * 100 + i):040x}" for i in range(10)]
        return FakeProcess(pid)

    def rpc(url, method, params=None, timeout=1.5):
        port = int(url.rsplit(":", 1)[1])
        if method == "web3_clientVersion":
            return "anvil/v1.0.0"
        if method == "eth_chainId":
            return hex(31337)
        if method == "eth_getBlockByNumber":
            # Ordinary managed Anvil starts at block zero. Fixture nodes use
            # their captured block number as the stable identity anchor.
            tag = (params or [None])[0]
            if tag in {"earliest", "latest", "0x0"}:
                return {"hash": genesis_by_port[port], "number": "0x0"}
            if tag == "0x3039":
                return {"hash": genesis_by_port[port], "number": "0x3039"}
            return None
        if method == "eth_accounts":
            return account_by_port[port]
        raise AssertionError(method)

    def identity(pid):
        process = processes.get(pid)
        if not process or not process["alive"]:
            return None
        return {
            "pid": pid,
            "start_ticks": pid * 10,
            "uid": os.getuid(),
            "executable": "/usr/local/bin/anvil",
            "argv": (
                f"anvil --host 127.0.0.1 --port {process['port']} --chain-id 31337"
                + (
                    f" --number {process['genesis_number']}"
                    if process.get("genesis_number") is not None else ""
                )
            ),
        }

    manager = NetworkManager(
        tmp_path,
        "/usr/local/bin/anvil",
        popen=popen,
        rpc_call=rpc,
        process_identity=identity,
        sleep=lambda _: None,
        port_range=range(16000, 16020),
        startup_attempts=2,
    )
    free_ports = iter(range(16000, 16020))
    manager._free_port = lambda: next(free_ports)

    def signal_process(pidfd, sig):
        assert sig == signal.SIGTERM
        pid = pidfd - 100000
        processes[pid]["alive"] = False

    monkeypatch.setattr("lowkey.network_manager.os.pidfd_open", lambda pid, flags: pid + 100000)
    monkeypatch.setattr("lowkey.network_manager.signal.pidfd_send_signal", signal_process)
    monkeypatch.setattr("lowkey.network_manager.os.close", lambda fd: None)
    return manager, processes, commands, genesis_by_port, account_by_port


def test_two_managed_anvils_have_distinct_session_and_chain_identity(tmp_path, monkeypatch):
    manager, processes, commands, genesis, accounts = make_manager(tmp_path, monkeypatch)
    first = manager.create("dev-a")
    second = manager.create("attack-a")

    assert first["id"] != second["id"]
    assert first["chain_id"] == second["chain_id"] == 31337
    assert first["genesis_hash"] != second["genesis_hash"]
    assert first["rpc"] != second["rpc"]
    assert first["actors"]["anvil-1"] != second["actors"]["anvil-1"]
    assert first["project_id"] == second["project_id"]
    assert len({p["pid"] for p in manager.list()}) == 2
    assert all("--mnemonic-random" in command for command in commands)
    assert manager.status("dev-a")["rpc_healthy"] is True
    assert manager.status("attack-a")["genesis_matches"] is True


def test_selected_network_routes_active_session_and_stop_isolated(tmp_path, monkeypatch):
    manager, processes, _, _, _ = make_manager(tmp_path, monkeypatch)
    alpha = manager.create("alpha")
    beta = manager.create("beta")

    assert manager.active()["name"] == "beta"
    selected = manager.use("alpha")
    assert selected["id"] == alpha["id"]
    assert manager.active()["rpc"] == alpha["rpc"]

    manager.stop("alpha")
    remaining = manager.list()
    alpha_row = next(row for row in remaining if row["id"] == alpha["id"])
    beta_row = next(row for row in remaining if row["id"] == beta["id"])
    assert alpha_row["status"] == "stopped"
    assert beta_row["process_owned"] is True
    assert manager.active()["id"] == beta["id"]


def test_no_active_selection_with_multiple_running_networks_is_ambiguous(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    manager.create("one")
    manager.create("two")
    state = json.loads(manager.state_path.read_text())
    state.pop("active_session_id", None)
    manager._write(state)

    with pytest.raises(NetworkError, match="Multiple managed Anvil networks"):
        manager.active()


def test_process_identity_mismatch_refuses_to_signal_pid(tmp_path, monkeypatch):
    manager, processes, _, _, _ = make_manager(tmp_path, monkeypatch)
    session = manager.create("protected")
    state = json.loads(manager.state_path.read_text())
    stored = state["managed_sessions"][session["id"]]
    stored["process_start_ticks"] += 1  # PID may have been reused.
    manager._write(state)
    sent = []
    monkeypatch.setattr("lowkey.network_manager.os.pidfd_open", lambda pid, flags: sent.append((pid, flags)) or (pid + 100000))
    monkeypatch.setattr("lowkey.network_manager.signal.pidfd_send_signal", lambda fd, sig: sent.append((fd, sig)))
    monkeypatch.setattr("lowkey.network_manager.os.close", lambda fd: None)

    with pytest.raises(NetworkError, match="Refusing to stop"):
        manager.stop("protected")
    assert sent == []
    assert processes[session["pid"]]["alive"] is True


def test_session_state_never_persists_fork_credentials_or_private_keys(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    session = manager.create("forked", fork_url="https://rpc.example/secret-path?token=TOPSECRET")
    raw = manager.state_path.read_text()
    assert "TOPSECRET" not in raw
    assert "secret-path" not in raw
    assert "private_key" not in raw.lower()
    assert session["fork_origin"] == "https://rpc.example"


def test_fork_block_requires_fork_url_and_chain_id_is_validated(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    with pytest.raises(NetworkError, match="fork-url"):
        manager.create("bad-fork", fork_block=10)
    with pytest.raises(NetworkError, match="positive integer"):
        manager.create("bad-chain", chain_id=0)


def test_duplicate_network_name_is_rejected_without_launching_another_process(tmp_path, monkeypatch):
    manager, _, commands, *_ = make_manager(tmp_path, monkeypatch)
    manager.create("same")
    before = len(commands)
    with pytest.raises(NetworkError, match="already exists"):
        manager.create("same")
    assert len(commands) == before


def test_actor_selection_is_persisted_inside_its_network_session_only(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    alpha = manager.create("alpha")
    beta = manager.create("beta")
    address = alpha["actors"]["anvil-1"]

    manager.set_actor(alpha["id"], "anvil-1")
    state = json.loads(manager.state_path.read_text())
    alpha_record = state["managed_sessions"][alpha["id"]]
    beta_record = state["managed_sessions"][beta["id"]]
    assert alpha_record["active_actor"] == "anvil-1"
    assert beta_record["active_actor"] == "lab-deployer"
    assert alpha_record["actors"]["anvil-1"] == address

    manager.set_actor(alpha["id"], None)
    assert json.loads(manager.state_path.read_text())["managed_sessions"][alpha["id"]]["active_actor"] is None


def test_supporting_deployment_operations_are_session_scoped_and_preserve_attempts(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    alpha = manager.create("alpha")
    beta = manager.create("beta")
    first = {
        "role": "solidity_library",
        "qualified_identity": "src/Math.sol:Math",
        "address": "0x" + "11" * 20,
        "runtime_verification": "MATCHED",
    }
    second = {**first, "runtime_verification": "MISMATCH", "address": "0x" + "22" * 20}
    failed = {
        "role": "supporting_contract",
        "qualified_identity": "src/Consumer.sol:Consumer",
        "address": None,
        "deployment_transaction": "0x" + "33" * 32,
    }

    manager.record_deployment(alpha["id"], first, operation_key="Math::tx-1")
    manager.record_deployment(alpha["id"], second, operation_key="Math::tx-2")
    manager.record_deployment(alpha["id"], failed, operation_key="Consumer::tx-3")

    alpha_records = manager.get_deployments(alpha["id"])
    beta_records = manager.get_deployments(beta["id"])
    assert len(alpha_records) == 3
    assert beta_records == {}
    assert any(item.get("runtime_verification") == "MATCHED" for item in alpha_records.values())
    assert any(item.get("runtime_verification") == "MISMATCH" for item in alpha_records.values())
    assert any(item["address"] is None for item in alpha_records.values())


def test_fixture_registration_anchors_exact_captured_block_context(tmp_path, monkeypatch):
    manager, processes, _, genesis, _ = make_manager(tmp_path, monkeypatch)
    launched = manager.create("fixture-seed")
    # Simulate the exact fixture-node shape produced by Anvil --number 12345:
    # the lowest block is 12345 and eth_getBlockByNumber("0x0") returns null.
    processes[launched["pid"]]["genesis_number"] = 12345
    requests = []
    expected_context = {
        "timestamp": 1700000000,
        "blockNumber": 12345,
        "chainId": 31337,
        "baseFeePerGas": 1000000000,
        "gasLimit": 30000000,
    }

    def fixture_rpc(url, method, params=None, timeout=1.5):
        port = int(url.rsplit(":", 1)[1])
        if method == "web3_clientVersion":
            return "anvil/v1.0.0"
        if method == "eth_chainId":
            return hex(31337)
        if method == "eth_getBlockByNumber":
            requests.append(list(params or []))
            if params == ["0x3039", False]:
                return {
                    "hash": genesis[port], "number": "0x3039",
                    "timestamp": hex(expected_context["timestamp"]),
                    "baseFeePerGas": hex(expected_context["baseFeePerGas"]),
                    "gasLimit": hex(expected_context["gasLimit"]),
                }
            return None
        if method == "eth_accounts":
            return ["0x" + f"{(port * 100 + i):040x}" for i in range(10)]
        raise AssertionError(method)

    manager._rpc = fixture_rpc
    registered = manager.register_existing_process(
        "fixture-context-nonzero-genesis",
        launched["rpc"],
        launched["pid"],
        purpose="project-fixture-block-context",
        expected_context=expected_context,
    )
    assert registered["identity_block_number"] == 12345
    assert registered["identity_block_hash"] == genesis[launched["port"]]
    assert registered["genesis_hash"] == genesis[launched["port"]]
    assert " --number 12345" in manager._identity(launched["pid"])["argv"]

    status = manager.status("fixture-context-nonzero-genesis")
    assert status["process_owned"] is True
    assert status["rpc_healthy"] is True
    assert status["identity_block_matches"] is True
    assert requests == [["0x3039", False], ["0x3039", False]]


def test_lowkey_owned_fixture_process_can_be_registered_and_stopped_by_session_id(tmp_path, monkeypatch):
    manager, processes, _, _, _ = make_manager(tmp_path, monkeypatch)
    launched = manager.create("fixture-seed")
    fixture_session = manager.register_existing_process(
        "fixture-context-test",
        launched["rpc"],
        launched["pid"],
        purpose="project-fixture-block-context",
        log_path=launched["log_path"],
    )
    assert fixture_session["purpose"] == "project-fixture-block-context"
    assert fixture_session["genesis_hash"] == launched["genesis_hash"]
    stopped = manager.stop_session(fixture_session["id"])
    assert stopped["status"] == "stopped"
    assert processes[launched["pid"]]["alive"] is False


def test_register_existing_process_rejects_unowned_or_non_anvil_pid(tmp_path, monkeypatch):
    manager, _, _, _, _ = make_manager(tmp_path, monkeypatch)
    with pytest.raises(NetworkError, match="process ownership"):
        manager.register_existing_process(
            "unowned", "http://127.0.0.1:16000", 999999,
            purpose="fixture",
        )


def test_corrupt_registry_fails_closed_instead_of_looking_like_no_sessions(tmp_path):
    audit = tmp_path / ".audit"
    audit.mkdir()
    (audit / "anvil.json").write_text('{"managed_sessions":', encoding="utf-8")
    manager = NetworkManager(tmp_path, process_identity=lambda _pid: None)
    with pytest.raises(NetworkError, match="invalid JSON"):
        manager.list()


def test_custom_actor_alias_is_scoped_to_one_managed_network(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    alpha = manager.create("alpha")
    beta = manager.create("beta")

    result = manager.register_actor(alpha["id"], 2, "Alice")
    assert result["created"] is True
    assert result["address"] == alpha["actors"]["anvil-2"]
    manager.set_actor(alpha["id"], "Alice")

    alpha_actors = manager.get_by_id(alpha["id"])["actors"]
    beta_actors = manager.get_by_id(beta["id"])["actors"]
    assert alpha_actors["Alice"] == alpha["actors"]["anvil-2"]
    assert "Alice" not in beta_actors
    assert manager.get_by_id(alpha["id"])["active_actor"] == "Alice"
    assert manager.get_by_id(beta["id"])["active_actor"] == "lab-deployer"


def test_actor_alias_registration_refuses_reserved_zero_and_conflicting_aliases(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    session = manager.create("isolated")
    with pytest.raises(NetworkError, match="reserved for lab-deployer"):
        manager.register_actor(session["id"], 0, "Owner")
    with pytest.raises(NetworkError, match="reserved by Lowkey"):
        manager.register_actor(session["id"], 1, "lab-deployer")
    with pytest.raises(NetworkError, match="already refers"):
        manager.register_actor(session["id"], 2, "anvil-1")


def test_actor_alias_registration_is_idempotent_for_same_account(tmp_path, monkeypatch):
    manager, *_ = make_manager(tmp_path, monkeypatch)
    session = manager.create("isolated")
    first = manager.register_actor(session["id"], 2, "Alice")
    second = manager.register_actor(session["id"], 2, "Alice")
    assert first["created"] is True
    assert second["created"] is False
    assert second["address"] == first["address"]


def test_legacy_registry_is_migrated_additively_and_backed_up(tmp_path):
    audit = tmp_path / ".audit"
    audit.mkdir()
    legacy = {
        "rpc": "http://127.0.0.1:8545",
        "fixture_target": "0x" + "11" * 20,
        "fixture_context": {"timestamp": 1700000000, "blockNumber": 42},
    }
    raw = json.dumps(legacy, sort_keys=True)
    state_path = audit / "anvil.json"
    state_path.write_text(raw, encoding="utf-8")

    manager = NetworkManager(tmp_path, process_identity=lambda _pid: None)
    migrated = manager._read()

    assert migrated["schema_version"] == 2
    assert migrated["managed_sessions"] == {}
    assert migrated["rpc"] == legacy["rpc"]
    assert migrated["fixture_target"] == legacy["fixture_target"]
    assert migrated["fixture_context"] == legacy["fixture_context"]
    persisted = json.loads(state_path.read_text(encoding="utf-8"))
    assert persisted["schema_version"] == 2
    assert persisted["managed_sessions"] == {}
    backup = state_path.with_name("anvil.json.v1.bak")
    assert backup.read_text(encoding="utf-8") == raw
    assert backup.stat().st_mode & 0o777 == 0o600


def test_malformed_managed_sessions_fails_closed_without_overwriting_registry(tmp_path):
    audit = tmp_path / ".audit"
    audit.mkdir()
    state_path = audit / "anvil.json"
    raw = json.dumps({"schema_version": 2, "managed_sessions": [], "legacy": {"keep": True}})
    state_path.write_text(raw, encoding="utf-8")
    manager = NetworkManager(tmp_path, process_identity=lambda _pid: None)

    with pytest.raises(NetworkError, match="managed_sessions.*object"):
        manager.list()

    assert state_path.read_text(encoding="utf-8") == raw


def test_malformed_managed_session_entry_fails_closed_without_discarding_other_records(tmp_path):
    audit = tmp_path / ".audit"
    audit.mkdir()
    state_path = audit / "anvil.json"
    payload = {
        "schema_version": 2,
        "managed_sessions": {
            "session-valid": {"id": "session-valid", "project_id": "project"},
            "session-corrupt": ["not", "a", "session", "object"],
        },
    }
    raw = json.dumps(payload)
    state_path.write_text(raw, encoding="utf-8")
    manager = NetworkManager(tmp_path, process_identity=lambda _pid: None)

    with pytest.raises(NetworkError, match="malformed managed session record"):
        manager.list()

    assert state_path.read_text(encoding="utf-8") == raw


def test_future_registry_schema_is_rejected_without_overwriting_registry(tmp_path):
    audit = tmp_path / ".audit"
    audit.mkdir()
    state_path = audit / "anvil.json"
    raw = json.dumps({"schema_version": 999, "managed_sessions": {}})
    state_path.write_text(raw, encoding="utf-8")
    manager = NetworkManager(tmp_path, process_identity=lambda _pid: None)

    with pytest.raises(NetworkError, match="newer than this Lowkey supports"):
        manager.list()

    assert state_path.read_text(encoding="utf-8") == raw


def test_missing_registry_is_not_materialized_as_an_empty_file(tmp_path):
    manager = NetworkManager(tmp_path, process_identity=lambda _pid: None)

    assert manager.list() == []
    assert not manager.state_path.exists()


def test_existing_legacy_backup_is_never_overwritten_with_different_content(tmp_path):
    audit = tmp_path / ".audit"
    audit.mkdir()
    state_path = audit / "anvil.json"
    backup_path = audit / "anvil.json.v1.bak"
    original = json.dumps({"rpc": "http://127.0.0.1:8545"})
    previous_backup = json.dumps({"rpc": "http://127.0.0.1:8546"})
    state_path.write_text(original, encoding="utf-8")
    backup_path.write_text(previous_backup, encoding="utf-8")
    manager = NetworkManager(tmp_path, process_identity=lambda _pid: None)

    with pytest.raises(NetworkError, match="refusing to overwrite"):
        manager._read()

    assert state_path.read_text(encoding="utf-8") == original
    assert backup_path.read_text(encoding="utf-8") == previous_backup


def _concurrent_register_actor(root, index, alias, result_queue):
    try:
        manager = NetworkManager(root)
        result_queue.put(("ok", manager.register_actor("session-a", index, alias)))
    except Exception as exc:
        result_queue.put(("error", f"{type(exc).__name__}: {exc}"))


def test_registry_serializes_concurrent_actor_updates_across_processes(tmp_path):
    import multiprocessing

    audit = tmp_path / ".audit"
    audit.mkdir()
    project_id = NetworkManager(tmp_path).project_id
    state = {
        "schema_version": 2,
        "managed_sessions": {
            "session-a": {
                "id": "session-a",
                "project_id": project_id,
                "name": "concurrent-test",
                "status": "running",
                "actors": {
                    "lab-deployer": "0x" + "11" * 20,
                    "anvil-1": "0x" + "22" * 20,
                    "anvil-2": "0x" + "33" * 20,
                },
                "deployments": {},
            }
        },
    }
    (audit / "anvil.json").write_text(json.dumps(state), encoding="utf-8")

    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    processes = [
        context.Process(target=_concurrent_register_actor, args=(str(tmp_path), 1, "Alice", queue)),
        context.Process(target=_concurrent_register_actor, args=(str(tmp_path), 2, "Bob", queue)),
    ]
    for process in processes:
        process.start()
    for process in processes:
        process.join(timeout=10)
    try:
        assert all(not process.is_alive() for process in processes)
        assert [process.exitcode for process in processes] == [0, 0]
        results = [queue.get(timeout=2), queue.get(timeout=2)]
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=2)
        queue.close()

    assert all(status == "ok" for status, _value in results), results
    records = NetworkManager(tmp_path).get_deployments("session-a")
    actors = json.loads((audit / "anvil.json").read_text(encoding="utf-8"))["managed_sessions"]["session-a"]["actors"]
    assert actors["Alice"] == "0x" + "22" * 20
    assert actors["Bob"] == "0x" + "33" * 20
    assert not records


def test_registry_file_lock_is_private_and_persistent(tmp_path):
    manager = NetworkManager(tmp_path)
    manager.list()
    lock_path = manager.state_path.with_name(manager.state_path.name + ".lock")
    assert lock_path.is_file()
    assert lock_path.stat().st_mode & 0o777 == 0o600
