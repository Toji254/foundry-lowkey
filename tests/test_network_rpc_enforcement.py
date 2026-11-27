import importlib.util
import pathlib
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lowkeycast_rpc_enforcement", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


def test_regular_cast_rpc_operation_fails_closed_without_resolved_rpc():
    with patch.object(lk, "effective_rpc", return_value=None), patch.object(lk, "cast_output") as cast:
        result = lk.run_cast(["chain-id"], {}, capture=True)
    assert isinstance(result, lk.CommandResult)
    assert result.code == 2
    assert "No Cast command was executed" in result.output
    cast.assert_not_called()


def test_regular_cast_explicit_rpc_is_preserved():
    with patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:9545") as resolver, patch.object(
        lk, "cast_output", return_value=(0, "31337", "")
    ) as cast:
        result = lk.run_cast(["chain-id", "--rpc-url", "http://127.0.0.1:9546"], {}, capture=True)
    assert str(result) == "31337"
    resolver.assert_called_once_with({}, explicit_rpc="http://127.0.0.1:9546", target=None)
    command = cast.call_args.args[0]
    assert command[-2:] == ["--rpc-url", "http://127.0.0.1:9546"]


def test_raw_cast_rpc_operation_fails_closed_without_resolved_rpc():
    with patch.object(lk, "effective_rpc", return_value=None), patch.object(lk, "cast_output") as cast:
        result = lk.run_raw({}, ["chain-id"])
    assert result == 2
    cast.assert_not_called()


def test_raw_cast_uses_central_resolver_when_no_explicit_rpc():
    with patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:9545"), patch.object(
        lk, "cast_output", return_value=(0, "31337", "")
    ) as cast, patch("builtins.print"):
        result = lk.run_raw({}, ["chain-id"])
    assert result == 0
    assert cast.call_args.args[0][-2:] == ["--rpc-url", "http://127.0.0.1:9545"]


def test_transaction_lookup_requires_selected_rpc_before_cast():
    tx_hash = "0x" + "a" * 64
    with patch.object(lk, "effective_rpc", return_value=None), patch.object(lk, "cast_output") as cast:
        result = lk.run_tx({"target": "0x" + "1" * 40}, [tx_hash])
    assert result == 2
    cast.assert_not_called()


def test_post_transaction_state_does_not_fall_back_to_cast_default_rpc():
    target = "0x" + "1" * 40
    function_item = {
        "type": "function",
        "name": "setBalance",
        "stateMutability": "nonpayable",
        "inputs": [{"name": "accountId", "type": "address"}],
        "outputs": [],
    }
    getter = {
        "type": "function",
        "name": "balances",
        "stateMutability": "view",
        "inputs": [{"name": "accountId", "type": "address"}],
        "outputs": [{"name": "status", "type": "uint256"}],
    }
    abi = [function_item, getter]
    with patch.object(lk, "effective_rpc", return_value=None), patch.object(lk, "cast_output") as cast:
        lines = lk._post_transaction_state_report(
            {}, target, abi, function_item,
            ["0x" + "2" * 40], None,
        )
    assert any("no explicit or unambiguous active Lowkey RPC" in line for line in lines)
    cast.assert_not_called()


def test_transaction_lookup_honors_explicit_rpc_override():
    tx_hash = "0x" + "b" * 64
    endpoint = "http://127.0.0.1:18545"
    with patch.object(lk, "effective_rpc", return_value=endpoint) as resolver, patch.object(
        lk, "cast_output", return_value=(0, "not-json", "")
    ) as cast, patch("builtins.print"):
        lk.run_tx({}, [tx_hash, "--rpc-url", endpoint])
    resolver.assert_called_once_with({}, explicit_rpc=endpoint)
    assert cast.call_args.args[0][-2:] == ["--rpc-url", endpoint]


def test_managed_project_does_not_autodiscover_unmanaged_anvil_when_unselected(tmp_path):
    manager = __import__("unittest").mock.Mock()
    manager.list.return_value = [{"id": "session-a", "status": "running"}]
    manager.active.return_value = None
    with patch.object(lk.audit_context, "foundry_project_root", return_value=str(tmp_path)), patch.object(
        lk, "NetworkManager", return_value=manager
    ), patch.object(lk, "detect_anvil_rpc") as autodiscover:
        assert lk.anvil_rpc_info({}) is None
    autodiscover.assert_not_called()


def test_managed_project_account_discovery_uses_only_selected_session_rpc(tmp_path):
    endpoint = "http://127.0.0.1:18546"
    manager = __import__("unittest").mock.Mock()
    manager.list.return_value = [{"id": "session-a", "status": "running"}]
    manager.active.return_value = {"id": "session-a", "rpc": endpoint}
    expected = {"url": endpoint, "accounts": []}
    with patch.object(lk.audit_context, "foundry_project_root", return_value=str(tmp_path)), patch.object(
        lk, "NetworkManager", return_value=manager
    ), patch.object(lk, "detect_anvil_rpc", return_value=expected) as detect:
        assert lk.anvil_rpc_info({}) == expected
    detect.assert_called_once_with(endpoint)


def test_managed_registry_error_never_falls_back_to_project_or_environment_rpc(tmp_path, monkeypatch):
    monkeypatch.setenv("LOWKEY_RPC_URL", "http://127.0.0.1:9999")
    config = {"_resolved_project_context": {"project_root": str(tmp_path)}}
    with patch.object(lk, "project_fixture_rpc_info", return_value=None), patch.object(
        lk, "NetworkManager", side_effect=ValueError("corrupt session metadata")
    ), patch.object(lk.audit_context, "foundry_project_root", return_value=tmp_path), patch(
        "builtins.print"
    ):
        assert lk.effective_rpc(config) is None
    assert "corrupt session metadata" in config["_network_selection_error"]


def test_explicit_rpc_override_is_not_replaced_by_managed_selection(tmp_path):
    endpoint = "http://127.0.0.1:18549"
    with patch.object(lk, "NetworkManager", side_effect=AssertionError("must not inspect manager")):
        assert lk.effective_rpc({}, explicit_rpc=endpoint) == endpoint


def test_explicit_rpc_override_uses_persisted_session_when_cache_is_empty(tmp_path):
    managed_rpc = "http://127.0.0.1:8545"
    foreign_rpc = "http://127.0.0.1:9545"
    manager = __import__("unittest").mock.Mock()
    manager.list.return_value = [{
        "id": "managed-session-a",
        "name": "dev",
        "rpc": managed_rpc,
        "status": "running",
    }]
    manager.active.return_value = {
        "id": "managed-session-a",
        "name": "dev",
        "rpc": managed_rpc,
    }
    config = {
        "target": "0x" + "a" * 40,
        "actor": "anvil-1",
        "wallets": {},
    }
    with (
        patch.object(lk, "project_fixture_rpc_info", return_value=None),
        patch.object(lk.audit_context, "foundry_project_root", return_value=str(tmp_path)),
        patch.object(lk, "NetworkManager", return_value=manager),
    ):
        assert lk.effective_rpc(config, explicit_rpc=foreign_rpc) == foreign_rpc
    manager.list.assert_called_once()
    manager.active.assert_called_once()
    assert config["_explicit_rpc_unscoped"] is True


def test_explicit_rpc_override_matching_persisted_session_keeps_manual_context(tmp_path):
    managed_rpc = "http://127.0.0.1:8545"
    manager = __import__("unittest").mock.Mock()
    manager.list.return_value = [{"id": "managed-session-a", "rpc": managed_rpc}]
    manager.active.return_value = {"id": "managed-session-a", "rpc": managed_rpc}
    config = {"target": "0x" + "a" * 40, "actor": "anvil-1", "wallets": {}}
    with (
        patch.object(lk, "project_fixture_rpc_info", return_value=None),
        patch.object(lk.audit_context, "foundry_project_root", return_value=str(tmp_path)),
        patch.object(lk, "NetworkManager", return_value=manager),
    ):
        assert lk.effective_rpc(config, explicit_rpc="HTTP://127.0.0.1:8545/") == "HTTP://127.0.0.1:8545/"
    assert "_explicit_rpc_unscoped" not in config
    manager.active.assert_called_once()


def test_explicit_rpc_override_to_another_network_detaches_session_actor_and_identity():
    session = {
        "id": "managed-session-a",
        "name": "dev",
        "rpc": "http://127.0.0.1:8545",
        "chain_id": 31337,
        "actors": {"lab-deployer": "0x" + "1" * 40, "anvil-1": "0x" + "2" * 40},
    }
    config = {
        "target": "0x" + "3" * 40,
        "actor": "anvil-1",
        "wallets": {"Alice": {"private_key": "1" * 64}},
        "_active_network_session": session,
    }
    with patch.object(lk, "project_fixture_rpc_info", return_value=None):
        assert lk.effective_rpc(config, explicit_rpc="http://127.0.0.1:9545") == "http://127.0.0.1:9545"
    assert config["_explicit_rpc_unscoped"] is True
    assert "_active_network_session" not in config
    assert "_network_actor_selection" not in config
    assert lk._actor_profile_entry(config, "anvil-1") is None
    assert lk._actor_profile_entry(config, "Alice") is None


def test_explicit_rpc_override_detaches_foreign_project_target(tmp_path):
    session = {
        "id": "managed-session-a",
        "name": "dev",
        "rpc": "http://127.0.0.1:8545",
        "actors": {"anvil-1": "0x" + "2" * 40},
    }
    config = {
        "actor": "anvil-1",
        "target": "0x" + "a" * 40,
        "target_contract": "ForeignVault",
        "wallets": {},
        "_active_network_session": session,
    }
    with (
        patch.object(lk, "project_fixture_rpc_info", return_value=None),
        patch.object(lk, "cast_output") as cast_output,
    ):
        # Model a command preflight resolving the override before run_cast
        # performs its own RPC resolution. The second pass must not restore
        # the target from the now-detached project context.
        assert lk.effective_rpc(
            config, explicit_rpc="http://127.0.0.1:9545",
            target=config["target"],
        ) == "http://127.0.0.1:9545"
        assert config.get("_explicit_rpc_unscoped") is True
        result = lk.run_cast(
            ["call", "owner", "--rpc-url", "http://127.0.0.1:9545"],
            config,
            capture=True,
        )
    assert result.code != 0
    assert "target" in result.output.lower()
    cast_output.assert_not_called()
    assert config.get("_explicit_rpc_unscoped") is True
    assert lk._actor_profile_entry(config, "anvil-1") is None
    assert lk.active_project_target(config, root=tmp_path) is None
    assert lk.resolve_target_ref(config, None, root=tmp_path) is None
    assert lk.resolve_target_ref(config, "Vault", root=tmp_path) is None
    assert lk.resolve_target_ref(config, "0x" + "b" * 40, root=tmp_path) == "0x" + "b" * 40


def test_explicit_rpc_override_remains_detached_across_repeated_resolution(tmp_path):
    session = {
        "id": "managed-session-a",
        "name": "dev",
        "rpc": "http://127.0.0.1:8545",
        "actors": {"anvil-1": "0x" + "2" * 40},
    }
    config = {
        "actor": "anvil-1",
        "target": "0x" + "a" * 40,
        "target_contract": "ForeignVault",
        "wallets": {},
        "_active_network_session": session,
    }
    foreign_rpc = "http://127.0.0.1:9545"
    with (
        patch.object(lk, "project_fixture_rpc_info", return_value=None),
        patch.object(lk, "cast_output") as cast_output,
    ):
        # The first explicit-RPC resolution detaches session identity. run_cast
        # resolves that same endpoint again during the same invocation.
        assert lk.effective_rpc(config, explicit_rpc=foreign_rpc) == foreign_rpc
        assert config.get("_explicit_rpc_unscoped") is True
        result = lk.run_cast(
            ["call", "owner", "--rpc-url", foreign_rpc],
            config,
            capture=True,
        )
    assert result.code != 0
    assert "target" in result.output.lower()
    cast_output.assert_not_called()
    assert config.get("_explicit_rpc_unscoped") is True
    assert lk._actor_profile_entry(config, "anvil-1") is None
    assert lk.active_project_target(config, root=tmp_path) is None


def test_explicit_rpc_override_preserves_explicit_target_address():
    explicit_target = "0x" + "b" * 40
    config = {
        "actor": "anvil-1",
        "target": "0x" + "a" * 40,
        "target_contract": "ForeignVault",
        "wallets": {},
        "_active_network_session": {
            "id": "managed-session-a",
            "rpc": "http://127.0.0.1:8545",
            "actors": {"anvil-1": "0x" + "2" * 40},
        },
    }
    with (
        patch.object(lk, "project_fixture_rpc_info", return_value=None),
        patch.object(lk, "cast_output", return_value=(0, "0x" + "00" * 32, "")) as cast_output,
    ):
        result = lk.run_cast(
            ["call", explicit_target, "owner", "--rpc-url", "http://127.0.0.1:9545"],
            config,
            capture=True,
        )
    assert config.get("_explicit_rpc_unscoped") is True
    assert result.code == 0
    executed = cast_output.call_args.args[0]
    assert executed[:3] == ["cast", "call", explicit_target]
    assert "--rpc-url" in executed and executed[executed.index("--rpc-url") + 1] == "http://127.0.0.1:9545"


def test_explicit_rpc_override_matching_active_session_keeps_actor_identity():
    session = {
        "id": "managed-session-a",
        "name": "dev",
        "rpc": "http://127.0.0.1:8545",
        "actors": {"anvil-1": "0x" + "2" * 40},
    }
    config = {"actor": "anvil-1", "wallets": {}, "_active_network_session": session}
    with patch.object(lk, "project_fixture_rpc_info", return_value=None):
        assert lk.effective_rpc(config, explicit_rpc="HTTP://127.0.0.1:8545/") == "HTTP://127.0.0.1:8545/"
    assert "_explicit_rpc_unscoped" not in config
    assert config["_active_network_session"]["id"] == "managed-session-a"
    assert lk._actor_profile_entry(config, "anvil-1")["address"] == "0x" + "2" * 40


def test_decoded_logs_fail_closed_without_selected_rpc():
    config = {}
    with patch.object(lk, "effective_rpc", return_value=None) as resolver, patch.object(
        lk, "_lowkey_command_error", return_value=2
    ) as command_error, patch.object(lk, "cast_output") as cast:
        result = lk.run_logs(config, ["--decode", "--from-block", "1"])

    assert result == 2
    resolver.assert_called_once_with(config, explicit_rpc=None)
    command_error.assert_called_once()
    cast.assert_not_called()


def test_decoded_logs_use_explicit_rpc_override():
    config = {}
    endpoint = "http://127.0.0.1:18547"
    with patch.object(lk, "effective_rpc", return_value=endpoint) as resolver, patch.object(
        lk, "cast_output", return_value=(0, "[]", "")
    ) as cast, patch("builtins.print"):
        result = lk.run_logs(config, ["--decode", "--rpc-url", endpoint])

    assert result == 0
    resolver.assert_called_once_with(config, explicit_rpc=endpoint)
    command = cast.call_args.args[0]
    assert command == ["cast", "logs", "--json", "--rpc-url", endpoint]


def test_snapshot_refuses_to_run_without_selected_rpc():
    config = {"target": "0x" + "11" * 20}
    with patch.object(lk, "effective_rpc", return_value=None) as resolver, patch.object(
        lk, "_lowkey_command_error", return_value=2
    ) as command_error, patch.object(lk, "run_cast") as cast, patch.object(
        lk, "snapshot_path"
    ) as path:
        result = lk.run_snapshot(config, ["1"])

    assert result == 2
    resolver.assert_called_once_with(config)
    command_error.assert_called_once()
    cast.assert_not_called()
    path.assert_not_called()


def test_snapshot_does_not_persist_when_a_storage_read_fails():
    config = {"target": "0x" + "11" * 20}
    failed_read = lk.CommandResult("RPC read failed", 2)
    with patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:18548"), patch.object(
        lk, "run_cast", return_value=failed_read
    ) as cast, patch.object(lk, "snapshot_path") as path, patch("sys.stderr"):
        result = lk.run_snapshot(config, ["1"])

    assert result == 2
    cast.assert_called_once_with(["st", "1"], config, capture=True)
    path.assert_not_called()

def test_receipt_without_rpc_is_blocked_not_reported_as_pending():
    tx_hash = "0x" + "a" * 64
    config = {"target": "0x" + "1" * 40}
    with patch.object(lk, "effective_rpc", return_value=None) as resolver, patch.object(
        lk, "_lowkey_command_error", return_value=2
    ) as command_error, patch.object(lk, "rpc_json") as rpc, patch.object(lk, "run_cast") as cast:
        result = lk.run_receipt(config, tx_hash=tx_hash)

    assert result == 2
    resolver.assert_called_once_with(config, explicit_rpc=None)
    command_error.assert_called_once()
    rpc.assert_not_called()
    cast.assert_not_called()


def test_raw_receipt_preserves_explicit_rpc_override():
    tx_hash = "0x" + "a" * 64
    endpoint = "http://127.0.0.1:18549"
    config = {}
    with patch.object(lk, "effective_rpc", return_value=endpoint) as resolver, patch.object(
        lk, "_transaction_target_for_hash", return_value=None
    ), patch.object(lk, "run_cast", return_value=0) as cast, patch.object(
        lk.audit_context, "record_tool"
    ):
        result = lk.run_receipt(config, tx_hash=tx_hash, args=["--raw", "--rpc-url", endpoint])

    assert result == 0
    resolver.assert_called_once_with(config, explicit_rpc=endpoint)
    cast.assert_called_once_with(
        ["receipt", tx_hash, "--async", "--rpc-url", endpoint],
        config,
    )


def test_trace_without_rpc_is_blocked_before_cast():
    tx_hash = "0x" + "b" * 64
    config = {"target": "0x" + "1" * 40}
    with patch.object(lk, "effective_rpc", return_value=None) as resolver, patch.object(
        lk, "_lowkey_command_error", return_value=2
    ) as command_error, patch.object(lk, "run_cast") as cast:
        result = lk.run_trace(config, [tx_hash])

    assert result == 2
    resolver.assert_called_once_with(config, explicit_rpc=None)
    command_error.assert_called_once()
    cast.assert_not_called()


def test_trace_uses_one_explicit_rpc_for_cast_and_metadata_reads():
    tx_hash = "0x" + "b" * 64
    endpoint = "http://127.0.0.1:18550"
    config = {}
    with patch.object(lk, "effective_rpc", return_value=endpoint) as resolver, patch.object(
        lk, "run_cast", return_value=lk.CommandResult("trace output", 0)
    ) as cast, patch.object(lk, "rpc_json", return_value=None) as rpc, patch.object(
        lk.audit_context, "record_tool"
    ), patch("builtins.print"):
        result = lk.run_trace(config, [tx_hash, "--rpc-url", endpoint])

    assert result == 0
    resolver.assert_called_once_with(config, explicit_rpc=endpoint)
    assert cast.call_args.args[0] == ["run", tx_hash, "--rpc-url", endpoint]
    rpc.assert_called_once_with(endpoint, "eth_getTransactionByHash", [tx_hash])

