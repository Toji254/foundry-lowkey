"""Managed network identity and deployment records must flow through Lowkey."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from lowkey.network_manager import NetworkError, NetworkManager

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lowkeycast_network_registry", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class NetworkDeploymentRegistryIntegrationTests(unittest.TestCase):
    def _write_state(self, root, *, session_id="session-a", rpc="http://127.0.0.1:18545", fixture=False, identity_block_number=None):
        project_id = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
        session = {
            "id": session_id,
            "project_id": project_id,
            "name": "local-dev",
            "chain_id": 31337,
            "rpc": rpc,
            "genesis_hash": "0x" + "ab" * 32,
            **({"identity_block_hash": "0x" + "ab" * 32, "identity_block_number": identity_block_number}
               if identity_block_number is not None else {}),
            "status": "running",
        }
        state = {
            "schema_version": 2,
            "managed_sessions": {session_id: session},
            "active_session_id": None if fixture else session_id,
            "fixture_session_id": session_id if fixture else None,
        }
        (root / ".audit").mkdir(exist_ok=True)
        (root / ".audit" / "anvil.json").write_text(json.dumps(state), encoding="utf-8")
        return session

    def _rpc_fakes(self, *, genesis_number=0, calls=None):
        def rpc(_url, method, params):
            if method == "eth_chainId":
                return "0x7a69"
            if method == "eth_getBlockByNumber":
                if calls is not None:
                    calls.append(list(params or []))
                # Legacy state uses earliest; new managed fixtures query their
                # explicitly persisted identity block number.
                accepted = {("earliest", False), (hex(genesis_number), False)}
                if tuple(params or []) not in accepted:
                    return None
                return {"hash": "0x" + "ab" * 32, "number": hex(genesis_number)}
            raise AssertionError(method)
        return rpc

    def test_register_fixture_process_anchors_to_captured_context_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            port = 18545
            pid = 424242
            context = {
                "timestamp": 1700000000,
                "blockNumber": 12345,
                "chainId": 31337,
                "baseFeePerGas": 1000000000,
                "gasLimit": 30000000,
            }
            header = {
                "hash": "0x" + "ab" * 32,
                "number": "0x3039",
                "timestamp": hex(context["timestamp"]),
                "baseFeePerGas": hex(context["baseFeePerGas"]),
                "gasLimit": hex(context["gasLimit"]),
            }
            calls = []

            def identity(_pid):
                self.assertEqual(_pid, pid)
                return {
                    "pid": pid,
                    "start_ticks": 99,
                    "uid": __import__("os").getuid(),
                    "executable": "/usr/local/bin/anvil",
                    "argv": f"anvil --host 127.0.0.1 --port {port} --chain-id 31337 --number 12345",
                }

            def rpc(_url, method, params=None, timeout=1.5):
                calls.append((method, list(params or [])))
                if method == "web3_clientVersion":
                    return "anvil/v1.9.0"
                if method == "eth_chainId":
                    return "0x7a69"
                if method == "eth_getBlockByNumber":
                    return header if params == ["0x3039", False] else None
                if method == "eth_accounts":
                    return ["0x" + "11" * 20, "0x" + "22" * 20]
                raise AssertionError(method)

            manager = NetworkManager(root, rpc_call=rpc, process_identity=identity)
            session = manager.register_existing_process(
                "fixture-context-test",
                f"http://127.0.0.1:{port}",
                pid,
                purpose="project-fixture-block-context",
                expected_context=context,
            )
            self.assertEqual(session["identity_block_number"], 12345)
            self.assertEqual(session["identity_block_hash"], header["hash"])
            self.assertEqual(session["genesis_hash"], header["hash"])
            self.assertIn(("eth_getBlockByNumber", ["0x3039", False]), calls)

            status = manager.status("fixture-context-test")
            self.assertTrue(status["process_owned"])
            self.assertTrue(status["rpc_healthy"])
            self.assertTrue(status["identity_block_matches"])

    def test_register_fixture_process_rejects_wrong_captured_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            port = 18546
            pid = 424243
            context = {
                "timestamp": 1700000000,
                "blockNumber": 12345,
                "chainId": 31337,
                "baseFeePerGas": 1000000000,
                "gasLimit": 30000000,
            }
            header = {
                "hash": "0x" + "ab" * 32,
                "number": "0x3039",
                "timestamp": hex(context["timestamp"] + 1),
                "baseFeePerGas": hex(context["baseFeePerGas"]),
                "gasLimit": hex(context["gasLimit"]),
            }

            def identity(_pid):
                return {
                    "pid": pid,
                    "start_ticks": 100,
                    "uid": __import__("os").getuid(),
                    "executable": "/usr/local/bin/anvil",
                    "argv": f"anvil --host 127.0.0.1 --port {port} --chain-id 31337 --number 12345",
                }

            def rpc(_url, method, params=None, timeout=1.5):
                if method == "web3_clientVersion":
                    return "anvil/v1.9.0"
                if method == "eth_chainId":
                    return "0x7a69"
                if method == "eth_getBlockByNumber":
                    return header if params == ["0x3039", False] else None
                if method == "eth_accounts":
                    return ["0x" + "11" * 20]
                raise AssertionError(method)

            manager = NetworkManager(root, rpc_call=rpc, process_identity=identity)
            with self.assertRaisesRegex(NetworkError, "timestamp does not match"):
                manager.register_existing_process(
                    "fixture-context-mismatch",
                    f"http://127.0.0.1:{port}",
                    pid,
                    purpose="project-fixture-block-context",
                    expected_context=context,
                )
            self.assertFalse(manager.state_path.exists())

    def test_current_identity_uses_active_managed_session_not_a_random_invocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write_state(root)
            manager = unittest.mock.Mock()
            manager.list.return_value = [{"id": "session-a", "process_owned": True, "status": "running"}]
            with patch.object(lk, "rpc_json", side_effect=self._rpc_fakes()), patch.object(
                lk, "_rpc_identity_fingerprint", return_value={"rpc_fingerprint": "fingerprint", "rpc_origin": "local"}
            ), patch.object(lk, "_project_network_manager", return_value=manager):
                identity = lk._current_deployment_network_identity({}, root, "http://127.0.0.1:18545")
            self.assertEqual(identity["network_session_id"], "session-a")
            self.assertEqual(identity["session_kind"], "managed-anvil")
            self.assertTrue(identity["reuse_permitted"])

    def test_current_identity_matches_fixture_session_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write_state(root, fixture=True)
            manager = unittest.mock.Mock()
            manager.list.return_value = [{"id": "session-a", "process_owned": True, "status": "running"}]
            with patch.object(lk, "rpc_json", side_effect=self._rpc_fakes()), patch.object(
                lk, "_rpc_identity_fingerprint", return_value={"rpc_fingerprint": "fingerprint", "rpc_origin": "local"}
            ), patch.object(lk, "_project_network_manager", return_value=manager):
                identity = lk._current_deployment_network_identity({}, root, "http://127.0.0.1:18545")
            self.assertEqual(identity["network_session_id"], "session-a")
            self.assertEqual(identity["session_kind"], "fixture-anvil")
            self.assertTrue(identity["reuse_permitted"])

    def test_current_identity_accepts_nonzero_genesis_when_block_zero_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write_state(root, fixture=True, identity_block_number=12345)
            manager = unittest.mock.Mock()
            manager.list.return_value = [{"id": "session-a", "process_owned": True, "status": "running"}]
            calls = []
            with patch.object(
                lk, "rpc_json", side_effect=self._rpc_fakes(genesis_number=12345, calls=calls)
            ), patch.object(
                lk, "_rpc_identity_fingerprint", return_value={"rpc_fingerprint": "fingerprint", "rpc_origin": "local"}
            ), patch.object(lk, "_project_network_manager", return_value=manager):
                identity = lk._current_deployment_network_identity({}, root, "http://127.0.0.1:18545")
            self.assertEqual(identity["network_session_id"], "session-a")
            self.assertTrue(identity["reuse_permitted"])
            self.assertEqual(identity["identity_block_number"], 12345)
            self.assertEqual(calls, [["0x3039", False]])

    def test_legacy_rpc_record_is_not_silently_associated_with_a_managed_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write_state(root, rpc="http://127.0.0.1:18545")
            with patch.object(lk, "rpc_json", side_effect=self._rpc_fakes()), patch.object(
                lk, "_rpc_identity_fingerprint", return_value={"rpc_fingerprint": "fingerprint", "rpc_origin": "local"}
            ):
                identity = lk._current_deployment_network_identity({}, root, "http://127.0.0.1:18546")
            self.assertNotEqual(identity["network_session_id"], "session-a")
            self.assertEqual(identity["session_kind"], "unmanaged-invocation")
            self.assertFalse(identity["reuse_permitted"])

    def test_supporting_deployment_is_persisted_in_network_session_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact_path = root / "out" / "Support.json"
            artifact_path.parent.mkdir()
            artifact_path.write_text('{"artifact":true}', encoding="utf-8")
            manager = unittest.mock.Mock()
            config = {
                "project_target_registry": {},
                "wallets": {"lab-deployer": {"address": "0x" + "33" * 20}},
                "actor": "lab-deployer",
            }
            network = {
                "network_session_id": "session-a", "project_id": "project-a",
                "chain_id": 31337, "genesis_hash": "0x" + "ab" * 32,
                "reuse_permitted": True,
            }
            with patch.object(lk, "_project_network_manager", return_value=manager), patch.object(
                lk, "cast_output", return_value=(0, "0x6000", "")
            ), patch.object(lk, "_runtime_code_keccak_hash", return_value="0x" + "cd" * 32), patch.object(
                lk, "save_config"
            ):
                record = lk._record_supporting_deployment(
                    config, root, "http://127.0.0.1:18545", artifact_path,
                    {"sourceName": "src/Support.sol", "contractName": "Support"},
                    "0x" + "22" * 20, network, role="supporting_contract",
                    verification=None, dependencies={},
                )
            self.assertEqual(record["network_registry_status"], "RECORDED")
            manager.record_deployment.assert_called_once()
            args = manager.record_deployment.call_args.args
            self.assertEqual(args[0], "session-a")
            self.assertEqual(args[1]["address"], "0x" + "22" * 20)
            self.assertEqual(args[1]["role"], "supporting_contract")
            self.assertEqual(args[1]["network"]["network_session_id"], "session-a")
            self.assertIn("operation_key", args[1])

    def test_supporting_deployment_is_not_duplicated_into_project_target_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact_path = root / "out" / "Support.json"
            artifact_path.parent.mkdir()
            artifact_path.write_text('{"artifact":true}', encoding="utf-8")
            config = {
                "project_target_registry": {},
                "wallets": {"lab-deployer": {"address": "0x" + "33" * 20}},
                "actor": "lab-deployer",
            }
            network = self._write_state(root)
            identity = {
                "network_session_id": "session-a", "project_id": network["project_id"],
                "project_root": str(root.resolve()), "session_kind": "managed-anvil",
                "chain_id": 31337, "genesis_hash": "0x" + "ab" * 32,
                "reuse_permitted": True,
            }
            with patch.object(lk, "cast_output", return_value=(0, "0x6000", "")), patch.object(
                lk, "save_config"
            ):
                record = lk._record_supporting_deployment(
                    config, root, "http://127.0.0.1:18545", artifact_path,
                    {"sourceName": "src/Support.sol", "contractName": "Support"},
                    "0x" + "22" * 20, identity, role="supporting_contract",
                    verification=None, dependencies={},
                )
            stored = lk._project_network_manager(root).get_deployments("session-a")
            self.assertEqual(len(stored), 1)
            self.assertEqual(next(iter(stored.values()))["qualified_identity"], "src/Support.sol:Support")
            self.assertEqual(record["network_registry_status"], "RECORDED")
            self.assertEqual(config["project_target_registry"], {})


    def test_matching_legacy_support_records_migrate_only_after_canonical_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            session = self._write_state(root)
            project_key = str(root.resolve())
            matching = {
                "role": "solidity_library",
                "qualified_identity": "src/Math.sol:Math",
                "address": "0x" + "22" * 20,
                "operation_key": "legacy-operation-1",
                "runtime_verification": "MATCHED",
                "network": {
                    "network_session_id": "session-a",
                    "project_id": session["project_id"],
                    "chain_id": 31337,
                    "genesis_hash": "0x" + "ab" * 32,
                },
            }
            unrelated = {
                **matching,
                "qualified_identity": "src/Other.sol:Other",
                "operation_key": "other-session-operation",
                "network": {
                    **matching["network"],
                    "network_session_id": "some-other-session",
                },
            }
            config = {
                "project_target_registry": {
                    project_key: {
                        "PrimaryProtocol": {"address": "0x" + "11" * 20},
                        "__supporting_deployments__": {
                            "legacy-good": matching,
                            "legacy-other-session": unrelated,
                        },
                    }
                }
            }
            identity = {
                "network_session_id": "session-a",
                "project_id": session["project_id"],
                "chain_id": 31337,
                "genesis_hash": "0x" + "ab" * 32,
                "reuse_permitted": True,
            }

            with patch.object(lk, "save_config"):
                records = lk._supporting_deployment_records(config, root, identity)

            stored = lk._project_network_manager(root).get_deployments("session-a")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["qualified_identity"], "src/Math.sol:Math")
            self.assertEqual(len(stored), 1)
            self.assertIn("operation:legacy-operation-1", stored)
            project_entries = config["project_target_registry"][project_key]
            self.assertIn("PrimaryProtocol", project_entries)
            self.assertEqual(
                project_entries["__supporting_deployments__"],
                {"legacy-other-session": unrelated},
            )


    def test_primary_target_setter_records_session_and_native_broadcast_transaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            session = self._write_state(root)
            artifact_path = root / "out" / "NativeTarget.json"
            artifact_path.parent.mkdir()
            artifact_path.write_text(json.dumps({
                "sourceName": "src/NativeTarget.sol",
                "contractName": "NativeTarget",
                "abi": [],
            }), encoding="utf-8")
            target = "0x" + "22" * 20
            transaction = "0x" + "44" * 32
            network = {
                "project_id": session["project_id"],
                "project_root": str(root.resolve()),
                "network_session_id": "session-a",
                "session_kind": "managed-anvil",
                "reuse_permitted": True,
                "chain_id": 31337,
                "genesis_hash": "0x" + "ab" * 32,
                "identity_block_hash": "0x" + "ab" * 32,
                "identity_block_number": 0,
                "rpc_fingerprint": "fingerprint",
                "rpc_origin": "local",
            }
            config = {"project_target_registry": {}, "wallets": {}, "actor": "lab-deployer"}
            runtime = {
                "status": "DEPLOYED",
                "verification": "MATCHED",
                "rpc": "http://127.0.0.1:18545",
                "chain_id": 31337,
                "block_number": 1,
                "runtime_code_hash": "0x" + "cd" * 32,
                "runtime_code_hash_algorithm": "keccak256",
                "initialization_status": "NOT_TESTED",
                "dependency_readiness": "NOT_TESTED",
                "protocol_readiness": "UNVERIFIED",
            }
            with patch.object(lk, "_sync_security_patterns"), patch.object(
                lk, "save_config"
            ), patch.object(lk.audit_context, "set_target"), patch.object(
                lk, "_live_target_state", return_value=runtime
            ), patch.object(lk, "_print_target_runtime_provenance"):
                lk.set_lab_target(
                    config,
                    root,
                    target,
                    "NativeTarget",
                    artifact_path,
                    network_identity=network,
                    deployment_transaction=transaction,
                )

            stored = lk._project_network_manager(root).get_deployments("session-a")
            self.assertEqual(len(stored), 1)
            record = next(iter(stored.values()))
            self.assertEqual(record["address"], target)
            self.assertEqual(record["role"], "primary_audit_target")
            self.assertEqual(record["deployment_transaction"], transaction)
            self.assertEqual(record["network"]["network_session_id"], "session-a")
            self.assertEqual(record["operation_key"], transaction)
            project_record = config["project_target_registry"][str(root.resolve())]["NativeTarget"]
            self.assertEqual(project_record["network_registry_status"], "RECORDED")

    def test_native_foundry_signer_never_uses_default_key_for_different_session_actor(self):
        session_actor = "0x" + "11" * 20
        unrelated_key_address = "0x" + "22" * 20
        with patch.object(lk, "cast_output", return_value=(0, unrelated_key_address, "")):
            selected_key, auth_args = lk._foundry_script_broadcast_auth(
                "0x" + "33" * 32, [session_actor]
            )
        self.assertIsNone(selected_key)
        self.assertEqual(auth_args, ["--unlocked", "--sender", session_actor])

    def test_native_foundry_signer_uses_private_key_only_when_it_matches_session_actor(self):
        session_actor = "0x" + "11" * 20
        key = "0x" + "33" * 32
        with patch.object(lk, "cast_output", return_value=(0, session_actor, "")):
            selected_key, auth_args = lk._foundry_script_broadcast_auth(key, [session_actor])
        self.assertEqual(selected_key, key)
        self.assertEqual(auth_args, ["--private-key", key])


if __name__ == "__main__":
    unittest.main()
