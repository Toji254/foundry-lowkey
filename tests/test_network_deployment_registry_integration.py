"""Managed network identity and deployment records must flow through Lowkey."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lowkeycast_network_registry", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class NetworkDeploymentRegistryIntegrationTests(unittest.TestCase):
    def _write_state(self, root, *, session_id="session-a", rpc="http://127.0.0.1:18545", fixture=False):
        project_id = hashlib.sha256(str(root.resolve()).encode()).hexdigest()
        session = {
            "id": session_id,
            "project_id": project_id,
            "name": "local-dev",
            "chain_id": 31337,
            "rpc": rpc,
            "genesis_hash": "0x" + "ab" * 32,
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

    def _rpc_fakes(self):
        def rpc(_url, method, _params):
            return {
                "eth_chainId": "0x7a69",
                "eth_getBlockByNumber": {"hash": "0x" + "ab" * 32},
            }[method]
        return rpc

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


if __name__ == "__main__":
    unittest.main()
