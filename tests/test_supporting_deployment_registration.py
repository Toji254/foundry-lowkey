"""Application-level tests for target ownership during recursive deployments."""
from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import hashlib
import json
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lowkeycast_supporting", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)

PRIMARY = "0x" + "11" * 20
SUPPORT = "0x" + "22" * 20
DEPLOYER = "0x" + "33" * 20
TX = "0x" + "44" * 32
GENESIS_HASH = "0x" + "55" * 32


def runtime_result(status="MATCHED"):
    return lk.runtime_verification.RuntimeVerification(
        "DEPLOYED", status, 2, 2, False,
        None if status == "MATCHED" else "test runtime mismatch", "AVAILABLE",
        "0x" + "66" * 32, "0x" + "66" * 32,
    )


def artifact(name="Support", source="src/Support.sol", bytecode="0x6000"):
    return {
        "sourceName": source,
        "contractName": name,
        "abi": [],
        "bytecode": {"object": bytecode},
        "deployedBytecode": {"object": "0x6000", "immutableReferences": {}},
    }


class SupportingDeploymentRegistrationTests(unittest.TestCase):
    def _base_config(self):
        return {
            "target": PRIMARY,
            "target_contract": "PrimaryProtocol",
            "lab_system": {
                "root": PRIMARY,
                "target": PRIMARY,
                "root_model": "PrimaryProtocol",
                "target_model": "PrimaryProtocol",
            },
            "project_target_registry": {},
            "wallets": {"lab-deployer": {"address": DEPLOYER}},
            "actor": "lab-deployer",
            "labels": {},
            "aliases": {},
            "targets": {},
            "project_roots": {},
            "target_owners": {},
        }

    def _prepare_network(self, root):
        project_id = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()
        session_id = "managed-session-a"
        audit = root / ".audit"
        audit.mkdir(parents=True, exist_ok=True)
        state = {
            "schema_version": 2,
            "managed_sessions": {
                session_id: {
                    "id": session_id,
                    "project_id": project_id,
                    "name": "test-network",
                    "chain_id": 31337,
                    "rpc": "http://127.0.0.1:8545",
                    "genesis_hash": GENESIS_HASH,
                    "status": "running",
                    "deployments": {},
                }
            },
            "active_session_id": session_id,
        }
        (audit / "anvil.json").write_text(json.dumps(state), encoding="utf-8")
        return {
            "project_id": project_id,
            "project_root": str(root.resolve()),
            "network_session_id": session_id,
            "session_kind": "managed-anvil",
            "reuse_permitted": True,
            "chain_id": 31337,
            "genesis_hash": GENESIS_HASH,
            "rpc_fingerprint": "rpc-fingerprint",
        }

    def _session_records(self, root, network):
        return lk._project_network_manager(root).get_deployments(network["network_session_id"])

    def _patch_plan(self, config, root, artifact_value, network, *, deploy_result=(SUPPORT, None), verification=None, receipt=None):
        candidate = (
            100, artifact_value["contractName"], root / "out" / f'{artifact_value["contractName"]}.json',
            artifact_value, [], f'{artifact_value["sourceName"]}:{artifact_value["contractName"]}',
        )

        def deploy(*_args, **_kwargs):
            if receipt is not None:
                config["_last_deployment_receipt"] = dict(receipt)
            elif deploy_result[0]:
                config["_last_deployment_receipt"] = {
                    "tx_hash": TX, "target": deploy_result[0], "deployer": DEPLOYER,
                }
            return deploy_result

        return [
            (lk, "_current_deployment_network_identity", network),
            (lk, "discover_generic_lab_contract", candidate),
            (lk, "artifact_is_locked_implementation", False),
            (lk, "discover_contract_dependencies", []),
            (lk, "_deploy_artifact_locally", deploy),
            (lk, "cast_output", (0, "0x6000", "")),
            (lk.runtime_verification, "verify_runtime", verification or runtime_result()),
            (lk, "_ensure_lab_deployer", None),
            (lk, "inspect_proxy_details", {"kind": None, "is_proxy": False}),
            (lk, "_print_lab_owner_identity", None),
            (lk, "_print_security_scope", None),
            (lk, "save_config", None),
            (lk.project_tools, "detect_project", {"kind": "foundry"}),
        ]

    def _activate_plan(self, stack, plan):
        active = []
        for module, name, value in plan:
            if callable(value):
                active.append(stack.enter_context(patch.object(module, name, side_effect=value)))
            else:
                active.append(stack.enter_context(patch.object(module, name, return_value=value)))
        return active

    def test_supporting_record_keeps_primary_target_and_lab_state_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            network = self._prepare_network(root)
            file_path = root / "out" / "Support.json"
            file_path.parent.mkdir()
            file_path.write_text('{"artifact":true}', encoding="utf-8")
            config = self._base_config()
            original_system = dict(config["lab_system"])
            config["_last_deployment_receipt"] = {"tx_hash": TX, "deployer": DEPLOYER}
            with patch.object(lk, "cast_output", return_value=(0, "0x6000", "")), patch.object(lk, "save_config"):
                record = lk._record_supporting_deployment(
                    config, root, "http://127.0.0.1:8545", file_path,
                    artifact(), SUPPORT, network, role="supporting_contract",
                    verification=runtime_result(), dependencies={},
                )

            self.assertEqual(config["target"], PRIMARY)
            self.assertEqual(config["target_contract"], "PrimaryProtocol")
            self.assertEqual(config["lab_system"], original_system)
            self.assertEqual(record["role"], "supporting_contract")
            self.assertEqual(record["network"]["network_session_id"], network["network_session_id"])
            self.assertEqual(record["deployment_transaction"], TX)
            self.assertEqual(record["runtime_verification"], "MATCHED")
            self.assertEqual(record["protocol_readiness"], "UNVERIFIED")
            self.assertNotIn("_last_deployment_receipt", config)

    def test_real_run_generic_lab_support_path_never_calls_primary_target_setter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            network = self._prepare_network(root)
            config = self._base_config()
            plan = self._patch_plan(config, root, artifact(), network)
            with ExitStack() as stack:
                self._activate_plan(stack, plan)
                set_target = stack.enter_context(patch.object(lk, "set_lab_target"))
                result = lk.run_generic_lab(
                    config, root, "http://127.0.0.1:8545", [DEPLOYER], "0x" + "77" * 32,
                    requested="Support", deployment_only=True, _skip_dependency_discovery=True,
                    _network_identity=network,
                )

            self.assertEqual(result, 0)
            self.assertEqual(config["target"], PRIMARY)
            self.assertEqual(config["target_contract"], "PrimaryProtocol")
            self.assertEqual(config["lab_system"]["target"], PRIMARY)
            records = self._session_records(root, network)
            support_record = next(iter(records.values()))
            self.assertEqual(support_record["address"], SUPPORT)
            self.assertEqual(support_record["deployment_stage"], "VERIFIED")
            set_target.assert_not_called()

    def test_runtime_verification_failure_records_partial_support_deployment_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            network = self._prepare_network(root)
            config = self._base_config()
            plan = self._patch_plan(config, root, artifact(), network, verification=runtime_result("MISMATCH"))
            with ExitStack() as stack:
                self._activate_plan(stack, plan)
                set_target = stack.enter_context(patch.object(lk, "set_lab_target"))
                result = lk.run_generic_lab(
                    config, root, "http://127.0.0.1:8545", [DEPLOYER], "0x" + "77" * 32,
                    requested="Support", deployment_only=True, _skip_dependency_discovery=True,
                    _network_identity=network,
                )

            self.assertNotEqual(result, 0)
            self.assertEqual(config["target"], PRIMARY)
            self.assertEqual(config["lab_system"]["target"], PRIMARY)
            records = self._session_records(root, network)
            record = next(iter(records.values()))
            self.assertEqual(record["runtime_verification"], "MISMATCH")
            self.assertEqual(record["deployment_stage"], "FAILED")
            set_target.assert_not_called()

    def test_dependency_tx_submitted_without_recovered_address_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            network = self._prepare_network(root)
            config = self._base_config()
            receipt = {"tx_hash": TX, "target": None, "deployer": DEPLOYER, "submitted_at": "test"}
            plan = self._patch_plan(
                config, root, artifact(), network, deploy_result=(None, "could not recover deployed address"),
                receipt=receipt,
            )
            with ExitStack() as stack:
                self._activate_plan(stack, plan)
                set_target = stack.enter_context(patch.object(lk, "set_lab_target"))
                result = lk.run_generic_lab(
                    config, root, "http://127.0.0.1:8545", [DEPLOYER], "0x" + "77" * 32,
                    requested="Support", deployment_only=True, _skip_dependency_discovery=True,
                    _network_identity=network,
                )
            self.assertNotEqual(result, 0)
            records = self._session_records(root, network)
            record = next(iter(records.values()))
            self.assertIsNone(record["address"])
            self.assertEqual(record["deployment_transaction"], TX)
            self.assertEqual(config["target"], PRIMARY)
            set_target.assert_not_called()

    def test_managed_supporting_deployment_blocks_success_when_registry_write_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            network = self._prepare_network(root)
            config = self._base_config()
            plan = self._patch_plan(config, root, artifact(), network)
            manager = Mock()
            manager.record_deployment.side_effect = RuntimeError("disk write denied")
            with ExitStack() as stack:
                self._activate_plan(stack, plan)
                stack.enter_context(patch.object(lk, "_project_network_manager", return_value=manager))
                set_target = stack.enter_context(patch.object(lk, "set_lab_target"))
                result = lk.run_generic_lab(
                    config, root, "http://127.0.0.1:8545", [DEPLOYER], "0x" + "77" * 32,
                    requested="Support", deployment_only=True, _skip_dependency_discovery=True,
                    _network_identity=network,
                )
            self.assertNotEqual(result, 0)
            self.assertEqual(config["target"], PRIMARY)
            self.assertEqual(config["lab_system"]["target"], PRIMARY)
            manager.record_deployment.assert_called_once()
            set_target.assert_not_called()

    def test_library_linking_failure_blocks_main_deployment_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            network = self._prepare_network(root)
            config = self._base_config()
            linked_artifact = artifact("Pool", "src/Pool.sol", "0x60" + "00" * 20 + "00")
            linked_artifact["bytecode"]["linkReferences"] = {
                "src/MathLibrary.sol": {"MathLibrary": [{"start": 1, "length": 20}]}
            }
            candidate = (100, "Pool", root / "out" / "Pool.json", linked_artifact, [], "src/Pool.sol:Pool")
            with patch.object(lk, "_current_deployment_network_identity", return_value=network), \
                 patch.object(lk, "discover_generic_lab_contract", return_value=candidate), \
                 patch.object(lk, "artifact_is_locked_implementation", return_value=False), \
                 patch.object(lk, "discover_contract_dependencies", return_value=[]), \
                 patch.object(lk, "_deploy_artifact_library_dependencies", return_value=(None, {}, None, "library artifact unresolved")), \
                 patch.object(lk, "_deploy_artifact_locally") as deploy, \
                 patch.object(lk, "set_lab_target") as set_target:
                result = lk.run_generic_lab(
                    config, root, "http://127.0.0.1:8545", [DEPLOYER], "0x" + "77" * 32,
                    requested="Pool", _skip_dependency_discovery=True, _network_identity=network,
                )
            self.assertNotEqual(result, 0)
            deploy.assert_not_called()
            set_target.assert_not_called()
            self.assertEqual(config["target"], PRIMARY)
            self.assertEqual(config["lab_system"]["target"], PRIMARY)

    def test_main_target_deployment_failure_does_not_switch_primary_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            network = self._prepare_network(root)
            config = self._base_config()
            candidate = (100, "Pool", root / "out" / "Pool.json", artifact("Pool", "src/Pool.sol"), [], "src/Pool.sol:Pool")
            with patch.object(lk, "_current_deployment_network_identity", return_value=network), \
                 patch.object(lk, "discover_generic_lab_contract", return_value=candidate), \
                 patch.object(lk, "artifact_is_locked_implementation", return_value=False), \
                 patch.object(lk, "discover_contract_dependencies", return_value=[]), \
                 patch.object(lk, "_deploy_artifact_locally", return_value=(None, "broadcast failed")), \
                 patch.object(lk.project_tools, "detect_project", return_value={"kind": "foundry"}), \
                 patch.object(lk, "set_lab_target") as set_target:
                result = lk.run_generic_lab(
                    config, root, "http://127.0.0.1:8545", [DEPLOYER], "0x" + "77" * 32,
                    requested="Pool", _skip_dependency_discovery=True, _network_identity=network,
                )
            self.assertNotEqual(result, 0)
            set_target.assert_not_called()
            self.assertEqual(config["target"], PRIMARY)
            self.assertEqual(config["lab_system"]["target"], PRIMARY)


if __name__ == "__main__":
    unittest.main()
