"""Application-level tests for side-effect-free deployment planning."""
from __future__ import annotations

import importlib.util
import io
import pathlib
import tempfile
import unittest
from unittest.mock import call, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("lowkeycast_deployment_preflight", ROOT / "lowkey" / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)

PRIMARY = "0x" + "11" * 20
SUPPORT = "0x" + "22" * 20
DEPLOYER = "0x" + "33" * 20
NETWORK = {
    "project_id": "project-fingerprint",
    "project_root": "/tmp/example-project",
    "network_session_id": "managed-session-a",
    "session_kind": "managed-anvil",
    "reuse_permitted": True,
    "chain_id": 31337,
    "genesis_hash": "0x" + "55" * 32,
    "rpc_fingerprint": "rpc-fingerprint",
}


def artifact(name: str, source: str):
    return {
        "sourceName": source,
        "contractName": name,
        "abi": [],
        "bytecode": {"object": "0x6000"},
        "deployedBytecode": {"object": "0x6000", "immutableReferences": {}},
    }


class DeploymentPlanPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.main_path = self.root / "out" / "Consumer.json"
        self.dep_path = self.root / "out" / "Support.json"
        self.main_path.parent.mkdir(parents=True)
        self.main_path.write_text("{}", encoding="utf-8")
        self.dep_path.write_text("{}", encoding="utf-8")
        self.main_artifact = artifact("Consumer", "src/Consumer.sol")
        self.dep_artifact = artifact("Support", "src/Support.sol")
        self.main_candidate = (100, "Consumer", self.main_path, self.main_artifact, [], "src/Consumer.sol:Consumer")
        self.dep_candidate = (90, "Support", self.dep_path, self.dep_artifact, [], "src/Support.sol:Support")
        self.config = {
            "target": PRIMARY,
            "target_contract": "ExistingPrimary",
            "lab_system": {"root": PRIMARY, "target": PRIMARY, "root_model": "ExistingPrimary", "target_model": "ExistingPrimary"},
            "project_target_registry": {},
            "wallets": {"lab-deployer": {"address": DEPLOYER}},
            "actor": "lab-deployer",
            "labels": {}, "aliases": {}, "targets": {}, "project_roots": {}, "target_owners": {},
        }

    def tearDown(self):
        self.temp.cleanup()

    def _common_patches(self, stack):
        stack.enter_context(patch.object(lk, "_current_deployment_network_identity", return_value=NETWORK))
        stack.enter_context(patch.object(lk, "discover_generic_lab_contract", return_value=self.main_candidate))
        stack.enter_context(patch.object(lk, "discover_contract_dependencies", return_value=["Support"]))
        stack.enter_context(patch.object(lk, "_discover_artifact_lab_contract_scoped", return_value=self.dep_candidate))
        stack.enter_context(patch.object(lk, "artifact_is_locked_implementation", return_value=False))
        stack.enter_context(patch.object(lk, "_matching_supporting_deployment", return_value=None))

    def _interactive_stdin(self, stack, value: str):
        stream = io.StringIO(value)
        stack.enter_context(patch.object(lk.sys, "stdin", stream))
        stack.enter_context(patch.object(stream, "isatty", return_value=True))

    def test_cancelled_dependency_plan_sends_no_transaction(self):
        with patch.object(lk, "save_config"):
            from contextlib import ExitStack
            with ExitStack() as stack:
                self._common_patches(stack)
                self._interactive_stdin(stack, "2\n")
                deploy = stack.enter_context(patch.object(lk, "_deploy_artifact_locally"))
                set_target = stack.enter_context(patch.object(lk, "set_lab_target"))
                result = lk.run_generic_lab(
                    self.config, self.root, "http://127.0.0.1:8545", [DEPLOYER], "secret",
                    requested="Consumer", _network_identity=NETWORK,
                )
        self.assertNotEqual(result, 0)
        deploy.assert_not_called()
        set_target.assert_not_called()
        self.assertEqual(self.config["target"], PRIMARY)
        self.assertEqual(self.config["lab_system"]["target"], PRIMARY)

    def test_constructor_cancellation_happens_before_linked_library_deployment(self):
        from contextlib import ExitStack
        from types import SimpleNamespace
        main_artifact = dict(self.main_artifact)
        main_artifact["abi"] = [{
            "type": "constructor",
            "inputs": [{"name": "vault", "type": "address", "internalType": "contract IVault"}],
        }]
        candidate = (
            100, "Consumer", self.main_path, main_artifact,
            main_artifact["abi"][0]["inputs"], "src/Consumer.sol:Consumer",
        )
        library_identity = lk.library_linker.ArtifactIdentity("src/MathLibrary.sol", "MathLibrary")
        library_artifact = {
            **artifact("MathLibrary", "src/MathLibrary.sol"),
            "_lowkeyArtifactPath": str(self.dep_path),
        }
        link_ref = SimpleNamespace(identity=library_identity, start=1, length=20)
        with patch.object(lk, "save_config"):
            with ExitStack() as stack:
                stack.enter_context(patch.object(lk, "_current_deployment_network_identity", return_value=NETWORK))
                stack.enter_context(patch.object(lk, "discover_generic_lab_contract", return_value=candidate))
                stack.enter_context(patch.object(lk, "discover_contract_dependencies", return_value=[]))
                stack.enter_context(patch.object(lk, "artifact_is_locked_implementation", return_value=False))
                stack.enter_context(patch.object(lk, "_artifact_catalog", return_value={library_identity.qualified_name: library_artifact}))
                stack.enter_context(patch.object(lk.library_linker, "extract_link_references", side_effect=lambda item, kind: (link_ref,) if item.get("contractName") == "Consumer" else ()))
                stack.enter_context(patch.object(lk.library_linker, "recursive_library_order", return_value=(library_identity,)))
                stack.enter_context(patch.object(lk.library_linker, "resolve_library_artifact", return_value=library_artifact))
                stack.enter_context(patch.object(lk, "artifact_is_deployable", return_value=True))
                stack.enter_context(patch.object(lk, "_compiler_contract_kind", return_value="library"))
                collect = stack.enter_context(patch.object(lk, "_collect_constructor_deployment_values", return_value=(None, "local lab cancelled")))
                deploy_library = stack.enter_context(patch.object(lk, "_deploy_artifact_library_dependencies"))
                deploy_primary = stack.enter_context(patch.object(lk, "_deploy_artifact_locally"))
                set_target = stack.enter_context(patch.object(lk, "set_lab_target"))
                result = lk.run_generic_lab(
                    self.config, self.root, "http://127.0.0.1:8545", [DEPLOYER], "secret",
                    requested="Consumer", _network_identity=NETWORK,
                )
        self.assertNotEqual(result, 0)
        collect.assert_called_once()
        deploy_library.assert_not_called()
        deploy_primary.assert_not_called()
        set_target.assert_not_called()
        self.assertEqual(self.config["target"], PRIMARY)

    def test_dependency_executes_only_after_plan_approval_and_before_primary(self):
        from contextlib import ExitStack
        calls = []
        deploy_results = [(SUPPORT, None), (None, "primary deployment rejected")]

        def deploy(*args, **kwargs):
            calls.append(kwargs.get("creation_bytecode") or "ordinary")
            return deploy_results.pop(0)

        with patch.object(lk, "save_config"):
            with ExitStack() as stack:
                self._common_patches(stack)
                # Main target discovery first, then recursive support discovery.
                stack.enter_context(patch.object(
                    lk, "discover_generic_lab_contract",
                    side_effect=[self.main_candidate, self.dep_candidate],
                ))
                dependency_discovery = stack.enter_context(patch.object(
                    lk, "_discover_artifact_lab_contract_scoped",
                    return_value=self.dep_candidate,
                ))
                selected_dir = self.root / "src" / "primary"
                selected_dir.mkdir(parents=True)
                selected_source = selected_dir / "Consumer.sol"
                selected_source.write_text("contract Consumer {}", encoding="utf-8")
                self._interactive_stdin(stack, "1\n")
                stack.enter_context(patch.object(lk, "_deploy_artifact_locally", side_effect=deploy))
                stack.enter_context(patch.object(lk, "_record_supporting_deployment", return_value={"network_registry_status": "RECORDED"}))
                stack.enter_context(patch.object(lk, "cast_output", return_value=(0, "0x6000", "")))
                stack.enter_context(patch.object(lk.runtime_verification, "verify_runtime", return_value=lk.runtime_verification.RuntimeVerification(
                    "DEPLOYED", "MATCHED", 2, 2, False, None, "AVAILABLE", "0x" + "66" * 32, "0x" + "66" * 32
                )))
                stack.enter_context(patch.object(lk.project_tools, "detect_project", return_value={"kind": "foundry"}))
                stack.enter_context(patch.object(lk, "set_lab_target"))
                result = lk.run_generic_lab(
                    self.config, self.root, "http://127.0.0.1:8545", [DEPLOYER], "secret",
                    requested="Consumer", _network_identity=NETWORK,
                    target_scope=selected_dir, source_file=selected_source,
                )
        self.assertNotEqual(result, 0)
        dependency_discovery.assert_called_once_with(
            self.root, "Support", target_scope=self.root, source_file=None,
        )
        self.assertEqual(calls, ["ordinary", "ordinary"])
        self.assertEqual(self.config["target"], PRIMARY)
        self.assertEqual(self.config["lab_system"]["target"], PRIMARY)


if __name__ == "__main__":
    unittest.main()
