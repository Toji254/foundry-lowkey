import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkey_lk", MODULE)
lk = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(lk)


class TargetScopingTests(unittest.TestCase):
    def test_target_aliases_ignore_targets_owned_by_other_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            current_root = pathlib.Path(tmp) / "curve"
            other_root = pathlib.Path(tmp) / "bounty"
            current_root.mkdir()
            other_root.mkdir()

            config = {
                "aliases": {
                    "curve": "0x1111111111111111111111111111111111111111",
                    "bounty": "0x2222222222222222222222222222222222222222",
                },
                "targets": {},
                "project_roots": {
                    "0x1111111111111111111111111111111111111111": str(current_root),
                    "0x2222222222222222222222222222222222222222": str(other_root),
                },
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=current_root):
                aliases = lk.target_aliases(config, current_root)

            self.assertEqual(
                aliases,
                {"curve": "0x1111111111111111111111111111111111111111"},
            )

    def test_project_target_list_hides_test_mock_alias_even_when_owned_by_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            address = "0x1111111111111111111111111111111111111111"
            mock_path = root / "tests" / "shared" / "contracts" / "BlockHashOracleMock.vy"
            mock_path.parent.mkdir(parents=True)
            mock_path.write_text("# mock\n", encoding="utf-8")

            config = {
                "aliases": {"BlockHashOracleMock": address},
                "targets": {},
                "project_roots": {address: str(root)},
                "abi_paths": {address: str(mock_path)},
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                aliases = lk.target_aliases(config, root)

            self.assertEqual(aliases, {})

    def test_numeric_target_resolution_is_project_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            current_root = pathlib.Path(tmp) / "curve"
            other_root = pathlib.Path(tmp) / "bounty"
            current_root.mkdir()
            other_root.mkdir()

            config = {
                "aliases": {
                    "bounty": "0x2222222222222222222222222222222222222222",
                    "curve": "0x1111111111111111111111111111111111111111",
                },
                "targets": {},
                "project_roots": {
                    "0x1111111111111111111111111111111111111111": str(current_root),
                    "0x2222222222222222222222222222222222222222": str(other_root),
                },
            }

            self.assertEqual(
                lk.resolve_target_ref(config, "1", current_root),
                "0x1111111111111111111111111111111111111111",
            )

    def test_vyper_builder_source_filter_excludes_test_and_mock_trees(self):
        import sys

        forge_module_path = ROOT / "lowkey" / "forge_tools.py"
        forge_spec = importlib.util.spec_from_file_location("lowkey_forge_tools", forge_module_path)
        forge_tools = importlib.util.module_from_spec(forge_spec)
        assert forge_spec.loader is not None

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "contracts").mkdir()
            (root / "contracts" / "ScrvusdOracleV2.vy").write_text("# app\n", encoding="utf-8")
            (root / "tests" / "shared" / "contracts").mkdir(parents=True)
            (root / "tests" / "shared" / "contracts" / "BlockHashOracleMock.vy").write_text("# mock\n", encoding="utf-8")

            forge_tools.project_tools = None
            forge_spec.loader.exec_module(forge_tools)
            sources = forge_tools._project_vyper_sources(root)

            self.assertEqual(
                [p.relative_to(root).as_posix() for p in sources],
                ["contracts/ScrvusdOracleV2.vy"],
            )

    def test_test_only_vyper_mock_is_not_application_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "tests" / "shared" / "contracts"
            source.mkdir(parents=True)
            source_path = source / "BlockHashOracleMock.vy"
            source_path.write_text("# test mock\n", encoding="utf-8")
            artifact = {
                "contractName": "BlockHashOracleMock",
                "sourceName": "tests/shared/contracts/BlockHashOracleMock.vy",
                "bytecode": {"object": "0x6000"},
                "abi": [],
            }
            self.assertFalse(lk.artifact_is_project_application(root, source_path, artifact))

    def test_target_list_separates_protocol_from_lab_support(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            app_artifact = root / "out" / "ConfidencePool.sol" / "ConfidencePool.json"
            mock_artifact = root / "out" / "MockERC20.sol" / "MockERC20.json"
            app_artifact.parent.mkdir(parents=True)
            mock_artifact.parent.mkdir(parents=True)

            app_artifact.write_text(
                json.dumps({
                    "contractName": "ConfidencePool",
                    "sourceName": "src/ConfidencePool.sol",
                    "abi": [],
                }),
                encoding="utf-8",
            )
            mock_artifact.write_text(
                json.dumps({
                    "contractName": "MockERC20",
                    "sourceName": "test/mocks/MockERC20.sol",
                    "abi": [],
                }),
                encoding="utf-8",
            )

            root_context = {
                "target": {
                    "address": "0x" + "1" * 40,
                    "contract": "ConfidencePool",
                    "artifact": str(app_artifact),
                    "source": "project-lab",
                }
            }

            with patch.object(lk, "project_context_target", return_value=root_context["target"]),                  patch.object(lk, "target_aliases", return_value={
                     "MockERC20": "0x" + "2" * 40,
                 }),                  patch.object(lk, "discover_deployments", return_value=[]),                  patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                config = {
                    "target": "0x" + "1" * 40,
                    "aliases": {},
                    "targets": {},
                    "project_roots": {},
                    "abi_paths": {
                        "0x" + "1" * 40: str(app_artifact),
                        "0x" + "2" * 40: str(mock_artifact),
                    },
                }

                stream = io.StringIO()
                with patch("sys.stdout", stream):
                    self.assertEqual(lk.run_targets(config), 0)

            rendered = stream.getvalue()
            self.assertIn("AUDIT TARGETS", rendered)
            self.assertIn("ConfidencePool", rendered)
            self.assertIn("Source       : src/ConfidencePool.sol", rendered)
            self.assertNotIn("MockERC20", rendered)
            self.assertIn("Lab/test support hidden: 1", rendered)

    def test_broadcast_run_latest_is_grouped_with_timestamped_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            broadcast = root / "broadcast" / "LowkeyAutoConfidencePoolLab.s.sol" / "31337"
            broadcast.mkdir(parents=True)
            timestamp = 1790512249
            payload = {
                "timestamp": timestamp,
                "transactions": [
                    {
                        "transactionType": "CREATE",
                        "contractName": "ConfidencePoolFactory",
                        "contractAddress": "0x" + "1" * 40,
                        "hash": "0x" + "a" * 64,
                    },
                    {
                        "transactionType": "CREATE",
                        "contractName": "ConfidencePool",
                        "contractAddress": "0x" + "2" * 40,
                        "hash": "0x" + "b" * 64,
                    },
                ],
            }
            encoded = json.dumps(payload)
            (broadcast / f"run-{timestamp * 1000}.json").write_text(encoded, encoding="utf-8")
            (broadcast / "run-latest.json").write_text(encoded, encoding="utf-8")

            records = lk.discover_deployments(root)

            self.assertEqual(len(records), 2)
            self.assertEqual(
                {pathlib.Path(item["file"]).name for item in records},
                {f"run-{timestamp * 1000}.json"},
            )
            self.assertTrue(all(item["run_timestamp"] == timestamp for item in records))

    def test_target_command_selects_numbered_protocol_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            first = "0x" + "1" * 40
            second = "0x" + "2" * 40
            config = {
                "target": first,
                "target_contract": "ConfidencePool",
                "aliases": {},
                "targets": {},
                "project_roots": {},
                "abi_paths": {},
            }
            entries = [
                {
                    "name": "ConfidencePool",
                    "contract": "ConfidencePool",
                    "address": first,
                    "artifact": None,
                    "source": "broadcast",
                },
                {
                    "name": "ConfidencePoolFactory",
                    "contract": "ConfidencePoolFactory",
                    "address": second,
                    "artifact": None,
                    "source": "broadcast",
                },
            ]

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "_project_target_entries", return_value=entries), \
                 patch.object(lk, "_target_entry_is_protocol", return_value=True), \
                 patch.object(lk, "save_config"), \
                 patch.object(lk.audit_context, "set_target"):
                code = lk.dispatch_command("target", ["2"], config)

            self.assertEqual(code, 0)
            self.assertEqual(config["target"], second)
            self.assertEqual(config["target_contract"], "ConfidencePoolFactory")

    def test_interactive_targets_selects_current_project_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            current_root = pathlib.Path(tmp) / "curve"
            current_root.mkdir()
            address = "0x1111111111111111111111111111111111111111"
            config = {
                "target": None,
                "target_contract": None,
                "aliases": {"curve": address},
                "targets": {},
                "project_roots": {address: str(current_root)},
                "abi_paths": {},
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=current_root), \
                 patch.object(lk, "project_context_target", return_value=None), \
                 patch.object(lk, "discover_deployments", return_value=[]), \
                 patch.object(lk, "save_config"), \
                 patch.object(lk.audit_context, "set_target"), \
                 patch("builtins.input", return_value="1"):
                code = lk.run_targets(config, interactive=True)

            self.assertEqual(code, 0)
            self.assertEqual(config["target"], address)
            self.assertEqual(config["target_contract"], "curve")


    def test_discover_deployments_includes_nested_additional_contracts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            broadcast = root / "broadcast" / "LocalAudit.s.sol" / "31337"
            broadcast.mkdir(parents=True)
            payload = {
                "timestamp": 123,
                "transactions": [{
                    "transactionType": "CREATE",
                    "contractName": "ConfidencePoolFactory",
                    "contractAddress": "0x" + "1" * 40,
                    "hash": "0x" + "a" * 64,
                    "additionalContracts": [{
                        "transactionType": "CREATE",
                        "address": "0x" + "2" * 40,
                        "contractName": "ConfidencePool",
                    }],
                }],
            }
            (broadcast / "run-123000.json").write_text(json.dumps(payload), encoding="utf-8")
            records = lk.discover_deployments(root)
            self.assertEqual({item["address"] for item in records}, {"0x" + "1" * 40, "0x" + "2" * 40})
            clone = next(item for item in records if item["address"] == "0x" + "2" * 40)
            self.assertEqual(clone["deployment_kind"], "additional")
            self.assertEqual(clone["parent_contract"], "ConfidencePoolFactory")

    def test_auto_target_prefers_live_application_clone_over_implementation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            implementation = "0x" + "1" * 40
            clone = "0x" + "2" * 40
            artifact = root / "out" / "ConfidencePool.sol" / "ConfidencePool.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(json.dumps({
                "contractName": "ConfidencePool",
                "sourceName": "src/ConfidencePool.sol",
                "bytecode": {"object": "0x6000"},
                "deployedBytecode": {"object": "0x6000"},
                "abi": [],
            }), encoding="utf-8")
            records = [
                {"contract": "ConfidencePool", "address": implementation, "deployment_kind": "transaction", "run_timestamp": 200, "time": 200},
                {"contract": "Unknown", "address": clone, "deployment_kind": "additional", "run_timestamp": 200, "time": 200},
            ]
            config = {"abi_paths": {}, "rpc": "http://127.0.0.1:8545"}
            with patch.object(lk, "local_artifact_paths", return_value=[str(artifact)]),                  patch.object(lk, "read_artifact", return_value=json.loads(artifact.read_text())),                  patch.object(lk, "_live_target_artifact_match", side_effect=lambda cfg, addr, art: "clone-or-proxy" if addr == clone else "runtime"),                  patch.object(lk, "_live_runtime", return_value="0x6000"):
                ranked = lk._auto_target_records(config, root, records, requested="ConfidencePool")
            self.assertEqual(ranked[0]["address"], clone)
            self.assertEqual(ranked[0]["_resolved_contract"], "ConfidencePool")


if __name__ == "__main__":
    unittest.main()
