import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import types
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

            def write_artifact(root, name, address):
                source = root / "src" / f"{name}.sol"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(f"pragma solidity ^0.8.20; contract {name} {{}}", encoding="utf-8")
                artifact = root / "out" / f"{name}.sol" / f"{name}.json"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(json.dumps({
                    "contractName": name,
                    "sourceName": f"src/{name}.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "deployedBytecode": {"object": "0x6000"},
                }), encoding="utf-8")
                return artifact

            curve_artifact = write_artifact(current_root, "Curve", "0x1111111111111111111111111111111111111111")
            bounty_artifact = write_artifact(other_root, "Bounty", "0x2222222222222222222222222222222222222222")
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
                "abi_paths": {
                    "0x1111111111111111111111111111111111111111": str(curve_artifact),
                    "0x2222222222222222222222222222222222222222": str(bounty_artifact),
                },
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=current_root):
                aliases = lk.target_aliases(config, current_root)

            self.assertEqual(
                aliases,
                {"curve": "0x1111111111111111111111111111111111111111"},
            )

    def test_project_context_identity_wins_when_anvil_reuses_a_global_alias_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "telephone"
            root.mkdir()
            address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            context_target = {
                "address": address,
                "contract": "Telephone",
                "artifact": str(root / "out" / "telephone.sol" / "Telephone.json"),
                "source": "project-lab",
            }
            config = {
                "aliases": {
                    "CoinFlip": address,
                    "Telephone": address,
                },
                "targets": {
                    "CoinFlip": address,
                    "Telephone": address,
                },
                "project_roots": {address: str(root)},
                "target_owners": {address: str(root)},
                "abi_paths": {},
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                with patch.object(lk, "project_context_target", return_value=context_target):
                    with patch.object(
                        lk,
                        "_project_target_entries",
                        return_value=[{
                            "name": "Telephone",
                            "contract": "Telephone",
                            "address": address,
                        }],
                    ):
                        with patch.object(lk, "_target_entry_is_protocol", return_value=True):
                            self.assertEqual(lk.target_aliases(config, root), {"Telephone": address})
                            self.assertEqual(lk.resolve_target_ref(config, "Telephone", root), address)
                            self.assertIsNone(lk.resolve_target_ref(config, "CoinFlip", root))
                            self.assertEqual(
                                lk.apply_labels(address, config),
                                f"Telephone ({address})",
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

            def write_artifact(root, name):
                source = root / "src" / f"{name}.sol"
                source.parent.mkdir(parents=True)
                source.write_text(
                    f"pragma solidity ^0.8.20; contract {name} {{}}",
                    encoding="utf-8",
                )
                artifact = root / "out" / f"{name}.sol" / f"{name}.json"
                artifact.parent.mkdir(parents=True)
                artifact.write_text(json.dumps({
                    "contractName": name,
                    "sourceName": f"src/{name}.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "deployedBytecode": {"object": "0x6000"},
                }), encoding="utf-8")
                return artifact

            current_artifact = write_artifact(current_root, "curve")
            other_artifact = write_artifact(other_root, "bounty")
            current_address = "0x1111111111111111111111111111111111111111"
            other_address = "0x2222222222222222222222222222222222222222"
            config = {
                "aliases": {"bounty": other_address, "curve": current_address},
                "targets": {},
                "project_roots": {
                    current_address: str(current_root),
                    other_address: str(other_root),
                },
                "abi_paths": {
                    current_address: str(current_artifact),
                    other_address: str(other_artifact),
                },
            }

            self.assertEqual(
                lk.resolve_target_ref(config, "1", current_root),
                current_address,
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

    def test_explicit_project_alias_keeps_sibling_project_abi_target_selectable(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = pathlib.Path(tmp)
            root = workspace / "TargetHolder"
            sibling = workspace / "Ethernaut" / "Fallout"
            root.mkdir()
            sibling.mkdir(parents=True)
            address = "0x" + "3" * 40
            artifact = sibling / "out" / "Fallout.sol" / "Fallout.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "contractName": "Fallout",
                    "sourceName": "src/Fallout.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )
            config = {
                "aliases": {"Fallout": address},
                "targets": {"Fallout": address},
                # ABI discovery belongs to the sibling repository, while this
                # explicit alias is owned by the active TargetHolder project.
                "project_roots": {address: str(sibling)},
                "target_owners": {address: str(root)},
                "abi_paths": {address: str(artifact)},
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                self.assertEqual(lk.target_aliases(config, root), {})

            # The same external ABI becomes available only after explicit
            # project-local registration; shared address ownership alone is
            # not enough to pull sibling-project state into this project.
            config["project_target_registry"] = {
                str(root): {
                    "Fallout": {"address": address, "artifact": str(artifact), "explicit": True}
                }
            }
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                aliases = lk.target_aliases(config, root)

            self.assertEqual(aliases, {"Fallout": address})
            self.assertEqual(lk.resolve_target_ref(config, "Fallout", root), address)

    def test_manual_target_registration_does_not_overwrite_external_abi_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = pathlib.Path(tmp)
            root = workspace / "TargetHolder"
            sibling = workspace / "Ethernaut" / "Fallout"
            root.mkdir()
            sibling.mkdir(parents=True)
            address = "0x" + "4" * 40
            config = {"project_roots": {address: str(sibling)}}

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                lk.remember_project_target(config, root, "Fallout", address)

            self.assertEqual(config["project_roots"][address], str(sibling))
            self.assertEqual(config["target_owners"][address], str(root))
            self.assertEqual(config["aliases"]["Fallout"], address)
            self.assertEqual(
                lk.target_aliases(config, root),
                {"Fallout": address},
            )
            self.assertTrue(
                config["project_target_registry"][str(root)]["Fallout"]["explicit"]
            )

    def test_selecting_explicit_sibling_alias_preserves_manual_project_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = pathlib.Path(tmp)
            root = workspace / "TargetHolder"
            sibling = workspace / "Ethernaut" / "Fallout"
            root.mkdir()
            sibling.mkdir(parents=True)
            # audit_context writes project-local target memory only for a
            # recognized project; a Foundry manifest makes this fixture real.
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            address = "0x" + "5" * 40
            artifact = sibling / "out" / "Fallout.sol" / "Fallout.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "contractName": "Fallout",
                    "sourceName": "src/Fallout.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )
            config = {
                "target": None,
                "target_contract": None,
                "aliases": {"Fallout": address},
                "targets": {"Fallout": address},
                "project_roots": {address: str(sibling)},
                "target_owners": {address: str(root)},
                "abi_paths": {address: str(artifact)},
                "rpc": None,
            }
            entry = {
                "name": "Fallout",
                "contract": "Fallout",
                "address": address,
                "artifact": str(artifact),
                "source_file": "src/Fallout.sol",
                "source": "project-config",
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                with patch.object(lk, "effective_rpc", return_value=None):
                    with patch.object(lk, "save_config"):
                        with patch("sys.stdout", io.StringIO()):
                            self.assertEqual(lk._select_project_target(config, entry, root), 0)
                            selected = lk.project_context_target(root)
                            self.assertIsNotNone(selected)
                            self.assertEqual(selected["address"], address)
                            self.assertEqual(selected["source"], "manual")

                            lk.activate_project_target(config, root)

            self.assertEqual(config["target"], address)
            self.assertEqual(config["target_contract"], "Fallout")
            self.assertEqual(config["abi_paths"][address], str(artifact))

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
                "rpc": "http://127.0.0.1:0",
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
            source = current_root / "src" / "curve.sol"
            source.parent.mkdir(parents=True)
            source.write_text("pragma solidity ^0.8.20; contract curve {}", encoding="utf-8")
            artifact = current_root / "out" / "curve.sol" / "curve.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(json.dumps({
                "contractName": "curve",
                "sourceName": "src/curve.sol",
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "deployedBytecode": {"object": "0x6000"},
            }), encoding="utf-8")
            config = {
                "target": None,
                "target_contract": None,
                "aliases": {"curve": address},
                "targets": {},
                "project_roots": {address: str(current_root)},
                "abi_paths": {address: str(artifact)},
                "rpc": "http://127.0.0.1:0",
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
            (root / "src").mkdir(parents=True)
            (root / "src" / "ConfidencePool.sol").write_text(
                "pragma solidity ^0.8.20; contract ConfidencePool {}",
                encoding="utf-8",
            )
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


    def test_legacy_alias_is_rejected_when_reused_address_artifact_has_another_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            source = root / "src" / "Delegate.sol"
            source.parent.mkdir(parents=True)
            source.write_text("pragma solidity ^0.8.20; contract Delegate {}", encoding="utf-8")
            artifact = root / "out" / "Delegate.sol" / "Delegate.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(json.dumps({
                "contractName": "Delegate",
                "sourceName": "src/Delegate.sol",
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "deployedBytecode": {"object": "0x6000"},
            }), encoding="utf-8")
            address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
            config = {
                "aliases": {"Fallback": address},
                "targets": {"Fallback": address},
                "project_roots": {address: str(root)},
                "target_owners": {address: str(root)},
                "abi_paths": {address: str(artifact)},
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                self.assertEqual(lk.target_aliases(config, root), {})

    def test_project_target_registry_keeps_same_contract_identity_isolated_by_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = pathlib.Path(tmp)
            current_root = workspace / "current"
            other_root = workspace / "other"
            current_root.mkdir()
            other_root.mkdir()
            address = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

            def write_vault(root):
                source = root / "src" / "Vault.sol"
                source.parent.mkdir(parents=True)
                source.write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
                artifact = root / "out" / "Vault.sol" / "Vault.json"
                artifact.parent.mkdir(parents=True)
                artifact.write_text(json.dumps({
                    "contractName": "Vault",
                    "sourceName": "src/Vault.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "deployedBytecode": {"object": "0x6000"},
                }), encoding="utf-8")
                return artifact

            current_artifact = write_vault(current_root)
            other_artifact = write_vault(other_root)
            config = {
                "aliases": {"Vault": address},
                "targets": {"Vault": address},
                "project_roots": {address: str(other_root)},
                "target_owners": {address: str(other_root)},
                "abi_paths": {address: str(other_artifact)},
                "project_target_registry": {
                    str(current_root): {
                        "Vault": {"address": address, "artifact": str(current_artifact)}
                    },
                    str(other_root): {
                        "Vault": {"address": address, "artifact": str(other_artifact)}
                    },
                },
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=current_root):
                self.assertEqual(lk.target_aliases(config, current_root), {"Vault": address})
            with patch.object(lk.audit_context, "foundry_project_root", return_value=other_root):
                self.assertEqual(lk.target_aliases(config, other_root), {"Vault": address})

    def test_multi_contract_same_source_uses_contract_scoped_relationships_and_dependency_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Delegate.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Delegate {
    address public owner;
    constructor(address initialOwner) { owner = initialOwner; }
    function pwn() public { owner = msg.sender; }
}
contract Delegation {
    address public owner;
    Delegate delegate;
    constructor(address implementation) {
        delegate = Delegate(implementation);
        owner = msg.sender;
    }
    fallback() external {
        (bool ok,) = address(delegate).delegatecall(msg.data);
        require(ok);
    }
}
""",
                encoding="utf-8",
            )
            for name in ("Delegate", "Delegation"):
                artifact = root / "out" / "Delegate.sol" / f"{name}.json"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(json.dumps({
                    "contractName": name,
                    "sourceName": "src/Delegate.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "deployedBytecode": {"object": "0x6000"},
                }), encoding="utf-8")

            self.assertEqual(lk.discover_audit_target_contract(root), "Delegation")
            self.assertEqual(lk._preferred_lab_contract(root, None, "Delegate"), "Delegation")
            self.assertEqual(
                lk._preferred_lab_contract(root, None, "Delegate", "Delegate"),
                "Delegation",
            )
            self.assertEqual(
                lk._preferred_lab_contract(root, None, "Delegate", "Delegation"),
                "Delegation",
            )
            self.assertEqual(lk.discover_contract_dependencies(root, "Delegation"), ["Delegate"])
            candidate = lk.discover_generic_lab_contract(root)
            self.assertIsNotNone(candidate)
            self.assertEqual(candidate[1], "Delegation")

    def test_ambiguous_application_contracts_are_not_selected_alphabetically(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Protocol.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Alpha {} contract Zeta {}",
                encoding="utf-8",
            )
            for name in ("Alpha", "Zeta"):
                artifact = root / "out" / "Protocol.sol" / f"{name}.json"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(json.dumps({
                    "contractName": name,
                    "sourceName": "src/Protocol.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "deployedBytecode": {"object": "0x6000"},
                }), encoding="utf-8")

            self.assertIsNone(lk.discover_audit_target_contract(root))
            self.assertIsNone(lk.discover_generic_lab_contract(root))

    def test_universal_ai_flag_is_preserved_for_lab_review(self):
        self.assertEqual(
            lk._extract_universal_ai_flag(["lab", "--ai"]),
            (False, ["lab", "--ai"]),
        )
        self.assertEqual(
            lk._extract_universal_ai_flag(["lab", "Vault", "--ai"]),
            (False, ["lab", "Vault", "--ai"]),
        )


    def test_explicit_lab_review_does_not_trigger_a_second_ai_or_jev_footer(self):
        self.assertTrue(lk._is_lab_ai_review_request("lab", ["--ai"]))
        self.assertTrue(lk._is_lab_ai_review_request("lab", ["Vault", "--ai-review"]))
        self.assertFalse(lk._is_lab_ai_review_request("lab", ["Vault"]))
        self.assertFalse(lk._is_lab_ai_review_request("status", ["--ai"]))



    def test_constructor_picker_uses_project_identity_artifact_and_excludes_sibling_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = pathlib.Path(tmp)
            current_root = workspace / "Current"
            sibling_root = workspace / "Sibling"
            current_root.mkdir()
            sibling_root.mkdir()
            current_address = "0x" + "1" * 40
            sibling_address = "0x" + "2" * 40

            def write_contract(root, name):
                source = root / "src" / f"{name}.sol"
                source.parent.mkdir(parents=True)
                source.write_text(
                    f"pragma solidity ^0.8.20; contract {name} {{}}",
                    encoding="utf-8",
                )
                artifact = root / "out" / f"{name}.sol" / f"{name}.json"
                artifact.parent.mkdir(parents=True)
                artifact.write_text(json.dumps({
                    "contractName": name,
                    "sourceName": f"src/{name}.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "deployedBytecode": {"object": "0x6000"},
                }), encoding="utf-8")
                return artifact

            current_artifact = write_contract(current_root, "CurrentDependency")
            sibling_artifact = write_contract(sibling_root, "SiblingDependency")
            config = {
                "wallets": {},
                "aliases": {
                    "CurrentDependency": current_address,
                    "SiblingDependency": sibling_address,
                },
                "targets": {},
                "project_roots": {
                    current_address: str(current_root),
                    sibling_address: str(sibling_root),
                },
                "target_owners": {
                    current_address: str(current_root),
                    sibling_address: str(sibling_root),
                },
                "abi_paths": {
                    current_address: str(current_artifact),
                    sibling_address: str(sibling_artifact),
                },
                "project_target_registry": {
                    str(current_root): {
                        "CurrentDependency": {
                            "address": current_address,
                            "artifact": str(current_artifact),
                        },
                    },
                    str(sibling_root): {
                        "SiblingDependency": {
                            "address": sibling_address,
                            "artifact": str(sibling_artifact),
                        },
                    },
                },
                "_lab_system_root": str(current_root),
            }
            checked_artifacts = []

            def live_check(_config, address, _rpc, artifact_path=None):
                checked_artifacts.append((address, artifact_path))
                return True

            with patch.object(lk.audit_context, "foundry_project_root", return_value=current_root):
                with patch.object(lk, "_lab_remembered_contract_is_live", side_effect=live_check):
                    choices = lk._lab_address_choices(config, [], rpc="http://127.0.0.1:8545")

            self.assertEqual(choices, [("CurrentDependency", current_address)])
            self.assertEqual(checked_artifacts, [(current_address, str(current_artifact))])



    def test_explicit_ai_review_failure_aborts_before_build_or_deployment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp).resolve()
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")

            def fail_review(_root, _contract=None):
                raise RuntimeError("provider returned malformed protocol review JSON")

            fake_ai = types.SimpleNamespace(
                status=lambda: {
                    "usable": True,
                    "jev_free_tier_mode": False,
                },
                review_project_protocol=fail_review,
            )

            previous_status = lk._COMMAND_STATUS
            lk._COMMAND_STATUS = 0
            try:
                with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                    with patch.object(lk, "is_workspace_root", return_value=False):
                        with patch.dict(sys.modules, {"ai_harness": fake_ai}):
                            with patch.object(lk, "_run_project_build") as build:
                                with patch.object(lk, "ensure_project_anvil") as anvil:
                                    with patch.object(lk, "_record_last_error"):
                                        with contextlib.redirect_stderr(io.StringIO()):
                                            result = lk.run_lab({}, ["--ai-review"])
                self.assertNotEqual(result, 0)
                build.assert_not_called()
                anvil.assert_not_called()
            finally:
                lk._COMMAND_STATUS = previous_status


    def test_cyclic_constructor_dependencies_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Cycle.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; "
                "contract Alpha { Beta beta; } "
                "contract Beta { Alpha alpha; }",
                encoding="utf-8",
            )
            for name in ("Alpha", "Beta"):
                artifact = root / "out" / "Cycle.sol" / f"{name}.json"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(json.dumps({
                    "contractName": name,
                    "sourceName": "src/Cycle.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "deployedBytecode": {"object": "0x6000"},
                }), encoding="utf-8")

            with self.assertRaisesRegex(lk.ContractDependencyCycleError, "Alpha -> Beta -> Alpha"):
                lk.discover_contract_dependencies(root, "Alpha")


    def test_ai_primary_target_requires_a_matching_built_first_party_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Main.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Main {}",
                encoding="utf-8",
            )

            # Before the native build, source text alone is not deployment
            # evidence and an AI-proposed name must not become the target.
            self.assertIsNone(lk.validate_ai_primary_contract_suggestion(root, "Main"))

            artifact = root / "out" / "Main.sol" / "Main.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(json.dumps({
                "contractName": "Main",
                "sourceName": "src/Main.sol",
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "deployedBytecode": {"object": "0x6000"},
            }), encoding="utf-8")

            self.assertEqual(
                lk.validate_ai_primary_contract_suggestion(root, "Main"),
                "Main",
            )
            self.assertIsNone(
                lk.validate_ai_primary_contract_suggestion(root, "Unrelated"),
            )



if __name__ == "__main__":
    unittest.main()
