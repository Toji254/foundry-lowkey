import importlib.util
import json
import os
import pathlib
from pathlib import Path
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout, redirect_stderr
import io
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class LowkeyCastTests(unittest.TestCase):
    def test_select_project_target_rejects_stale_no_code_address(self):
        address = "0x" + "1" * 40
        config = {"rpc": "http://127.0.0.1:8545"}
        entry = {
            "name": "Fallback",
            "contract": "Fallback",
            "address": address,
            "artifact": "out/Fallback.sol/Fallback.json",
        }

        with patch.object(
            lk,
            "cast_output",
            return_value=(0, "0x", ""),
        ):
            code = lk._select_project_target(config, entry, pathlib.Path("/tmp/testi"))

        self.assertEqual(code, 1)
        self.assertNotIn("target", config)

    def test_parse_lab_marker_preserves_default_and_custom_marker_contract(self):
        target = "0x" + "4" * 40
        created = "0x" + "5" * 40

        self.assertEqual(
            lk.parse_lab_marker(f"LOWKEY_TARGET {target}"),
            target,
        )
        self.assertEqual(
            lk.parse_lab_marker(f"LOWKEY_CREATE {created}", "LOWKEY_CREATE"),
            created,
        )
        self.assertIsNone(lk.parse_lab_marker("no lab target here"))

    def test_parse_lab_marker_accepts_forge_prefixed_console_output(self):
        target = "0x" + "6" * 40
        output = "\n".join([
            "  [123] 0x0000000000000000000000000000000000000000",
            f"  LOWKEY_TARGET {target} (script console)",
            "  return value: done",
        ])

        self.assertEqual(lk.parse_lab_marker(output), target)
        self.assertEqual(lk.parse_lab_system(output)["target"], target)

    def test_tracked_scarb_manifest_drift_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            nested = root / "workspace" / "app"
            nested.mkdir(parents=True)
            manifest = root / "Scarb.toml"
            manifest.write_text('[workspace]\n[workspace.dependencies]\nsnforge_std = "0.34.0"\n', encoding="utf-8")

            subprocess.run(["git", "init"], cwd=root, capture_output=True, text=True, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Lowkey Tests"],
                cwd=root, capture_output=True, text=True, check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "lowkey-tests@example.invalid"],
                cwd=root, capture_output=True, text=True, check=True,
            )
            subprocess.run(["git", "add", "Scarb.toml"], cwd=root, capture_output=True, text=True, check=True)
            subprocess.run(
                ["git", "commit", "-m", "initial"],
                cwd=root, capture_output=True, text=True, check=True,
            )

            manifest.write_text('[workspace]\n[workspace.dependencies]\nsnforge_std = "0.64.0"\n', encoding="utf-8")

            self.assertEqual(
                lk._tracked_scarb_manifest_drift(nested),
                ["Scarb.toml"],
            )

    def run_cli(self, *args):
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HOME"] = home
            return subprocess.run(
                [sys.executable, str(MODULE), *args],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )

    def test_pnpm_lockfile_v6_uses_compatible_corepack_pnpm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text('{"devDependencies":{"@openzeppelin/contracts":"^5.0.2"}}\n', encoding="utf-8")
            (root / "pnpm-lock.yaml").write_text("lockfileVersion: 6.0\n", encoding="utf-8")
            with patch.object(lk.shutil, "which", side_effect=lambda name: name == "corepack"):
                command = lk._node_package_bootstrap_command(root)
        self.assertEqual(command, ["corepack", "pnpm@8", "install", "--frozen-lockfile"])

    def test_explicit_package_manager_pin_wins_over_lockfile_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"packageManager":"pnpm@9.15.0","devDependencies":{}}\n',
                encoding="utf-8",
            )
            (root / "pnpm-lock.yaml").write_text("lockfileVersion: 6.0\n", encoding="utf-8")
            with patch.object(lk.shutil, "which", side_effect=lambda name: name == "corepack"):
                command = lk._node_package_bootstrap_command(root)
        self.assertEqual(command, ["corepack", "pnpm@9.15.0", "install", "--frozen-lockfile"])
    def test_foundry_dependency_recovery_repairs_partial_node_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".gitmodules").write_text(
                '[submodule "contracts/lib/forge-std"]\n'
                '\tpath = contracts/lib/forge-std\n'
                '\turl = https://github.com/foundry-rs/forge-std.git\n',
                encoding="utf-8",
            )
            (root / "package.json").write_text(
                '{"devDependencies":{"@openzeppelin/contracts":"^5.0.2"}}\n',
                encoding="utf-8",
            )
            (root / "pnpm-lock.yaml").write_text("lockfileVersion: 9.0\n", encoding="utf-8")
            (root / "node_modules").mkdir()

            build_output = (
                'Source "node_modules/@openzeppelin/contracts/access/Ownable.sol" not found\n'
            )
            with patch.object(
                lk.shutil,
                "which",
                side_effect=lambda name: name in {"git", "pnpm"},
            ):
                commands = lk._foundry_native_bootstrap_commands(root, build_output)

        self.assertEqual(
            commands,
            [
                ["git", "submodule", "sync", "--recursive"],
                ["git", "submodule", "update", "--init", "--recursive", "--force"],
                ["git", "clone", "--depth", "1", "https://github.com/foundry-rs/forge-std.git", "contracts/lib/forge-std"],
                ["pnpm", "install", "--frozen-lockfile"],
            ],
        )

    def test_foundry_dependency_recovery_uses_package_manager_only_when_dependency_failure_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"devDependencies":{"@openzeppelin/contracts":"^5.0.2"}}\n',
                encoding="utf-8",
            )
            (root / "pnpm-lock.yaml").write_text("lockfileVersion: 9.0\n", encoding="utf-8")
            (root / "node_modules").mkdir()

            unrelated = 'Source "contracts/src/Missing.sol" not found'
            with patch.object(
                lk.shutil,
                "which",
                side_effect=lambda name: name == "pnpm",
            ):
                commands = lk._foundry_native_bootstrap_commands(root, unrelated)

        self.assertEqual(commands, [])

    def test_declared_submodule_health_detects_successful_command_with_empty_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".gitmodules").write_text(
                '[submodule "forge-std"]\n\tpath = contracts/lib/forge-std\n'
                '\turl = https://github.com/foundry-rs/forge-std.git\n',
                encoding="utf-8",
            )
            (root / "contracts" / "lib" / "forge-std").mkdir(parents=True)

            self.assertEqual(
                lk._submodule_bootstrap_health(root),
                ["contracts/lib/forge-std"],
            )
    def test_source_walker_prunes_dependency_and_generated_trees(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "node_modules" / "huge").mkdir(parents=True)
            (root / "lib" / "vendor").mkdir(parents=True)
            (root / ".git" / "objects").mkdir(parents=True)
            (root / "dist").mkdir()
            (root / "src" / "App.sol").write_text("contract App {}", encoding="utf-8")
            (root / "node_modules" / "huge" / "Bad.sol").write_text("contract Bad {}", encoding="utf-8")
            (root / "lib" / "vendor" / "Lib.sol").write_text("library Lib {}", encoding="utf-8")
            (root / "dist" / "Generated.sol").write_text("contract Generated {}", encoding="utf-8")

            files = lk.project_tools.project_source_files(root, {"sol"})

        self.assertEqual(files, [root / "src" / "App.sol"])
    def test_address_validation(self):
        self.assertTrue(lk.is_address("0x" + "1" * 40))
        self.assertFalse(lk.is_address("0x" + "1" * 64))
        self.assertFalse(lk.is_address(None))

    def test_abi_is_materialized_as_pretty_project_local_json(self):
        target = "0x" + "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text(
                "[profile.default]\nsrc = \"src\"\nout = \"out\"\n",
                encoding="utf-8",
            )
            artifact = root / "out" / "BountyArena.sol" / "BountyArena.json"
            artifact.parent.mkdir(parents=True)
            abi = [
                {
                    "type": "function",
                    "name": "createbounty",
                    "inputs": [
                        {"name": "addr", "type": "address", "internalType": "address"},
                        {"name": "amount", "type": "uint256", "internalType": "uint256"},
                    ],
                    "outputs": [{"name": "", "type": "bytes32", "internalType": "bytes32"}],
                    "stateMutability": "payable",
                }
            ]
            artifact.write_text(
                json.dumps(
                    {
                        "contractName": "BountyArena",
                        "abi": abi,
                        "bytecode": {"object": "0x6000"},
                    }
                ),
                encoding="utf-8",
            )
            config = {
                "target": target,
                "target_contract": "BountyArena",
                "abi_paths": {},
                "project_roots": {target: str(root)},
            }

            remembered = lk.remember_abi_path(config, target, str(artifact))
            audit_file = root / ".audit" / "abi" / "BountyArena.json"

            self.assertEqual(remembered, str(artifact.resolve()))
            self.assertEqual(config["abi_paths"][target], str(artifact.resolve()))
            self.assertTrue(audit_file.is_file())

            rendered = audit_file.read_text(encoding="utf-8")
            payload = json.loads(rendered)
            self.assertEqual(payload["contractName"], "BountyArena")
            self.assertEqual(payload["abi"], abi)
            self.assertIn("\n  \"abi\": [", rendered)
            self.assertTrue(rendered.endswith("\n"))

    def test_transaction_send_summary_exposes_clickable_evidence(self):
        tx_hash = "0x" + "1" * 64
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            evidence = lk.walkthrough._transaction_evidence_path(root, tx_hash)
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text("<html>transaction</html>", encoding="utf-8")
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                rendered = lk.format_send_summary(
                    "transactionHash " + tx_hash + "\nstatus 1\n",
                    {"wallets": {}, "labels": {}, "aliases": {}, "targets": {}},
                    "ping()",
                )
        self.assertIn("Ctrl+Click", rendered)
        self.assertIn(tx_hash, rendered)
        self.assertIn("\x1b]8;;file://", rendered)

    def test_receipt_records_audit_evidence(self):
        tx_hash = "0x" + "1" * 64
        with patch.object(lk, "run_cast", return_value=0) as run_cast:
            with patch.object(lk, "audit_context") as ctx:
                result = lk.run_receipt({"last_tx": tx_hash})
        self.assertEqual(result, 0)
        run_cast.assert_called_once_with(["receipt", tx_hash, "--async"], {"last_tx": tx_hash})
        ctx.set_latest.assert_called_once()
        ctx.record_tool.assert_called_once()
        self.assertEqual(ctx.record_tool.call_args.args[0], "receipt")

    def test_lab_numeric_grouping_is_normalized(self):
        self.assertEqual(
            lk._normalize_human_numeric_input("1,000,000", "uint256", "limit"),
            "1000000",
        )
        self.assertEqual(
            lk._normalize_human_numeric_input("1 ETH", "uint256", "amount"),
            "1000000000000000000",
        )

    def test_wizard_treats_positional_value_as_argument_and_infers_send(self):
        target = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "buyNft",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "amount", "type": "uint256"}],
            "outputs": [],
        }]
        config = {"target": target}

        with patch.object(lk, "load_abi", return_value=abi), patch.object(
            lk, "run_cast", return_value=0
        ) as run_cast:
            result = lk.run_wizard(config, ["buyNft", "5"])

        self.assertEqual(result, 0)
        run_cast.assert_called_once_with(
            ["send", "buyNft(uint256)", "5", "--confirm"],
            config,
        )

    def test_wizard_infers_call_for_view_function_with_positional_value(self):
        target = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "balanceOf",
            "stateMutability": "view",
            "inputs": [{"name": "owner", "type": "address"}],
            "outputs": [{"name": "", "type": "uint256"}],
        }]
        owner = "0x" + "2" * 40
        config = {"target": target}

        with patch.object(lk, "load_abi", return_value=abi), patch.object(
            lk, "run_cast", return_value=0
        ) as run_cast:
            result = lk.run_wizard(config, ["balanceOf", owner])

        self.assertEqual(result, 0)
        run_cast.assert_called_once_with(
            ["call", "balanceOf(address)", owner],
            config,
        )

    def test_lab_wizard_handles_fixed_and_nested_arrays_generically(self):
        config = {"wallets": {}}
        accounts = ["0x" + "1" * 40]

        fixed = {"name": "values", "type": "uint256[2]"}
        with patch("builtins.input", side_effect=["1,000", "2_000"]):
            rendered = lk._lab_prompt_value(
                config, accounts, "Example", fixed, path="params[1]"
            )
        self.assertEqual(rendered, "[1000,2000]")

        nested = {"name": "matrix", "type": "string[][]"}
        with patch("builtins.input", side_effect=["1", "2", "alpha", "beta"]):
            rendered = lk._lab_prompt_value(
                config, accounts, "Example", nested, path="params[2]"
            )
        self.assertEqual(rendered, '[["alpha","beta"]]')


    def test_wizard_extracts_and_decodes_transaction_return_value(self):
        config = {
            "target": "0x" + "1" * 40,
            "target_contract": "Example",
            "rpc": "http://127.0.0.1:8545",
            "last_tx": "0x" + "2" * 64,
            "wallets": {},
        }
        item = {
            "type": "function",
            "name": "createEscrow",
            "inputs": [
                {"name": "amount", "type": "uint256"},
                {"name": "recipient", "type": "address"},
            ],
            "outputs": [{"name": "id", "type": "bytes32"}],
        }
        trace = json.dumps({
            "failed": False,
            "returnValue": "aa" * 32,
        })
        decoded = "0x" + "aa" * 32
        with patch.object(lk, "effective_rpc", return_value=config["rpc"]), \
             patch.object(
                 lk,
                 "cast_output",
                 side_effect=[(0, trace, ""), (0, decoded, "")],
             ) as cast:
            result = lk._wizard_transaction_return(config, config["last_tx"], item)

        self.assertEqual(result["raw"], "0x" + "aa" * 32)
        self.assertEqual(result["decoded"], decoded)
        self.assertEqual(cast.call_args_list[0].args[0], [
            "cast", "rpc", "debug_traceTransaction", config["last_tx"],
            "--rpc-url", config["rpc"],
        ])
        self.assertEqual(cast.call_count, 2)

    def test_wizard_value_first_form_surfaces_transaction_return(self):
        target = "0x" + "1" * 40
        config = {
            "target": target,
            "target_contract": "Example",
            "rpc": "http://127.0.0.1:8545",
            "wallets": {},
        }
        abi = [{
            "type": "function",
            "name": "createEscrow",
            "inputs": [{"name": "recipient", "type": "address"}],
            "outputs": [{"name": "id", "type": "bytes32"}],
            "stateMutability": "nonpayable",
        }]
        tx_hash = "0x" + "2" * 64
        config["last_tx"] = tx_hash
        trace_result = {
            "raw": "0x" + "aa" * 32,
            "decoded": "0x" + "aa" * 32,
            "decode_error": None,
        }
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "run_cast", return_value=0) as send, \
             patch.object(lk, "_wizard_transaction_return", return_value=trace_result), \
             redirect_stdout(io.StringIO()) as output:
            code = lk.run_wizard(
                config,
                ["createEscrow", "0x" + "3" * 40],
            )

        self.assertEqual(code, 0)
        send.assert_called_once_with(
            ["send", "createEscrow(address)", "0x" + "3" * 40, "--confirm"],
            config,
        )
        rendered = output.getvalue()
        self.assertIn("RETURN VALUES", rendered)
        self.assertIn("Raw return data:", rendered)
        self.assertIn("Decoded:", rendered)
        self.assertIn(
            "id = 0x" + "aa" * 32 + " [bytes32]",
            rendered,
        )

    def test_tuple_canonicalization(self):
        self.assertEqual(
            lk.canonical_type({
                "type": "tuple",
                "components": [{"type": "address"}, {"type": "uint256"}],
            }),
            "(address,uint256)",
        )
        self.assertEqual(
            lk.canonical_type({
                "type": "tuple[]",
                "components": [{"type": "address"}, {"type": "uint256[]"}],
            }),
            "(address,uint256[])[]",
        )

    def test_output_signature(self):
        item = {
            "name": "quote",
            "inputs": [{"type": "address"}],
            "outputs": [{"type": "uint256"}, {"type": "bool"}],
        }
        self.assertEqual(
            lk.format_output_signature(item),
            "quote(address)(uint256,bool)",
        )

    def test_overload_matching(self):
        abi = [
            {"type": "function", "name": "foo", "inputs": [{"type": "uint256"}]},
            {"type": "function", "name": "foo", "inputs": [{"type": "address"}]},
        ]
        self.assertEqual(len(lk.matching_functions(abi, "foo")), 2)
        self.assertEqual(len(lk.matching_functions(abi, "foo(uint256)")), 1)

    def test_target_resolution(self):
        first = "0x" + "1" * 40
        second = "0x" + "2" * 40
        config = {
            "target": None,
            "aliases": {"alpha": first, "beta": second},
            "targets": {},
        }
        self.assertEqual(lk.resolve_target_ref(config, "alpha"), first)
        self.assertEqual(lk.resolve_target_ref(config, "1"), first)

    def test_artifact_discovery_honors_configured_foundry_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "contracts/src"\nout = "forge-artifacts"\n',
                encoding="utf-8",
            )
            artifact_dir = root / "forge-artifacts" / "AaveDIVAWrapper.sol"
            artifact_dir.mkdir(parents=True)
            (artifact_dir / "AaveDIVAWrapper.json").write_text(
                json.dumps({
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "contractName": "AaveDIVAWrapper",
                    "sourceName": "contracts/src/AaveDIVAWrapper.sol",
                }),
                encoding="utf-8",
            )
            paths = lk.artifact_json_files(root)

        self.assertIn(str(artifact_dir / "AaveDIVAWrapper.json"), paths)

    def test_artifact_discovery_keeps_common_defaults_with_custom_foundry_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text(
                '[profile.default]\nout = "forge-artifacts"\n',
                encoding="utf-8",
            )
            default_dir = root / "out" / "Legacy.sol"
            custom_dir = root / "forge-artifacts" / "Current.sol"
            default_dir.mkdir(parents=True)
            custom_dir.mkdir(parents=True)
            (default_dir / "Legacy.json").write_text('{"abi":[]}\n', encoding="utf-8")
            (custom_dir / "Current.json").write_text('{"abi":[]}\n', encoding="utf-8")
            paths = lk.artifact_json_files(root)

        self.assertIn(str(default_dir / "Legacy.json"), paths)
        self.assertIn(str(custom_dir / "Current.json"), paths)
    def test_artifact_discovery_honors_configured_foundry_output_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "contracts/src"\nout = "forge-artifacts"\n',
                encoding="utf-8",
            )
            artifact_dir = root / "forge-artifacts" / "AaveDIVAWrapper.sol"
            artifact_dir.mkdir(parents=True)
            (artifact_dir / "AaveDIVAWrapper.json").write_text(
                json.dumps({
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                    "contractName": "AaveDIVAWrapper",
                    "sourceName": "contracts/src/AaveDIVAWrapper.sol",
                }),
                encoding="utf-8",
            )
            paths = lk.artifact_json_files(root)
        self.assertIn(str(artifact_dir / "AaveDIVAWrapper.json"), paths)
    def test_auto_lab_ignores_dependency_library_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "lib").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")

            (root / "src" / "ConfidencePoolFactory.sol").write_text(
                "pragma solidity ^0.8.20; contract ConfidencePoolFactory { }",
                encoding="utf-8",
            )
            (root / "lib" / "Address.sol").write_text(
                "pragma solidity ^0.8.20; library Address { }",
                encoding="utf-8",
            )

            app_out = root / "out" / "ConfidencePoolFactory.sol"
            lib_out = root / "out" / "Address.sol"
            app_out.mkdir(parents=True)
            lib_out.mkdir(parents=True)
            common_abi = {"abi": [], "bytecode": {"object": "0x6000"}}
            app_artifact = {
                **common_abi,
                "contractName": "ConfidencePoolFactory",
                "sourceName": "src/ConfidencePoolFactory.sol",
            }
            lib_artifact = {
                **common_abi,
                "contractName": "Address",
                "sourceName": "lib/openzeppelin-contracts/contracts/utils/Address.sol",
            }
            (app_out / "ConfidencePoolFactory.json").write_text(json.dumps(app_artifact), encoding="utf-8")
            (lib_out / "Address.json").write_text(json.dumps(lib_artifact), encoding="utf-8")

            chosen = lk.discover_generic_lab_contract(root)

        self.assertIsNotNone(chosen)
        self.assertEqual(chosen[1], "ConfidencePoolFactory")

    def test_artifact_source_name_never_fabricates_src_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "out" / "Address.sol").mkdir(parents=True)
            artifact = {
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "contractName": "Address",
            }
            path = str(root / "out" / "Address.sol" / "Address.json")
            self.assertIsNone(lk.artifact_source_name(artifact, path))

    def test_application_artifact_recovers_missing_source_name_from_project_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "ConfidencePoolFactory.sol").write_text(
                "pragma solidity ^0.8.20; contract ConfidencePoolFactory { }",
                encoding="utf-8",
            )
            (root / "foundry.toml").write_text(
                '[profile.default]\\nsrc = "src"\\n',
                encoding="utf-8",
            )
            artifact = {
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "contractName": "ConfidencePoolFactory",
            }
            path = root / "out" / "ConfidencePoolFactory.sol" / "ConfidencePoolFactory.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(artifact), encoding="utf-8")

            self.assertEqual(
                lk.artifact_source_name(artifact, str(path), root),
                "src/ConfidencePoolFactory.sol",
            )
            self.assertTrue(lk.artifact_is_project_application(root, str(path), artifact))

    def test_application_artifact_requires_existing_source_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            artifact = {
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "contractName": "Address",
                "sourceName": "src/Address.sol",
            }
            path = root / "out" / "Address.sol" / "Address.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(artifact), encoding="utf-8")
            self.assertFalse(lk.artifact_is_project_application(root, str(path), artifact))

    def test_project_context_rejects_stale_dependency_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "lib").mkdir()
            (root / "out" / "ConfidencePoolFactory.sol").mkdir(parents=True)
            (root / "out" / "Address.sol").mkdir(parents=True)
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")

            (root / "src" / "ConfidencePoolFactory.sol").write_text(
                "pragma solidity ^0.8.20; contract ConfidencePoolFactory { }",
                encoding="utf-8",
            )
            (root / "lib" / "Address.sol").write_text(
                "pragma solidity ^0.8.20; library Address { }",
                encoding="utf-8",
            )

            app_artifact = {
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "contractName": "ConfidencePoolFactory",
                "sourceName": "src/ConfidencePoolFactory.sol",
            }
            lib_artifact = {
                "abi": [],
                "bytecode": {"object": "0x6000"},
                "contractName": "Address",
                "sourceName": "lib/openzeppelin-contracts/contracts/utils/Address.sol",
            }
            (root / "out" / "ConfidencePoolFactory.sol" / "ConfidencePoolFactory.json").write_text(
                json.dumps(app_artifact), encoding="utf-8"
            )
            (root / "out" / "Address.sol" / "Address.json").write_text(
                json.dumps(lib_artifact), encoding="utf-8"
            )

            stale = "0x" + "a" * 40
            lk.audit_context.set_target(
                root,
                address=stale,
                contract="Address",
                artifact=str(root / "out" / "Address.sol" / "Address.json"),
                source="project-lab",
            )

            self.assertIsNone(lk.project_context_target(root))
            config = {"target": stale, "target_contract": "Address", "aliases": {}, "targets": {}, "abi_paths": {}, "rpc": None}
            with patch.object(lk, "discover_audit_target_contract", return_value=None),                  patch.object(lk, "_live_target_candidate", return_value=None),                  patch.object(lk, "discover_deployments", return_value=[]):
                self.assertIsNone(lk._bootstrap_audit_target(config, root, allow_deploy=False))

    def test_live_target_candidate_ignores_dependency_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "lib").mkdir()
            (root / "out" / "ConfidencePoolFactory.sol").mkdir(parents=True)
            (root / "out" / "Address.sol").mkdir(parents=True)
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "ConfidencePoolFactory.sol").write_text(
                "pragma solidity ^0.8.20; contract ConfidencePoolFactory { }",
                encoding="utf-8",
            )
            (root / "lib" / "Address.sol").write_text(
                "pragma solidity ^0.8.20; library Address { }",
                encoding="utf-8",
            )

            app = {
                "abi": [], "bytecode": {"object": "0x6000"},
                "contractName": "ConfidencePoolFactory",
                "sourceName": "src/ConfidencePoolFactory.sol",
            }
            dep = {
                "abi": [], "bytecode": {"object": "0x6000"},
                "contractName": "Address",
                "sourceName": "lib/openzeppelin-contracts/contracts/utils/Address.sol",
            }
            (root / "out" / "ConfidencePoolFactory.sol" / "ConfidencePoolFactory.json").write_text(
                json.dumps(app), encoding="utf-8"
            )
            (root / "out" / "Address.sol" / "Address.json").write_text(
                json.dumps(dep), encoding="utf-8"
            )

            config = {
                "aliases": {
                    "Address": "0x" + "1" * 40,
                    "ConfidencePoolFactory": "0x" + "2" * 40,
                },
                "targets": {},
            }
            with patch.object(lk, "anvil_rpc_info", return_value={"url": "http://127.0.0.1:8545"}), \
                 patch.object(
                     lk,
                     "cast_output",
                     side_effect=lambda args: (0, "0x6000", "") if len(args) > 2 and args[2] in config["aliases"].values() else (1, "", ""),
                 ):
                candidate = lk._live_target_candidate(
                    config,
                    root,
                    "ConfidencePoolFactory",
                )

            self.assertIsNotNone(candidate)
            self.assertEqual(candidate["contract"], "ConfidencePoolFactory")


    @patch.object(lk, "_validate_project_lab_target", return_value=("CanonicalTarget", "/tmp/CanonicalTarget.json", None))
    @patch.object(lk, "run_foundry")
    def test_project_lab_lowkey_target_wins_over_system_markers(
        self,
        run_foundry,
        validate_target,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            script = root / "script" / "LocalAudit.s.sol"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "pragma solidity ^0.8.20; contract LocalAudit { function run() external {} }",
                encoding="utf-8",
            )

            canonical = "0x" + "1" * 40
            factory = "0x" + "2" * 40
            pool = "0x" + "3" * 40
            run_foundry.return_value = lk.CommandResult(
                "\n".join([
                    f"LOWKEY_TARGET {canonical}",
                    f"LOWKEY_FACTORY {factory}",
                    f"LOWKEY_POOL {pool}",
                ]),
                0,
            )

            config = {
                "actor": None,
                "wallets": {},
                "labels": {},
                "aliases": {},
                "targets": {},
                "abi_paths": {},
            }

            with patch.object(lk, "auto_abi_path", return_value=None):
                with patch.object(
                    lk,
                    "derive_default_anvil_key",
                    return_value="0x" + "4" * 64,
                ):
                    with patch.object(lk, "set_lab_target"):
                        result = lk.run_project_lab_script(
                            config,
                            root,
                            str(script),
                            "http://127.0.0.1:8545",
                            ["0x" + "5" * 40],
                            "0x" + "4" * 64,
                        )

            self.assertEqual(result, 0)
            self.assertEqual(validate_target.call_args.args[3], canonical)
            self.assertEqual(config["lab_system"]["factory"], factory)
            self.assertEqual(config["lab_system"]["pool"], pool)
            self.assertEqual(config["lab_system"]["target"], canonical)

    @patch.object(lk, "run_cast")
    @patch.object(lk, "run_foundry")
    @patch.object(lk, "derive_default_anvil_key", return_value="0x" + "1" * 64)
    @patch.object(
        lk,
        "anvil_rpc_info",
        return_value={
            "url": "http://127.0.0.1:8545",
            "accounts": [
                "0x" + "2" * 40,
                "0x" + "3" * 40,
            ],
        },
    )
    @patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545")
    @patch.object(lk, "actor_display", return_value="lab-deployer")
    def test_project_lab_script_lets_forge_auto_select_single_script(
        self,
        _actor_display,
        _rpc,
        _anvil,
        _key,
        run_foundry,
        run_cast,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\n',
                encoding="utf-8",
            )
            script = root / "script" / "LowkeyAutoConfidencePoolLab.s.sol"
            script.parent.mkdir(parents=True)
            script.write_text("contract LowkeyAutoConfidencePoolLab {}", encoding="utf-8")

            run_foundry.return_value = lk.CommandResult(
                "LOWKEY_TARGET 0x" + "4" * 40,
                0,
            )
            run_cast.return_value = lk.CommandResult("0x6000", 0)

            config = {
                "actor": None,
                "wallets": {},
                "labels": {},
                "aliases": {},
                "targets": {},
                "abi_paths": {},
            }
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root),                  patch.object(lk, "auto_abi_path", return_value=None):
                result = lk.run_project_lab_script(
                    config,
                    root,
                    str(script),
                    "http://127.0.0.1:8545",
                    [
                        "0x" + "2" * 40,
                        "0x" + "3" * 40,
                    ],
                    "0x" + "1" * 64,
                )

        self.assertEqual(result, 0)
        command = run_foundry.call_args.args[0]
        self.assertEqual(command[:2], ["script", "script/LowkeyAutoConfidencePoolLab.s.sol"])
        self.assertNotIn("script/LowkeyAutoConfidencePoolLab.s.sol:LowkeyAutoConfidencePoolLab", command)

    def test_promoted_test_fixture_is_generated_from_project_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            test_path = root / "test" / "PoolHarness.t.sol"
            test_path.parent.mkdir(parents=True, exist_ok=True)
            test_path.write_text(
                """
pragma solidity ^0.8.20;
contract PoolHarness {
    function setUp() public {}
    function createPool() internal returns (address newPool, bytes memory args) {
        newPool = address(new Pool());
        args = "";
    }
}
contract Pool {
    uint256 public value = 1;
}
""",
                encoding="utf-8",
            )
            fixture = lk.discover_local_lab_fixture(root, "Pool")
            self.assertIsNotNone(fixture)
            self.assertEqual(fixture["contract"], "PoolHarness")
            self.assertEqual(fixture["create_function"], "createPool")
            self.assertTrue(fixture["tuple_return"])

            script = lk._generate_test_fixture_lab_script(root, fixture)
            self.assertTrue(pathlib.Path(script).is_file())
            content = pathlib.Path(script).read_text(encoding="utf-8")
            self.assertIn("is PoolHarness", content)
            self.assertIn("(target, ) = createPool();", content)
            self.assertIn("LOWKEY_TARGET", content)

    def test_walkthrough_failure_diagnosis_is_crash_safe(self):
        import pathlib
        model = lk.walkthrough.ContractModel(
            name="Fixture",
            source="src/Fixture.sol",
            artifact="out/Fixture.sol/Fixture.json",
            abi=[],
        )
        step = lk.walkthrough.Step(
            1, "Alice", "Fixture", "0x" + "1" * 40,
            "ping()", [],
        )
        with patch.object(
            lk.walkthrough,
            "_diagnose_argument_contracts",
            side_effect=TypeError("unexpected keyword argument"),
        ), patch.object(
            lk.walkthrough,
            "_probe_source_guards",
            return_value=(None, ["source guard: none"]),
        ), patch.object(
            lk.walkthrough,
            "_read_zero_address_diagnostics",
            return_value=(None, []),
        ), patch.object(
            lk.walkthrough,
            "_source_guard_lines",
            return_value=["source guard: none"],
        ), patch.object(
            lk.walkthrough,
            "_cmd",
            return_value=(1, "", "cannot encode"),
        ):
            origin, diagnostics = lk.walkthrough._diagnose_failed_call(
                pathlib.Path("/tmp"),
                "http://127.0.0.1:8545",
                step,
                model,
                [model],
                "0x" + "2" * 40,
            )
        self.assertIsNone(origin)
        self.assertTrue(any("dependency diagnosis unavailable" in item for item in diagnostics))
        self.assertTrue(any("could not encode" in item for item in diagnostics))

    def test_walkthrough_vyper_layout_normalization(self):
        layout = {
            "storage_layout": {
                "owner": {"type": "address", "slot": 0},
                "count": {"type": "uint256", "slot": 1},
            }
        }
        normalized = lk.walkthrough._normalize_vyper_layout(layout)
        self.assertEqual(
            normalized["storage"],
            [
                {"label": "owner", "slot": "0", "type": "address", "offset": 0},
                {"label": "count", "slot": "1", "type": "uint256", "offset": 0},
            ],
        )

    def test_walkthrough_maps_source_name_less_foundry_artifact_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "out" / "EthEscrow.sol").mkdir(parents=True)
            (root / "src" / "EthEscrow.sol").write_text(
                "pragma solidity ^0.8.20; contract Escrow { function ping() external {} }",
                encoding="utf-8",
            )
            artifact = {
                "contractName": "Escrow",
                "abi": [
                    {
                        "type": "function",
                        "name": "ping",
                        "inputs": [],
                        "outputs": [],
                        "stateMutability": "nonpayable",
                    }
                ],
                "bytecode": "0x6000",
                "deployedBytecode": "0x6000",
            }
            (root / "out" / "EthEscrow.sol" / "Escrow.json").write_text(
                json.dumps(artifact), encoding="utf-8"
            )
            models = lk.walkthrough._artifact_models(root)
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0].name, "Escrow")
        self.assertEqual(models[0].source, "src/EthEscrow.sol")

    def test_walkthrough_accepts_hardhat_style_artifact_layout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "contracts").mkdir()
            (root / "artifacts" / "contracts" / "Vault.sol").mkdir(parents=True)
            (root / "contracts" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { uint256 public value; function ping(uint256 x) external { value=x; } }",
                encoding="utf-8",
            )
            artifact = {
                "_format": "hh-sol-artifact-1",
                "contractName": "Vault",
                "sourceName": "contracts/Vault.sol",
                "abi": [
                    {
                        "type": "function",
                        "name": "ping",
                        "inputs": [{"name": "x", "type": "uint256"}],
                        "outputs": [],
                        "stateMutability": "nonpayable",
                    }
                ],
                "bytecode": "0x6000",
                "deployedBytecode": "0x6000",
            }
            path = root / "artifacts" / "contracts" / "Vault.sol" / "Vault.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            models = lk.walkthrough._artifact_models(root)
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0].name, "Vault")
        self.assertEqual(models[0].source, "contracts/Vault.sol")

    def test_walkthrough_generic_deploy_uses_cast_create_option_order(self):
        model = lk.walkthrough.ContractModel(
            name="Counter",
            source="contracts/Counter.vy",
            artifact=".audit/walkthrough/vyper/Counter.json",
            abi=[],
            kind="vyper",
        )
        actor = lk.walkthrough.Actor("Alice", "0x" + "1" * 40, 0)
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            artifact = root / model.artifact
            artifact.parent.mkdir(parents=True)
            artifact.write_text(json.dumps({
                "bytecode": {"object": "0x60006000556000"},
                "abi": [],
            }), encoding="utf-8")
            calls = []
            def fake_cmd(args, cwd=None, timeout=30):
                calls.append(args)
                return 0, "Transaction hash: " + "0x" + "2" * 64, ""
            with patch.object(lk.walkthrough, "_cmd", side_effect=fake_cmd),                  patch.object(lk.walkthrough, "_actor_rpc_setup"),                  patch.object(
                     lk.walkthrough, "_receipt",
                     return_value={"contractAddress": "0x" + "3" * 40},
                 ):
                address, reason = lk.walkthrough._deploy_generic_local_target(
                    root, "http://127.0.0.1:8545", model, [actor]
                )
        self.assertEqual(address, "0x" + "3" * 40)
        self.assertIsNone(reason)
        self.assertEqual(calls[0][0:2], ["cast", "send"])
        self.assertIn("--create", calls[0])
        self.assertLess(calls[0].index("--rpc-url"), calls[0].index("--create"))
        self.assertLess(calls[0].index("--create"), calls[0].index("0x60006000556000"))

    def test_generic_lab_never_promotes_cast_sender_as_deployment_target(self):
        sender = "0x" + "1" * 40
        deployed = "0x" + "3" * 40
        tx_hash = "0x" + "2" * 64

        artifact = {
            "contractName": "Fallback",
            "abi": [],
            "bytecode": {"object": "0x6000"},
        }

        completed = subprocess.CompletedProcess(
            ["cast", "send"],
            0,
            stdout=f"transactionHash: {tx_hash}\nfrom: {sender}\n",
            stderr="",
        )

        def fake_cast(args):
            if args[:2] == ["cast", "receipt"]:
                return 0, json.dumps({"contractAddress": deployed}), ""
            if args[:2] == ["cast", "code"]:
                address = args[2]
                return (0, "0x6000", "") if address.lower() == deployed.lower() else (0, "0x", "")
            return 1, "", "unexpected cast call"

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with patch.object(lk.subprocess, "run", return_value=completed), \
                 patch.object(lk, "cast_output", side_effect=fake_cast):
                address, reason = lk._deploy_artifact_locally(
                    {}, root, "http://127.0.0.1:8545",
                    [sender], artifact, [],
                )

        self.assertEqual(address, deployed)
        self.assertIsNone(reason)

    def test_walkthrough_vyper_replay_is_not_solidity_script(self):
        model = lk.walkthrough.ContractModel(
            name="Counter",
            source="contracts/Counter.vy",
            artifact=".audit/walkthrough/vyper/Counter.json",
            abi=[{
                "type": "function",
                "name": "increment",
                "inputs": [{"name": "value", "type": "uint256"}],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
            functions=["increment(uint256)"],
            kind="vyper",
        )
        step = lk.walkthrough.Step(
            1, "Alice", model.name, "0x" + "1" * 40,
            "increment(uint256)", [1], status="success",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            path = lk.walkthrough._generate_replay_script(
                root, model, step.address, [step]
            )
            self.assertTrue(path.name.endswith(".sh"))
            content = path.read_text(encoding="utf-8")
            self.assertIn('cast send "$TARGET"', content)
            self.assertIn("increment(uint256)", content)

    def test_walkthrough_infers_payable_value_from_msg_value_equality(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir(parents=True)
            source = src / "Vault.sol"
            source.write_text(
                "pragma solidity ^0.8.20;\\n"
                "contract Vault {\\n"
                "    function deposit(uint256 amount) external payable {\\n"
                "        require(amount == msg.value, 'attach eth');\\n"
                "    }\\n"
                "}\\n",
                encoding="utf-8",
            )
            model = lk.walkthrough.ContractModel(
                name="Vault",
                source="src/Vault.sol",
                artifact="out/Vault.sol/Vault.json",
                abi=[{
                    "type": "function",
                    "name": "deposit",
                    "inputs": [{"name": "amount", "type": "uint256"}],
                    "outputs": [],
                    "stateMutability": "payable",
                }],
            )
            fn = model.abi[0]
            self.assertEqual(
                lk.walkthrough._value_for(fn, model=model, root=root, args=[10**18]),
                10**18,
            )

    def test_walkthrough_transaction_evidence_is_clickable_and_confirmable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            tx_hash = "0x" + "1" * 64
            step = lk.walkthrough.Step(
                1,
                "Alice",
                "Fixture",
                "0x" + "2" * 40,
                "deposit(uint256)",
                [123],
                value_wei=123,
                status="success",
                tx_hash=tx_hash,
                calldata="0xdeadbeef",
            )
            receipt = {
                "status": "0x1",
                "blockNumber": "0x2a",
                "gasUsed": "0x5208",
            }
            transaction = {
                "hash": tx_hash,
                "from": "0x" + "3" * 40,
                "to": step.address,
                "value": hex(123),
                "nonce": "0x1",
                "gas": "0x100000",
                "input": "0xdeadbeef",
                "blockNumber": "0x2a",
            }
            with patch.object(lk.walkthrough, "_rpc_call", return_value=transaction):
                page = lk.walkthrough._write_transaction_evidence(
                    root, "http://127.0.0.1:8545", step, receipt
                )
            self.assertIsNotNone(page)
            self.assertTrue(pathlib.Path(page).is_file())
            content = pathlib.Path(page).read_text(encoding="utf-8")
            self.assertIn(tx_hash, content)
            self.assertIn("CONFIRMED / SUCCESS", content)
            self.assertIn("cast tx " + tx_hash, content)
            link = lk.walkthrough._transaction_link(root, tx_hash)
            self.assertIn("\x1b]8;;file://", link)
            self.assertIn("transactions/" + tx_hash + ".html", link)

    def test_walkthrough_empty_revert_explains_contract_argument(self):
        model = lk.walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[{
                "type": "function",
                "name": "create",
                "inputs": [{"name": "agreement", "type": "address"}],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
            calls=[{
                "kind": "cross-contract",
                "from": "create",
                "to_contract": "IAgreement",
                "to_function": "owner()",
                "via": "agreement",
                "interface": "IAgreement",
            }],
        )
        agreement = "0x" + "2" * 40
        step = lk.walkthrough.Step(
            1, "Alice", "Factory", "0x" + "3" * 40,
            "create(address)", [agreement],
        )
        with patch.object(lk.walkthrough, "_runtime_code", return_value="0x"):
            origin, diagnostics = lk.walkthrough._diagnose_argument_contracts(
                "http://127.0.0.1:8545", step, model
            )
        self.assertIsNotNone(origin)
        self.assertTrue(any("no contract code" in item for item in diagnostics))

    def test_walkthrough_function_story_keeps_function_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir(parents=True)
            source = src / "Factory.sol"
            source.write_text(
                "pragma solidity ^0.8.20;\ncontract Factory {\n    function create(address) external {}\n}\n",
                encoding="utf-8",
            )
            model = lk.walkthrough.ContractModel(
                name="Factory",
                source="src/Factory.sol",
                artifact="out/Factory.sol/Factory.json",
                abi=[{
                    "type": "function",
                    "name": "create",
                    "inputs": [{"name": "recipient", "type": "address"}],
                    "outputs": [],
                }],
                function_locations={"create": 3},
            )
            step = lk.walkthrough.Step(
                1, "Alice", "Factory", "0x" + "1" * 40,
                "create(address)", ["0x" + "2" * 40],
            )
            rendered = lk.walkthrough._render_interaction_graph_full(
                root, step,
                [lk.walkthrough.Actor("Alice", "0x" + "2" * 40, 0)],
                model, [model], False,
            )
            self.assertIn("create(Alice)", rendered)
            self.assertIn("\x1b]8;;", rendered)

    def test_walkthrough_source_target_uses_vscode_when_editor_is_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault {}", encoding="utf-8")
            with patch.dict(os.environ, {"LOWKEY_EDITOR_LINK": "vscode"}, clear=False):
                target = lk.walkthrough._source_target(root, "src/Vault.sol", 12)
            self.assertTrue(target.startswith("vscode://file/"))
            self.assertTrue(target.endswith(":12"))

    def test_walkthrough_source_target_file_fallback_is_portable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Vault With Space.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault {}", encoding="utf-8")
            with patch.dict(os.environ, {"LOWKEY_EDITOR_LINK": "file"}, clear=False):
                target = lk.walkthrough._source_target(root, "src/Vault With Space.sol", 12)
            self.assertTrue(target.startswith("file://"))
            self.assertIn("Vault%20With%20Space.sol", target)
            self.assertNotIn("#L12", target)

    def test_parse_lab_system(self):
        output = "\n".join([
            "LOWKEY_TARGET 0x" + "1" * 40,
            "LOWKEY_FACTORY 0x" + "2" * 40,
            "LOWKEY_STAKE_TOKEN: 0x" + "3" * 40,
            "LOWKEY_BOB 0x" + "4" * 40,
        ])
        parsed = lk.parse_lab_system(output)
        self.assertEqual(parsed["factory"], "0x" + "2" * 40)
        self.assertEqual(parsed["stake_token"], "0x" + "3" * 40)
        self.assertEqual(parsed["bob"], "0x" + "4" * 40)

    def test_walkthrough_human_action_describes_asset_flow(self):
        step = lk.walkthrough.Step(
            1, "Alice", "ConfidencePool", "0x" + "1" * 40,
            "stake(uint256)", [10**18],
        )
        lines = lk.walkthrough._friendly_action(
            step,
            [lk.walkthrough.Actor("Alice", "0x" + "2" * 40, 0)],
        )
        rendered = "\n".join(lines)
        self.assertIn("Alice", rendered)
        self.assertIn("token flow", rendered)
        self.assertIn("ConfidencePool", rendered)

    def test_walkthrough_story_connects_steps_vertically(self):
        steps = [
            lk.walkthrough.Step(1, "Alice", "ConfidencePool", "0x" + "1" * 40,
                                "stake(uint256)", [1], status="success"),
            lk.walkthrough.Step(2, "Bob", "ConfidencePool", "0x" + "1" * 40,
                                "withdraw()", [], status="blocked", error="Not ready"),
        ]
        rendered = lk.walkthrough._render_protocol_story(
            pathlib.Path.cwd(),
            steps, steps[-1],
            [lk.walkthrough.Actor("Alice", "0x" + "2" * 40, 0),
             lk.walkthrough.Actor("Bob", "0x" + "3" * 40, 1)],
            [],
            False,
        )
        self.assertIn("FUNCTION 01", rendered)
        self.assertIn("FUNCTION 02", rendered)
        self.assertIn("▼", rendered)
        self.assertIn("token flow", rendered)
        self.assertIn("Not ready", rendered)

    def test_walkthrough_decodes_project_custom_error(self):
        model = lk.walkthrough.ContractModel(
            name="ConfidencePoolFactory",
            source="src/ConfidencePoolFactory.sol",
            artifact="out/ConfidencePoolFactory.sol/ConfidencePoolFactory.json",
            abi=[{
                "type": "error",
                "name": "StakeTokenNotAllowed",
                "inputs": [],
            }],
        )
        with patch.object(lk.walkthrough, "_cmd", return_value=(0, "0x5e0ff495", "")):
            decoded = lk.walkthrough._decode_custom_error(
                'server returned error data: "0x5e0ff495"', [model]
            )
        self.assertEqual(decoded, "StakeTokenNotAllowed()")

    def test_walkthrough_uninitialized_initializer_is_rejected(self):
        model = lk.walkthrough.ContractModel(
            name="ConfidencePoolFactory",
            source="src/ConfidencePoolFactory.sol",
            artifact="out/ConfidencePoolFactory.sol/ConfidencePoolFactory.json",
            abi=[
                {
                    "type": "function",
                    "name": "initialize",
                    "stateMutability": "nonpayable",
                    "inputs": [],
                    "outputs": [],
                },
                {
                    "type": "function",
                    "name": "owner",
                    "stateMutability": "view",
                    "inputs": [],
                    "outputs": [{"type": "address"}],
                },
                {
                    "type": "function",
                    "name": "safeHarborRegistry",
                    "stateMutability": "view",
                    "inputs": [],
                    "outputs": [{"type": "address"}],
                },
            ],
        )
        zero = "0x" + "0" * 40
        with patch.object(lk.walkthrough, "_runtime_code", return_value="0x6001"), \
             patch.object(lk.walkthrough, "_artifact_runtime_code", return_value="0x6002"), \
             patch.object(lk.walkthrough, "_cmd", return_value=(0, zero, "")):
            ok, reason = lk.walkthrough._target_is_live_instance(
                pathlib.Path("/tmp"), "http://127.0.0.1:8545", "0x" + "1" * 40, model
            )
        self.assertFalse(ok)
        self.assertIn("unset", reason)

    def test_walkthrough_interface_maps_to_concrete_first_party_implementation(self):
        pool = lk.walkthrough.ContractModel(
            name="ConfidencePool",
            source="src/ConfidencePool.sol",
            artifact="out/ConfidencePool.sol/ConfidencePool.json",
            bases=["IConfidencePool"],
            imports=["src/interfaces/IConfidencePool.sol"],
        )
        factory = lk.walkthrough.ContractModel(
            name="ConfidencePoolFactory",
            source="src/ConfidencePoolFactory.sol",
            artifact="out/ConfidencePoolFactory.sol/ConfidencePoolFactory.json",
            bases=["IConfidencePoolFactory"],
            imports=["src/interfaces/IConfidencePoolFactory.sol", "src/interfaces/IConfidencePool.sol"],
        )
        mapping = lk.walkthrough._implementation_mapping([pool, factory])
        self.assertEqual(mapping["IConfidencePool"], "ConfidencePool")

    def test_walkthrough_create_pool_story_explains_protocol_flow(self):
        step = lk.walkthrough.Step(
            1,
            "Alice",
            "ConfidencePoolFactory",
            "0x" + "1" * 40,
            "createPool(address,address,uint256,uint256,address,address[])",
            ["0x" + "2" * 40, "0x" + "3" * 40, 123, 10**18, "0x" + "4" * 40, ["0x" + "2" * 40]],
        )
        actor_list = [
            lk.walkthrough.Actor("Alice", "0x" + "2" * 40, 0),
            lk.walkthrough.Actor("Bob", "0x" + "3" * 40, 1),
        ]
        rendered = "\n".join(lk.walkthrough._friendly_action(step, actor_list))
        self.assertIn("factory checks", rendered)
        self.assertIn("child pool", rendered)
        self.assertIn("initialized", rendered)

    def test_walkthrough_function_link_uses_vscode_source_target(self):
        model = lk.walkthrough.ContractModel(
            name="ConfidencePoolFactory",
            source="src/ConfidencePoolFactory.sol",
            artifact="out/ConfidencePoolFactory.sol/ConfidencePoolFactory.json",
            function_locations={"setStakeTokenAllowed": 142},
        )
        step = lk.walkthrough.Step(
            1, "Alice", model.name, "0x" + "1" * 40,
            "setStakeTokenAllowed(address,bool)", ["0x" + "2" * 40, True],
        )
        old = os.environ.get("VSCODE_PID")
        os.environ["VSCODE_PID"] = "1"
        try:
            rendered = lk.walkthrough._render_interaction_graph(
                pathlib.Path("/tmp/project"), step, [], model, [model], False
            )
        finally:
            if old is None:
                os.environ.pop("VSCODE_PID", None)
            else:
                os.environ["VSCODE_PID"] = old
        self.assertIn("vscode://file/", rendered)
        self.assertIn("setStakeTokenAllowed", rendered)

    def test_local_lab_fixture_discovery_prefers_requested_project_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            test_root = root / "test"
            test_root.mkdir(parents=True)
            (test_root / "Other.t.sol").write_text(
                "pragma solidity ^0.8.20; contract OtherTest { function setUp() public {} function createPool() internal returns (address) { return address(0); } }",
                encoding="utf-8",
            )
            (test_root / "Target.t.sol").write_text(
                "pragma solidity ^0.8.20; contract TargetHarness { function setUp() public {} function createPool() internal returns (address) { return address(0); } }",
                encoding="utf-8",
            )
            fixture = lk.discover_local_lab_fixture(root, "TargetHarness")
            self.assertIsNotNone(fixture)
            self.assertEqual(fixture["contract"], "TargetHarness")

    def test_bootstrap_does_not_reuse_saved_target_without_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "out" / "ConfidencePool.sol").mkdir(parents=True)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\n',
                encoding="utf-8",
            )
            source = root / "src" / "ConfidencePool.sol"
            source.write_text(
                "pragma solidity ^0.8.20; contract ConfidencePool { function initialize() external {} }",
                encoding="utf-8",
            )
            artifact = root / "out" / "ConfidencePool.sol" / "ConfidencePool.json"
            artifact.write_text(
                json.dumps({
                    "contractName": "ConfidencePool",
                    "sourceName": "src/ConfidencePool.sol",
                    "abi": [{
                        "type": "function", "name": "initialize",
                        "stateMutability": "nonpayable", "inputs": [], "outputs": []
                    }],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )

            address = "0x" + "a" * 40
            lk.audit_context.set_target(
                root,
                address=address,
                contract="ConfidencePool",
                artifact=str(artifact),
                source="project-lab",
            )
            config = {
                "target": address,
                "target_contract": "ConfidencePool",
                "rpc": None,
                "aliases": {},
                "targets": {},
                "abi_paths": {},
            }

            with patch.object(lk, "discover_audit_target_contract", return_value="ConfidencePool"),                  patch.object(lk, "_live_target_candidate", return_value=None),                  patch.object(lk, "discover_deployments", return_value=[]),                  patch.object(lk, "run_lab", return_value=0) as run_lab:
                result = lk._bootstrap_audit_target(config, root, allow_deploy=True)

            run_lab.assert_called_once_with(config, [])
            self.assertIsNone(result)

    def test_target_named_deployment_auto_selects_matching_broadcast(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            broadcast=root/"broadcast"
            out=root/"out"/"EthEscrow.s.sol"/"EscrowContract"
            broadcast.mkdir(parents=True)
            out.mkdir(parents=True)
            payload={
                "transactions":[
                    {
                        "transactionType":"CREATE",
                        "contractName":"Escrow",
                        "contractAddress":"0x"+"e"*40,
                        "hash":"0x"+"1"*64,
                    }
                ]
            }
            (broadcast/"EthEscrow.s.sol"/"31337").mkdir(parents=True)
            (broadcast/"EthEscrow.s.sol"/"31337"/"run-latest.json").write_text(json.dumps(payload),encoding="utf-8")
            artifact={"contractName":"Escrow","abi":[]}
            artifact_path=out/"Escrow.json"
            artifact_path.write_text(json.dumps(artifact),encoding="utf-8")
            old=os.getcwd()
            os.chdir(root)
            try:
                config={"target":None,"aliases":{},"targets":{},"abi_paths":{},"rpc":None}
                with patch.object(lk,"save_config"):
                    output=io.StringIO()
                    with redirect_stdout(output):
                        result=lk.run_auto_target(config,"escrow")
            finally:
                os.chdir(old)
        self.assertEqual(result,0)
        self.assertEqual(config["target"],"0x"+"e"*40)
        self.assertEqual(config["aliases"]["escrow"],"0x"+"e"*40)
        self.assertEqual(config["target_contract"],"Escrow")
        self.assertIn("Target selected: escrow ->",output.getvalue())

    def test_target_named_deployment_missing_is_error(self):
        with patch.object(
            lk,
            "discover_deployments",
            return_value=[{"contract":"Escrow","address":"0x"+"e"*40}],
        ):
            config={"aliases":{},"targets":{},"abi_paths":{}}
            with patch.object(lk,"save_config"):
                self.assertEqual(lk.run_auto_target(config,"Missing"),2)


    def test_secret_redaction(self):
        key = "0x" + "a" * 64
        redacted = lk.redact_secrets("--private-key " + key)
        self.assertIn("<redacted>", redacted)
        self.assertNotIn(key, redacted)
        self.assertIn("<redacted>", lk.redact_secrets("--jwt-secret supersecret"))

    def test_rpc_redaction(self):
        value = lk.redact_secrets("--rpc-url https://example.com/sensitive-token")
        self.assertNotIn("sensitive-token", value)
        self.assertIn("<redacted>", value)

    def test_eth_humanization(self):
        self.assertIn("1.0000 ETH", lk.humanize_value("1000000000000000000", assume_wei=True))

    def test_private_key_normalization(self):
        raw = "b" * 64
        self.assertEqual(lk.normalize_private_key(raw), "0x" + raw)
        self.assertIsNone(lk.normalize_private_key("bad-key"))

    def test_audit_delegates_to_single_presenter_without_implicit_checks(self):
        config = {}
        captured = {}

        def fake_audit(args):
            captured["args"] = args
            print("LOWKEY CONNECTED AUDIT")
            return 0

        with patch.object(lk, "_sync_audit_context"), patch("forge_tools.run_audit", side_effect=fake_audit):
            output = io.StringIO()
            with redirect_stdout(output):
                result = lk.run_audit(config, [])

        self.assertEqual(result, 0)
        self.assertEqual(captured["args"], [])
        self.assertEqual(output.getvalue().count("LOWKEY CONNECTED AUDIT"), 1)

    def test_audit_preserves_explicit_checks(self):
        config = {}
        captured = {}

        def fake_audit(args):
            captured["args"] = args
            return 0

        with patch.object(lk, "_sync_audit_context"), patch("forge_tools.run_audit", side_effect=fake_audit):
            self.assertEqual(lk.run_audit(config, ["--checks"]), 0)

        self.assertEqual(captured["args"], ["--checks"])
    def test_compact_audit_checks_dispatch(self):
        config = {"target": None}
        with patch.object(lk, "run_audit_mode", return_value=0) as runner:
            result = lk.dispatch_command("audit--checks", [], config)
        self.assertEqual(result, 0)
        runner.assert_called_once_with(config, ["--checks"])

    def test_version_reports_runtime_state(self):
        with patch.object(
            lk,
            "runtime_sync_status",
            return_value={
                "status": "ok",
                "detail": "installed runtime abc123",
                "source_repo": "/tmp/lowkey",
            },
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                lk.run_version()
        rendered = output.getvalue()
        self.assertIn("LowkeyCast 2.1", rendered)
        self.assertIn("Runtime: OK", rendered)
        self.assertIn("installed runtime abc123", rendered)

    def test_runtime_fixes(self):
        self.assertTrue(hasattr(lk, "Path"))
        self.assertTrue(lk.AUDIT_CHECKLIST)

    def test_source_checkout_execution_ignores_installed_runtime_mismatch(self):
        with patch.object(
            lk,
            "runtime_sync_status",
            return_value={
                "status": "stale",
                "detail": "installed runtime old",
                "source_repo": str(ROOT),
            },
        ), patch.object(lk, "dispatch_command", return_value=0),              patch.object(lk, "_sync_audit_context"),              patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path(".")),              patch.object(lk.audit_context, "emit"):
            original_argv = lk.sys.argv
            lk.sys.argv = ["lk", "fn", "buyNft"]
            try:
                with self.assertRaises(SystemExit) as raised:
                    lk.main()
            finally:
                lk.sys.argv = original_argv
        self.assertEqual(raised.exception.code, 0)

    def test_mapping_human_view_decodes_struct_fields(self):
        target = "0x" + "1" * 40
        alice = "0x" + "2" * 40
        bob = "0x" + "3" * 40
        mapped_slot = "0x" + "ab" * 32
        types = {
            "t_mapping": {
                "encoding": "mapping",
                "key": "t_uint256",
                "value": "t_struct",
            },
            "t_uint256": {
                "label": "uint256",
                "encoding": "inplace",
                "numberOfBytes": "32",
            },
            "t_address": {
                "label": "address",
                "encoding": "inplace",
                "numberOfBytes": "20",
            },
            "t_struct": {
                "label": "struct Escrow.Create",
                "members": [
                    {"label": "creator", "slot": "0", "offset": 0, "type": "t_address"},
                    {"label": "recipient", "slot": "1", "offset": 0, "type": "t_address"},
                    {"label": "amount", "slot": "2", "offset": 0, "type": "t_uint256"},
                ],
            },
        }
        storage = [{"label": "escrow", "slot": "1", "type": "t_mapping"}]
        config = {
            "target": target,
            "wallets": {
                "Alice": {"address": alice},
                "Bob": {"address": bob},
            },
        }

        def word(address):
            return "0x" + "0" * 24 + address[2:]

        reads = [
            lk.CommandResult(word(alice), 0),
            lk.CommandResult(word(bob), 0),
            lk.CommandResult("0x" + format(10**18, "064x"), 0),
        ]
        output = io.StringIO()
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)),              patch.object(lk, "run_cast", side_effect=reads):
            with redirect_stdout(output):
                result = lk.run_mapping_human_view(
                    config, "1", "uint256", "1", mapped_slot
                )

        self.assertTrue(result)
        rendered = output.getvalue()
        self.assertIn("Mapping:      escrow", rendered)
        self.assertIn("Key:          1", rendered)
        self.assertIn("creator", rendered)
        self.assertIn("Alice (0x" + "2" * 40 + ")", rendered)
        self.assertIn("Bob (0x" + "3" * 40 + ")", rendered)
        self.assertIn("1000000000000000000 wei [~1.0000 ETH]", rendered)
        self.assertIn("raw mapping slot", rendered)

    def test_local_cast_commands_do_not_receive_rpc_url(self):
        config = {"rpc": "http://127.0.0.1:8545"}
        expected_commands = [
            ["index", "uint256", "1", "1"],
            ["selectors", "0x6000"],
            ["constructor-args", "0x" + "1" * 40],
            ["creation-code", "0x" + "1" * 40],
        ]
        for args in expected_commands:
            with self.subTest(command=args[0]), patch.object(
                lk, "cast_output", return_value=(0, "0x" + "0" * 64, "")
            ) as cast_output:
                result = lk.run_cast(args, config, capture=True)
            self.assertEqual(result.code, 0)
            actual = cast_output.call_args.args[0]
            self.assertEqual(actual[:len(args)+1], ["cast", *args])
            self.assertNotIn("--rpc-url", actual)

    def test_mapping_rejects_failed_slot_calculation(self):
        target = "0x" + "1" * 40
        config = {"target": target}
        failure = lk.CommandResult(
            "error: unexpected argument '--rpc-url' found", 1
        )
        with patch.object(lk, "run_cast", return_value=failure) as run_cast:
            result = lk.run_mapping(config, "uint256", "1", "1")
        self.assertEqual(result, 2)
        run_cast.assert_called_once_with(
            ["index", "uint256", "1", "1"], config, capture=True
        )

    def test_mapping_reads_computed_slot_only_after_success(self):
        target = "0x" + "1" * 40
        config = {"target": target}
        slot = "0x" + "ab" * 32
        with patch.object(
            lk,
            "run_cast",
            side_effect=[lk.CommandResult(slot, 0), 0],
        ) as run_cast:
            result = lk.run_mapping(config, "uint256", "1", "1")
        self.assertEqual(result, 0)
        self.assertEqual(run_cast.call_args_list[0].args[0], ["index", "uint256", "1", "1"])
        self.assertEqual(run_cast.call_args_list[0].args[1]["target"], target)
        self.assertEqual(
            run_cast.call_args_list[1].args[0],
            ["st", slot],
        )

    def test_creation_name_detection_handles_lowercase_names(self):
        self.assertTrue(lk._creation_function_name("createescrow"))
        self.assertTrue(lk._creation_function_name("createEscrow"))
        self.assertTrue(lk._creation_function_name("registerPool"))
        self.assertFalse(lk._creation_function_name("withdraw"))

    def test_read_recovers_from_cast_fixed_bytes_error(self):
        target = "0x" + "1" * 40
        identifier = "0x" + "a" * 64
        item = {
            "type": "function",
            "name": "escrow",
            "inputs": [{"name": "id", "type": "bytes32"}],
            "outputs": [{"name": "result", "type": "bytes32"}],
            "stateMutability": "view",
        }
        encoded = "0x1234"
        config = {"target": target, "target_contract": "Escrow", "wallets": {}, "labels": {}}
        patches = [
            patch.object(lk, "load_abi", return_value=[item]),
            patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"),
            patch.object(
                lk,
                "cast_output",
                side_effect=[
                    (1, "", "parser error: invalid string length"),
                    (0, encoded, ""),
                ],
            ),
            patch.object(lk, "rpc_json", return_value="0x" + "00" * 32),
            patch.object(lk, "decode_abi_output", return_value=(identifier, None)),
        ]
        output = io.StringIO()
        with patches[0], patches[1], patches[2] as cast_output, patches[3] as rpc_json, patches[4], redirect_stdout(output):
            result = lk.run_cast(["call", "escrow", identifier], config)

        self.assertEqual(result, 0)
        self.assertEqual(cast_output.call_args_list[1].args[0], [
            "cast", "calldata", "escrow(bytes32)", identifier,
        ])
        rpc_json.assert_called_once_with(
            "http://127.0.0.1:8545",
            "eth_call",
            [{"to": target, "data": encoded}, "latest"],
        )
        self.assertIn("Returns:", output.getvalue())

    def test_receipt_uses_async(self):
        tx_hash = "0x" + "1" * 64
        config = {"last_tx": tx_hash}
        with patch.object(lk, "run_cast") as run_cast:
            with patch.object(lk, "audit_context") as audit_context:
                lk.run_receipt(config)
            run_cast.assert_called_once()
            call_args = run_cast.call_args.args
            self.assertEqual(call_args[0], ["receipt", tx_hash, "--async"])
            self.assertEqual(call_args[1], {"last_tx": tx_hash})
            self.assertIsNot(call_args[1], config)
            audit_context.set_latest.assert_called_once()
            audit_context.record_tool.assert_called_once()

    def test_scan_records_source_triage_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "X.sol"
            source.write_text(
                'contract X { function f() external { (bool ok,) = msg.sender.call{value: 1}(""); require(ok); } }',
                encoding="utf-8",
            )
            with patch.object(lk, "audit_context") as ctx:
                lk.run_scan([str(root)])
            ctx.foundry_project_root.assert_called_once()
            ctx.record_tool.assert_called_once()
            self.assertEqual(ctx.record_tool.call_args.args[0], "source-triage")

    def test_scan_smoke(self):
        source = "contract X { function f() external { (bool ok,) = msg.sender.call{value: 1}(\"\"); require(ok); } function g() external { address a = tx.origin; } }"
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "X.sol"
            path.write_text(source, encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                lk.run_scan([tmp])
            self.assertIn("REENTRANCY REVIEW", output.getvalue())
            self.assertIn("TX.ORIGIN", output.getvalue())

    def test_event_command_does_not_use_topics_flag(self):
        with patch.object(lk, "cast_output", return_value=(0, "decoded", "")) as cast_output:
            result = lk.run_event({}, ["Transfer(address,address,uint256)", "0x", "0x01"])
            self.assertEqual(result, 0)
            cast_output.assert_called_once_with([
                "cast", "decode-event", "--sig",
                "Transfer(address,address,uint256)", "0x01"
            ])

    def test_event_failure_returns_nonzero(self):
        with patch.object(lk, "cast_output", return_value=(1, "", "decode failed")):
            self.assertEqual(lk.run_event({}, ["Transfer(address,address,uint256)", "0xdeadbeef"]), 1)

    def test_event_success(self):
        output=io.StringIO()
        with patch.object(lk, "cast_output", return_value=(0, "42", "")):
            with redirect_stdout(output):
                result=lk.run_event(
                    {},
                    [
                        "Ping(uint256)",
                        "0x000000000000000000000000000000000000000000000000000000000000002a",
                    ],
                )
        self.assertEqual(result, 0)
        self.assertIn("42", output.getvalue())

    def test_indexed_event_decoding_uses_abi_topics(self):
        event = {
            "type": "event",
            "name": "Transfer",
            "inputs": [
                {"name": "from", "type": "address", "indexed": True},
                {"name": "to", "type": "address", "indexed": True},
                {"name": "amount", "type": "uint256", "indexed": False},
            ],
        }
        topic0 = "0x" + "a" * 64
        topics = [topic0, "0x" + "0" * 24 + "1" * 40, "0x" + "0" * 24 + "2" * 40]

        def cast_result(args, input_text=None):
            if args[1] == "sig-event":
                return 0, topic0, ""
            return 0, "42", ""

        with tempfile.TemporaryDirectory() as tmp:
            abi_path = pathlib.Path(tmp) / "abi.json"
            abi_path.write_text(json.dumps({"abi": [event]}), encoding="utf-8")
            output = io.StringIO()
            with patch.object(lk, "cast_output", side_effect=cast_result):
                with redirect_stdout(output):
                    result = lk.run_event(
                        {"target": "target", "abi_paths": {"target": str(abi_path)}},
                        ["Transfer(address,address,uint256)", "0x" , *topics],
                    )
        self.assertEqual(result, 0)
        self.assertIn("Indexed from", output.getvalue())
        self.assertIn("Data: 42", output.getvalue())

    def test_anvil_detection(self):
        address = "0x" + "1" * 40
        with patch.object(lk, "local_port_open", return_value=True):
            with patch.object(
                lk,
                "rpc_json",
                side_effect=["anvil/v1.8.1", [address]],
            ):
                info = lk.detect_anvil_rpc(None)
        self.assertEqual(info["url"], "http://127.0.0.1:8545")
        self.assertEqual(info["accounts"], [address])

    def test_effective_rpc_auto_detects_anvil(self):
        address="0x"+"1"*40
        info={"url":"http://127.0.0.1:8545","client":"anvil/v1.8.1","accounts":[address]}
        config={"rpc":None}
        with patch.object(lk, "detect_anvil_rpc", return_value=info):
            self.assertEqual(lk.effective_rpc(config), "http://127.0.0.1:8545")
            self.assertEqual(config["_auto_rpc_info"], info)

    def test_default_anvil_actor_selection_and_unique_assignment(self):
        address0 = "0x" + "1" * 40
        address1 = "0x" + "2" * 40
        config = {"wallets": {}, "actor": None}
        info = {"url": "http://127.0.0.1:8545", "accounts": [address0, address1]}
        with patch.object(lk, "detect_anvil_rpc", return_value=info),              patch.object(lk, "save_config"):
            self.assertEqual(lk.select_anvil_actor(config, 0, "Alice"), 2)
            self.assertEqual(lk.select_anvil_actor(config, 1, "Alice"), 0)
            self.assertEqual(config["actor"], "Alice")
            self.assertEqual(config["wallets"]["Alice"]["anvil_index"], 1)
            self.assertEqual(lk.select_anvil_actor(config, 1, "Bob"), 2)

    def test_actor_index_without_name_selects_existing_profile(self):
        address0 = "0x" + "1" * 40
        address1 = "0x" + "2" * 40
        config = {
            "actor": None,
            "wallets": {
                "lab-deployer": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": address0,
                    "internal": True,
                },
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 1,
                    "address": address1,
                },
            },
            "labels": {address1: "Alice"},
        }
        info = {"url": "http://127.0.0.1:8545", "accounts": [address0, address1]}
        with patch.object(lk, "anvil_rpc_info", return_value=info), patch.object(lk, "save_config"):
            self.assertEqual(lk.select_existing_anvil_actor(config, 0), 0)
            self.assertEqual(config["actor"], "lab-deployer")
            self.assertEqual(lk.select_existing_anvil_actor(config, 1), 0)
            self.assertEqual(config["actor"], "Alice")

    def test_unassigned_actor_rows_are_not_marked_active(self):
        address0 = "0x" + "1" * 40
        address1 = "0x" + "2" * 40
        config = {"actor": None, "wallets": {}, "labels": {}}
        info = {"url": "http://127.0.0.1:8545", "accounts": [address0, address1]}
        with patch.object(lk, "anvil_rpc_info", return_value=info), patch.object(lk, "save_config"), patch("builtins.print") as printed:
            lk.list_anvil_actors(config)
        lines = [call.args[0] for call in printed.call_args_list if call.args]
        account_lines = [str(line) for line in lines if str(address0) in str(line) or str(address1) in str(line)]
        self.assertTrue(account_lines)
        self.assertTrue(all(not line.lstrip().startswith("*") for line in account_lines))

    def test_anvil_actor_key_is_not_stored(self):
        address="0x"+"1"*40
        config={
            "wallets":{
                "Alice":{
                    "source":"anvil-default",
                    "anvil_index":1,
                    "address":address,
                }
            },
            "actor":"Alice",
        }
        info={"url":"http://127.0.0.1:8545","accounts":["0x"+"0"*40, address]}
        with patch.object(lk, "anvil_rpc_info", return_value=info),              patch.object(lk, "derive_default_anvil_key", return_value="0x"+"b"*64),              patch.object(lk, "cast_output", return_value=(0, address, "")):
            self.assertEqual(lk.resolve_wallet_key(config), "0x"+"b"*64)
        self.assertNotIn("private_key", config["wallets"]["Alice"])

    def test_stale_anvil_actor_is_rebound_to_current_account(self):
        recorded="0x"+"1"*40
        actual="0x"+"2"*40
        key="0x"+"b"*64
        config={
            "wallets":{
                "Alice":{
                    "source":"anvil-default",
                    "anvil_index":1,
                    "address":recorded,
                }
            },
            "actor":"Alice",
            "labels":{recorded:"Alice"},
        }
        info={"url":"http://127.0.0.1:8545","accounts":["0x"+"0"*40, actual]}
        with patch.object(lk, "anvil_rpc_info", return_value=info),              patch.object(lk, "derive_default_anvil_key", return_value=key),              patch.object(lk, "cast_output", return_value=(0, actual, "")),              patch.object(lk, "save_config") as save_config:
            self.assertEqual(lk.resolve_wallet_key(config), key)

        self.assertEqual(config["wallets"]["Alice"]["address"], actual)
        self.assertNotIn(recorded, config["labels"])
        self.assertEqual(config["labels"][actual], "Alice")
        save_config.assert_called_once()

    def test_stale_internal_anvil_actor_is_rebound_without_public_label(self):
        recorded="0x"+"1"*40
        actual="0x"+"2"*40
        key="0x"+"b"*64
        config={
            "wallets":{
                "lab-deployer":{
                    "source":"anvil-default",
                    "anvil_index":0,
                    "address":recorded,
                    "internal":True,
                }
            },
            "actor":"lab-deployer",
            "labels":{recorded:"lab-deployer"},
        }
        info={"url":"http://127.0.0.1:8545","accounts":[actual]}
        with patch.object(lk, "anvil_rpc_info", return_value=info),              patch.object(lk, "derive_default_anvil_key", return_value=key),              patch.object(lk, "cast_output", return_value=(0, actual, "")),              patch.object(lk, "save_config") as save_config:
            self.assertEqual(lk.resolve_wallet_key(config), key)

        self.assertEqual(config["wallets"]["lab-deployer"]["address"], actual)
        self.assertNotIn(recorded, config["labels"])
        self.assertNotIn(actual, config["labels"])
        save_config.assert_called_once()

    def test_status_repairs_stale_anvil_actor_before_display(self):
        recorded="0x"+"1"*40
        actual="0x"+"2"*40
        config={
            "wallets":{
                "lab-deployer":{
                    "source":"anvil-default",
                    "anvil_index":0,
                    "address":recorded,
                    "internal":True,
                }
            },
            "actor":"lab-deployer",
            "target":None,
            "rpc":None,
            "labels":{recorded:"lab-deployer"},
        }
        info={"url":"http://127.0.0.1:8545","accounts":[actual]}
        with patch.object(lk, "effective_rpc", return_value=info["url"]), \
             patch.object(lk, "anvil_rpc_info", return_value=info), \
             patch.object(lk, "save_config"), \
             patch.object(lk, "_sync_security_patterns"), \
             patch.object(lk, "_security_pattern_summary", return_value={"total":0,"reviews":0,"confirmed":0,"candidates":0}), \
             patch("builtins.print") as printed:
            result=lk.run_status(config)

        self.assertIsNone(result)
        rendered="\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn(actual, rendered)
        self.assertNotIn(recorded, rendered)

    def test_actor_listing_repairs_stale_anvil_actor_before_display(self):
        recorded="0x"+"1"*40
        actual="0x"+"2"*40
        config={
            "wallets":{
                "lab-deployer":{
                    "source":"anvil-default",
                    "anvil_index":0,
                    "address":recorded,
                    "internal":True,
                }
            },
            "actor":"lab-deployer",
            "labels":{recorded:"lab-deployer"},
        }
        info={"url":"http://127.0.0.1:8545","accounts":[actual]}
        with patch.object(lk, "anvil_rpc_info", return_value=info), \
             patch.object(lk, "save_config"), \
             patch("builtins.print") as printed:
            result=lk.list_anvil_actors(config)

        self.assertIsNone(result)
        rendered="\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn(actual, rendered)
        self.assertNotIn(recorded, rendered)

    def test_load_abi_auto_from_local_artifact(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "release",
                    "inputs": [],
                    "stateMutability": "nonpayable",
                }
            ],
            "storageLayout": {"storage": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            with patch.object(lk, "local_artifact_paths", return_value=[str(path)]):
                config = {"target_contract": "Escrow", "abi_paths": {}}
                abi = lk.load_abi("0x" + "1" * 40, config)
        self.assertEqual(abi[0]["name"], "release")
        self.assertEqual(
            config["abi_paths"]["0x" + "1" * 40],
            str(path),
        )

    def test_saved_relative_abi_path_resolves_from_outside_project(self):
        target = "0x" + "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            outside = pathlib.Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            out = root / "out"
            out.mkdir()
            artifact_path = out / "Escrow.json"
            artifact_path.write_text(json.dumps({
                "contractName": "Escrow",
                "abi": [{"type": "function", "name": "release", "inputs": [], "stateMutability": "nonpayable"}],
            }), encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {target: "out/Escrow.json"},
                "project_roots": {target: str(root)},
            }
            old = os.getcwd()
            os.chdir(outside)
            try:
                resolved = lk.resolve_abi_path(config, target)
                self.assertEqual(resolved, str(artifact_path.resolve()))
                abi = lk.load_abi(target, config)
            finally:
                os.chdir(old)
        self.assertEqual(abi[0]["name"], "release")

    def test_relative_abi_path_migrates_to_remembered_project_root(self):
        target = "0x" + "2" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            out = root / "out"
            out.mkdir()
            artifact_path = out / "Escrow.json"
            artifact_path.write_text(json.dumps({
                "contractName": "Escrow",
                "abi": [],
            }), encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {target: "out/Escrow.json"},
                "project_roots": {},
            }
            old = os.getcwd()
            os.chdir(root)
            try:
                lk.load_abi(target, config)
            finally:
                os.chdir(old)
        self.assertEqual(config["project_roots"][target], str(root.resolve()))
        self.assertEqual(config["abi_paths"][target], str(artifact_path.resolve()))
        self.assertTrue(config.get("_config_dirty"))

    def test_auto_abi_path_uses_remembered_project_root(self):
        target = "0x" + "3" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            outside = root / "outside"
            outside.mkdir(parents=True)
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            out = root / "out"
            out.mkdir()
            artifact_path = out / "Escrow.json"
            artifact_path.write_text(json.dumps({
                "contractName": "Escrow",
                "abi": [],
            }), encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {},
                "project_roots": {target: str(root)},
            }
            old = os.getcwd()
            os.chdir(outside)
            try:
                with patch.object(lk, "effective_rpc", return_value=None):
                    path = lk.auto_abi_path(target, config)
            finally:
                os.chdir(old)
        self.assertEqual(path, str(artifact_path))
        
    def test_functions_separate_storage_getters(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "release",
                    "inputs": [],
                    "stateMutability": "nonpayable",
                },
                {
                    "type": "function",
                    "name": "balances",
                    "inputs": [{"type": "address"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "escrow",
                    "inputs": [{"type": "uint256"}],
                    "stateMutability": "view",
                },
            ],
            "storageLayout": {
                "storage": [
                    {
                        "label": "balances",
                        "slot": "0",
                        "type": "t_mapping(t_address,t_uint256)",
                    },
                    {
                        "label": "escrow",
                        "slot": "1",
                        "type": "t_mapping(t_uint256,t_struct(Create))",
                    },
                ]
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "Escrow",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            output = io.StringIO()
            with redirect_stdout(output):
                lk.run_functions(config)
        rendered = output.getvalue()
        self.assertIn("WRITE FUNCTIONS:", rendered)
        self.assertIn("STORAGE GETTERS:", rendered)
        self.assertNotIn(
            "balances(address)",
            rendered.split("WRITE FUNCTIONS:", 1)[1]
            .split("STORAGE GETTERS:", 1)[0],
        )

    def test_functions_fallback_to_forge_storage_layout(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "release",
                    "inputs": [],
                    "stateMutability": "nonpayable",
                },
                {
                    "type": "function",
                    "name": "escrow",
                    "inputs": [{"type": "uint256"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "status",
                    "inputs": [],
                    "stateMutability": "view",
                },
            ],
        }
        forge_layout = {
            "storage": [
                {"label": "escrow", "slot": "1", "type": "t_mapping(t_uint256,t_struct(Create))"}
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "Escrow",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            with patch.object(
                lk,
                "cast_output",
                return_value=(0, json.dumps(forge_layout), ""),
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    lk.run_functions(config)
        rendered = output.getvalue()
        self.assertIn("STORAGE GETTERS:", rendered)
        self.assertIn("escrow(uint256)  [public storage getter]", rendered)
        self.assertIn("READ FUNCTIONS:", rendered)
        self.assertIn("status()", rendered)
        self.assertNotIn(
            "escrow(uint256)",
            rendered.split("READ FUNCTIONS:", 1)[1]
            .split("STORAGE GETTERS:", 1)[0],
        )


    def test_functions_use_loaded_artifact_contract_name_for_storage_layout(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "escrow",
                    "inputs": [{"type": "uint256"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "status",
                    "inputs": [],
                    "stateMutability": "view",
                },
            ],
        }
        forge_layout = {
            "storage": [
                {"label": "escrow", "slot": "1", "type": "t_mapping(t_uint256,t_struct(Create))"}
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "StaleContractName",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            with patch.object(
                lk,
                "cast_output",
                return_value=(0, json.dumps(forge_layout), ""),
            ) as cast:
                output = io.StringIO()
                with redirect_stdout(output):
                    lk.run_functions(config)
        self.assertEqual(cast.call_args.args[0][:2], ["forge", "inspect"])
        self.assertEqual(cast.call_args.args[0][2], "Escrow")
        self.assertIn("STORAGE GETTERS:", output.getvalue())
        self.assertIn("escrow(uint256)  [public storage getter]", output.getvalue())

    def test_functions_fallback_to_source_public_storage_names(self):
        artifact = {
            "contractName": "Escrow",
            "abi": [
                {
                    "type": "function",
                    "name": "balances",
                    "inputs": [{"type": "address"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "escrow",
                    "inputs": [{"type": "uint256"}],
                    "stateMutability": "view",
                },
                {
                    "type": "function",
                    "name": "status",
                    "inputs": [],
                    "stateMutability": "view",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "EthEscrow.sol").write_text(
                """
                contract Escrow {
                    mapping(address => uint256) public balances;
                    mapping(uint256 => uint256) public escrow;
                    uint256 public status;
                }
                """,
                encoding="utf-8",
            )
            path = root / "Escrow.json"
            path.write_text(json.dumps(artifact), encoding="utf-8")
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "Escrow",
                "abi_paths": {"0x" + "1" * 40: str(path)},
            }
            old = os.getcwd()
            os.chdir(root)
            try:
                with patch.object(lk, "cast_output", return_value=(1, "", "")):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        lk.run_functions(config)
            finally:
                os.chdir(old)
        rendered = output.getvalue()
        self.assertIn("STORAGE GETTERS:", rendered)
        self.assertIn("balances(address)  [public storage getter]", rendered)
        self.assertIn("escrow(uint256)  [public storage getter]", rendered)
        self.assertIn("status()  [public storage getter]", rendered)



    def test_build_and_test_route_to_native_project_planners(self):
        with patch.object(lk, "detected_project_root", return_value=pathlib.Path("/tmp/demo")), \
             patch.object(lk, "detect_project", return_value={"root": "/tmp/demo", "backend": "cargo", "stacks": ["cargo"]}), \
             patch.object(lk, "project_build_command", return_value=(pathlib.Path("/tmp/demo"), ["cargo", "build"], "Cargo.toml")), \
             patch.object(lk, "project_test_command", return_value=(pathlib.Path("/tmp/demo"), ["cargo", "test"], "Cargo.toml")), \
             patch.object(lk.subprocess, "run", return_value=type("R", (), {"returncode": 0})()):
            self.assertEqual(lk.run_native_project_command({}, "build", []), 0)
            self.assertEqual(lk.run_native_project_command({}, "test", []), 0)

    def test_native_command_without_plan_is_review_needed(self):
        with patch.object(lk, "detected_project_root", return_value=pathlib.Path("/tmp/demo")), \
             patch.object(lk, "detect_project", return_value={"root": "/tmp/demo", "backend": "generic", "stacks": []}), \
             patch.object(lk, "project_build_command", return_value=None):
            self.assertEqual(lk.run_native_project_command({}, "build", []), 2)

    def test_deps_refuses_unselected_multi_project_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            for name in ("alpha", "beta"):
                project = root / "packages" / name
                (project / "src").mkdir(parents=True)
                (project / "src" / "Main.sol").write_text("contract Main {}\n", encoding="utf-8")
                (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            old = os.getcwd()
            try:
                os.chdir(root)
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    code = lk.run_deps([])
            finally:
                os.chdir(old)
            self.assertEqual(code, 2)

    def test_lab_generic_refuses_noninteractive_constructor_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            config = {"_lowkey_active_project_root": str(root)}
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "is_workspace_root", return_value=False), \
                 patch.object(lk, "project_tools", None), \
                 patch.object(lk.sys.stdin, "isatty", return_value=False):
                code = lk.run_lab(config, ["--generic", "Vault"])
            self.assertEqual(code, 2)

    def test_deps_default_project_shows_project_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "script").mkdir()
            (root / "src" / "Escrow.sol").write_text(
                "contract Escrow {}", encoding="utf-8"
            )
            (root / "script" / "Deploy.s.sol").write_text(
                'import "forge-std/Script.sol";\n'
                'import "../src/Escrow.sol";\n'
                'contract Deploy {}',
                encoding="utf-8",
            )
            old = os.getcwd()
            try:
                os.chdir(root)
                output = io.StringIO()
                with redirect_stdout(output):
                    lk.run_deps([])
            finally:
                os.chdir(old)
        self.assertIn(
            "script/Deploy.s.sol -> imports forge-std/Script.sol",
            output.getvalue(),
        )
        self.assertIn(
            "script/Deploy.s.sol -> imports ../src/Escrow.sol",
            output.getvalue(),
        )

    def test_project_map_active_workspace_selection_opens_selected_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            for name in ("app", "shared"):
                nested = root / "packages" / name
                (nested / "src").mkdir(parents=True)
                (nested / "src" / "Main.sol").write_text("contract Main {}\n", encoding="utf-8")
                (nested / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")

            old = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(lk.set_workspace_selection(root, root / "packages" / "app"))
                with patch.object(lk.project_tools, "render_project_map") as render:
                    render.return_value = {"project": {}, "graph": {}, "human": {}}
                    output = io.StringIO()
                    with redirect_stdout(output):
                        result = lk.run_project_map({}, [])
            finally:
                os.chdir(old)

            self.assertEqual(result, 0)
            render.assert_called_once_with((root / "packages" / "app").resolve())

    def test_project_map_does_not_claim_coverage_without_application_units(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            output = io.StringIO()
            with redirect_stdout(output):
                lk.project_tools.render_project_map(root)
            report = output.getvalue()
            self.assertIn("protocol security was not analyzed", report)
            self.assertIn("Dependency resolution was not assessed", report)
            self.assertNotIn("All imports used by analyzed application code were resolved", report)

    def test_project_map_json_mode_emits_only_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            src = root / "src"
            src.mkdir()
            (src / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            old = os.getcwd()
            output = io.StringIO()
            try:
                os.chdir(root)
                with redirect_stdout(output):
                    result = lk.run_project_map({}, ["--json"])
            finally:
                os.chdir(old)
            self.assertEqual(result, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["project"]["root"], str(root))

    def test_project_map_explicit_workspace_project_selector_ignores_active_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            for name in ("app", "shared"):
                nested = root / "packages" / name
                (nested / "src").mkdir(parents=True)
                (nested / "src" / "Main.sol").write_text("contract Main {}\n", encoding="utf-8")
                (nested / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")

            old = os.getcwd()
            try:
                os.chdir(root / "packages")
                self.assertTrue(lk.set_workspace_selection(root, root / "packages" / "app"))
                with patch.object(lk.project_tools, "render_project_map") as render:
                    render.return_value = {"project": {}, "graph": {}, "human": {}}
                    output = io.StringIO()
                    with redirect_stdout(output):
                        result = lk.run_project_map({}, ["2"])
            finally:
                os.chdir(old)

            self.assertEqual(result, 0)
            render.assert_called_once_with((root / "packages" / "shared").resolve())
            self.assertIn("Active project: packages/shared", output.getvalue())

    def test_project_map_from_project_directory_uses_that_project_not_workspace_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            projects = {}
            for name in ("app", "shared"):
                nested = root / "packages" / name
                (nested / "src").mkdir(parents=True)
                (nested / "src" / "Main.sol").write_text("contract Main {}\n", encoding="utf-8")
                (nested / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
                projects[name] = nested

            old = os.getcwd()
            try:
                os.chdir(projects["shared"])
                self.assertTrue(lk.set_workspace_selection(root, projects["app"]))
                with patch.object(lk.project_tools, "render_project_map") as render:
                    render.return_value = {"project": {}, "graph": {}, "human": {}}
                    result = lk.run_project_map({}, [])
            finally:
                os.chdir(old)

            self.assertEqual(result, 0)
            render.assert_called_once_with(projects["shared"].resolve())

    def test_workspace_paths_follow_selected_project_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            selected = root / "packages" / "app"
            selected.mkdir(parents=True)
            (selected / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            old = os.getcwd()
            try:
                os.chdir(root)
                self.assertTrue(lk.set_workspace_selection(root, selected))
                paths = lk.workspace_paths()
            finally:
                os.chdir(old)
            self.assertEqual(pathlib.Path(paths["root"]).resolve(), (selected / ".audit").resolve())

    def test_project_scope_menu_uses_richer_workspace_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            for name in ("app", "dep"):
                project = root / "packages" / name
                (project / "src").mkdir(parents=True)
                (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            old = os.getcwd()
            try:
                os.chdir(root)
                candidates = lk.discover_nested_projects(root)
                output = io.StringIO()
                with redirect_stdout(output):
                    lk._print_workspace_scope_choices(candidates)
            finally:
                os.chdir(old)
            rendered = output.getvalue()
            self.assertIn("PRIMARY AUDIT CANDIDATE", rendered)
            self.assertIn("Contracts", rendered)
            self.assertIn("Tests", rendered)

    def test_help_long_alias(self):
        result = self.run_cli("--h")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LOWKEY", result.stdout)
        self.assertIn("lk actor 0 Alice", result.stdout)

    def test_cli_failure_exit_codes(self):
        cases = [
            ("event", "Transfer(address,address,uint256)", "0xdeadbeef", "0x1"),
            ("target", "not-an-address"),
            ("receipt", "not-a-hash"),
            ("scan", "/path/does/not/exist"),
            ("definitely-not-a-command",),
            ("raw", "definitely-not-a-cast-command"),
            ("receipt", "0x" + "0" * 64),
            ("functions",),
            ("abi",),
            ("recon",),
            ("proxy",),
            ("snapshot",),
            ("gas",),
            ("namespace",),
            ("proof",),
            ("decode",),
            ("wizard",),
            ("test-gen",),
            ("matrix", "test", "missing-scenario"),
        ]
        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_scan_regression_markers(self):
        source = """
        contract Regression {
            function f(address target) external payable {
                target.call{value: 1 ether}(\"\");
                target.delegatecall(\"\");
                address caller = tx.origin;
            }
        }
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "Regression.sol"
            path.write_text(source, encoding="utf-8")
            result = self.run_cli("scan", tmp)
            single_file_result = self.run_cli("scan", str(path))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(single_file_result.returncode, 0, single_file_result.stderr)
        self.assertIn("REENTRANCY REVIEW", result.stdout)
        self.assertIn("DELEGATECALL", result.stdout)
        self.assertIn("TX.ORIGIN", result.stdout)
        self.assertIn("REENTRANCY REVIEW", single_file_result.stdout)
        self.assertIn("DELEGATECALL", single_file_result.stdout)
        self.assertIn("TX.ORIGIN", single_file_result.stdout)
        self.assertIn("Coverage      : partial", single_file_result.stdout)

    def test_doctor_reports_missing_dependencies(self):
        with patch.object(lk.shutil, "which", return_value=None):
            self.assertEqual(lk.run_doctor(), 1)

    def test_solidity_identifier(self):
        self.assertEqual(
            lk.solidity_identifier("unauthorized release #1"),
            "unauthorized_release__1",
        )


    def test_humanize_value_is_explicit(self):
        raw = "1000000000000000000"
        self.assertEqual(lk.humanize_value(raw), raw)
        self.assertIn("1.0000 ETH", lk.humanize_value(raw, assume_wei=True))

    def test_actor_addresses_are_humanized_across_shared_output_renderer(self):
        alice = "0x" + "1" * 40
        config = {
            "actor": "Alice",
            "wallets": {
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": alice,
                }
            },
            "labels": {},
        }
        rendered = lk.apply_labels(f"from={alice} to={alice}", config)
        self.assertEqual(
            rendered,
            f"from=Alice ({alice}) to=Alice ({alice})",
        )

    def test_multi_value_abi_status_annotation_does_not_get_generic_unit_suffix(self):
        item = {
            "type": "function",
            "name": "escrow",
            "outputs": [
                {"name": "amount", "type": "uint256"},
                {"name": "currentStatus", "type": "uint8"},
            ],
        }
        abi = [
            item,
            {"type": "function", "name": "createescrow", "stateMutability": "payable", "inputs": [], "outputs": []},
        ]
        decoded = "2000000000000000000\n0"
        rendered = lk.format_human_abi_return(
            item, decoded, {"labels": {}}, abi
        )
        self.assertIn(
            "  amount = 2 ETH (2,000,000,000,000,000,000 wei, inferred) [uint256]",
            rendered,
        )
        self.assertIn(
            "  current status = 0 (status/state code) [uint8]",
            rendered,
        )
        self.assertNotIn(
            "current status=0 (status/state code) units",
            rendered,
        )

    def test_actor_identity_is_used_in_anvil_and_common_display(self):
        alice = "0x" + "1" * 40
        config = {
            "actor": "Alice",
            "wallets": {
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 1,
                    "address": alice,
                }
            },
            "labels": {},
        }
        self.assertEqual(lk.actor_display(config), f"Alice ({alice}) [Anvil #1]")

        with patch.object(
            lk,
            "anvil_rpc_info",
            return_value={"url": "http://127.0.0.1:8545", "accounts": ["0x" + "0" * 40, alice]},
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                lk.list_anvil_actors(config)
        rendered = output.getvalue()
        self.assertIn(f"Alice ({alice})", rendered)
        self.assertNotIn(f"{alice} -> Alice", rendered)

    def test_actor_reset_deselects_without_deleting_profile(self):
        alice = "0x" + "1" * 40
        config = {
            "actor": "Alice",
            "wallets": {
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": alice,
                }
            },
            "labels": {},
        }
        with patch.object(lk, "save_config"):
            result = lk.dispatch_command("actor", ["reset"], config)
        self.assertEqual(result, 0)
        self.assertIsNone(config["actor"])
        self.assertIn("Alice", config["wallets"])

    def test_known_actor_addresses_render_as_name_with_address(self):
        address = "0x" + "a" * 40
        config = {
            "actor": "Alice",
            "wallets": {
                "lab-deployer": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": address,
                    "internal": True,
                },
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": address,
                },
            },
            "labels": {},
        }
        rendered = lk.apply_labels(
            f"From: {address}\nTo: {address}\nAlready: Alice ({address})",
            config,
        )
        self.assertIn(f"From: Alice ({address})", rendered)
        self.assertIn(f"To: Alice ({address})", rendered)
        self.assertIn(f"Already: Alice ({address})", rendered)
        self.assertNotIn(f"Alice (Alice ({address}))", rendered)

    def test_human_abi_return_uses_stale_internal_anvil_actor_identity(self):
        actual = "0x" + "b" * 40
        stale = "0x" + "c" * 40
        item = {
            "type": "function",
            "name": "escrow",
            "outputs": [{"name": "creator", "type": "address"}],
        }
        config = {
            "actor": "lab-deployer",
            "wallets": {
                "lab-deployer": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": stale,
                    "internal": True,
                },
            },
            "labels": {},
        }
        with patch.object(
            lk,
            "anvil_rpc_info",
            return_value={"url": "http://127.0.0.1:8545", "accounts": [actual]},
        ):
            rendered = lk.format_human_abi_return(item, actual, config, [item])
        self.assertIn(f"Returns:\n  creator = lab-deployer ({actual}) [address]", rendered)

    def test_human_abi_return_uses_actor_identity_for_addresses(self):
        address = "0x" + "b" * 40
        item = {
            "type": "function",
            "name": "ownerOf",
            "outputs": [{"name": "owner", "type": "address"}],
        }
        config = {
            "actor": "Alice",
            "wallets": {
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": address,
                },
            },
            "labels": {},
        }
        rendered = lk.format_human_abi_return(item, address, config, [item])
        self.assertIn(f"Returns:\n  owner = Alice ({address}) [address]", rendered)


    def test_format_call_display_uses_actor_identity_for_address_arguments(self):
        address = "0x" + "c" * 40
        target = "0x" + "d" * 40
        item = {
            "type": "function",
            "name": "getBalance",
            "stateMutability": "view",
            "inputs": [{"name": "user", "type": "address"}],
            "outputs": [{"name": "balance", "type": "uint256"}],
        }
        config = {
            "target": target,
            "actor": "Alice",
            "wallets": {
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": address,
                }
            },
            "labels": {},
        }
        with patch.object(lk, "load_abi", return_value=[item]):
            rendered = lk.format_call_display(
                config,
                "getBalance(address)",
                [address],
            )
        self.assertEqual(rendered, f"getBalance(Alice ({address}))")

    def test_run_cast_decodes_abi_return_data_for_humans(self):
        target = "0x" + "1" * 40
        owner = "0x" + "2" * 40
        raw = "0x" + "0" * 64
        abi = [
            {
                "type": "function",
                "name": "balanceOf",
                "stateMutability": "view",
                "inputs": [{"name": "owner", "type": "address"}],
                "outputs": [{"name": "balance", "type": "uint256"}],
            }
        ]
        config = {"target": target, "wallets": {}, "labels": {}}
        with patch.object(lk, "load_abi", return_value=abi), patch.object(
            lk,
            "cast_output",
            side_effect=[(0, raw, ""), (0, "0", "")],
        ):
            output = io.StringIO()
            with redirect_stdout(output):
                result = lk.run_cast(["call", "balanceOf", owner], config)

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("balance = 0 units (unit not specified by ABI) [uint256]", rendered)
        self.assertNotIn(raw, rendered)
        self.assertNotIn("ABI encoded", rendered)

    def test_human_abi_return_resolves_enum_member_names_from_source(self):
        item = {
            "type": "function",
            "name": "escrow",
            "outputs": [
                {
                    "name": "currentStatus",
                    "type": "uint8",
                    "internalType": "enum Escrow.status",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "Escrow.sol"
            source.write_text(
                "contract Escrow {\n"
                "    enum status { waiting, funded, rejected, released }\n"
                "}\n",
                encoding="utf-8",
            )
            with patch.object(lk, "source_sol_files", return_value=[str(source)]),                  patch.object(lk.audit_context, "foundry_project_root", return_value=str(root)):
                rendered = lk.format_human_abi_return(
                    item,
                    "0",
                    {"labels": {}},
                    [item],
                )

        self.assertIn(
            "Returns:\n  current status = waiting (enum value 0) [uint8]",
            rendered,
        )
        self.assertNotIn("status/state code", rendered)
        self.assertNotIn("units", rendered)

    def test_human_abi_return_explains_zero_addresses_and_status_fields(self):
        item = {
            "type": "function",
            "name": "escrow",
            "outputs": [
                {"name": "creator", "type": "address"},
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
                {"name": "currentStatus", "type": "uint8"},
            ],
        }
        abi = [
            item,
            {"type": "function", "name": "createescrow", "stateMutability": "payable", "inputs": [], "outputs": []},
        ]
        decoded = (
            "0x0000000000000000000000000000000000000000\n"
            "0x0000000000000000000000000000000000000000\n"
            "0\n"
            "0"
        )
        rendered = lk.format_human_abi_return(item, decoded, {"labels": {}}, abi)
        self.assertIn("Returns:\n", rendered)
        self.assertIn("  creator = zero address (not set) [address]", rendered)
        self.assertIn("  recipient = zero address (not set) [address]", rendered)
        self.assertIn("  amount = 0 ETH (0 wei, inferred) [uint256]", rendered)
        self.assertIn("  current status = 0 (status/state code) [uint8]", rendered)
        self.assertNotIn(", recipient=", rendered)

    def test_human_abi_return_preserves_multi_value_lines(self):
        item = {
            "type": "function",
            "name": "quote",
            "outputs": [
                {"name": "amount", "type": "uint256"},
                {"name": "recipient", "type": "address"},
            ],
        }
        decoded = "1\n0x2222222222222222222222222222222222222222"
        rendered = lk.format_human_abi_return(item, decoded, {"labels": {}}, [item])
        self.assertIn("Returns:\n", rendered)
        self.assertIn("  amount = 1 units (unit not specified by ABI) [uint256]", rendered)
        self.assertIn("  recipient = 0x2222222222222222222222222222222222222222 [address]", rendered)

    def test_function_recommendations_use_parameter_names(self):
        abi = [{
            "type": "function",
            "name": "ownerOf",
            "stateMutability": "view",
            "inputs": [{"name": "tokenId", "type": "uint256"}],
            "outputs": [{"name": "", "type": "address"}],
        }]
        self.assertEqual(
            lk._function_recommendation_command("read", abi[0], abi),
            "lk read ownerOf <tokenId>",
        )

    def test_custom_balance_of_does_not_claim_token_kind_without_evidence(self):
        item = {
            "type": "function",
            "name": "balanceOf",
            "outputs": [{"name": "balance", "type": "uint256"}],
        }
        rendered = lk.format_human_abi_return(item, "7", {"labels": {}}, [item])
        self.assertIn("7 units (unit not specified by ABI)", rendered)
        self.assertNotIn("7 tokens", rendered)

    def test_run_cast_labels_raw_return_data_when_abi_decode_fails(self):
        target = "0x" + "1" * 40
        owner = "0x" + "2" * 40
        raw = "0x" + "0" * 64
        abi = [
            {
                "type": "function",
                "name": "balanceOf",
                "stateMutability": "view",
                "inputs": [{"name": "owner", "type": "address"}],
                "outputs": [{"name": "balance", "type": "uint256"}],
            }
        ]
        config = {"target": target, "wallets": {}, "labels": {}}
        with patch.object(lk, "load_abi", return_value=abi), patch.object(
            lk,
            "cast_output",
            side_effect=[(0, raw, ""), (1, "", "decode failed")],
        ):
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                result = lk.run_cast(["call", "balanceOf", owner], config)

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("Return: ABI decoding failed", rendered)
        self.assertIn("Raw return data:", rendered)
        self.assertIn(raw, rendered)

    def test_abi_selector_uses_three_tuple(self):
        with patch.object(lk, "cast_output", return_value=(0, "0x12345678\n", "")):
            self.assertEqual(lk.abi_selector("foo(uint256)"), "0x12345678")

    def test_encode_target_call_rejects_placeholder(self):
        config={"target":"0x"+"1"*40}
        with patch.object(lk,"load_abi",return_value=[
            {"type":"function","name":"acceptescrow","inputs":[{"name":"accepted","type":"bool"}],"stateMutability":"nonpayable"}
        ]):
            with self.assertRaisesRegex(ValueError, "Replace '...'"):
                lk.encode_target_call(config,"acceptescrow",["..."])

    def test_encode_target_call_rejects_signature_not_in_active_target_abi(self):
        config={"target":"0x"+"1"*40}
        abi=[
            {
                "type":"function",
                "name":"createescrow",
                "inputs":[{"name":"recipient","type":"address"}],
                "stateMutability":"payable",
            }
        ]
        with patch.object(lk, "load_abi", return_value=abi):
            with self.assertRaisesRegex(
                ValueError,
                r"Function signature 'createescrow\(uint256,address\)' is not present.*createescrow\(address\)",
            ):
                lk.encode_target_call(
                    config,
                    "createescrow(uint256,address)",
                    ["111", "0x"+"2"*40],
                )

    def test_encode_target_call_reports_argument_count(self):
        config={"target":"0x"+"1"*40}
        abi=[{
            "type":"function","name":"createescrow",
            "inputs":[{"name":"amount","type":"uint256"},{"name":"recipient","type":"address"}],
            "stateMutability":"payable"
        }]
        with patch.object(lk,"load_abi",return_value=abi):
            with self.assertRaisesRegex(ValueError, r"expects 2 argument\(s\), got 1"):
                lk.encode_target_call(config,"createescrow",["1 ether"])

    def test_split_lab_options_accepts_separated_eth_unit(self):
        values, actor, value, keep, repeat = lk.split_lab_options(
            ["release", "--actor", "Alice", "--value", "1", "ether"]
        )
        self.assertEqual(values, ["release"])
        self.assertEqual(actor, "Alice")
        self.assertEqual(value, "1 ether")
        self.assertFalse(keep)
        self.assertEqual(repeat, 1)

    def test_split_lab_options_parses_repeat_flag_and_limits(self):
        values, actor, value, keep, repeat = lk.split_lab_options(
            ["createescrow", "--value", "1ether", "--repeat", "3"]
        )
        self.assertEqual(values, ["createescrow"])
        self.assertIsNone(actor)
        self.assertEqual(value, "1ether")
        self.assertFalse(keep)
        self.assertEqual(repeat, 3)

        with self.assertRaisesRegex(ValueError, r"--repeat needs a positive integer"):
            lk.split_lab_options(["createescrow", "--repeat"])
        with self.assertRaisesRegex(ValueError, r"--repeat must be at least 1"):
            lk.split_lab_options(["createescrow", "--repeat", "0"])
        with self.assertRaisesRegex(ValueError, r"--repeat cannot exceed 100"):
            lk.split_lab_options(["createescrow", "--repeat", "101"])

    def test_encode_target_call_resolves_actor_name_for_address_argument(self):
        config = {
            "target": "0x" + "1" * 40,
            "wallets": {
                "Bob": {"address": "0x" + "2" * 40},
            },
        }
        abi = [{
            "type": "function",
            "name": "createescrow",
            "inputs": [
                {"name": "amount", "type": "uint256"},
                {"name": "recipient", "type": "address"},
            ],
            "stateMutability": "payable",
        }]
        with patch.object(lk, "load_abi", return_value=abi),              patch.object(lk, "cast_output", return_value=(0, "0xabcdef", "")) as cast:
            signature, encoded = lk.encode_target_call(
                config, "createescrow", ["1ether", "Bob"]
            )
        self.assertEqual(signature, "createescrow(uint256,address)")
        self.assertEqual(encoded, "abcdef")
        self.assertEqual(cast.call_args.args[0][-2:], ["1000000000000000000", "0x" + "2" * 40])

    def test_lab_flags_have_simple_aliases_and_auto_eth(self):
        values, actor, value, keep, repeat = lk.split_lab_options(
            ["createescrow", "1", "ether", "Bob", "--as", "Alice"]
        )
        self.assertEqual(values, ["createescrow", "1", "ether", "Bob"])
        self.assertEqual(actor, "Alice")
        self.assertEqual(value, "auto")
        self.assertFalse(keep)
        self.assertEqual(repeat, 1)

        config={
            "target":"0x"+"1"*40,
            "wallets":{"Bob":{"address":"0x"+"2"*40}},
        }
        abi=[{
            "type":"function",
            "name":"createescrow",
            "inputs":[
                {"name":"amount","type":"uint256"},
                {"name":"recipient","type":"address"},
            ],
            "stateMutability":"payable",
        }]
        with patch.object(lk,"load_abi",return_value=abi):
            self.assertEqual(
                lk.resolve_lab_value(
                    config,
                    "createescrow(uint256,address)",
                    ["1","ether","Bob"],
                    "auto",
                ),
                "1 ether",
            )

    def test_run_cast_resolves_actor_name_for_address_argument(self):
        target="0x"+"1"*40
        config={
            "target":target,
            "wallets":{"Bob":{"address":"0x"+"2"*40}},
            "actor":"Alice",
        }
        abi=[{
            "type":"function",
            "name":"sendTo",
            "inputs":[{"name":"to","type":"address"}],
            "stateMutability":"nonpayable",
        }]
        with patch.object(lk,"load_abi",return_value=abi), \
             patch.object(lk,"cast_output",return_value=(0,"ok","")) as cast:
            self.assertEqual(lk.run_cast(["send","sendTo","Bob"],config),0)
        sent=cast.call_args.args[0]
        self.assertIn("sendTo(address)",sent)
        self.assertIn("0x"+"2"*40,sent)

    def test_encode_target_call_normalizes_ether_argument(self):
        config={
            "target":"0x"+"1"*40,
            "wallets":{"Bob":{"address":"0x"+"2"*40}},
        }
        abi=[{
            "type":"function",
            "name":"createescrow",
            "inputs":[
                {"name":"amount","type":"uint256"},
                {"name":"recipient","type":"address"},
            ],
            "stateMutability":"payable",
        }]
        with patch.object(lk,"load_abi",return_value=abi), \
             patch.object(lk,"cast_output",return_value=(0,"0xabcdef","")) as cast:
            lk.encode_target_call(config,"createescrow",["1ether","Bob"])
        sent=cast.call_args.args[0]
        self.assertIn("1000000000000000000",sent)
        self.assertIn("0x"+"2"*40,sent)


    def test_split_lab_options(self):
        values, actor, value, keep, repeat = lk.split_lab_options(
            ["release", "1", "0x" + "1" * 40, "--actor", "Alice", "--value", "1ether", "--keep"]
        )
        self.assertEqual(values, ["release", "1", "0x" + "1" * 40])
        self.assertEqual(repeat, 1)
        self.assertEqual(actor, "Alice")
        self.assertEqual(value, "1ether")
        self.assertTrue(keep)
        self.assertEqual(repeat, 1)

    def test_as_restores_previous_actor(self):
        config = {
            "actor": "Alice",
            "wallets": {"Alice": {"address": "0x" + "1" * 40}, "Bob": {"address": "0x" + "2" * 40}},
        }
        seen = {}

        def fake_dispatch(cmd, args, cfg, from_batch=False):
            seen["actor"] = cfg["actor"]
            return 0

        with patch.object(lk, "dispatch_command", side_effect=fake_dispatch):
            self.assertEqual(lk.run_as(config, ["Bob", "status"]), 0)
        self.assertEqual(seen["actor"], "Bob")
        self.assertEqual(config["actor"], "Alice")

    def test_probe_generates_actor_probe(self):
        config = {
            "target": "0x" + "3" * 40,
            "actor": "Alice",
            "wallets": {"Alice": {"address": "0x" + "1" * 40}},
        }
        captured = {}

        def fake_write(prefix, content, announce=True):
            captured["prefix"] = prefix
            captured["content"] = content
            return "test/Lowkey_probe.t.sol"

        with patch.object(lk, "encode_target_call", return_value=("ping(uint256)", "abcdef")), \
             patch.object(lk, "write_generated_test", side_effect=fake_write), \
             patch.object(lk, "run_foundry", return_value=0):
            self.assertEqual(lk.run_probe(config, ["ping", "7", "--actor", "Alice"]), 0)
        self.assertIn("vm.startPrank", captured["content"])
        self.assertIn('hex"abcdef"', captured["content"])
        self.assertIn("ACTOR Alice", captured["content"])

    def test_existing_public_actor_on_reserved_account_zero_cannot_be_selected(self):
        address = "0x" + "1" * 40
        config = {
            "actor": None,
            "wallets": {
                "Alice": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": address,
                }
            },
            "labels": {address: "Alice"},
        }
        with patch.object(lk, "save_config"), patch.object(
            lk, "anvil_rpc_info",
            return_value={"url": "http://127.0.0.1:8545", "accounts": [address]},
        ):
            result = lk.dispatch_command("actor", ["Alice"], config)
        self.assertEqual(result, 2)
        self.assertIsNone(config["actor"])

    def test_configured_actor_addresses_exclude_internal_and_reserved_profiles(self):
        address0 = "0x" + "1" * 40
        address1 = "0x" + "2" * 40
        config = {
            "actor": None,
            "wallets": {
                "lab-deployer": {
                    "source": "anvil-default", "anvil_index": 0,
                    "address": address0, "internal": True,
                },
                "Alice": {
                    "source": "anvil-default", "anvil_index": 0,
                    "address": address0,
                },
                "Bob": {
                    "source": "anvil-default", "anvil_index": 1,
                    "address": address1,
                },
            },
        }
        self.assertEqual(lk.configured_actor_addresses(config), [("Bob", address1)])

    def test_state_diff_generates_recording(self):
        config = {
            "target": "0x" + "3" * 40,
            "actor": "Alice",
            "wallets": {"Alice": {"address": "0x" + "1" * 40}},
        }
        captured = {}

        def fake_write(prefix, content, announce=True):
            captured["content"] = content
            return "test/Lowkey_state_diff.t.sol"

        with patch.object(lk, "encode_target_call", return_value=("ping()", "abcdef")),              patch.object(lk, "write_generated_test", side_effect=fake_write),              patch.object(lk, "run_foundry", return_value=lk.CommandResult("", 0)):
            self.assertEqual(lk.run_state_diff(config, ["ping", "--repeat", "3"]), 0)
        self.assertIn("vm.startStateDiffRecording()", captured["content"])
        self.assertIn("vm.stopAndReturnStateDiff()", captured["content"])
        self.assertIn("vm.getStorageAccesses()", captured["content"])
        self.assertIn("Vm.StorageAccess[] memory storage_accesses", captured["content"])
        self.assertIn("if (access.account != TARGET)", captured["content"])
        self.assertIn('console2.log("STORAGE_CHANGES", changed);', captured["content"])
        self.assertIn("vm.startPrank(ACTOR);", captured["content"])
        self.assertIn("for (uint256 i = 0; i < 3; i++)", captured["content"])
        self.assertIn('console2.log("CALL_RETURN_DATA");', captured["content"])


    def test_fallback_storage_labels_do_not_guess_scalar_mapping_slots(self):
        config = {"target": "0x" + "1" * 40}
        types = {
            "t_mapping": {
                "encoding": "mapping",
                "key": "t_address",
                "value": "t_uint256",
            },
            "t_address": {"label": "address", "numberOfBytes": 20},
            "t_uint256": {"label": "uint256", "numberOfBytes": 32},
        }
        changed = ["0x" + format(10, "064x")]
        storage = [{"label": "balances", "slot": "0", "type": "t_mapping"}]
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)):
            labels = lk.fallback_storage_labels(config, changed)
        self.assertNotIn(changed[0].lower(), labels)

    def test_fallback_storage_labels_group_generic_struct_mapping_changes(self):
        config = {"target": "0x" + "1" * 40}
        types = {
            "t_mapping": {
                "encoding": "mapping",
                "key": "t_bytes32",
                "value": "t_struct",
            },
            "t_struct": {
                "encoding": "inplace",
                "members": [
                    {"label": "creator", "slot": "0", "offset": 0, "type": "t_address"},
                    {"label": "amount", "slot": "1", "offset": 0, "type": "t_uint256"},
                    {"label": "status", "slot": "2", "offset": 0, "type": "t_uint8"},
                ],
            },
            "t_address": {"label": "address", "numberOfBytes": 20},
            "t_uint256": {"label": "uint256", "numberOfBytes": 32},
            "t_uint8": {"label": "uint8", "numberOfBytes": 1},
            "t_bytes32": {"label": "bytes32", "numberOfBytes": 32},
        }
        base = 10
        changed = [
            "0x" + format(base, "064x"),
            "0x" + format(base + 1, "064x"),
            "0x" + format(base + 2, "064x"),
        ]
        storage = [{"label": "escrow", "slot": "5", "type": "t_mapping"}]
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)):
            labels = lk.fallback_storage_labels(config, changed)
        self.assertEqual(
            labels[changed[0].lower()][0],
            "escrow[unresolved key].creator [inferred]",
        )
        self.assertEqual(
            labels[changed[1].lower()][0],
            "escrow[unresolved key].amount [inferred]",
        )
        self.assertEqual(
            labels[changed[2].lower()][0],
            "escrow[unresolved key].status [inferred]",
        )

    def test_fallback_storage_labels_uses_observed_types_to_break_partial_struct_tie(self):
        config = {"target": "0x" + "1" * 40}
        types = {
            "t_mapping": {
                "encoding": "mapping",
                "key": "t_bytes32",
                "value": "t_struct",
            },
            "t_struct": {
                "encoding": "inplace",
                "members": [
                    {"label": "creator", "slot": "0", "offset": 0, "type": "t_address"},
                    {"label": "hunter", "slot": "1", "offset": 0, "type": "t_address"},
                    {"label": "amount", "slot": "2", "offset": 0, "type": "t_uint256"},
                    {"label": "completed", "slot": "3", "offset": 0, "type": "t_bool"},
                ],
            },
            "t_address": {"label": "address", "numberOfBytes": 20},
            "t_uint256": {"label": "uint256", "numberOfBytes": 32},
            "t_bool": {"label": "bool", "numberOfBytes": 1},
            "t_bytes32": {"label": "bytes32", "numberOfBytes": 32},
        }
        changed = [
            {
                "slot": "0x" + format(50, "064x"),
                "from": "0x" + "0" * 64,
                "to": "0x" + "0" * 24 + "1" * 40,
            },
            {
                "slot": "0x" + format(51, "064x"),
                "from": "0x" + "0" * 64,
                "to": "0x" + "0" * 24 + "2" * 40,
            },
            {
                "slot": "0x" + format(52, "064x"),
                "from": "0x" + "0" * 64,
                "to": "0x" + format(10**18, "064x"),
            },
        ]
        storage = [{"label": "escrows", "slot": "5", "type": "t_mapping"}]

        with patch.object(lk, "storage_layout_details", return_value=(types, storage)):
            labels = lk.fallback_storage_labels(config, changed)

        self.assertEqual(
            labels[changed[0]["slot"]][0],
            "escrows[unresolved key].creator [inferred]",
        )
        self.assertEqual(
            labels[changed[1]["slot"]][0],
            "escrows[unresolved key].hunter [inferred]",
        )
        self.assertEqual(
            labels[changed[2]["slot"]][0],
            "escrows[unresolved key].amount [inferred]",
        )

    def test_fallback_storage_labels_leave_ambiguous_alignment_raw(self):
        config = {"target": "0x" + "1" * 40}
        types = {
            "t_mapping": {
                "encoding": "mapping",
                "key": "t_bytes32",
                "value": "t_struct",
            },
            "t_struct": {
                "encoding": "inplace",
                "members": [
                    {"label": "first", "slot": "0", "offset": 0, "type": "t_uint256"},
                    {"label": "second", "slot": "1", "offset": 0, "type": "t_uint256"},
                ],
            },
            "t_uint256": {"label": "uint256", "numberOfBytes": 32},
            "t_bytes32": {"label": "bytes32", "numberOfBytes": 32},
        }
        changed = ["0x" + format(10, "064x")]
        storage = [{"label": "items", "slot": "5", "type": "t_mapping"}]
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)):
            labels = lk.fallback_storage_labels(config, changed)
        self.assertNotIn(changed[0].lower(), labels)

    def test_fallback_storage_labels_handles_distant_real_storage_slots(self):
        config = {"target": "0x" + "1" * 40}
        types = {
            "t_mapping": {
                "encoding": "mapping",
                "key": "t_bytes32",
                "value": "t_struct",
            },
            "t_struct": {
                "encoding": "inplace",
                "members": [
                    {"label": "creator", "slot": "0", "offset": 0, "type": "t_address"},
                    {"label": "amount", "slot": "1", "offset": 0, "type": "t_uint256"},
                    {"label": "status", "slot": "2", "offset": 0, "type": "t_uint8"},
                ],
            },
            "t_address": {"label": "address", "numberOfBytes": 20},
            "t_uint256": {"label": "uint256", "numberOfBytes": 32},
            "t_uint8": {"label": "uint8", "numberOfBytes": 1},
            "t_bytes32": {"label": "bytes32", "numberOfBytes": 32},
        }
        changed = [
            "0x" + format(10, "064x"),
            "0x" + format(2**255, "064x"),
        ]
        storage = [{"label": "escrow", "slot": "5", "type": "t_mapping"}]
        with patch.object(lk, "storage_layout_details", return_value=(types, storage)):
            labels = lk.fallback_storage_labels(config, changed)
        self.assertEqual(labels, {})

    def test_state_diff_parser_accepts_repeated_call_results(self):
        output = (
            "[PASS] test_state_diff() (gas: 321)\n"
            "Logs:\n"
            "  REPEAT_CALL: 1\n"
            "  CALL_RETURN_DATA\n"
            "  0x" + "aa" * 32 + "\n"
            "  REPEAT_CALL: 2\n"
            "  CALL_RETURN_DATA\n"
            "  0x" + "aa" * 32 + "\n"
            "  CALL createescrow(address)\n"
            "  REPEAT_COUNT: 2\n"
            "  SUCCESS: true\n"
            "  ETH_SENT 1000000000000000000\n"
            "  STORAGE_CHANGES 0\n"
        )
        parsed = lk.parse_state_diff_output(output)
        self.assertEqual(parsed["repeat_count"], 2)
        self.assertEqual(
            parsed["repeat_returns"],
            ["0x" + "aa" * 32, "0x" + "aa" * 32],
        )
        self.assertTrue(parsed["success"])

    def test_state_diff_parser_accepts_recorded_state_write(self):
        slot = "0x" + "a" * 64
        before = "0x" + "0" * 64
        after = "0x" + "b" * 64
        output = (
            "[PASS] test_state_diff() (gas: 123)\n"
            "Logs:\n"
            "  CALL createescrow(uint256,address)\n"
            "  SUCCESS true\n"
            "  ETH_SENT 1000000000000000000\n"
            "  STATE_SLOT\n"
            "  " + slot + "\n"
            "  STATE_FROM\n"
            "  " + before + "\n"
            "  STATE_TO\n"
            "  " + after + "\n"
            "  STORAGE_CHANGES 1\n"
        )
        parsed = lk.parse_state_diff_output(output)
        self.assertEqual(parsed["changes_expected"], 1)
        self.assertEqual(len(parsed["slots"]), 1)
        self.assertEqual(parsed["slots"][0]["slot"], slot)
        self.assertEqual(parsed["slots"][0]["from"], before)
        self.assertEqual(parsed["slots"][0]["to"], after)

    def test_signal_evidence_attaches_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc = \"src\"\n", encoding="utf-8")
            signal = lk.audit_context.add_signal({
                "tool": "slither",
                "check": "reentrancy-eth",
                "title": "ETH reentrancy review",
                "file": "src/Escrow.sol",
                "line": 42,
            }, root)
            evidence = {
                "kind": "state-diff",
                "function": "release()",
                "success": True,
                "storage_changes": [{
                    "slot": "0x" + "ab" * 32,
                    "label": "escrow[1].amount",
                    "from": "0x" + "0" * 64,
                    "to": "0x" + "1" * 64,
                    "from_display": "0 ETH",
                    "to_display": "1 ETH",
                }],
            }
            first = lk.audit_context.attach_signal_evidence(signal["id"], evidence, root)
            second = lk.audit_context.attach_signal_evidence(signal["id"], evidence, root)

            self.assertEqual(len(first["evidence"]), 1)
            self.assertEqual(second["evidence"][0]["storage_changes"][0]["label"], "escrow[1].amount")

    def test_findings_and_focus_render_linked_storage_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc = \"src\"\n", encoding="utf-8")
            signal = lk.audit_context.add_signal({
                "tool": "slither",
                "check": "low-level-calls",
                "title": "Raw external call",
                "file": "src/Escrow.sol",
                "line": 18,
                "function": "release",
            }, root)
            lk.audit_context.attach_signal_evidence(signal["id"], {
                "kind": "state-diff",
                "function": "release()",
                "caller": "Alice",
                "success": True,
                "gas": 247291,
                "storage_changes": [{
                    "slot": "0x" + "cd" * 32,
                    "label": "escrow[1].recipient",
                    "from": "0x" + "2" * 64,
                    "to": "0x" + "1" * 64,
                    "from_display": "Bob (0x" + "2" * 40 + ")",
                    "to_display": "Alice (0x" + "1" * 40 + ")",
                }],
            }, root)
            old = os.getcwd()
            os.chdir(root)
            try:
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(lk.run_signals({}, ["all"]), 0)
                rendered = output.getvalue()
                self.assertIn("Evidence   : 1 captured", rendered)
                self.assertIn("slot: 0x" + "cd" * 32, rendered)

                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(lk.run_investigate({}, [signal["id"]]), 0)
                self.assertIn("Evidence (1):", output.getvalue())
                self.assertIn("escrow[1].recipient", output.getvalue())
            finally:
                os.chdir(old)
    def test_selector_compare_uses_runtime_and_abi(self):
        target = "0x" + "1" * 40
        config = {
            "target": target,
            "abi_paths": {target: "/tmp/abi.json"},
            "target_contract": "Fixture",
        }
        abi = [{"type": "function", "name": "ping", "inputs": [{"type": "uint256"}]}]
        with patch.object(lk, "run_cast", return_value=lk.CommandResult("0x6000", 0)), \
             patch.object(lk, "load_abi", return_value=abi), \
             patch.object(
                 lk, "cast_output",
                 side_effect=[
                     (0, "0x12345678", ""),
                     (0, "0x12345678", ""),
                 ],
             ), \
             patch.object(lk, "abi_selector", return_value="0x12345678"):
            output = io.StringIO()
            with redirect_stdout(output):
                result = lk.run_selector_compare(config, [])
        self.assertEqual(result, 0)
        self.assertIn("RUNTIME-ONLY:", output.getvalue())
        self.assertIn("ABI-ONLY:", output.getvalue())




    def test_decode_calldata_auto_resolves_loaded_abi(self):
        config={"target":"0x"+"1"*40}
        abi=[{"type":"function","name":"ping","inputs":[{"type":"uint256"}]}]
        with patch.object(lk,"load_abi",return_value=abi), \
             patch.object(lk,"abi_selector",return_value="0x773acdef"), \
             patch.object(lk,"run_cast",return_value=0) as run:
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(lk.run_cast_deep(config,["decode-calldata","0x773acdef"+"0"*63+"7"]),0)
        self.assertEqual(
            run.call_args.args[0][:3],
            ["decode-calldata","ping(uint256)","0x773acdef"+"0"*63+"7"],
        )
        self.assertIn("Signature: ping(uint256)",output.getvalue())

    def test_cast_deep_commands(self):
        target="0x"+"1"*40
        config={"target":target,"abi_paths":{target:"/tmp/abi.json"}}
        calls=[]
        def fake_run(args,cfg,capture=False):
            calls.append(args)
            return 0
        with patch.object(lk,"run_cast",side_effect=fake_run),              patch.object(lk,"auto_abi_path",return_value="/tmp/abi.json"),              patch.object(lk,"load_abi",return_value=[{"type":"function","name":"ping","inputs":[{"type":"uint256"}]}]),              patch.object(lk,"abi_selector",return_value="0x12345678"),              patch.object(lk,"resolve_function",return_value="ping(uint256)"):
            self.assertEqual(lk.run_cast_deep(config,["4byte","0x12345678"]),0)
            self.assertEqual(lk.run_cast_deep(config,["4byte-event","0x"+"a"*64]),0)
            self.assertEqual(lk.run_cast_deep(config,["4byte-calldata","0x12345678"]),0)
            self.assertEqual(lk.run_cast_deep(config,["access-list","ping","7"]),0)
            self.assertEqual(lk.run_cast_deep(config,["interface"]),0)
            self.assertEqual(lk.run_cast_deep(config,["constructor-args"]),0)
            self.assertEqual(lk.run_cast_deep(config,["creation-code"]),0)
            self.assertEqual(lk.run_cast_deep(config,["decode-calldata","0x12345678"]),0)
            self.assertEqual(lk.run_cast_deep(config,["abi-encode","uint256","7"]),0)
        self.assertTrue(any(x[0]=="interface" for x in calls))
        self.assertTrue(any(x[0]=="constructor-args" for x in calls))
        self.assertTrue(any(x[0]=="creation-code" for x in calls))
        self.assertTrue(any(x[0]=="access-list" for x in calls))

    def test_seams_command_surfaces_cross_signals(self):
        config={"target":"0x"+"1"*40}
        abi=[{
            "type":"function","name":"withdraw",
            "inputs":[{"name":"to","type":"address"}],
            "stateMutability":"payable"
        }]
        output=io.StringIO()
        with patch.object(lk,"load_abi",return_value=abi), redirect_stdout(output):
            self.assertEqual(lk.run_seams(config),0)
        rendered=output.getvalue()
        self.assertIn("state-write + address input",rendered)
        self.assertIn("state-write + asset/value flow",rendered)

    def test_matrix_test_executes_returned_generated_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=lk.WORKSPACE_DIR
            lk.WORKSPACE_DIR=tmp
            try:
                lk.run_matrix({},["init"])
                paths=lk.workspace_paths()
                lk.write_json_file(paths["matrix_actors"],{"Alice":{"address":"0x"+"1"*40}})
                lk.write_json_file(paths["matrix_scenarios"],[{
                    "name":"smoke","target":"0x"+"2"*40,
                    "function":"ping()","actor":"Alice","expected":"success"
                }])
                output=io.StringIO()
                with patch.object(lk,"run_foundry",return_value=0) as run, \
                     patch.object(lk,"write_generated_test",return_value=os.path.join(tmp,"Matrix_smoke.t.sol")):
                    with redirect_stdout(output):
                        self.assertEqual(lk.run_matrix(
                            {"target":"0x"+"2"*40,"abi_paths":{},"wallets":{}},
                            ["test","smoke"]
                        ),0)
                self.assertEqual(run.call_args.args[0][0],"test")
            finally:
                lk.WORKSPACE_DIR=old

    def test_txpool_uses_rpc_methods_not_cast_flag(self):
        config={"rpc":"http://127.0.0.1:8545"}
        with patch.object(lk,"rpc_json",side_effect=[
            {"pending":"0x1","queued":"0x2"},
            {"pending":{},"queued":{}},
        ]) as rpc_json:
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(lk.run_txpool(config, []),0)
                self.assertEqual(lk.run_txpool(config, ["content"]),0)
        self.assertEqual(rpc_json.call_args_list[0].args[:2], ("http://127.0.0.1:8545","txpool_status"))
        self.assertEqual(rpc_json.call_args_list[1].args[:2], ("http://127.0.0.1:8545","txpool_content"))

    def test_foundry_test_wrappers(self):
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_fuzz(["--fuzz-runs", "10"]), 0)
            self.assertEqual(run.call_args.args[0][:1], ["test"])
            self.assertEqual(lk.run_invariant({}, ["--match-test", "invariant_x"]), 0)
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_mutate(["--match-path", "test/X.t.sol"]), 0)
            self.assertEqual(run.call_args.args[0][:2], ["test", "--mutate"])
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_symbolic(["emit"]), 0)
            self.assertEqual(run.call_args.args[0][:2], ["test", "--symbolic"])
            self.assertIn("--emit-regression", run.call_args.args[0])


    def test_cheatcode_reference_and_brutalize(self):
        output=io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(lk.run_cheatcodes(["store"]), 0)
        self.assertIn("vm.store", output.getvalue())
        with patch.object(lk, "run_foundry", return_value=0) as run:
            self.assertEqual(lk.run_brutalize(["--match-test", "testFoo"]), 0)
        self.assertEqual(run.call_args.args[0][:2], ["test", "--brutalize"])

    def test_probe_all_configured_actors(self):
        config={
            "target":"0x"+"3"*40,
            "actor":"Alice",
            "wallets":{
                "Alice":{"address":"0x"+"1"*40},
                "Bob":{"address":"0x"+"2"*40},
            },
        }
        captured={}
        def fake_write(prefix,content):
            captured["content"]=content
            return "test/Lowkey_probe.t.sol"
        with patch.object(lk, "encode_target_call", return_value=("ping()", "abcdef")), \
             patch.object(lk, "write_generated_test", side_effect=fake_write), \
             patch.object(lk, "run_foundry", return_value=0):
            self.assertEqual(lk.run_probe(config, ["ping"]), 0)
        self.assertIn("ACTOR Alice", captured["content"])
        self.assertIn("ACTOR Bob", captured["content"])


    def test_impersonated_actor_configuration(self):
        address="0x"+"1"*40
        config={"wallets":{},"actor":None,"rpc":"http://127.0.0.1:8545"}
        info={"url":"http://127.0.0.1:8545","client":"anvil/v1.8.3","accounts":[]}
        with patch.object(lk,"anvil_rpc_info",return_value=info), \
             patch.object(lk,"run_cast",return_value=lk.CommandResult("0x0",0)), \
             patch.object(lk,"save_config"):
            self.assertEqual(lk.run_impersonate(config,[address,"whale"]),0)
        self.assertEqual(config["actor"],"whale")
        self.assertEqual(config["wallets"]["whale"]["source"],"anvil-impersonated")

    def test_run_cast_uses_unlocked_for_impersonated_actor(self):
        target="0x"+"3"*40
        actor="0x"+"1"*40
        config={
            "target":target,
            "rpc":"http://127.0.0.1:8545",
            "actor":"whale",
            "wallets":{"whale":{"source":"anvil-impersonated","address":actor}},
        }
        with patch.object(lk,"cast_output",return_value=(0,"ok","")) as cast_output:
            self.assertEqual(lk.run_cast(["send","ping()"],config),0)
        sent_args=cast_output.call_args.args[0]
        self.assertIn("--unlocked",sent_args)
        self.assertIn(actor,sent_args)

    def test_proxy_aware_abi_discovery(self):
        target="0x"+"1"*40
        implementation="0x"+"2"*40
        artifact={
            "contractName":"Impl",
            "abi":[{"type":"function","name":"release","inputs":[],"stateMutability":"nonpayable"}],
            "deployedBytecode":{"object":"0x60016000"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path=pathlib.Path(tmp)/"Impl.json"
            path.write_text(json.dumps(artifact),encoding="utf-8")
            with patch.object(lk,"local_artifact_paths",return_value=[str(path)]), \
                 patch.object(lk,"effective_rpc",return_value="http://127.0.0.1:8545"), \
                 patch.object(lk,"discover_deployments",return_value=[]), \
                 patch.object(lk,"cast_output",side_effect=[
                     (0,implementation,""),
                     (0,"0x60016000",""),
                 ]):
                config={"target_contract":None,"abi_paths":{}}
                result=lk.auto_abi_path(target,config)
        self.assertEqual(result,str(path))
        self.assertEqual(config["target_contract"],"Impl")
        self.assertEqual(config["abi_paths"][target],str(path))


    def test_storage_layout_inspection_uses_target_project_root(self):
        target = "0x" + "4" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            outside = pathlib.Path(tmp) / "outside"
            root.mkdir()
            outside.mkdir()
            (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Escrow",
                "abi_paths": {target: str(root / "out" / "Escrow.json")},
                "project_roots": {target: str(root)},
            }
            forge_layout = {
                "storage": [{"label": "escrow", "slot": "1", "type": "t_mapping"}],
                "types": {"t_mapping": {"encoding": "mapping", "key": "t_uint256", "value": "t_uint256"}},
            }
            old = os.getcwd()
            os.chdir(outside)
            try:
                with patch.object(
                    lk, "read_artifact", return_value={"contractName": "Escrow", "storageLayout": {}}
                ), patch.object(
                    lk.subprocess, "run",
                    return_value=subprocess.CompletedProcess(
                        ["forge"], 0, json.dumps(forge_layout), ""
                    ),
                ) as run:
                    types, storage = lk.storage_layout_details(config)
            finally:
                os.chdir(old)
        self.assertEqual(storage, forge_layout["storage"])
        self.assertEqual(types, forge_layout["types"])
        self.assertEqual(run.call_args.kwargs["cwd"], str(root))

    def test_fork_state_dump_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=os.path.join(tmp,"state.json")
            config={"rpc":"http://127.0.0.1:8545"}
            with patch.object(lk,"anvil_rpc_info",return_value={"url":config["rpc"]}), \
                 patch.object(lk,"rpc_json",side_effect=["0xabcdef",True]):
                self.assertEqual(lk.run_fork_state(config,["dump",path]),0)
                self.assertEqual(lk.run_fork_state(config,["load",path]),0)
            self.assertEqual(pathlib.Path(path).read_text(), "0xabcdef")

    def test_fork_status_without_fork_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=lk.FORK_FILE
            lk.FORK_FILE=os.path.join(tmp,"fork.json")
            try:
                output=io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(lk.run_fork(["status"]),0)
                self.assertIn("Fork: stopped",output.getvalue())
            finally:
                lk.FORK_FILE=old

    def test_symbolic_emit_alias(self):
        with patch.object(lk,"run_foundry",return_value=0) as run:
            self.assertEqual(lk.run_symbolic(["emit","--match-test","testFoo"]),0)
        self.assertIn("--emit-regression",run.call_args.args[0])

    def test_project_lab_target_survives_context_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "out" / "Fixture.sol").mkdir(parents=True)
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (root / "src" / "Fixture.sol").write_text(
                "pragma solidity ^0.8.20; contract Fixture { }",
                encoding="utf-8",
            )
            (root / "out" / "Fixture.sol" / "Fixture.json").write_text(
                json.dumps({
                    "contractName": "Fixture",
                    "sourceName": "src/Fixture.sol",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )
            lk.audit_context.set_target(
                root,
                address="0x" + "1" * 40,
                contract="Fixture",
                artifact=str(root / "out" / "Fixture.sol" / "Fixture.json"),
                source="project-lab",
            )
            config = {"target": None, "target_contract": None, "abi_paths": {}, "rpc": None, "actor": None}
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root),                  patch.object(lk, "effective_rpc", return_value=None):
                state = lk._sync_audit_context(config, root)
            self.assertEqual(state["target"]["address"], "0x" + "1" * 40)
            self.assertEqual(state["target"]["contract"], "Fixture")
            self.assertEqual(state["target"]["source"], "project-lab")

    def test_investigate_sets_shared_focus_and_suggests_tools(self):
        signal={
            "id":"SLITHER-ABC123",
            "tool":"slither",
            "title":"Low-level external call",
            "impact":"Informational",
            "confidence":"High",
            "file":"src/Vault.sol",
            "line":42,
            "function":"withdraw()",
            "description":"External call path",
            "meaning":"Review the external call boundary.",
            "why":"The callee controls execution.",
            "next":"Trace state changes.",
        }
        root=pathlib.Path.cwd()
        with patch.object(lk.audit_context,"set_focus",return_value=signal) as set_focus, \
             patch.object(lk.audit_context,"foundry_project_root",return_value=root):
            output=io.StringIO()
            with redirect_stdout(output):
                result=lk.run_investigate({},["SLITHER-ABC123"])
        self.assertEqual(result,0)
        set_focus.assert_called_once_with("SLITHER-ABC123",root)
        rendered=output.getvalue()
        self.assertIn("LOWKEY INVESTIGATION FOCUS",rendered)
        self.assertIn("lk changes 'withdraw()'",rendered)


    def test_investigate_quotes_full_abi_signatures_for_shell(self):
        signal={
            "id":"SLITHER-ABC123",
            "tool":"slither",
            "title":"Reentrancy risk",
            "impact":"Medium",
            "confidence":"Medium",
            "file":"src/Vault.sol",
            "line":42,
            "function":"createPool(address,address,uint256,uint256,address,address[])",
            "description":"External call path",
        }
        root=pathlib.Path.cwd()
        with patch.object(lk.audit_context,"set_focus",return_value=signal) as set_focus,              patch.object(lk.audit_context,"foundry_project_root",return_value=root):
            output=io.StringIO()
            with redirect_stdout(output):
                result=lk.run_investigate({},["SLITHER-ABC123"])
        self.assertEqual(result,0)
        set_focus.assert_called_once_with("SLITHER-ABC123",root)
        rendered=output.getvalue()
        self.assertIn("lk fn 'createPool(address,address,uint256,uint256,address,address[])'",rendered)
        self.assertIn("lk ask 'createPool(address,address,uint256,uint256,address,address[])'",rendered)
        self.assertIn("lk changes 'createPool(address,address,uint256,uint256,address,address[])'",rendered)
        self.assertIn("lk generate test 'createPool(address,address,uint256,uint256,address,address[])'",rendered)

    def test_audit_mode_restores_menu_and_runs_automatic_poc_path(self):
        config={"target":"0x"+"1"*40,"session_active":True}
        choices=iter(["0"])
        with patch.object(lk,"save_config"),              patch.object(lk,"run_workspace"),              patch.object(lk,"run_matrix"),              patch.object(lk,"run_checklist"),              patch.object(lk,"run_session_lifecycle"),              patch.object(lk,"run_scan",return_value=0) as scan,              patch.object(lk,"run_audit",return_value=0) as audit,              patch("builtins.input",side_effect=lambda prompt: next(choices)),              patch.object(lk.audit_context,"load",return_value={"target":{"address":config["target"]}}):
            output=io.StringIO()
            with redirect_stdout(output):
                result=lk.run_audit_mode(config,[],interactive=True)
        self.assertEqual(result,0)
        scan.assert_called_once_with([])
        audit.assert_called_once_with(config,["--checks"])
        rendered=output.getvalue()
        self.assertIn("7) full evidence pass   8) generate PoC   9) protocol walkthrough   0) exit",rendered)

    def test_dispatch_uses_audit_session_commands(self):
        config = {"target": None}
        with patch.object(lk, "run_audit_mode", return_value=0) as audit_mode,              patch.object(lk, "run_context", return_value=0) as context,              patch.object(lk, "run_signals", return_value=0) as findings,              patch.object(lk, "run_investigate", return_value=0) as focus:
            self.assertEqual(lk.dispatch_command("audit", [], config), 0)
            self.assertEqual(lk.dispatch_command("audit", ["auto", "--checks"], config), 0)
            self.assertEqual(lk.dispatch_command("findings", [], config), 0)
            self.assertEqual(lk.dispatch_command("focus", ["SIG-1"], config), 0)
            self.assertEqual(lk.dispatch_command("context", [], config), 0)
        audit_mode.assert_any_call(config, [])
        audit_mode.assert_any_call(config, ["auto", "--checks"])
        self.assertEqual(audit_mode.call_count, 2)
        findings.assert_called_once()
        focus.assert_called_once()
        context.assert_called_once()


    def test_audit_detects_existing_anvil_without_starting_one(self):
        config={"target":"0x"+"1"*40,"session_active":True,"actor":None,"wallets":{},"labels":{}}
        info={"url":"http://127.0.0.1:8545","accounts":["0x"+"2"*40]}
        choices=iter(["0"])
        with patch.object(lk,"save_config"),              patch.object(lk,"run_workspace"),              patch.object(lk,"run_matrix"),              patch.object(lk,"run_checklist"),              patch.object(lk,"run_session_lifecycle"),              patch.object(lk,"anvil_rpc_info",return_value=info),              patch.object(lk,"ensure_project_anvil") as ensure,              patch.object(lk,"_bootstrap_audit_target",return_value=config["target"]),              patch.object(lk,"run_scan",return_value=0),              patch.object(lk,"run_audit",return_value=0),              patch("builtins.input",side_effect=lambda prompt: next(choices)),              patch.object(lk.audit_context,"load",return_value={"target":{"address":config["target"]}}):
            result=lk.run_audit_mode(config,[],interactive=True)
        self.assertEqual(result,0)
        ensure.assert_not_called()
        self.assertEqual(config["actor"],"lab-deployer")
        self.assertEqual(config["wallets"]["lab-deployer"]["address"],"0x"+"2"*40)

    def test_audit_auto_starts_anvil_when_missing(self):
        config={"target":None,"session_active":True,"actor":None,"wallets":{},"labels":{}}
        info={"url":"http://127.0.0.1:8545","accounts":["0x"+"3"*40]}
        choices=iter(["0"])
        with patch.object(lk,"save_config"),              patch.object(lk,"run_workspace"),              patch.object(lk,"run_matrix"),              patch.object(lk,"run_checklist"),              patch.object(lk,"run_session_lifecycle"),              patch.object(lk,"anvil_rpc_info",return_value=None),              patch.object(lk,"detect_project",return_value={"stacks":["foundry"]}),              patch.object(lk,"ensure_project_anvil",return_value=info) as ensure,              patch.object(lk,"_bootstrap_audit_target",return_value=None),              patch.object(lk,"run_scan",return_value=0),              patch.object(lk,"run_audit",return_value=0),              patch("builtins.input",side_effect=lambda prompt: next(choices)),              patch.object(lk.audit_context,"load",return_value={}):
            result=lk.run_audit_mode(config,["auto"],interactive=True)
        self.assertEqual(result,0)
        ensure.assert_called_once_with(config, lk.audit_context.foundry_project_root())
        self.assertEqual(config["actor"],"lab-deployer")
        self.assertEqual(config["wallets"]["lab-deployer"]["address"],"0x"+"3"*40)

    def test_audit_noninteractive_skips_menu(self):
        config={"target":"0x"+"4"*40,"session_active":True,"actor":None,"wallets":{},"labels":{}}
        with patch.object(lk,"save_config"),              patch.object(lk,"run_workspace"),              patch.object(lk,"run_matrix"),              patch.object(lk,"run_checklist"),              patch.object(lk,"run_session_lifecycle"),              patch.object(lk,"anvil_rpc_info",return_value=None),              patch.object(lk,"_bootstrap_audit_target",return_value=config["target"]),              patch.object(lk,"run_scan",return_value=0),              patch.object(lk,"run_audit",return_value=0),              patch("builtins.input") as prompt:
            result=lk.run_audit_mode(config,[],interactive=False)
        self.assertEqual(result,0)
        prompt.assert_not_called()

    def test_dispatch_exposes_shared_audit_commands(self):
        with patch.object(lk, "run_context", return_value=0) as context,              patch.object(lk, "run_signals", return_value=0) as signals:
            lk.dispatch_command("context", [], {})
            lk.dispatch_command("signals", [], {})
        context.assert_called_once()
        signals.assert_called_once()


    def test_dispatch_exposes_lab_commands(self):
        config = {}
        calls = {}
        with patch.object(lk, "run_calldata", side_effect=lambda *_: calls.setdefault("calldata", 1)), \
             patch.object(lk, "run_probe", side_effect=lambda *_: calls.setdefault("probe", 1)), \
             patch.object(lk, "run_state_diff", side_effect=lambda *_: calls.setdefault("state-diff", 1)), \
             patch.object(lk, "run_fuzz", side_effect=lambda *_: calls.setdefault("fuzz", 1)), \
             patch.object(lk, "run_invariant", side_effect=lambda *_: calls.setdefault("invariant", 1)), \
             patch.object(lk, "run_mutate", side_effect=lambda *_: calls.setdefault("mutate", 1)), \
             patch.object(lk, "run_symbolic", side_effect=lambda *_: calls.setdefault("symbolic", 1)):
            lk.dispatch_command("calldata", ["0x12345678"], config)
            lk.dispatch_command("probe", ["ping"], config)
            lk.dispatch_command("state-diff", ["ping"], config)
            lk.dispatch_command("fuzz", [], config)
            lk.dispatch_command("invariant", [], config)
            lk.dispatch_command("mutate", [], config)
            lk.dispatch_command("symbolic", [], config)
        self.assertEqual(
            set(calls),
            {"calldata", "probe", "state-diff", "fuzz", "invariant", "mutate", "symbolic"},
        )

    def test_parse_state_diff_output_extracts_changed_slots(self):
        output = """
[PASS] test_state_diff() (gas: 247291)
Logs:
  CALL createescrow(uint256,address)
  SUCCESS true
  ETH_SENT 1000000000000000000
  STORAGE_CHANGES 1
  SLOT
  0x""" + "1" * 64 + """
  FROM
  0x""" + "0" * 64 + """
  TO
  0x""" + "0" * 63 + "1" + """
"""
        parsed = lk.parse_state_diff_output(output)
        self.assertEqual(parsed["gas"], 247291)
        self.assertEqual(parsed["call"], "createescrow(uint256,address)")
        self.assertTrue(parsed["success"])
        self.assertEqual(parsed["eth_sent"], 10**18)
        self.assertEqual(len(parsed["slots"]), 1)
        self.assertEqual(parsed["slots"][0]["to"], "0x" + "0" * 63 + "1")

    def test_source_mapping_declarations_parses_public_struct_mapping(self):
        from tempfile import TemporaryDirectory

        source = """pragma solidity ^0.8.20;
contract Escrow {
    mapping(address => uint256 amount) public balances;
    mapping(uint256 value => Create Escrow) public escrow;

    enum status { waiting, funded, rejected, released }

    struct Create {
        address creator;
        address recipient;
        uint256 amount;
        status currentstatus;
    }
}
"""
        with TemporaryDirectory() as directory:
            path = Path(directory) / "Escrow.sol"
            path.write_text(source)
            declarations = lk.source_mapping_declarations(directory)

        self.assertEqual([item["label"] for item in declarations], ["balances", "escrow"])
        self.assertEqual(declarations[0]["key_type"], "address")
        self.assertEqual(declarations[0]["value_type"], "uint256")
        self.assertEqual(declarations[1]["key_type"], "uint256")
        self.assertEqual(declarations[1]["value_type"], "Create")
        self.assertEqual(
            [name for name, _ in declarations[1]["fields"]],
            ["creator", "recipient", "amount", "currentstatus"],
        )

    def test_storage_type_label_normalizes_internal_foundry_ids(self):
        types = {
            "t_address": {"label": "t_address"},
            "t_uint256": {"label": "t_uint256"},
        }
        self.assertEqual(lk.storage_type_label(types, "t_address"), "address")
        self.assertEqual(lk.storage_type_label(types, "t_uint256"), "uint256")

    def test_mapping_slot_match_decodes_struct_field_name(self):
        address = "0x" + "1" * 40
        changed_slot = "0x" + "2" * 64
        types = {
            "t_address": {"label": "address", "encoding": "inplace"},
            "t_uint256": {"label": "uint256", "encoding": "inplace"},
            "t_struct(Create)_storage": {
                "encoding": "inplace",
                "members": [
                    {"label": "creator", "slot": "0", "type": "t_address"},
                    {"label": "amount", "slot": "1", "type": "t_uint256"},
                ],
            },
            "t_mapping(uint256,t_struct(Create)_storage)": {
                "encoding": "mapping",
                "key": "t_uint256",
                "value": "t_struct(Create)_storage",
            },
        }
        storage = [{
            "label": "escrow",
            "slot": "1",
            "type": "t_mapping(uint256,t_struct(Create)_storage)",
        }]

        def fake_index(args, input_text=None):
            candidate = str(args[3])
            if candidate == "1":
                return 0, changed_slot, ""
            return 0, "0x" + "3" * 64, ""

        with patch.object(lk, "storage_layout_details", return_value=(types, storage)),              patch.object(lk, "configured_actor_addresses", return_value=[("Alice", address)]),              patch.object(lk, "cast_output", side_effect=fake_index):
            labels = lk.mapping_slot_matches(
                {"target": "0x" + "9" * 40, "wallets": {"Alice": {"address": address}}},
                "createescrow(uint256,address)",
                ["1 ether", "Bob"],
                address,
                [changed_slot],
            )

        self.assertEqual(
            labels[changed_slot.lower()],
            ("escrow[1].creator", "t_address"),
        )

    def test_dispatch_exposes_simple_audit_aliases(self):
        config={}
        calls={}
        with patch.object(lk,"run_probe",side_effect=lambda *_: calls.setdefault("try",1)), \
             patch.object(lk,"run_state_diff",side_effect=lambda *_: calls.setdefault("changes",1)), \
             patch.object(lk,"run_cast",side_effect=lambda *_: calls.setdefault("cast",1)):
            lk.dispatch_command("try",["release"],config)
            lk.dispatch_command("changes",["release"],config)
            lk.dispatch_command("read",["release"],config)
            lk.dispatch_command("send",["release"],config)
        self.assertEqual(set(calls),{"try","changes","cast"})


    def test_generated_test_path_is_stable_for_same_content(self):
        first = lk.generated_test_path("probe_release", "same-content")
        second = lk.generated_test_path("probe_release", "same-content")
        third = lk.generated_test_path("probe_release", "different-content")
        self.assertEqual(first, second)
        self.assertNotEqual(first, third)

    def test_state_diff_parser_accepts_fallback_write(self):
        slot = "0x" + "a" * 64
        after = "0x" + "b" * 64
        output = (
            "[PASS] test_state_diff() (gas: 123)\n"
            "Logs:\n"
            "  CALL createescrow(uint256,address)\n"
            "  SUCCESS true\n"
            "  ETH_SENT 1000000000000000000\n"
            "  FALLBACK_WRITES 1\n"
            "  SLOT\n"
            "  " + slot + "\n"
            "  FROM\n"
            "  unknown\n"
            "  TO\n"
            "  " + after + "\n"
            "  STORAGE_CHANGES 0\n"
        )
        parsed = lk.parse_state_diff_output(output)
        self.assertEqual(parsed["fallback_writes"], 1)
        self.assertEqual(len(parsed["slots"]), 1)
        self.assertEqual(parsed["slots"][0]["slot"], slot)
        self.assertEqual(parsed["slots"][0]["from"], "unknown")

    def test_state_diff_links_evidence_to_active_focus(self):
        config = {
            "target": "0x" + "3" * 40,
            "actor": "Alice",
            "wallets": {"Alice": {"address": "0x" + "1" * 40}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc = \"src\"\n", encoding="utf-8")
            signal = lk.audit_context.add_signal({
                "tool": "slither",
                "check": "low-level-calls",
                "title": "Raw external call",
                "file": "src/Escrow.sol",
                "line": 7,
                "function": "release",
            }, root)
            lk.audit_context.update(root, focus={"signal_id": signal["id"], "title": signal["title"]})
            output = (
                "[PASS] test_state_diff() (gas: 123)\n"
                "Logs:\n"
                "  CALL release()\n"
                "  SUCCESS true\n"
                "  ETH_SENT 1000000000000000000\n"
                "  STORAGE_CHANGES 1\n"
                "  SLOT\n"
                "  0x" + "a" * 64 + "\n"
                "  FROM\n"
                "  0x" + "0" * 64 + "\n"
                "  TO\n"
                "  0x" + "1" * 64 + "\n"
            )
            with patch.object(lk, "encode_target_call", return_value=("release()", "abcdef")), \
                 patch.object(lk, "write_generated_test", return_value=str(root / "test" / "Lowkey_state_diff.t.sol")), \
                 patch.object(lk, "run_foundry", return_value=lk.CommandResult(output, 0)), \
                 patch.object(lk, "storage_layout_details", return_value=({}, [])), \
                 patch.object(lk, "mapping_slot_matches", return_value={}):
                old = os.getcwd()
                os.chdir(root)
                try:
                    self.assertEqual(lk.run_state_diff(config, ["release"]), 0)
                finally:
                    os.chdir(old)

            refreshed = lk.audit_context.load(root)
            linked = next(item for item in refreshed["signals"] if item["id"] == signal["id"])
            self.assertEqual(len(linked["evidence"]), 1)
            self.assertEqual(linked["evidence"][0]["storage_changes"][0]["slot"], "0x" + "a" * 64)
            self.assertEqual(linked["evidence"][0]["storage_changes"][0]["from"], "0x" + "0" * 64)
            self.assertEqual(linked["evidence"][0]["storage_changes"][0]["to"], "0x" + "1" * 64)
    def test_state_diff_parser_extracts_json_storage_write(self):
        slot = "0x" + "a" * 64
        previous = "0x" + "0" * 64
        new_value = "0x" + "0" * 63 + "7"
        output = (
            "[PASS] test_state_diff() (gas: 123)\n"
            "Logs:\n"
            "  CALL ping(uint256)\n"
            "  SUCCESS true\n"
            "  ETH_SENT 0\n"
            "  STATE_DIFF_JSON_BEGIN\n"
            '  {"storageAccesses":[{"slot":"' + slot + '","isWrite":true,"previousValue":"' + previous + '","newValue":"' + new_value + '","reverted":false}]}\n'
            "  STATE_DIFF_JSON_END\n"
            "  STORAGE_CHANGES 0\n"
        )
        parsed = lk.parse_state_diff_output(output)
        self.assertTrue(parsed["state_diff_json"])
        self.assertEqual(len(parsed["slots"]), 1)
        self.assertEqual(parsed["slots"][0]["slot"], slot)



    def test_walkthrough_random_values_cover_bool_uint_and_actor_swap(self):
        actors = [
            lk.walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            lk.walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
            lk.walkthrough.Actor("Attacker", "0x" + "3" * 40, 2),
        ]
        rng = __import__("random").Random(7)
        bool_value = lk.walkthrough._random_sol_value(
            {"type": "bool", "name": "allowed"}, actors, actors[0].address, rng
        )
        uint_value = lk.walkthrough._random_sol_value(
            {"type": "uint256", "name": "amount"}, actors, actors[0].address, rng
        )
        address_value = lk.walkthrough._random_sol_value(
            {"type": "address", "name": "recipient"}, actors, actors[0].address, rng
        )
        self.assertIsInstance(bool_value, bool)
        self.assertIsInstance(uint_value, int)
        self.assertIn(address_value, {a.address for a in actors} | {"0x" + "0" * 40})

    def test_walkthrough_clickable_function_link_contains_vscode_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Example.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20;\ncontract Example {\n    function ping() external {}\n}\n",
                encoding="utf-8",
            )
            model = lk.walkthrough.ContractModel(
                name="Example",
                source="src/Example.sol",
                artifact="out/Example.sol/Example.json",
                abi=[{"type":"function","name":"ping","inputs":[],"outputs":[]}],
                function_locations={"ping": 3},
            )
            previous = os.environ.pop("LOWKEY_NO_LINKS", None)
            try:
                linked = lk.walkthrough._function_link(root, model, "ping")
            finally:
                if previous is not None:
                    os.environ["LOWKEY_NO_LINKS"] = previous
            self.assertIn("ping", linked)
            self.assertIn("\x1b]8;;", linked)
            self.assertTrue("vscode://file/" in linked or "file://" in linked)

    def test_walkthrough_source_graph_resolves_interface_to_implementation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir()
            factory_source = src / "Factory.sol"
            child_source = src / "Child.sol"
            factory_source.write_text(
                """pragma solidity ^0.8.20;
interface IChild { function initialize(address owner) external; }
contract Factory {
    function create(address child) external { IChild(child).initialize(msg.sender); }
}
""",
                encoding="utf-8",
            )
            child_source.write_text(
                """pragma solidity ^0.8.20;
interface IChild { function initialize(address owner) external; }
contract Child is IChild {
    function initialize(address owner) external {}
}
""",
                encoding="utf-8",
            )
            factory = lk.walkthrough.ContractModel(
                name="Factory",
                source=str(factory_source),
                artifact="out/Factory.sol/Factory.json",
                abi=[{"type":"function","name":"create","inputs":[{"type":"address","name":"child"}]}],
                functions=["create(address)"],
            )
            child = lk.walkthrough.ContractModel(
                name="Child",
                source=str(child_source),
                artifact="out/Child.sol/Child.json",
                abi=[{"type":"function","name":"initialize","inputs":[{"type":"address","name":"owner"}]}],
                functions=["initialize(address)"],
                bases=["IChild"],
            )
            factory_source_text=factory_source.read_text(encoding="utf-8")
            factory.type_bindings={"child":"IChild"}
            edges = lk.walkthrough._build_source_calls(factory, [factory, child], factory_source_text)
            self.assertTrue(any(
                edge["to_contract"] == "Child" and edge["to_function"] == "initialize"
                for edge in edges
            ))

    def test_walkthrough_story_accepts_models_for_clickable_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Example.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20;\ncontract Example {\n    function ping() external {}\n}\n",
                encoding="utf-8",
            )
            model = lk.walkthrough.ContractModel(
                name="Example",
                source="src/Example.sol",
                artifact="out/Example.sol/Example.json",
                abi=[{"type":"function","name":"ping","inputs":[],"outputs":[]}],
                function_locations={"ping": 3},
            )
            step = lk.walkthrough.Step(
                1, "Alice", "Example", "0x" + "1" * 40, "ping()", [],
            )
            rendered = lk.walkthrough._render_protocol_story(
                root, [step], step,
                [lk.walkthrough.Actor("Alice","0x"+"2"*40,0)],
                [model],
                False,
            )
            self.assertIn("ping", rendered)


    def test_walkthrough_infers_msg_value_from_source_not_function_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            source = root / "src" / "BountyArena.sol"
            source.write_text(
                """pragma solidity ^0.8.20;
contract BountyArena {
    function createBounty(address addr, uint256 amount) external payable {
        require(amount >= 0, "topup");
        require(amount == msg.value, "attach eth");
    }
}
""",
                encoding="utf-8",
            )
            model = lk.walkthrough.ContractModel(
                name="BountyArena",
                source="src/BountyArena.sol",
                artifact="out/BountyArena.sol/BountyArena.json",
            )
            fn = {
                "type": "function",
                "name": "createBounty",
                "stateMutability": "payable",
                "inputs": [
                    {"name": "addr", "type": "address"},
                    {"name": "amount", "type": "uint256"},
                ],
            }
            amount = 10**18
            self.assertEqual(
                lk.walkthrough._value_for(
                    fn,
                    model=model,
                    root=root,
                    args=["0x" + "1" * 40, amount],
                ),
                amount,
            )

    def test_walkthrough_payable_without_payment_guard_remains_conservative(self):
        fn = {
            "type": "function",
            "name": "createThing",
            "stateMutability": "payable",
            "inputs": [{"name": "amount", "type": "uint256"}],
        }
        self.assertEqual(
            lk.walkthrough._value_for(fn, args=[10**18]),
            0,
        )

    def test_walkthrough_failed_call_diagnostic_signature_accepts_caller_address(self):
        model = lk.walkthrough.ContractModel(
            name="Factory",
            source="src/Factory.sol",
            artifact="out/Factory.sol/Factory.json",
            abi=[{
                "type": "function",
                "name": "create",
                "inputs": [],
                "outputs": [],
                "stateMutability": "nonpayable",
            }],
        )
        step = lk.walkthrough.Step(
            1, "Alice", "Factory", "0x" + "1" * 40,
            "create()", [],
        )
        with patch.object(
            lk.walkthrough,
            "_diagnose_argument_contracts",
            return_value=(None, []),
        ), patch.object(
            lk.walkthrough,
            "_probe_source_guards",
            return_value=(None, []),
        ), patch.object(
            lk.walkthrough,
            "_read_zero_address_diagnostics",
            return_value=(None, []),
        ), patch.object(
            lk.walkthrough,
            "_source_guard_lines",
            return_value=[],
        ), patch.object(
            lk.walkthrough,
            "_cmd",
            return_value=(1, "", "encode failed"),
        ):
            origin, diagnostics = lk.walkthrough._diagnose_failed_call(
                pathlib.Path("."),
                "http://127.0.0.1:8545",
                step,
                model,
                [model],
                "0x" + "2" * 40,
            )
        self.assertIsNone(origin)
        self.assertTrue(any("could not encode" in item for item in diagnostics))


    def test_event_decoder_error_propagates_nonzero_status(self):
        config = {"target": None}
        with patch.object(lk, "cast_output", return_value=(0, "", "Error: ABI decoding failed: buffer overrun while deserializing")):
            result = lk.run_event(config, ["Ping(uint256)", "0xdeadbeef"])
        self.assertNotEqual(result, 0)
    def test_event_decoder_stdout_error_also_propagates_nonzero_status(self):
        config = {"target": None}
        with patch.object(lk, "cast_output", return_value=(0, "Error: ABI decoding failed: buffer overrun while deserializing", "")):
            result = lk.run_event(config, ["Ping(uint256)", "0xdeadbeef"])
        self.assertNotEqual(result, 0)


    def test_walkthrough_expected_admin_is_not_marked_as_review_candidate(self):
        step = lk.walkthrough.Step(
            1,
            "Alice",
            "ConfidencePoolFactory",
            "0x" + "1" * 40,
            "setDefaultOutcomeModerator(address)",
            ["0x" + "2" * 40],
            status="success",
            diagnostics=["Alice owner == caller", "ownership check passed"],
        )
        status, why, next_step = lk.walkthrough._human_probe_status(step)
        self.assertEqual(status, "🟦 EXPECTED ADMIN")
        self.assertIn("owner/admin", why)
        self.assertIn("untrusted actor", next_step)

    def test_benchmark_adapter_is_protocol_pluggable(self):
        model = lk.walkthrough.ContractModel(
            name="Counter",
            source="src/Counter.sol",
            artifact="out/Counter.sol/Counter.json",
            functions=["increment()"],
        )
        adapter = importlib.import_module("lowkey.walkthrough_benchmarks")
        self.assertIsNone(adapter.get_benchmark_adapter(model, [model], {}))

    def test_real_world_pattern_scanner_covers_recurring_bug_families(self):
        patterns = importlib.import_module("lowkey.walkthrough_finding_patterns")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            source = '''
            pragma solidity ^0.8.20;
            contract PatternFixture {
                mapping(address => uint256) public balances;
                mapping(address => bool) public claimed;
                address public owner;
                uint256[] public items;
                function claim(uint256 amount) external {
                    payable(msg.sender).transfer(amount);
                    balances[msg.sender] -= amount;
                }
                function unsafeToken(address token, uint256 amount) external {
                    token.transfer(msg.sender, amount);
                }
                function oracle(address feed) external {
                    (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound) = IFeed(feed).latestRoundData();
                    answer;
                    roundId; startedAt; updatedAt; answeredInRound;
                }
                function processAll() external {
                    for (uint256 i = 0; i < items.length; ++i) { items[i] += 1; }
                }
                function verify(bytes32 digest, bytes calldata sig) external {
                    ecrecover(digest, uint8(0), bytes32(0), bytes32(0));
                    sig;
                }
                function initialize(address owner_) external { owner = owner_; }
                function randomWinner() external returns (uint256) { return uint256(block.timestamp); }
                function feePath() external { uint256 fee = 100; fee; }
                function callbackPrice(address pool) external { pool.call(abi.encodeWithSignature("poke()")); IPrice(pool).price(); }
            }
            interface IFeed { function latestRoundData() external view returns (uint80,int256,uint256,uint256,uint80); }
            '''
            (root / "src" / "PatternFixture.sol").write_text(source, encoding="utf-8")
            abi = [
                {"type": "function", "name": name, "stateMutability": "nonpayable", "inputs": []}
                for name in ("processAll", "verify", "initialize", "unsafeToken", "claim", "oracle", "feePath", "callbackPrice")
            ]
            abi += [{"type": "function", "name": "randomWinner", "stateMutability": "nonpayable", "inputs": []}]
            model = lk.walkthrough.ContractModel(
                name="PatternFixture", source="src/PatternFixture.sol", artifact="out/PatternFixture.json",
                abi=abi, arrays=[{"name": "items", "type": "uint256[]"}]
            )
            results = patterns.scan_model(root, model)
            ids = {item.pattern_id for item in results}
            self.assertIn("REPLAY-001", ids)
            self.assertIn("REENTRANCY-001", ids)
            self.assertIn("ORACLE-001", ids)
            self.assertIn("DOS-001", ids)
            self.assertIn("SIG-001", ids)
            self.assertIn("TOKEN-001", ids)
            self.assertIn("INIT-001", ids)
            self.assertIn("RNG-001", ids)
            self.assertIn("READONLY-001", ids)
            self.assertIn("ECONOMIC-001", ids)

    def test_real_world_pattern_scanner_covers_zero_address_and_expiry_boundaries(self):
        patterns = importlib.import_module("lowkey.walkthrough_finding_patterns")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            source = '''
            pragma solidity ^0.8.20;
            contract BoundaryFixture {
                address public router;
                function setRouter(address router_) external { router = router_; }
                function execute(uint256 deadline) external { require(deadline >= block.timestamp); }
            }
            '''
            (root / "src" / "BoundaryFixture.sol").write_text(source, encoding="utf-8")
            model = lk.walkthrough.ContractModel(
                name="BoundaryFixture", source="src/BoundaryFixture.sol", artifact="out/BoundaryFixture.json",
                abi=[
                    {"type": "function", "name": "setRouter", "stateMutability": "nonpayable", "inputs": [{"name": "router_", "type": "address"}]},
                    {"type": "function", "name": "execute", "stateMutability": "nonpayable", "inputs": [{"name": "deadline", "type": "uint256"}]},
                ],
            )
            ids = {item.pattern_id for item in patterns.scan_model(root, model)}
            self.assertIn("ZEROADDR-001", ids)
            self.assertIn("TIME-001", ids)

    def test_real_world_pattern_scanner_supports_vyper_functions(self):
        patterns = importlib.import_module("lowkey.walkthrough_finding_patterns")
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            source = '''
@external
def withdraw(amount: uint256):
    raw_call(msg.sender, b"", value=amount)
    balances[msg.sender] -= amount
'''
            (root / "src" / "Vault.vy").write_text(source, encoding="utf-8")
            model = lk.walkthrough.ContractModel(
                name="Vault", source="src/Vault.vy", artifact="out/Vault.json", kind="vyper",
                abi=[{"type": "function", "name": "withdraw", "stateMutability": "nonpayable", "inputs": [{"name": "amount", "type": "uint256"}]}],
            )
            results = patterns.scan_model(root, model)
            ids = {item.pattern_id for item in results}
            self.assertIn("REPLAY-001", ids)
            self.assertIn("REENTRANCY-001", ids)

    def test_replay_pattern_requires_a_real_second_value_delta_for_confirmation(self):
        patterns = importlib.import_module("lowkey.walkthrough_finding_patterns")
        actors = [
            lk.walkthrough.Actor("Alice", "0x" + "1" * 40, 0),
            lk.walkthrough.Actor("Bob", "0x" + "2" * 40, 1),
            lk.walkthrough.Actor("Attacker", "0x" + "3" * 40, 2),
        ]
        first = lk.walkthrough.Step(1, "Attacker", "Vault", "0x" + "4" * 40, "claim()", [], status="success")
        second = lk.walkthrough.Step(2, "Attacker", "Vault", "0x" + "4" * 40, "claim()", [], status="success")
        key = actors[2].address.lower()
        second.token_balance_before = {key: 10}
        second.token_balance_after = {key: 10}
        story = lk.walkthrough.WalkthroughStory("RP-01", "Replay probe", "test", [])
        patterns.assess_replay_story(story, [first, second], actors)
        self.assertEqual(story.signal, "REVIEW")

        second.token_balance_after = {key: 11}
        patterns.assess_replay_story(story, [first, second], actors)
        self.assertEqual(story.signal, "CONFIRMED")

    def test_benchmark_adapter_can_be_registered_without_core_changes(self):
        adapter_module = importlib.import_module("lowkey.walkthrough_benchmarks")

        class DemoAdapter:
            adapter_id = "demo"
            display_name = "Demo"
            def matches(self, model, models, config):
                return model.name == "DemoContract"

        adapter_module.register_benchmark_adapter(DemoAdapter)
        model = lk.walkthrough.ContractModel(
            name="DemoContract", source="src/Demo.sol", artifact="out/Demo.json"
        )
        selected = adapter_module.get_benchmark_adapter(model, [model], {})
        self.assertIsNotNone(selected)
        self.assertEqual(selected.adapter_id, "demo")
        adapter_module._REGISTERED_BENCHMARK_ADAPTERS.remove(DemoAdapter)

    def test_fn_help_is_not_treated_as_a_function_query(self):
        config = lk.fresh_config()
        with patch("builtins.print"):
            result = lk.run_functions(config, "-h")
        self.assertEqual(result, 0)

    def test_finding_without_args_returns_usage_cleanly(self):
        config = lk.fresh_config()
        with patch("builtins.print"):
            result = lk.dispatch_command("finding", [], config)
        self.assertEqual(result, 0)

    def test_focus_quoted_function_signature_explains_function_vs_signal(self):
        config = lk.fresh_config()
        config["target"] = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "batchRedeemWToken",
            "inputs": [
                {
                    "name": "",
                    "type": "tuple[]",
                    "components": [
                        {"name": "wToken", "type": "address"},
                        {"name": "wTokenAmount", "type": "uint256"},
                        {"name": "recipient", "type": "address"},
                    ],
                }
            ],
        }]
        with patch.object(lk, "load_abi", return_value=abi), patch("builtins.print") as printed:
            result = lk.run_investigate(
                config,
                ["batchRedeemWToken((address,uint256,address)[])"],
            )
        self.assertEqual(result, 0)
        rendered = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn("LOWKEY FUNCTION FOCUS", rendered)
        self.assertIn("Focus stores an audit signal, not a function selection.", rendered)

    def test_actor_rebinds_anvil_default_profile(self):
        old = '0x' + '1' * 40
        new = '0x' + '2' * 40
        config = {
            'actor': 'Alice',
            'wallets': {
                'Alice': {'source': 'anvil-default', 'anvil_index': 0, 'address': old},
            },
            'labels': {old: 'Alice'},
        }
        info = {'url': 'http://127.0.0.1:8545', 'accounts': [old, '0x' + '3' * 40, '0x' + '4' * 40, new]}
        with patch.object(lk, 'anvil_rpc_info', return_value=info), patch.object(lk, 'save_config'):
            result = lk.select_anvil_actor(config, 3, 'Alice')
        self.assertEqual(result, 0)
        self.assertEqual(config['wallets']['Alice']['anvil_index'], 3)
        self.assertEqual(config['wallets']['Alice']['address'], new)
        self.assertNotIn(old, config.get('labels', {}))
        self.assertEqual(lk.assigned_anvil_address(config, new), 'Alice')
        self.assertIsNone(lk.assigned_anvil_address(config, old))

    def test_project_lab_uses_lab_deployer_for_reserved_account_zero_display(self):
        config = {
            "actor": "Alice",
            "wallets": {
                "Alice": {"source": "anvil-default", "anvil_index": 0, "address": "0x"+"1"*40},
            },
            "labels": {},
            "aliases": {},
            "targets": {},
            "abi_paths": {},
            "project_roots": {},
        }
        address = "0x"+"1"*40
        target = "0x"+"2"*40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            script = root / "script" / "LocalAudit.s.sol"
            script.parent.mkdir(parents=True, exist_ok=True)
            script.write_text(
                "pragma solidity ^0.8.20; contract LocalAudit { function run() external {} }",
                encoding="utf-8",
            )

            def ensure_deployer(cfg, addr, index=0, select_if_empty=False):
                cfg["wallets"]["lab-deployer"] = {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": addr,
                    "internal": True,
                }
                cfg["actor"] = "lab-deployer"

            with patch.object(lk, "_ensure_lab_deployer", side_effect=ensure_deployer), \
                 patch.object(lk, "run_foundry", return_value=lk.CommandResult(f"LOWKEY_TARGET {target}", 0)), \
                 patch.object(lk, "_lab_script_environment", return_value=({}, [])), \
                 patch.object(lk, "_validate_project_lab_target", return_value=("Escrow", "/tmp/Escrow.json", None)), \
                 patch.object(lk, "set_lab_target"), \
                 patch.object(lk, "_print_security_scope"), \
                 patch.object(lk, "audit_context"), \
                 patch.object(lk, "_project_source_mutations", return_value=[]), \
                 patch.object(lk, "discover_deployments", return_value=[]), \
                 patch.object(lk, "derive_default_anvil_key", return_value="0x"+"3"*64):
                result = lk.run_project_lab_script(
                    config, root, str(script), "http://127.0.0.1:8545",
                    [address], "0x"+"3"*64,
                )

        self.assertEqual(result, 0)
        self.assertEqual(config["actor"], "lab-deployer")
        self.assertEqual(
            lk.actor_display(config),
            "lab-deployer (0x"+"1"*40+") [Anvil #0]",
        )

    def test_internal_lab_deployer_is_still_used_for_address_labels(self):
        address = "0x" + "1" * 40
        config = {
            "actor": "lab-deployer",
            "wallets": {
                "lab-deployer": {
                    "source": "anvil-default",
                    "anvil_index": 0,
                    "address": address,
                    "internal": True,
                }
            },
            "labels": {},
        }
        rendered = lk.apply_labels(f"creator = {address} [address]", config)
        self.assertEqual(rendered, f"creator = lab-deployer ({address}) [address]")

    def test_internal_lab_deployer_reclaims_reserved_account(self):
        address = '0x' + '1' * 40
        config = {
            'actor': 'Alice',
            'wallets': {
                'Alice': {'source': 'anvil-default', 'anvil_index': 0, 'address': address},
            },
            'labels': {address: 'Alice'},
        }
        with patch.object(lk, 'save_config'):
            lk._ensure_lab_deployer(config, address, 0)
        self.assertEqual(config['actor'], 'lab-deployer')
        self.assertTrue(config['wallets']['lab-deployer']['internal'])
        self.assertIsNone(lk.assigned_anvil_address(config, address))
        self.assertNotIn(address, config['labels'])

    def test_security_pattern_is_first_class_project_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            signal = lk.audit_context.add_security_pattern(
                root,
                pattern_id="REPLAY-001",
                title="Replayable payout / claim path",
                contract="Fallback",
                function="withdraw()",
                file="src/Fallback.sol",
                line=30,
                logic="A one-shot entitlement is dangerous when repeated payout does not consume state.",
                description="withdraw() is an economic payout path.",
                next_step="Compare state and value across two persistent calls.",
                provenance=["public audit research"],
                verification_status="REVIEW",
                verification_evidence=["same isolated call succeeded; persistent delta not proven"],
                evidence_mode="source+stateful",
            )
            self.assertEqual(signal["category"], "security-pattern")
            self.assertEqual(signal["pattern_id"], "REPLAY-001")
            self.assertEqual(signal["verification_status"], "REVIEW")
            self.assertEqual(
                lk.audit_context.security_patterns(root, function="withdraw()")[0]["id"],
                signal["id"],
            )

    def test_security_pattern_summary_is_shared_with_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            lk.audit_context.add_security_pattern(
                root,
                pattern_id="AUTH-001",
                title="Authorization signal",
                contract="Demo",
                function="setValue()",
                file="src/Demo.sol",
                line=10,
                verification_status="CANDIDATE",
            )
            summary = lk._security_pattern_summary(root)
            self.assertEqual(summary["total"], 1)
            self.assertEqual(summary["candidates"], 1)

    def test_security_pattern_rescan_preserves_live_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            first = lk.audit_context.add_security_pattern(
                root,
                pattern_id="REPLAY-001",
                title="Replay path",
                contract="Demo",
                function="withdraw()",
                file="src/Demo.sol",
                verification_status="REVIEW",
                verification_evidence=["persistent story result"],
                evidence_mode="source+stateful",
            )
            second = lk.audit_context.add_security_pattern(
                root,
                pattern_id="REPLAY-001",
                title="Replay path",
                contract="Demo",
                function="withdraw()",
                file="src/Demo.sol",
                verification_status="CANDIDATE",
                verification_evidence=[],
                evidence_mode="source",
            )
            self.assertEqual(second["verification_status"], "REVIEW")
            self.assertIn("persistent story result", second["verification"]["evidence"])

    def test_risk_surface_includes_shared_security_pattern_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            target = "0x" + "1" * 40
            artifact = root / "Demo.json"
            artifact.write_text(json.dumps({
                "contractName": "Demo",
                "abi": [{
                    "type": "function",
                    "name": "withdraw",
                    "inputs": [],
                    "outputs": [],
                    "stateMutability": "nonpayable",
                }],
            }), encoding="utf-8")
            config = {
                "target": target,
                "target_contract": "Demo",
                "abi_paths": {target: str(artifact)},
            }
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root):
                lk.audit_context.add_security_pattern(
                    root,
                    pattern_id="REPLAY-001",
                    title="Replay path",
                    contract="Demo",
                    function="withdraw()",
                    file="src/Demo.sol",
                    verification_status="REVIEW",
                )
                with patch.object(lk, "_sync_security_patterns"):
                    with patch("sys.stdout", new_callable=io.StringIO) as stream:
                        with patch.object(lk, "load_abi", return_value=json.loads(artifact.read_text())["abi"]):
                            lk.run_risk(config)
                    rendered = stream.getvalue()
            self.assertIn("SECURITY PATTERN SIGNALS", rendered)
            self.assertIn("REPLAY-001", rendered)
            self.assertIn("REVIEW", rendered)

    def test_lab_target_refreshes_shared_security_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            address = "0x" + "1" * 40
            with patch.object(lk, "_sync_security_patterns") as sync:
                lk.set_lab_target({}, root, address, "Demo", "out/Demo.json")
            sync.assert_called_once_with(root)



    def test_security_pattern_summary_delegates_to_shared_audit_context(self):
        expected = {"total": 3, "reviews": 1, "confirmed": 1, "candidates": 1}
        with patch.object(lk.audit_context, "security_pattern_summary", return_value=expected):
            self.assertEqual(lk._security_pattern_summary(pathlib.Path("/tmp/project")), expected)

if __name__ == "__main__":
    unittest.main()

