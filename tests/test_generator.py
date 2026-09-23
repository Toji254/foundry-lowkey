import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "generator.py"

spec = importlib.util.spec_from_file_location("lowkey_generator", MODULE)
generator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = generator
spec.loader.exec_module(generator)


class LowkeyGeneratorTests(unittest.TestCase):
    def test_parse_send_extracts_call_without_private_key(self):
        command = (
            "cast send 0x" + "1" * 40
            + ' "createescrow(uint256,address)" 100 Bob --value 1ether'
            + " --private-key 0x" + "a" * 64
        )
        parsed = generator._parse_send(command)
        self.assertIsNotNone(parsed)
        target, function, args, value = parsed
        self.assertEqual(target, "0x" + "1" * 40)
        self.assertEqual(function, "createescrow(uint256,address)")
        self.assertEqual(args, ["100", "Bob"])
        self.assertEqual(value, "1ether")

    def test_value_normalization(self):
        self.assertEqual(generator._value("1ether"), "1 ether")
        self.assertEqual(generator._value("2gwei"), "2 gwei")
        self.assertEqual(generator._value("1.5ether"), "1500000000000000000")

    def test_deployment_renderer_teaches_and_uses_constructor_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Vault { constructor(address owner) {} function owner() external view returns(address) {} }",
                encoding="utf-8",
            )
            artifact = root / "out" / "Vault.sol" / "Vault.json"
            artifact.parent.mkdir(parents=True)
            payload = {
                "contractName": "Vault",
                "abi": [
                    {
                        "type": "constructor",
                        "inputs": [{"name": "owner", "type": "address"}],
                    },
                    {
                        "type": "function",
                        "name": "owner",
                        "inputs": [],
                        "outputs": [{"type": "address"}],
                        "stateMutability": "view",
                    },
                ],
            }
            artifact.write_text(json.dumps(payload), encoding="utf-8")
            output, env_help = generator.render_deployment(root, "Vault", artifact, payload)
            self.assertIn('vm.envAddress("LOWKEY_CONSTRUCTOR_ARG_1")', output)
            self.assertIn("constructor input", output.lower())
            self.assertIn("vm.startBroadcast()", output)
            self.assertIn("vm.writeJson", output)
            self.assertIn("LOWKEY_CONSTRUCTOR_ARG_1", env_help[0])

    def test_find_artifact_ignores_stale_symbol_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "EthEscrow.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )

            stale = root / "out" / "EthEscrow.sol" / "EthEscrow.json"
            stale.parent.mkdir(parents=True)
            stale.write_text(
                json.dumps({
                    "contractName": "EthEscrow",
                    "abi": [],
                    "bytecode": {"object": "0x6001"},
                }),
                encoding="utf-8",
            )

            real = root / "out" / "EthEscrow.sol" / "Escrow.json"
            real.write_text(
                json.dumps({
                    "contractName": "Escrow",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )

            found = generator.find_artifact(root, "EthEscrow")

            self.assertIsNotNone(found)
            path, payload = found
            self.assertEqual(path, real)
            self.assertEqual(payload["contractName"], "Escrow")


    def test_find_artifact_prefers_source_file_over_stale_symbol(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "EthEscrow.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )

            source_artifact = root / "out" / "EthEscrow.sol" / "Escrow.json"
            source_artifact.parent.mkdir(parents=True)
            source_artifact.write_text(
                json.dumps({
                    "contractName": "Escrow",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )

            stale = root / "out" / "Other.sol" / "EthEscrow.json"
            stale.parent.mkdir(parents=True)
            stale.write_text(
                json.dumps({
                    "contractName": "EthEscrow",
                    "abi": [],
                    "bytecode": {"object": "0x6001"},
                }),
                encoding="utf-8",
            )

            found = generator.find_artifact(root, "EthEscrow")

            self.assertIsNotNone(found)
            path, payload = found
            self.assertEqual(path, source_artifact)
            self.assertEqual(payload["contractName"], "Escrow")


    def test_find_artifact_resolves_artifact_without_contract_name_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "EthEscrow.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )
            artifact = root / "out" / "EthEscrow.sol" / "Escrow.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )

            found = generator.find_artifact(root, "EthEscrow")

            self.assertIsNotNone(found)
            self.assertEqual(found[0], artifact)


    def test_find_artifact_accepts_source_artifact_without_bytecode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "EthEscrow.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )
            artifact = root / "out" / "EthEscrow.sol" / "Escrow.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "contractName": "Escrow",
                    "abi": [],
                }),
                encoding="utf-8",
            )

            found = generator.find_artifact(root, "EthEscrow")

            self.assertIsNotNone(found)
            self.assertEqual(found[0], artifact)
            self.assertEqual(found[1]["contractName"], "Escrow")


    def test_find_artifact_resolves_source_filename_symbol(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "EthEscrow.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )
            artifact = root / "out" / "EthEscrow.sol" / "Escrow.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "contractName": "Escrow",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )

            found = generator.find_artifact(root, "EthEscrow")

            self.assertIsNotNone(found)
            path, payload = found
            self.assertEqual(path.name, "Escrow.json")
            self.assertEqual(payload["contractName"], "Escrow")


    def test_find_artifact_rejects_only_stale_source_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "EthEscrow.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )

            stale = root / "out" / "EthEscrow.sol" / "EthEscrow.json"
            stale.parent.mkdir(parents=True)
            stale.write_text(
                json.dumps({
                    "contractName": "EthEscrow",
                    "abi": [],
                    "bytecode": {"object": "0x6001"},
                }),
                encoding="utf-8",
            )

            self.assertIsNone(generator.find_artifact(root, "EthEscrow"))


    def test_generate_deployment_uses_artifact_stem_without_contract_name_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "src" / "EthEscrow.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )
            artifact = root / "out" / "EthEscrow.sol" / "Escrow.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )
            with patch.object(generator.Path, "cwd", return_value=root):
                with patch.object(generator, "_run", return_value=(0, "", "")):
                    result = generator.run_generate({}, ["deployment", "EthEscrow"])
            self.assertEqual(result, 0)
            generated = root / "script" / "LowkeyDeploy_Escrow.s.sol"
            self.assertTrue(generated.exists())
            text = generated.read_text(encoding="utf-8")
            self.assertIn("import { Escrow }", text)
            self.assertIn("instance = new Escrow();", text)


    def test_generate_deployment_replaces_stale_lowkey_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir(parents=True)
            (root / "src" / "EthEscrow.sol").write_text(
                "pragma solidity ^0.8.20; contract Escrow {}",
                encoding="utf-8",
            )
            artifact = root / "out" / "EthEscrow.sol" / "Escrow.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "contractName": "Escrow",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )

            script_dir = root / "script"
            script_dir.mkdir()
            old_named = script_dir / "LowkeyDeploy_EthEscrow_20260923.s.sol"
            old_named.write_text(
                "// /// @title Lowkey-generated deployment for EthEscrow\n",
                encoding="utf-8",
            )
            user_file = script_dir / "LowkeyDeploy_EthEscrow_Custom.s.sol"
            user_file.write_text(
                "// user-authored deployment script\n",
                encoding="utf-8",
            )

            with patch.object(generator.Path, "cwd", return_value=root):
                with patch.object(generator, "_run", return_value=(0, "", "")):
                    result = generator.run_generate({}, ["deployment", "EthEscrow"])

            self.assertEqual(result, 0)
            self.assertFalse(old_named.exists())
            self.assertTrue(user_file.exists())
            self.assertTrue((script_dir / "LowkeyDeploy_Escrow.s.sol").exists())


    def test_generate_deployment_writes_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir(parents=True)
            (root / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault {}",
                encoding="utf-8",
            )
            artifact = root / "out" / "Vault.sol" / "Vault.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps({
                    "contractName": "Vault",
                    "abi": [],
                    "bytecode": {"object": "0x6000"},
                }),
                encoding="utf-8",
            )
            with patch.object(generator.Path, "cwd", return_value=root):
                with patch.object(generator, "_run", return_value=(0, "", "")) as run:
                    result = generator.run_generate({}, ["deployment", "Vault"])
            self.assertEqual(result, 0)
            generated = root / "script" / "LowkeyDeploy_Vault.s.sol"
            self.assertTrue(generated.exists())
            self.assertIn("Lowkey-generated deployment", generated.read_text(encoding="utf-8"))
            self.assertEqual(run.call_args.args[2], ["build", "--skip", "test", "--skip", "script"])

    def test_generate_test_uses_supplied_calldata(self):
        target = "0x" + "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with patch.object(generator.Path, "cwd", return_value=root):
                result = generator.run_generate(
                    {"target": target},
                    ["test", "foo()", "--calldata", "0xdeadbeef"],
                )
            self.assertEqual(result, 0)
            generated = next((root / "test").glob("LowkeyTest_*.t.sol"))
            text = generated.read_text(encoding="utf-8")
            self.assertIn('hex"deadbeef"', text)
            self.assertIn("vm.prank(attacker)", text)
            self.assertIn("vm.snapshot()", text)

    def test_audit_candidate_prefers_focused_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            context = {
                "focus": {"signal_id": "SLITHER-FOCUSED"},
                "signals": [
                    {
                        "id": "SLITHER-OTHER",
                        "status": "open",
                        "impact": "High",
                        "confidence": "High",
                        "check": "reentrancy-eth",
                    },
                    {
                        "id": "SLITHER-FOCUSED",
                        "status": "investigating",
                        "impact": "Low",
                        "confidence": "Low",
                        "check": "tx-origin",
                        "title": "tx.origin used for authorization",
                        "file": "src/Vault.sol",
                        "line": 42,
                        "function": "withdraw(address)",
                        "description": "Authorization path uses tx.origin.",
                        "next": "Build a proxy-contract reproduction.",
                    },
                ],
                "latest": {"tx_hash": "0x" + "a" * 64},
                "tools": {
                    "slither": {"finding_count": 2},
                    "source-triage": {"count": 4},
                    "risk": {"functions": [{}, {}]},
                    "trace": {"summary": "transaction trace 0xdead..."},
                },
            }
            with patch.object(generator.audit_context, "load", return_value=context):
                evidence = generator._audit_candidate(root)
            self.assertEqual(evidence["candidate"]["id"], "SLITHER-FOCUSED")
            self.assertEqual(evidence["candidate"]["mode"], "authorization")
            self.assertEqual(evidence["tools"]["slither_findings"], 2)
            self.assertEqual(evidence["tools"]["source_triage_markers"], 4)

    def test_generate_test_writes_evidence_brief(self):
        target = "0x" + "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            context = {
                "target": {"address": target, "contract": "Target"},
                "focus": {"signal_id": "SLITHER-ABC"},
                "signals": [{
                    "id": "SLITHER-ABC",
                    "status": "investigating",
                    "impact": "Medium",
                    "confidence": "High",
                    "check": "tx-origin",
                    "title": "Authorization review",
                    "file": "src/Vault.sol",
                    "line": 12,
                    "function": "withdraw(address)",
                    "description": "Authorization depends on transaction origin.",
                    "next": "Test with a proxy caller.",
                    "actions": ["probe", "matrix", "generate test"],
                }],
                "latest": {"tx_hash": None},
                "tools": {
                    "slither": {"finding_count": 1},
                    "source-triage": {"count": 2},
                    "risk": {"functions": [{"signature": "withdraw(address)"}]},
                },
            }
            with patch.object(generator.Path, "cwd", return_value=root):
                with patch.object(generator.audit_context, "load", return_value=context):
                    result = generator.run_generate({}, ["test", "withdraw(address)", "--calldata", "0xdeadbeef"])
            self.assertEqual(result, 0)
            generated = next((root / "test").glob("LowkeyTest_*.t.sol"))
            source = generated.read_text(encoding="utf-8")
            self.assertIn("SLITHER-ABC", source)
            self.assertIn("Authorization review", source)

            briefs = list((root / ".audit" / "poc").glob("LowkeyTest_*.json"))
            self.assertEqual(len(briefs), 1)
            brief = json.loads(briefs[0].read_text(encoding="utf-8"))
            self.assertEqual(brief["evidence"]["candidate"]["id"], "SLITHER-ABC")
            self.assertEqual(brief["evidence"]["tools"]["slither_findings"], 1)

    def test_generate_poc_allows_focused_signal_without_concrete_send(self):
        target = "0x" + "2" * 40
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            context = {
                "focus": {"signal_id": "SLITHER-DEF"},
                "signals": [{
                    "id": "SLITHER-DEF",
                    "status": "investigating",
                    "impact": "Medium",
                    "confidence": "Medium",
                    "check": "reentrancy-eth",
                    "title": "ETH reentrancy",
                    "file": "src/Vault.sol",
                    "line": 20,
                    "description": "External ETH call needs reentrancy review.",
                }],
                "latest": {},
                "tools": {},
            }
            with patch.object(generator.Path, "cwd", return_value=root):
                with patch.object(generator.audit_context, "load", return_value=context):
                    result = generator.run_generate({"target": target}, ["poc"])
            self.assertEqual(result, 0)
            generated = next((root / "script").glob("LowkeyPoC_*.s.sol"))
            source = generated.read_text(encoding="utf-8")
            self.assertIn("SLITHER-DEF", source)
            self.assertIn("PLACEHOLDER", source)

    def test_help_mentions_all_generation_modes(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = generator.run_generate({}, ["--help"])
        self.assertEqual(result, 0)
        self.assertIn("lk generate deployment", output.getvalue())
        self.assertIn("lk generate poc", output.getvalue())
        self.assertIn("lk generate test", output.getvalue())



    def test_validate_calldata_rejects_shell_text(self):
        with self.assertRaises(ValueError):
            generator._validate_calldata("~/Smart-contract-development-journey/ETH\\ Escrow")

    def test_validate_value_rejects_shell_text(self):
        with self.assertRaises(ValueError):
            generator._validate_value("cd ~/Smart-contract-development-journey")


if __name__ == "__main__":
    unittest.main()
