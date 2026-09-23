import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "generator.py"

spec = importlib.util.spec_from_file_location("lowkey_generator", MODULE)
generator = importlib.util.module_from_spec(spec)
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
            artifact.write_text(json.dumps({"contractName": "Vault", "abi": []}), encoding="utf-8")
            with patch.object(generator.Path, "cwd", return_value=root):
                with patch.object(generator, "_run", return_value=(0, "", "")):
                    result = generator.run_generate({}, ["deployment", "Vault"])
            self.assertEqual(result, 0)
            generated = root / "script" / "LowkeyDeploy_Vault.s.sol"
            self.assertTrue(generated.exists())
            self.assertIn("Lowkey-generated deployment", generated.read_text(encoding="utf-8"))

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
            self.assertIn("0xdeadbeef", text)
            self.assertIn("vm.prank(attacker)", text)
            self.assertIn("vm.snapshot()", text)

    def test_help_mentions_all_generation_modes(self):
        output = io.StringIO()
        with redirect_stdout(output):
            result = generator.run_generate({}, ["--help"])
        self.assertEqual(result, 0)
        self.assertIn("lk generate deployment", output.getvalue())
        self.assertIn("lk generate poc", output.getvalue())
        self.assertIn("lk generate test", output.getvalue())


if __name__ == "__main__":
    unittest.main()
