import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkey_chisel_workflow", MODULE)
lk = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(lk)


class ChiselWorkflowTests(unittest.TestCase):
    def _project(self, root, name="Vault", source="src/Vault.sol", abi=None, bytecode=None):
        root.mkdir(parents=True, exist_ok=True)
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nout = "out"\n',
            encoding="utf-8",
        )
        source_path = root / source
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(
            "pragma solidity ^0.8.20;\ncontract " + name + " {}\n",
            encoding="utf-8",
        )
        artifact_path = root / "out" / pathlib.Path(source).name / f"{name}.json"
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact = {
            "contractName": name,
            "sourceName": source,
            "abi": abi if abi is not None else [],
            "bytecode": bytecode if bytecode is not None else {"object": "0x60006000", "linkReferences": {}},
        }
        artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
        return artifact_path

    def test_discovers_only_deployable_first_party_solidity_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            self._project(root, "Vault")
            self._project(root, "VaultFactory", "src/VaultFactory.sol")

            # Interfaces and test-only artifacts must not become runnable targets.
            test_source = root / "test" / "IVault.t.sol"
            test_source.parent.mkdir(parents=True)
            test_source.write_text("interface IVault {}\n", encoding="utf-8")
            test_artifact = root / "out" / "IVault.t.sol" / "IVault.json"
            test_artifact.parent.mkdir(parents=True)
            test_artifact.write_text(json.dumps({
                "contractName": "IVault",
                "sourceName": "test/IVault.t.sol",
                "abi": [],
                "bytecode": {"object": "0x6000"},
            }), encoding="utf-8")

            found = lk._chisel_project_contracts(root)

            self.assertEqual(
                [(item["name"], item["source"]) for item in found],
                [("Vault", "src/Vault.sol"), ("VaultFactory", "src/VaultFactory.sol")],
            )

    def test_explicit_contract_name_and_source_path_resolve(self):
        candidates = [
            {"name": "Vault", "source": "src/Vault.sol"},
            {"name": "VaultFactory", "source": "src/VaultFactory.sol"},
        ]
        selected, error = lk._select_chisel_contract(candidates, "VaultFactory")
        self.assertIsNone(error)
        self.assertEqual(selected["name"], "VaultFactory")

        selected, error = lk._select_chisel_contract(candidates, "src/Vault.sol")
        self.assertIsNone(error)
        self.assertEqual(selected["name"], "Vault")

    def test_remembered_project_target_wins_over_ambiguous_candidates(self):
        candidates = [
            {"name": "Vault", "source": "src/Vault.sol", "artifact": "/tmp/Vault.json"},
            {"name": "VaultFactory", "source": "src/VaultFactory.sol", "artifact": "/tmp/VaultFactory.json"},
        ]
        remembered = {"contract": "VaultFactory", "artifact": "/tmp/VaultFactory.json"}
        with patch.object(lk, "project_context_target", return_value=remembered):
            selected, error = lk._select_chisel_contract(candidates, config={}, root=pathlib.Path("/tmp/project"))
        self.assertIsNone(error)
        self.assertEqual(selected["name"], "VaultFactory")

    def test_ambiguous_noninteractive_selection_explains_contract_flag(self):
        candidates = [
            {"name": "Vault", "source": "src/Vault.sol"},
            {"name": "VaultFactory", "source": "src/VaultFactory.sol"},
        ]
        with patch.object(lk, "project_context_target", return_value=None), \
             patch.object(lk.sys.stdin, "isatty", return_value=False):
            selected, error = lk._select_chisel_contract(candidates, config={}, root=pathlib.Path("/tmp/project"))
        self.assertIsNone(selected)
        self.assertIn("lk chisel --contract", error)
        self.assertIn("VaultFactory", error)


    def test_interface_guide_lists_abi_reads_writes_payable_events_and_returns(self):
        contract = {
            "abi": [
                {
                    "type": "function",
                    "name": "EscrowID",
                    "stateMutability": "view",
                    "inputs": [{"name": "ID", "type": "bytes32"}],
                    "outputs": [
                        {"name": "creator", "type": "address"},
                        {"name": "recipient", "type": "address"},
                        {"name": "amount", "type": "uint256"},
                        {"name": "currentstatus", "type": "uint8"},
                        {"name": "id", "type": "bytes32"},
                    ],
                },
                {
                    "type": "function",
                    "name": "createEscrow",
                    "stateMutability": "payable",
                    "inputs": [{"name": "recipient", "type": "address"}],
                    "outputs": [{"name": "escrowId", "type": "bytes32"}],
                },
                {
                    "type": "function",
                    "name": "acceptEscrow",
                    "stateMutability": "nonpayable",
                    "inputs": [{"name": "escrowId", "type": "bytes32"}],
                    "outputs": [],
                },
                {
                    "type": "event",
                    "name": "CreateEscrow",
                    "inputs": [
                        {"name": "recipient", "type": "address", "indexed": True},
                        {"name": "amount", "type": "uint256", "indexed": False},
                    ],
                },
            ]
        }

        interface = lk._chisel_contract_interface(contract)

        self.assertIn(("READ", "EscrowID(bytes32 ID) -> (address creator, address recipient, uint256 amount, uint8 currentstatus, bytes32 id)"), interface["functions"])
        self.assertIn(("WRITE", "acceptEscrow(bytes32 escrowId)"), interface["functions"])
        self.assertIn(("PAYABLE", "createEscrow(address recipient) -> bytes32 escrowId"), interface["functions"])
        self.assertEqual(interface["events"], ["CreateEscrow(address indexed recipient, uint256 amount)"])

    def test_interface_guide_explains_valid_repl_input_and_private_visibility(self):
        contract = {
            "abi": [
                {
                    "type": "function",
                    "name": "balanceOf",
                    "stateMutability": "view",
                    "inputs": [{"name": "account", "type": "address"}],
                    "outputs": [{"name": "", "type": "uint256"}],
                }
            ]
        }
        output = io.StringIO()
        with redirect_stdout(output):
            lk._chisel_print_contract_guide(contract, auto_instance=True)

        rendered = output.getvalue()
        self.assertIn("[READ   ] balanceOf(address account) -> uint256 return1", rendered)
        self.assertIn("WITHOUT a trailing semicolon", rendered)
        self.assertIn("ABI signatures are a reference, not commands", rendered)
        self.assertIn("private state such as a private nonce has no getter", rendered)


    def test_prelude_imports_contract_and_auto_instantiates_safe_constructor(self):
        contract = {
            "name": "Vault",
            "source": "src/Vault.sol",
            "constructor_inputs": [],
            "constructor_payable": False,
            "has_linked_libraries": False,
        }
        with tempfile.TemporaryDirectory() as tmp:
            prelude = lk._write_chisel_prelude(contract, tmp)
            import_source = (pathlib.Path(tmp) / "00-lowkey-import.sol").read_text(encoding="utf-8")
            instance_source = (pathlib.Path(tmp) / "10-lowkey-instance.sol").read_text(encoding="utf-8")

        self.assertTrue(prelude["auto_instance"])
        self.assertIn('import {Vault as LowkeyLoadedTarget} from "src/Vault.sol";', import_source)
        self.assertIn("new LowkeyLoadedTarget()", instance_source)
        self.assertIn("lowkeyTarget", prelude["next_step"])

    def test_constructor_arguments_payable_and_linked_libraries_are_not_guessed(self):
        cases = [
            ({
                "name": "Vault",
                "source": "src/Vault.sol",
                "constructor_inputs": [{"name": "owner", "type": "address"}],
                "constructor_payable": False,
                "has_linked_libraries": False,
            }, "address owner"),
            ({
                "name": "Vault",
                "source": "src/Vault.sol",
                "constructor_inputs": [],
                "constructor_payable": True,
                "has_linked_libraries": False,
            }, "payable"),
            ({
                "name": "Vault",
                "source": "src/Vault.sol",
                "constructor_inputs": [],
                "constructor_payable": False,
                "has_linked_libraries": True,
            }, "linked libraries"),
        ]
        for contract, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as tmp:
                prelude = lk._write_chisel_prelude(contract, tmp)
                self.assertFalse(prelude["auto_instance"])
                self.assertFalse((pathlib.Path(tmp) / "10-lowkey-instance.sol").exists())
                self.assertIn(expected, prelude["next_step"])

    def test_run_chisel_builds_then_launches_with_project_prelude_and_native_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "foundry-app"
            artifact_path = self._project(root, "Vault")
            build_calls = []
            launch_calls = []

            class BuildResult:
                code = 0
                def __str__(self):
                    return "Compiler run successful"

            def fake_build(args, capture=False, cwd=None):
                build_calls.append((args, capture, pathlib.Path(cwd)))
                return BuildResult()

            def fake_launch(command, cwd=None):
                launch_calls.append((command, pathlib.Path(cwd)))
                prelude_index = command.index("--prelude") + 1
                prelude_dir = pathlib.Path(command[prelude_index])
                self.assertTrue((prelude_dir / "00-lowkey-import.sol").is_file())
                self.assertTrue((prelude_dir / "10-lowkey-instance.sol").is_file())
                self.assertIn("--profile", command)
                self.assertIn("lite", command)
                self.assertIn("-v", command)
                self.assertTrue(prelude_dir.is_dir())
                return SimpleNamespace(returncode=0)

            output = io.StringIO()
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "tool_path", return_value="/usr/bin/chisel"), \
                 patch.object(lk, "run_foundry", side_effect=fake_build), \
                 patch.object(lk.subprocess, "run", side_effect=fake_launch), \
                 redirect_stdout(output):
                result = lk.run_chisel(["--profile", "lite"], config={})

            self.assertEqual(result, 0)
            self.assertEqual(build_calls, [(["build", "--profile", "lite"], True, root)])
            self.assertEqual(launch_calls[0][1], root)
            self.assertIn("Vault", output.getvalue())
            self.assertIn("temporary Chisel EVM", output.getvalue())
            prelude_path = pathlib.Path(launch_calls[0][0][launch_calls[0][0].index("--prelude") + 1])
            self.assertFalse(prelude_path.exists(), "temporary bootstrap files should be removed after Chisel exits")

    def test_build_failure_prevents_chisel_from_starting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "foundry-app"
            self._project(root, "Vault")

            class BuildResult:
                code = 1
                def __str__(self):
                    return "ParserError: expected ;"

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "tool_path", return_value="/usr/bin/chisel"), \
                 patch.object(lk, "run_foundry", return_value=BuildResult()), \
                 patch.object(lk.subprocess, "run") as launch, \
                 redirect_stdout(io.StringIO()):
                result = lk.run_chisel([], config={})

            self.assertNotEqual(result, 0)
            launch.assert_not_called()

    def test_no_build_uses_existing_artifacts_without_running_forge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "foundry-app"
            self._project(root, "Vault")

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "tool_path", return_value="/usr/bin/chisel"), \
                 patch.object(lk, "run_foundry", side_effect=AssertionError("build must be skipped")), \
                 patch.object(lk.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as launch, \
                 redirect_stdout(io.StringIO()):
                result = lk.run_chisel(["--no-build"], config={})

            self.assertEqual(result, 0)
            launch.assert_called_once()

    def test_native_chisel_help_and_session_commands_bypass_project_bootstrap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "foundry-app"
            self._project(root, "Vault")

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "tool_path", return_value="/usr/bin/chisel"), \
                 patch.object(lk, "run_foundry", side_effect=AssertionError("native command must bypass build")), \
                 patch.object(lk.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as launch:
                result = lk.run_chisel(["list"], config={})

            self.assertEqual(result, 0)
            self.assertEqual(launch.call_args.args[0], ["/usr/bin/chisel", "list"])

    def test_native_chisel_help_bypasses_build_and_contract_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "foundry-app"
            self._project(root, "Vault")
            self._project(root, "VaultFactory", "src/VaultFactory.sol")

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "tool_path", return_value="/usr/bin/chisel"), \
                 patch.object(lk, "run_foundry", side_effect=AssertionError("help must bypass build")), \
                 patch.object(lk.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as launch:
                result = lk.run_chisel(["--help"], config={})

            self.assertEqual(result, 0)
            self.assertEqual(launch.call_args.args[0], ["/usr/bin/chisel", "--help"])

    def test_contract_aware_eval_builds_and_loads_the_selected_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "foundry-app"
            self._project(root, "Vault")
            build_calls = []

            class BuildResult:
                code = 0
                def __str__(self):
                    return "Compiler run successful"

            def fake_build(args, capture=False, cwd=None):
                build_calls.append((args, capture, pathlib.Path(cwd)))
                return BuildResult()

            def fake_launch(command, cwd=None):
                prelude_dir = pathlib.Path(command[command.index("--prelude") + 1])
                self.assertTrue((prelude_dir / "00-lowkey-import.sol").is_file())
                self.assertTrue((prelude_dir / "10-lowkey-instance.sol").is_file())
                eval_index = command.index("eval")
                self.assertLess(command.index("--prelude"), eval_index)
                self.assertEqual(command[eval_index + 1], "lowkeyTarget.increment() == 1")
                return SimpleNamespace(returncode=0)

            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(lk, "tool_path", return_value="/usr/bin/chisel"), \
                 patch.object(lk, "run_foundry", side_effect=fake_build), \
                 patch.object(lk.subprocess, "run", side_effect=fake_launch), \
                 redirect_stdout(io.StringIO()):
                result = lk.run_chisel(
                    ["--contract", "Vault", "eval", "lowkeyTarget.increment() == 1"],
                    config={},
                )

            self.assertEqual(result, 0)
            self.assertEqual(build_calls, [(["build"], True, root)])


if __name__ == "__main__":
    unittest.main()
