"""Regression tests for the compact doctor and safer wizard/transaction UX."""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"
spec = importlib.util.spec_from_file_location("lowkey_ux_test_module", MODULE)
lk = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lk
spec.loader.exec_module(lk)


class LowkeyDiagnosticUxTests(unittest.TestCase):
    def test_doctor_compact_summary_reports_actual_engine_inventory(self):
        report = """\
PASS  runtime: OK
PASS  python3: /usr/bin/python3 (Python 3.14.8)
PASS  forge: /home/user/.foundry/bin/forge (forge Version: 1.9.0)
PASS  cast: /home/user/.foundry/bin/cast (cast Version: 1.9.0)
PASS  anvil: /home/user/.foundry/bin/anvil (anvil Version: 1.9.0)
PASS  slither: /home/user/.local/bin/slither (0.11.6)
PASS  project build: Forge can compile the application sources.
Repair plan     : none needed
PASS  dependency command: cast decode-event
PASS  dependency command: cast receipt
"""
        engines = [
            {"name": "forge", "available": True, "test_kinds": ["unit", "fuzz"]},
            {"name": "slither", "available": True, "test_kinds": []},
            {"name": "halmos", "available": False, "test_kinds": ["formal"]},
        ]
        output = io.StringIO()
        with patch.object(lk.audit_context, "foundry_project_root", return_value=Path("/tmp/Voting Contract")), \
             patch.object(lk, "_doctor_engine_inventory", return_value={
                 "engines": engines,
                 "plugin_errors": [{"name": "broken-test-plugin", "error": "factory import failed"}],
                 "error": None,
             }), \
             patch.object(lk, "_doctor_supplemental_tool_inventory", return_value=[
                 {"name": "Scarb / Cairo", "path": "/usr/bin/scarb"},
                 {"name": "crytic-compile", "path": "/usr/bin/crytic-compile"},
             ]), \
             redirect_stdout(output):
            lk._doctor_compact_summary(report, 0)

        rendered = output.getvalue()
        self.assertIn("STATUS   NEEDS ATTENTION", rendered)
        self.assertIn("PROJECT  Voting Contract", rendered)
        self.assertIn("Installed: 2 / 3 registered", rendered)
        self.assertIn("Forge", rendered)
        self.assertIn("Slither", rendered)
        self.assertIn("Not installed: Halmos", rendered)
        self.assertIn("Plugin registration warnings: 1", rendered)
        self.assertIn("broken-test-plugin: factory import failed", rendered)
        self.assertIn("Extra toolchains: 2 detected", rendered)
        self.assertIn("Scarb / Cairo", rendered)
        self.assertIn("crytic-compile", rendered)
        self.assertIn("Forge is included in the count", rendered)
        self.assertEqual(rendered.count("Slither"), 1)
        self.assertIn("project build", rendered)
        self.assertNotIn("dependency command", rendered)
        self.assertNotIn("Workspace root", rendered)


    def test_supplemental_tool_inventory_detects_cairo_and_solidity_support_tools(self):
        native = {
            "scarb": True,
            "snforge": True,
            "vyper": False,
            "hardhat": False,
            "ape": False,
            "brownie": False,
            "anchor": False,
            "aptos": False,
            "sui": False,
            "cargo-audit": False,
            "cargo-geiger": False,
            "pytest": False,
            "boa": False,
        }
        def which(name):
            return {
                "scarb": "/usr/bin/scarb",
                "snforge": "/usr/bin/snforge",
                "hardhat": "/usr/bin/hardhat",
                "crytic-compile": "/home/user/.local/bin/crytic-compile",
                "solc-select": "/home/user/.local/bin/solc-select",
            }.get(name)

        with patch.object(lk, "detect_project", return_value={
            "native": native,
            "security_analyzers": ["aptos-move-prove"],
        }), \
             patch.object(lk.shutil, "which", side_effect=which):
            rows = lk._doctor_supplemental_tool_inventory(Path("/tmp/cairo-project"))

        names = {row["name"] for row in rows}
        self.assertIn("Scarb / Cairo", names)
        self.assertIn("Starknet Foundry", names)
        self.assertIn("crytic-compile", names)
        self.assertIn("solc-select", names)
        self.assertIn("Hardhat", names)
        self.assertIn("aptos-move-prove", names)
        self.assertEqual(len(rows), 6)

    def test_doctor_verbose_flag_preserves_full_diagnostics(self):
        output = io.StringIO()
        def detailed_report():
            print("FULL DIAGNOSTIC REPORT")
            return 0

        with patch.object(lk, "_run_doctor_detailed", side_effect=detailed_report), \
             patch.object(lk, "_doctor_verbose_engine_inventory") as engines, \
             patch.object(lk.audit_context, "foundry_project_root", return_value=Path("/tmp/project")), \
             redirect_stdout(output):
            result = lk.run_doctor(["--verbose"])

        self.assertEqual(result, 0)
        self.assertIn("FULL DIAGNOSTIC REPORT", output.getvalue())
        engines.assert_called_once_with(Path("/tmp/project"))

    def test_gas_estimation_revert_is_classified_as_contract_preflight_failure(self):
        target = "0x" + "1" * 40
        with patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
             patch.object(lk, "_send_value_as_wei", return_value=0), \
             patch.object(lk, "_rpc_json_response", return_value={
                 "error": {"message": "execution reverted: Atleat 2 OPTIONS"}
             }), \
             patch.object(lk, "_decode_contract_revert", return_value=None):
            result = lk._transaction_preview_gas(
                {},
                ["send", target],
                target,
                None,
                [],
                direct_eth_transfer=True,
            )

        self.assertFalse(result["available"])
        self.assertEqual(result["status"], "reverted")
        self.assertFalse(result["sender_resolved"])
        self.assertIn("Atleat 2 OPTIONS", result["reason"])

    def test_reverted_preflight_blocks_send_before_confirmation(self):
        target = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "setValue",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "value", "type": "uint256"}],
            "outputs": [],
        }]
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "_target_health_block", return_value=None), \
             patch.object(lk, "resolve_function", return_value="setValue(uint256)"), \
             patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
             patch.object(lk, "resolve_wallet_key", return_value=None), \
             patch.object(lk, "_print_transaction_preview", return_value={
                 "available": False,
                 "status": "reverted",
                 "reason": "Atleat 2 OPTIONS",
             }), \
             patch.object(lk, "cast_output") as cast_output, \
             patch("builtins.input") as prompt, \
             redirect_stdout(io.StringIO()):
            result = lk.run_cast(["send", "setValue", "5"], {"target": target})

        self.assertNotEqual(result, 0)
        prompt.assert_not_called()
        cast_output.assert_not_called()


    def test_yes_flag_skips_prompt_but_not_known_revert_preflight(self):
        target = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "setValue",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "value", "type": "uint256"}],
            "outputs": [],
        }]
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "_target_health_block", return_value=None), \
             patch.object(lk, "resolve_function", return_value="setValue(uint256)"), \
             patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
             patch.object(lk, "resolve_wallet_key", return_value=None), \
             patch.object(lk, "_transaction_preview_gas", return_value={
                 "available": False,
                 "status": "reverted",
                 "reason": "Atleat 2 OPTIONS",
             }), \
             patch.object(lk, "_print_transaction_gas_context") as gas_report, \
             patch.object(lk, "cast_output") as cast_output, \
             patch("builtins.input") as prompt, \
             redirect_stdout(io.StringIO()):
            result = lk.run_cast(["send", "setValue", "5", "--yes"], {"target": target})

        self.assertNotEqual(result, 0)
        gas_report.assert_called_once()
        cast_output.assert_not_called()
        prompt.assert_not_called()


    def test_nested_rpc_data_payload_is_forwarded_to_revert_decoder(self):
        target = "0x" + "1" * 40
        revert_data = "0x08c379a0" + "0" * 64
        response = {
            "error": {
                "message": "execution reverted",
                "data": {"originalError": {"data": revert_data}},
            }
        }
        with patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
             patch.object(lk, "_send_value_as_wei", return_value=0), \
             patch.object(lk, "_rpc_json_response", return_value=response), \
             patch.object(lk, "_decode_contract_revert", return_value={
                 "kind": "REVERT", "reason": "Atleat 2 OPTIONS"
             }) as decode:
            result = lk._transaction_preview_gas(
                {},
                ["send", target],
                target,
                None,
                [],
                direct_eth_transfer=True,
            )

        self.assertEqual(result["status"], "reverted")
        self.assertIn("Atleat 2 OPTIONS", result["reason"])
        self.assertIn(f"revert data: {revert_data}", decode.call_args.args[0])

    def test_private_key_is_resolved_for_gas_estimation_caller(self):
        target = "0x" + "1" * 40
        sender = "0x" + "2" * 40
        private_key = "0x" + "3" * 64
        with patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
             patch.object(lk, "_send_value_as_wei", return_value=0), \
             patch.object(lk, "cast_output", return_value=(0, sender, "")) as cast, \
             patch.object(lk, "_rpc_json_response", side_effect=[
                 {"result": "0x5208"},
                 {"result": "0x1"},
             ]) as rpc:
            result = lk._transaction_preview_gas(
                {},
                ["send", target, "--private-key", private_key],
                target,
                None,
                [],
                direct_eth_transfer=True,
            )

        self.assertTrue(result["available"])
        self.assertTrue(result["sender_resolved"])
        cast.assert_called_once_with(
            ["cast", "wallet", "address", "--private-key", private_key],
            timeout=5,
        )
        tx = rpc.call_args_list[0].args[2][0]
        self.assertEqual(tx["from"], sender)

    def test_yes_requires_resolved_sender_when_estimate_would_otherwise_use_rpc_default(self):
        target = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "setValue",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "value", "type": "uint256"}],
            "outputs": [],
        }]
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "_target_health_block", return_value=None), \
             patch.object(lk, "resolve_function", return_value="setValue(uint256)"), \
             patch.object(lk, "effective_rpc", return_value="http://127.0.0.1:8545"), \
             patch.object(lk, "resolve_wallet_key", return_value=None), \
             patch.object(lk, "_transaction_preview_gas", return_value={
                 "available": True,
                 "sender_resolved": False,
                 "gas_estimate": 50000,
             }), \
             patch.object(lk, "_print_transaction_gas_context") as preflight_report, \
             patch.object(lk, "cast_output") as cast_output, \
             patch("builtins.input") as prompt, \
             redirect_stdout(io.StringIO()):
            result = lk.run_cast(["send", "setValue", "5", "--yes"], {"target": target})

        self.assertNotEqual(result, 0)
        preflight_report.assert_called_once()
        cast_output.assert_not_called()
        prompt.assert_not_called()


    def test_yes_with_explicit_sender_can_continue_when_rpc_is_unavailable(self):
        target = "0x" + "1" * 40
        sender = "0x" + "2" * 40
        abi = [{
            "type": "function",
            "name": "setValue",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "value", "type": "uint256"}],
            "outputs": [],
        }]
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "_target_health_block", return_value=None), \
             patch.object(lk, "resolve_function", return_value="setValue(uint256)"), \
             patch.object(lk, "effective_rpc", return_value=None), \
             patch.object(lk, "resolve_wallet_key", return_value=None), \
             patch.object(lk, "cast_output", return_value=(0, "send accepted", "")) as cast, \
             redirect_stdout(io.StringIO()):
            result = lk.run_cast(
                ["send", "setValue", "5", "--from", sender, "--yes"],
                {"target": target},
            )

        self.assertEqual(result, 0)
        cast.assert_called_once()
        self.assertIn(sender, cast.call_args.args[0])

    def test_wallet_error_explains_no_signer_and_no_broadcast(self):
        rendered = lk._format_cli_error(
            "Error accessing local wallet. Did you pass a keystore, hardware wallet, private key or mnemonic?",
            command="send",
            config={},
        )
        self.assertIn("No signing account is configured", rendered)
        self.assertIn("No transaction was broadcast", rendered)
        self.assertIn("lk wallet list", rendered)
        self.assertIn("lk actors", rendered)
        self.assertNotIn("Check the sender nonce and receipt", rendered)

    def test_wizard_numeric_prompt_is_compact_by_default_and_expanded_on_request(self):
        target = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "setValue",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "value", "type": "uint256"}],
            "outputs": [],
        }]
        config = {"target": target}

        short_output = io.StringIO()
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "cast_output", return_value=(0, "0x1234", "")), \
             patch.object(lk, "run_cast", return_value=0), \
             patch("builtins.input", return_value="42") as prompt, \
             redirect_stdout(short_output):
            result = lk.run_wizard(config, ["setValue"])

        self.assertEqual(result, 0)
        self.assertIn("MODE: SEND", short_output.getvalue())
        self.assertNotIn("NUMERIC INPUT OPTIONS", short_output.getvalue())
        self.assertIn("integer; unit is defined by the contract", prompt.call_args.args[0])

        learning_output = io.StringIO()
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "cast_output", return_value=(0, "0x1234", "")), \
             patch.object(lk, "run_cast", return_value=0), \
             patch("builtins.input", return_value="42"), \
             redirect_stdout(learning_output):
            result = lk.run_wizard(config, ["setValue", "--learn"])

        self.assertEqual(result, 0)
        self.assertIn("NUMERIC INPUT OPTIONS", learning_output.getvalue())

    def test_wizard_invalid_numeric_unit_is_explained_without_traceback(self):
        target = "0x" + "1" * 40
        abi = [{
            "type": "function",
            "name": "setValue",
            "stateMutability": "nonpayable",
            "inputs": [{"name": "count", "type": "uint256"}],
            "outputs": [],
        }]
        errors = io.StringIO()
        with patch.object(lk, "load_abi", return_value=abi), \
             patch.object(lk, "run_cast") as run_cast, \
             patch("sys.stderr", errors):
            result = lk.run_wizard({"target": target}, ["setValue", "1 ether"])

        self.assertNotEqual(result, 0)
        self.assertIn("raw integer field", errors.getvalue())
        run_cast.assert_not_called()


if __name__ == "__main__":
    unittest.main()
