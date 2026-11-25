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
             patch.object(lk, "_doctor_engine_inventory", return_value={"engines": engines, "error": None}), \
             redirect_stdout(output):
            lk._doctor_compact_summary(report, 0)

        rendered = output.getvalue()
        self.assertIn("STATUS   HEALTHY", rendered)
        self.assertIn("PROJECT  Voting Contract", rendered)
        self.assertIn("Installed: 2 / 3 registered", rendered)
        self.assertIn("Forge", rendered)
        self.assertIn("Slither", rendered)
        self.assertIn("Not installed: Halmos", rendered)
        self.assertIn("Project build", rendered)
        self.assertNotIn("dependency command", rendered)
        self.assertNotIn("Workspace root", rendered)

    def test_doctor_verbose_flag_preserves_full_diagnostics(self):
        output = io.StringIO()
        with patch.object(lk, "_run_doctor_detailed", return_value=0), \
             patch.object(lk, "_doctor_verbose_engine_inventory") as engines, \
             patch.object(lk.audit_context, "foundry_project_root", return_value=Path("/tmp/project")), \
             redirect_stdout(output):
            result = lk.run_doctor(["--verbose"])

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "")
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
             patch("builtins.input", return_value="1 ether"), \
             patch("builtins.input", return_value="1 ether"), \
             patch("builtins.input", side_effect=["1 ether"]) as prompt, \
             patch("sys.stderr", errors):
            result = lk.run_wizard({"target": target}, ["setValue"])

        self.assertNotEqual(result, 0)
        self.assertIn("raw integer field", errors.getvalue())
        run_cast.assert_not_called()


if __name__ == "__main__":
    unittest.main()
