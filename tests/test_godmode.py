import importlib.util
import hashlib
import json
import pathlib
import tempfile
import unittest
from urllib.parse import urlparse
from contextlib import redirect_stdout
import io
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "godmode.py"
SPEC = importlib.util.spec_from_file_location("lowkey_godmode_tested", MODULE)
godmode = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = godmode
SPEC.loader.exec_module(godmode)
PROOF_SPEC = importlib.util.spec_from_file_location(
    "lowkey_proof_evidence_tested", ROOT / "lowkey" / "proof_evidence.py"
)
proof_evidence = importlib.util.module_from_spec(PROOF_SPEC)
sys.modules[PROOF_SPEC.name] = proof_evidence
PROOF_SPEC.loader.exec_module(proof_evidence)


class GodmodeTests(unittest.TestCase):
    def test_registry_covers_all_44_numbered_capabilities(self):
        self.assertEqual(len(godmode.CAPABILITIES), 44)
        self.assertEqual([row[0] for row in godmode.CAPABILITIES], list(range(1, 45)))
        self.assertEqual(len({row[1] for row in godmode.CAPABILITIES}), 44)

    def test_storage_slot_key_canonicalizes_short_and_full_forms(self):
        short = godmode.storage_slot_key("0x0")
        full = godmode.storage_slot_key("0x" + "0" * 64)
        self.assertEqual(short, full)
        self.assertEqual(len(short), 66)
        self.assertEqual(godmode.storage_slot_key("17"), "0x" + format(17, "064x"))
        self.assertEqual(godmode.storage_slot_key("01"), "0x" + format(1, "064x"))

    def test_push4_skips_push_data(self):
        # PUSH2 consumes 0x6311 as immediate data, including the 0x63 byte.
        code = "0x61" + "6311" + "63" + "aabbccdd" + "00"
        self.assertEqual(godmode.push4(code), ["0xaabbccdd"])

    def test_source_maps_find_fallback_and_ordered_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "Vault.sol").write_text("""
                contract Vault {
                    mapping(address => uint256) credit;
                    receive() external payable {}
                    function withdraw() external {
                        uint256 amount = credit[msg.sender];
                        (bool ok,) = msg.sender.call{value: amount}("");
                        require(ok);
                        credit[msg.sender] = 0;
                    }
                }
            """, encoding="utf-8")
            maps = godmode.source_maps(root)
            self.assertTrue(any(x["kind"] == "receive" for x in maps["fallback_map"]))
            self.assertTrue(any("credit" in x["variables"] for x in maps["reentrancy_graph"]))

    def _control_manifest(self, root):
        target = "0x" + "1" * 40
        sender = "0x" + "2" * 40
        wrapper = "0x" + "3" * 40
        manifest = {
            "target_address": target,
            "same_calls_id": "withdraw-same-entrypoint-v1",
            "metric_name": "attacker_portfolio_native_delta_wei",
            "prestate_addresses": [target, sender, wrapper],
            "prestate_slots": [{"address": target, "slot": "0x" + "0" * 64}],
            "metric_addresses": [sender, wrapper],
            "trace_expectations": [{
                "address": target,
                "control_min_calls": 1,
                "control_max_calls": 1,
                "attack_min_calls": 2,
                "attack_max_calls": 2,
                "description": "Reentrancy adds exactly one nested target withdrawal call."
            }],
            "control": {"argv": [sys.executable, "-c", "pass"]},
            "attack": {"argv": [sys.executable, "-c", "pass"]},
        }
        (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
        manifest_path = root / "control.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        proof_evidence.freeze_control_manifest(root, manifest_path, manifest)
        return manifest, target, sender, wrapper

    def _mock_trace_rpc(self, target, sender, wrapper, attack_calldata="0x12345678", control_gain=5, attack_gain=15, external_state=None, attack_tx_fields=None, gas_used=0, gas_price=0):
        state = external_state if external_state is not None else {"tx_hash": None, "input": None, "scenario_slot": "0x" + "0" * 64}

        def fake_rpc(url, method, params, timeout=20):
            if method == "evm_snapshot":
                return "0x1"
            if method == "evm_revert":
                return True
            if method == "anvil_setStorageAt":
                state["scenario_slot"] = params[2]
                return True
            if method == "eth_chainId":
                return "0x7a69"
            if method == "eth_blockNumber":
                return "0x65"
            if method == "eth_getBlockByNumber":
                return {
                    "hash": "0x" + "4" * 64,
                    "timestamp": "0x100",
                    "baseFeePerGas": "0x1",
                    "transactions": [state["tx_hash"]] if params[0] == "0x65" and state["tx_hash"] else [],
                }
            if method == "eth_getTransactionByHash":
                tx_hash = params[0]
                state["tx_hash"] = tx_hash
                state["input"] = attack_calldata if tx_hash == "0x" + "b" * 64 else "0x12345678"
                tx = {
                    "hash": tx_hash,
                    "from": sender,
                    "to": wrapper,
                    "input": state["input"],
                    "value": "0x0",
                    "nonce": "0x0",
                    "gas": "0x100000",
                    "gasPrice": "0x1",
                    "type": "0x0",
                    "accessList": [],
                }
                if tx_hash == "0x" + "b" * 64 and attack_tx_fields:
                    tx.update(attack_tx_fields)
                return tx
            if method == "eth_getTransactionReceipt":
                status = "0x0" if state["tx_hash"] == "0x" + "c" * 64 else "0x1"
                return {
                    "status": status, "blockNumber": "0x65", "transactionIndex": "0x0",
                    "gasUsed": hex(gas_used), "effectiveGasPrice": hex(gas_price),
                }
            if method == "eth_getBalance":
                if params[1] == "0x65":
                    gain = control_gain if state["tx_hash"] == "0x" + "a" * 64 else attack_gain
                    if params[0] == sender:
                        return hex(0x100 - gas_used * gas_price)
                    if params[0] == wrapper:
                        return hex(0x100 + gain + 1)
                return "0x100"
            if method == "eth_getTransactionCount":
                return "0x1"
            if method == "eth_getCode":
                return "0x6000" if params[0] == wrapper else "0x"
            if method == "eth_getStorageAt":
                if (params[0] == wrapper and
                    params[1] in {"0x0", "0x" + "0" * 64} and
                    params[2] == "latest"):
                    return state["scenario_slot"]
                return "0x" + "0" * 63 + "1"
            if method == "debug_traceTransaction" and params[1].get("tracer") == "prestateTracer":
                zero_slot = "0x" + "0" * 64
                one_word = "0x" + "0" * 63 + "1"
                zero_word = "0x" + "0" * 64
                return {
                    "pre": {target: {"storage": {zero_slot: one_word}}},
                    "post": {target: {"storage": {zero_slot: zero_word}}},
                }
            if method == "debug_traceTransaction":
                calls = [{
                    "type": "CALL",
                    "from": wrapper,
                    "to": target,
                    "input": "0xdeadbeef",
                    "value": "0x0",
                }]
                if state["tx_hash"] == "0x" + "b" * 64:
                    calls.append({
                        "type": "CALL",
                        "from": wrapper,
                        "to": target,
                        "input": "0xdeadbeef",
                        "value": "0x0",
                    })
                return {
                    "type": "CALL",
                    "from": sender,
                    "to": wrapper,
                    "input": state["input"],
                    "value": "0x0",
                    "calls": calls,
                }
            raise AssertionError("Unexpected RPC method: " + method)
        return fake_rpc

    def test_control_uses_rpc_derived_transaction_and_prestate(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _, target, sender, wrapper = self._control_manifest(root)
            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            run_index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                i = run_index["value"]
                run_index["value"] += 1
                output = f"LOWKEY_TRACE_TX_HASH {hashes[i]}\n"
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(target, sender, wrapper)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 0)
            self.assertIn(saved["status"], {"OBSERVED", "REJECTED"})
            self.assertEqual(saved["legacy_status"], "BREAK")
            self.assertEqual(saved["control_delta"], 10)
            self.assertTrue(saved["same_entry_call_verified"])
            self.assertTrue(saved["same_transaction_envelope_verified"])
            self.assertTrue(saved["same_prestate_verified"])
            self.assertEqual(saved["verification_method"].split()[0], "local-Anvil")
            self.assertEqual(saved["runs"]["attack"]["call_trace"][1]["to"], target)

    def test_control_rejects_different_root_calldata_even_when_metric_is_positive(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _, target, sender, wrapper = self._control_manifest(root)
            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            run_index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                i = run_index["value"]
                run_index["value"] += 1
                output = f"LOWKEY_TRACE_TX_HASH {hashes[i]}\n"
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(target, sender, wrapper, "0xaabbccdd")), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertIn(saved["status"], {"OBSERVED", "REJECTED"})
            self.assertFalse(saved["same_entry_call_verified"])

    def test_control_rejects_transaction_envelope_difference_even_when_root_call_matches(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _, target, sender, wrapper = self._control_manifest(root)
            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            run_index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                index = run_index["value"]
                run_index["value"] += 1
                return subprocess.CompletedProcess(argv, 0, f"LOWKEY_TRACE_TX_HASH {hashes[index]}\n", "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(
                     target, sender, wrapper, attack_tx_fields={"gasPrice": "0x2"})), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertIn(saved["status"], {"OBSERVED", "REJECTED"})
            self.assertTrue(saved["same_entry_call_verified"])
            self.assertFalse(saved["same_transaction_envelope_verified"])
            self.assertTrue(saved["same_prestate_verified"])
            self.assertTrue(any("transaction nonce/gas/fee/type/access-list envelope differs" in reason for reason in saved["reasons"]))

    def test_control_rejects_relative_improvement_without_positive_attack_profit(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _, target, sender, wrapper = self._control_manifest(root)
            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                tx_hash = hashes[index["value"]]
                index["value"] += 1
                return subprocess.CompletedProcess(argv, 0, f"LOWKEY_TRACE_TX_HASH {tx_hash}\n", "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(
                     target, sender, wrapper, control_gain=-5, attack_gain=-2)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertIn(saved["status"], {"OBSERVED", "REJECTED"})
            self.assertEqual(saved["control_delta"], 3)
            self.assertFalse(saved["attack_metric_positive_after_gas"])

    def test_control_supports_expected_revert_negative_control(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, target, sender, wrapper = self._control_manifest(root)
            manifest["require_negative_control"] = True
            manifest["trace_expectations"][0]["negative_control_min_calls"] = 1
            manifest["trace_expectations"][0]["negative_control_max_calls"] = 1
            manifest["negative_control"] = {
                "argv": [sys.executable, "-c", "pass"],
                "expected_receipt_status": "0x0",
            }
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            proof_evidence.freeze_control_manifest(root, root / "control.json", manifest)

            hashes = ["0x" + "a" * 64, "0x" + "b" * 64, "0x" + "c" * 64]
            index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                tx_hash = hashes[index["value"]]
                index["value"] += 1
                exit_code = 1 if tx_hash == "0x" + "c" * 64 else 0
                return subprocess.CompletedProcess(
                    argv, exit_code, f"LOWKEY_TRACE_TX_HASH {tx_hash}\n", "transaction reverted"
                )

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(target, sender, wrapper)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])

            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            negative = saved["runs"]["negative_control"]
            self.assertEqual(result, 0)
            self.assertTrue(saved["negative_control_present"])
            self.assertTrue(saved["negative_control_verified"])
            self.assertEqual(negative["receipt_status"], "0x0")
            self.assertEqual(negative["expected_receipt_status"], "0x0")
            self.assertEqual(negative["exit_code"], 1)
            self.assertTrue(negative["execution_verified"])
            self.assertEqual(
                saved["trace_checks"][0]["observed_call_counts"]["negative_control"], 1
            )
            self.assertEqual(saved["legacy_status"], "BREAK")
            self.assertEqual(saved["proof_status"], "OBSERVED")

    def test_control_blocks_rpc_state_fabrication_in_prepare_and_attack_scripts(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, target, sender, wrapper = self._control_manifest(root)
            scripts = root / "scripts"
            scripts.mkdir()
            bad = scripts / "prepare.py"
            bad.write_text('rpc("anvil_setStorageAt", [target, slot, value])\n', encoding="utf-8")
            manifest["scenario_parameters"] = [{
                "name": "mode", "address": wrapper, "slot": "0x0",
                "control_value": "0x0", "attack_value": "0x1",
            }]
            manifest["control"] = {
                "prepare_argv": [sys.executable, "scripts/prepare.py"],
                "argv": [sys.executable, "-c", "print('LOWKEY_TRACE_TX_HASH ' + 'a'*64)"],
            }
            manifest["attack"] = manifest["control"]
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            proof_evidence.freeze_control_manifest(root, root / "control.json", manifest)
            with patch.object(godmode, "rpc", side_effect=lambda url, method, params, timeout=20:
                              "0x1" if method == "evm_snapshot" else True), \
                 patch.object(godmode, "run") as run_mock, \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "UNPROVEN")
            self.assertIn("anvil_setStorageAt", saved["reasons"][0])
            run_mock.assert_not_called()

    def test_control_records_attacker_scenario_parameter_before_transaction(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, target, sender, wrapper = self._control_manifest(root)
            manifest["scenario_parameters"] = [{
                "name": "attacker_callback_flag",
                "address": wrapper,
                "slot": "0x0",
                "control_value": "0x0",
                "attack_value": "0x1",
                "description": "attacker-only callback mode",
            }]
            manifest["control"] = {"prepare_argv": ["prepare", "0"], "argv": ["send"]}
            manifest["attack"] = {"prepare_argv": ["prepare", "1"], "argv": ["send"]}
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            proof_evidence.freeze_control_manifest(root, root / "control.json", manifest)
            tx_hashes = iter(["0x" + "a" * 64, "0x" + "b" * 64])
            gain_by_tx = {"0x" + "a" * 64: 5, "0x" + "b" * 64: 15}

            rpc_state = {"tx_hash": None, "input": None, "scenario_slot": "0x" + "0" * 64}

            def fake_run(argv, cwd, timeout=300, env=None):
                if argv[0] == "prepare":
                    rpc_state["scenario_slot"] = "0x" + format(int(argv[1]), "064x")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                tx_hash = next(tx_hashes)
                return subprocess.CompletedProcess(argv, 0, f"LOWKEY_TRACE_TX_HASH {tx_hash}\n", "")

            rpc_mock = self._mock_trace_rpc(target, sender, wrapper, external_state=rpc_state)
            def rpc_with_scenario(url, method, params, timeout=20):
                if method == "eth_getBalance" and params[1] == "0x65":
                    gain = gain_by_tx[rpc_state["tx_hash"]]
                    if params[0] == sender:
                        return hex(0x100 - 1)
                    if params[0] == wrapper:
                        return hex(0x100 + gain + 1)
                return rpc_mock(url, method, params, timeout)

            # The state toggle is written during prepare, read by Lowkey before
            # the transaction, and then may be changed again by the callback.
            with patch.object(godmode, "rpc", side_effect=rpc_with_scenario), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 0, saved.get("reasons") or saved.get("rejection_codes"))
            self.assertEqual(saved["status"], "OBSERVED")
            self.assertEqual(saved["legacy_status"], "BREAK")
            control_param = saved["runs"]["control"]["scenario_parameters"][0]
            attack_param = saved["runs"]["attack"]["scenario_parameters"][0]
            self.assertTrue(control_param["verified_before_transaction"])
            self.assertTrue(attack_param["verified_before_transaction"])
            self.assertEqual(int(control_param["observed_value"], 16), 0)
            self.assertEqual(int(attack_param["observed_value"], 16), 1)

    def test_control_blocks_unexpected_attacker_scenario_parameter_before_sending_tx(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, target, sender, wrapper = self._control_manifest(root)
            manifest["scenario_parameters"] = [{
                "name": "attacker_callback_flag",
                "address": wrapper,
                "slot": "0x0",
                "control_value": "0x0",
                "attack_value": "0x1",
            }]
            manifest["control"] = {"prepare_argv": ["prepare", "0"], "argv": ["send"]}
            manifest["attack"] = {"prepare_argv": ["prepare", "0"], "argv": ["send"]}
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            proof_evidence.freeze_control_manifest(root, root / "control.json", manifest)
            calls = []
            rpc_state = {"tx_hash": None, "input": None, "scenario_slot": "0x" + "0" * 64}
            def fake_run(argv, cwd, timeout=300, env=None):
                calls.append(argv)
                if argv[0] == "prepare":
                    rpc_state["scenario_slot"] = "0x" + format(int(argv[1]), "064x")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return subprocess.CompletedProcess(argv, 0, "LOWKEY_TRACE_TX_HASH " + "0x" + "a" * 64 + "\n", "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(target, sender, wrapper, external_state=rpc_state)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "UNPROVEN")
            self.assertIn("attacker_callback_flag", saved["reasons"][0])
            # Control succeeds its prepare step and its transaction; attack fails
            # during preparation, so the second send is never executed.
            self.assertEqual([call[0] for call in calls], ["prepare", "send", "prepare"])

    def test_control_rejects_different_transaction_gas_envelope(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _, target, sender, wrapper = self._control_manifest(root)
            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            run_index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                i = run_index["value"]
                run_index["value"] += 1
                return subprocess.CompletedProcess(argv, 0, f"LOWKEY_TRACE_TX_HASH {hashes[i]}\n", "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(
                     target, sender, wrapper, attack_tx_fields={"gasPrice": "0x2"})), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertIn(saved["status"], {"OBSERVED", "REJECTED"})
            self.assertTrue(saved["same_entry_call_verified"])
            self.assertFalse(saved["same_transaction_envelope_verified"])
            self.assertTrue(saved["same_prestate_verified"])
            self.assertTrue(any("transaction nonce/gas/fee/type/access-list envelope differs" in reason for reason in saved["reasons"]))

    def test_control_rejects_script_supplied_hashes_without_a_mined_trace(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._control_manifest(root)

            def fake_run(argv, cwd, timeout=300, env=None):
                output = "LOWKEY_CALL_SEQUENCE_SHA256 " + "a" * 64
                return subprocess.CompletedProcess(argv, 0, output, "")

            def fake_rpc(url, method, params, timeout=20):
                if method == "evm_snapshot":
                    return "0x1"
                if method == "evm_revert":
                    return True
                raise AssertionError("Unexpected RPC call before a mined hash exists: " + method)

            with patch.object(godmode, "rpc", side_effect=fake_rpc), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "UNPROVEN")
            self.assertIn("LOWKEY_TRACE_TX_HASH", saved["reasons"][0])

    def test_reprove_reaches_profitable_only_with_a_pinned_mined_trace_and_real_gas(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            harness = root / "test" / "RealForkPoC.t.sol"
            harness.parent.mkdir()
            harness.write_text("contract RealForkPoC { function test_path() external {} }", encoding="utf-8")
            tx_hash = "0x" + "a" * 64
            target = "0x" + "1" * 40
            sender = "0x" + "2" * 40
            recipient = "0x" + "3" * 40
            before = 10**18
            after = before + 2 * 10**18

            def fake_rpc(url, method, params, timeout=20):
                if method == "eth_getTransactionByHash":
                    return {"hash": tx_hash, "from": sender, "to": target, "input": "0x12345678", "value": "0x0", "gasPrice": "0x3b9aca00"}
                if method == "eth_getTransactionReceipt":
                    return {"status": "0x1", "blockNumber": "0x65", "transactionIndex": "0x0",
                            "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00"}
                if method == "eth_getBlockByNumber":
                    if params[0] == "0x64":
                        return {"hash": "0x" + "4" * 64}
                    if params[0] == "0x65":
                        return {"transactions": [tx_hash]}
                if method == "eth_chainId":
                    return "0x7a69"
                if method == "eth_getCode":
                    return "0x6000"
                if method == "eth_getStorageAt":
                    return "0x" + "0" * 63 + "1"
                if method == "debug_traceTransaction":
                    if params[1].get("tracer") == "prestateTracer":
                        return {
                            "pre": {
                                target: {
                                    "balance": hex(before), "nonce": "0x0", "code": "0x6000",
                                    "storage": {"0x" + "0" * 64: "0x" + "0" * 63 + "1"},
                                },
                                sender: {"balance": hex(before), "nonce": "0x0", "code": "0x", "storage": {}},
                            },
                            "post": {
                                target: {
                                    "balance": hex(after), "nonce": "0x0", "code": "0x6000",
                                    "storage": {"0x" + "0" * 64: "0x" + "0" * 63 + "0"},
                                },
                                sender: {"balance": hex(before), "nonce": "0x0", "code": "0x", "storage": {}},
                            },
                        }
                    return {"type": "CALL", "from": sender, "to": target, "input": "0x12345678",
                            "value": "0x0", "calls": []}
                if method == "eth_getTransactionCount":
                    return "0x0"
                if method == "eth_getBalance":
                    if url == "https://archive.example":
                        return hex(10**18)
                    return hex(after if params[1] == "0x65" else before)
                raise AssertionError("Unexpected RPC method: " + method)

            def fake_run(argv, cwd, timeout=300, env=None):
                return subprocess.CompletedProcess(argv, 0, f"LOWKEY_TRACE_TX_HASH {tx_hash}\n", "")

            with patch.object(godmode, "rpc", side_effect=fake_rpc), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.reprove([
                    "test/RealForkPoC.t.sol", "--root", str(root),
                    "--rpc-url", "http://127.0.0.1:8545", "--fork-block", "100",
                    "--source-rpc-url", "https://archive.example",
                    "--prestate-slot", target + ":" + ("0x" + "0" * 64),
                    "--target-address", target, "--profit-address", recipient,
                    "--argv-json", json.dumps([sys.executable, "-c", "pass"]),
                ])
            saved = json.loads((root / ".audit/godmode/reprove.json").read_text())
            expected_fee = 21000 * 10**9
            self.assertEqual(result, 0)
            self.assertEqual(saved["status"], "PROFITABLE")
            self.assertEqual(saved["fork_parent_block"], 100)
            self.assertEqual(saved["transaction_block"], 101)
            self.assertEqual(saved["gas_cost_wei"], expected_fee)
            self.assertEqual(saved["net_profit_wei"], 2 * 10**18 - expected_fee)
            self.assertTrue(saved["human_confirmation_required"])

    def test_replay_script_scanner_blocks_rpc_state_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            replay = scripts / "replay.py"
            replay.write_text(
                'rpc("anvil_setStorageAt", [target, slot, value])\n'
                'rpc("anvil_setBalance", [attacker, balance])\n',
                encoding="utf-8",
            )
            result = godmode.inspect_reproduction_command(
                root, [sys.executable, "scripts/replay.py"]
            )
            kinds = {item["kind"] for item in result["state_fabrication_calls"]}
            self.assertTrue(result["blocked"])
            self.assertIn("rpc_storage_override", kinds)
            self.assertIn("rpc_balance_override", kinds)
            self.assertIn("scripts/replay.py", result["inspected_scripts"])

    def test_reprove_blocks_state_override_in_replay_script_before_rpc_or_execution(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            harness = root / "test" / "CleanLookingHarness.t.sol"
            harness.parent.mkdir()
            harness.write_text("contract CleanLookingHarness {}", encoding="utf-8")
            scripts = root / "scripts"
            scripts.mkdir()
            replay = scripts / "replay.py"
            replay.write_text('rpc("anvil_setStorageAt", [target, slot, value])\n', encoding="utf-8")
            with patch.object(godmode, "rpc") as rpc_mock, \
                 patch.object(godmode, "run") as run_mock, \
                 redirect_stdout(io.StringIO()):
                result = godmode.reprove([
                    "test/CleanLookingHarness.t.sol", "--root", str(root),
                    "--rpc-url", "http://127.0.0.1:8545", "--fork-block", "100",
                    "--target-address", "0x" + "1" * 40,
                    "--profit-address", "0x" + "2" * 40,
                    "--argv-json", json.dumps([sys.executable, "scripts/replay.py"]),
                ])
            saved = json.loads((root / ".audit/godmode/reprove.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "SIMULATED_BREAK")
            self.assertEqual(saved["command_run"], False)
            self.assertTrue(saved["execution_command"]["blocked"])
            rpc_mock.assert_not_called()
            run_mock.assert_not_called()

    def test_reprove_refuses_synthetic_funding_at_the_fork_stage(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            harness = root / "test" / "SyntheticPoC.t.sol"
            harness.parent.mkdir()
            harness.write_text("contract SyntheticPoC { function test_path() external { vm.deal(address(this), 1 ether); } }", encoding="utf-8")
            with patch.object(godmode, "rpc") as rpc_mock, redirect_stdout(io.StringIO()):
                result = godmode.reprove([
                    "test/SyntheticPoC.t.sol", "--root", str(root),
                    "--rpc-url", "http://127.0.0.1:8545", "--fork-block", "100",
                    "--target-address", "0x" + "1" * 40,
                    "--profit-address", "0x" + "2" * 40,
                    "--tx-hash", "0x" + "a" * 64,
                ])
            saved = json.loads((root / ".audit/godmode/reprove.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "SIMULATED_BREAK")
            self.assertIn("synthetic_eth", saved["blocked_cheatcodes"])
            rpc_mock.assert_not_called()

    def test_control_fidelity_scan_includes_transitive_support_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            harness = root / "test" / "Attack.t.sol"
            helper = root / "test" / "helpers" / "Setup.sol"
            harness.parent.mkdir(parents=True)
            helper.parent.mkdir(parents=True)
            harness.write_text("contract AttackHarness {}", encoding="utf-8")
            helper.write_text(
                "library Setup { function fund() internal { vm.deal(address(1), 1 ether); } }",
                encoding="utf-8",
            )
            fidelity = godmode._analyze_control_fidelity(
                root,
                {"harness": "test/Attack.t.sol", "support_files": ["test/helpers/Setup.sol"]},
                {},
            )
            self.assertTrue(fidelity["scan_complete"])
            self.assertFalse(fidelity["static_scan_clear"])
            self.assertFalse(fidelity["confirmation_eligible"])
            self.assertEqual(
                set(fidelity["scanned_files"]),
                {"test/Attack.t.sol", "test/helpers/Setup.sol"},
            )
            self.assertTrue(fidelity["synthetic_state"])
            self.assertIn("synthetic_eth", {row["kind"] for row in fidelity["signals"]})

    def test_harness_fidelity_detects_synthetic_state_and_never_confirms(self):
        source = """
        vm.deal(TARGET, 100 ether);
        vm.deal(address(attacker), 1 ether);
        vm.prank(attacker);
        vm.store(TARGET, bytes32(uint256(0)), bytes32(uint256(1)));
        vm.mockCall(ORACLE, payload, response);
        vm.warp(block.timestamp + 1 days);
        """
        result = godmode.analyze_harness_fidelity(source, "test/PoC.t.sol")
        kinds = {item["kind"] for item in result["signals"]}
        self.assertIn("synthetic_eth", kinds)
        self.assertIn("caller_impersonation", kinds)
        self.assertIn("storage_override", kinds)
        self.assertIn("external_call_mock", kinds)
        self.assertIn("time_or_block_override", kinds)
        self.assertTrue(result["synthetic_state"])
        self.assertEqual(result["classification"], "SIMULATED")
        self.assertFalse(result["confirmation_eligible"])
        self.assertFalse(result["net_profit_verified"])

    def test_non_economic_control_requires_semantics_and_caps_at_simulated_break(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, target, sender, wrapper = self._control_manifest(root)
            manifest["family"] = "dos"
            semantic_argv = [
                sys.executable, "-c",
                "print('LOWKEY_SEMANTIC_INVARIANT_PASS:test_dos_without_credit')"
            ]
            manifest["attack"]["semantic_check_argv"] = semantic_argv
            manifest["attack"]["semantic_check_test"] = "test_dos_without_credit"
            semantic_marker = "LOWKEY_SEMANTIC_INVARIANT_PASS:test_dos_without_credit"
            manifest_path = root / "control.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            proof_evidence.freeze_control_manifest(root, manifest_path, manifest)

            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            run_index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                if semantic_marker in " ".join(argv):
                    return subprocess.CompletedProcess(
                        argv, 0, semantic_marker + "\n", ""
                    )
                index = run_index["value"]
                run_index["value"] += 1
                return subprocess.CompletedProcess(
                    argv, 0, f"LOWKEY_TRACE_TX_HASH {hashes[index]}\n", ""
                )

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(
                     target, sender, wrapper, control_gain=15, attack_gain=15)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])

            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 0)
            self.assertEqual(saved["status"], "SIMULATED_BREAK")
            self.assertTrue(saved["semantic_invariant_verified"])
            self.assertTrue(saved["economic_policy"]["accepted"])
            self.assertEqual(saved["economic_policy"]["promotion_cap"], "SIMULATED_BREAK")
            self.assertEqual(saved["control_delta"], 0)
            self.assertNotIn("control_not_outperformed", saved["rejection_codes"])

    def test_control_rejects_non_positive_rpc_measured_portfolio_delta(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _, target, sender, wrapper = self._control_manifest(root)
            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            run_index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                i = run_index["value"]
                run_index["value"] += 1
                return subprocess.CompletedProcess(argv, 0, f"LOWKEY_TRACE_TX_HASH {hashes[i]}\n", "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(
                     target, sender, wrapper, control_gain=15, attack_gain=15)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "REJECTED")
            self.assertEqual(saved["outcome"], "rejected")
            self.assertIn("control_not_outperformed", saved["rejection_codes"])
            self.assertEqual(saved["control_delta"], 0)
            feedback = saved["memory_feedback"]
            self.assertEqual(feedback["status"], "recorded")
            self.assertEqual(feedback["context"]["backend"], "anvil-calltracer")
            self.assertTrue(feedback["context_key"])
            self.assertIn("did not exceed the control metric", feedback["evidence"])

    def test_successful_attack_is_rejected_when_net_profit_after_gas_is_negative(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _, target, sender, wrapper = self._control_manifest(root)
            hashes = ["0x" + "a" * 64, "0x" + "b" * 64]
            run_index = {"value": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                index = run_index["value"]
                run_index["value"] += 1
                return subprocess.CompletedProcess(
                    argv, 0, f"LOWKEY_TRACE_TX_HASH {hashes[index]}\n", ""
                )

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(
                     target, sender, wrapper, control_gain=20, attack_gain=10,
                     gas_used=15, gas_price=1)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])

            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["runs"]["control"]["receipt_status"], "0x1")
            self.assertEqual(saved["runs"]["attack"]["receipt_status"], "0x1")
            self.assertGreater(saved["runs"]["control"]["metric"], 0)
            self.assertLess(saved["runs"]["attack"]["metric"], 0)
            self.assertLess(saved["control_delta"], 0)
            self.assertEqual(saved["status"], "REJECTED")
            self.assertEqual(saved["outcome"], "rejected")
            self.assertIn("net_negative", saved["rejection_codes"])
            self.assertIn("control_not_outperformed", saved["rejection_codes"])

    def test_generator_drift_stops_control_without_rejecting_frozen_hypothesis(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest, _, _, _ = self._control_manifest(root)
            (root / "generator.py").write_text("print('v1')", encoding="utf-8")
            manifest["generator_files"] = ["generator.py"]
            manifest_path = root / "control.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            proof_evidence.freeze_control_manifest(root, manifest_path, manifest)
            (root / "generator.py").write_text("print('v2')", encoding="utf-8")

            with patch.object(godmode, "run") as run_mock, \
                 patch.object(godmode, "rpc") as rpc_mock, \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])

            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 2)
            self.assertEqual(saved["status"], "UNPROVEN")
            self.assertEqual(saved["outcome"], "not_run")
            self.assertFalse(saved["execution_attempted"])
            self.assertEqual(saved["rejection_codes"], [])
            self.assertEqual(saved["freeze"]["reason_code"], "generator_drift")
            self.assertTrue(saved["freeze"]["requires_refreeze"])
            run_mock.assert_not_called()
            rpc_mock.assert_not_called()

    def test_source_maps_classify_oracle_and_time_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "Oracle.sol").write_text("""
                contract OracleUser {
                    function quote() external view returns (uint256) {
                        (, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();
                        require(block.timestamp - updatedAt < 1 days);
                        return uint256(answer);
                    }
                }
            """, encoding="utf-8")
            maps = godmode.source_maps(root)
            self.assertTrue(any(x["kind"] == "chainlink_aggregator" for x in maps["oracle_map"]))
            self.assertTrue(any(x["kind"] == "timestamp" for x in maps["time_map"]))

    def test_report_renders_finding_fields_and_hash_sidecar(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            latest = root / ".audit/godmode/latest.json"
            latest.parent.mkdir(parents=True)
            latest.write_text(json.dumps({
                "overall_status": "EVIDENCE_REVIEW_REQUIRED",
                "target": "0x0000000000000000000000000000000000000001",
                "chain_id": "0x7a69",
                "fork_block": "0x10",
                "stages": [{"name": "control", "status": "passed"}],
                "signals": {},
                "findings": [{
                    "title": "Unauthorized withdrawal",
                    "severity": "High",
                    "severity_rubric": "Impact: direct asset theft",
                    "impact": "Attacker withdraws another user's balance",
                    "gas_used": 170000,
                    "net_profit": "0.4 ETH",
                    "harness": "test/Exploit.t.sol",
                    "reproduction_steps": ["Start local fork", "Run forge test"]
                }]
            }), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                result = godmode.report(["--root", str(root)])
            rendered = (root / ".audit/godmode/report.md").read_text()
            self.assertEqual(result, 0)
            self.assertIn("Unauthorized withdrawal", rendered)
            self.assertIn("Attacker withdraws another user's balance", rendered)
            self.assertTrue((root / ".audit/godmode/report.md.sha256").is_file())


    def _forge_artifact(self):
        target = "0x" + "1" * 40
        attacker = "0x" + "2" * 40
        wrapper = "0x" + "3" * 40
        code_hash = "0x" + "a" * 64
        return {
            "schema_version": 1,
            "trace_schema_version": 1,
            "backend": "forge-state-diff",
            "chain_id": 1,
            "block_number": 20_000_000,
            "target_address": target,
            "target_code_hash": code_hash,
            "fork_parent_hash": "0x" + "b" * 64,
            "accesses": [
                {
                    "kind": 0, "account": target, "accessor": wrapper,
                    "depth": 1, "value": 0, "data": "0x12345678",
                    "old_balance": 1000, "new_balance": 900,
                    "old_nonce": 1, "new_nonce": 1, "code_hash": code_hash,
                    "reverted": False,
                    "storage_accesses": [{
                        "account": target, "slot": 0, "previous_value": 5,
                        "new_value": 0, "is_write": True, "reverted": False,
                    }],
                },
                {
                    "kind": 0, "account": wrapper, "accessor": attacker,
                    "depth": 0, "value": 0, "data": "0xabcdef01",
                    "old_balance": 50, "new_balance": 150,
                    "old_nonce": 1, "new_nonce": 1,
                    "code_hash": "0x" + "c" * 64,
                    "reverted": False, "storage_accesses": [],
                },
            ],
        }

    def test_semantic_invariant_requires_a_recognized_passing_assertion(self):
        self.assertTrue(godmode._semantic_execution_verified(
            0, "[PASS] test_no_blocking_when_entitlement_missing()",
            "test_no_blocking_when_entitlement_missing"
        ))
        self.assertFalse(godmode._semantic_execution_verified(
            0, "[PASS] test_no_blocking_when_entitlement_missing()"
        ))
        self.assertFalse(godmode._semantic_execution_verified(
            0, "Suite result: ok. 1 passed; 0 failed; 0 skipped",
            "test_no_blocking_when_entitlement_missing"
        ))
        self.assertTrue(godmode._semantic_execution_verified(
            0, "LOWKEY_SEMANTIC_INVARIANT_PASS:test_dos_without_credit",
            "test_dos_without_credit"
        ))
        self.assertFalse(godmode._semantic_execution_verified(
            0, "LOWKEY_SEMANTIC_INVARIANT_PASS", "test_dos_without_credit"
        ))
        self.assertFalse(godmode._semantic_execution_verified(0, "Forge build succeeded"))
        self.assertFalse(godmode._semantic_execution_verified(0, "No tests found"))
        self.assertFalse(godmode._semantic_execution_verified(
            0, "Suite result: ok. 0 passed; 1 failed; 0 skipped"
        ))
        self.assertFalse(godmode._semantic_execution_verified(1, "[PASS] test_something"))

    def test_anvil_calltracer_rows_use_the_same_trace_event_schema(self):
        events = godmode._normalize_rpc_trace_events([{
            "type": "CALL", "from": "0x" + "2" * 40, "to": "0x" + "1" * 40,
            "depth": 1, "value": "0x2", "input": "0x12345678abcd", "error": "",
        }])
        self.assertEqual(events[0]["kind"], "Call")
        self.assertEqual(events[0]["value"], 2)
        self.assertEqual(events[0]["selector"], "0x12345678")
        self.assertIsNone(events[0]["storage"])
        self.assertEqual(events[0]["source_backend"], "anvil-calltracer")

    def test_paired_forge_runner_executes_shared_harness_once_and_reads_both_artifacts(self):
        import subprocess
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = "0x" + "1" * 40
            wrapper = "0x" + "3" * 40
            harness = root / "test" / "Paired.t.sol"
            harness.parent.mkdir()
            harness.write_text("contract Paired { function test_pair() external {} }", encoding="utf-8")
            control_entry = {
                "harness": "test/Paired.t.sol",
                "state_diff_file": ".audit/godmode/control-state-diff.json",
                "argv": ["forge", "test", "--match-path", "test/Paired.t.sol", "-vv"],
            }
            attack_entry = {
                "harness": "test/Paired.t.sol",
                "state_diff_file": ".audit/godmode/attack-state-diff.json",
                "argv": ["forge", "test", "--match-path", "test/Paired.t.sol", "-vv"],
            }
            artifact = self._forge_artifact()
            invocations = {"count": 0}

            def fake_run(argv, cwd, timeout=300, env=None):
                invocations["count"] += 1
                for entry in (control_entry, attack_entry):
                    path = pathlib.Path(cwd) / entry["state_diff_file"]
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(artifact), encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0, "paired Forge test passed", "")

            with patch.object(godmode, "run", side_effect=fake_run):
                rows = godmode._forge_control_run(
                    root, "http://127.0.0.1:8545", "control",
                    control_entry, {"target_address": target, "metric_addresses": [wrapper]},
                    {}, paired_entry=attack_entry,
                )

            self.assertEqual(invocations["count"], 1)
            self.assertEqual(set(rows), {"control", "attack"})
            self.assertTrue(rows["control"]["paired_execution"])
            self.assertTrue(rows["attack"]["paired_execution"])
            self.assertEqual(rows["control"]["target_code_hash"], rows["attack"]["target_code_hash"])
            self.assertEqual(rows["control"]["prestate_sha256"], rows["attack"]["prestate_sha256"])
            self.assertEqual(rows["control"]["trace_events"][0]["selector"], "0x12345678")
            self.assertEqual(rows["attack"]["trace_events"][0]["selector"], "0x12345678")

    def test_forge_control_adapter_consumes_real_forge_artifact_without_claiming_eoa_profit(self):
        import subprocess
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            target = "0x" + "1" * 40
            wrapper = "0x" + "3" * 40
            harness = root / "test" / "Attack.t.sol"
            harness.parent.mkdir()
            harness.write_text(
                'contract Attack { function setUp() public { vm.createSelectFork("mainnet", 20000000); } }',
                encoding="utf-8",
            )
            artifact = self._forge_artifact()
            entry = {
                "harness": "test/Attack.t.sol",
                "state_diff_file": ".audit/godmode/attack-state-diff.json",
                "argv": ["forge", "test", "--match-path", "test/Attack.t.sol", "-vv"],
            }
            spec = {"target_address": target, "metric_addresses": [wrapper]}

            def fake_run(argv, cwd, timeout=300, env=None):
                output = pathlib.Path(cwd) / entry["state_diff_file"]
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(json.dumps(artifact), encoding="utf-8")
                return subprocess.CompletedProcess(argv, 0, "Forge test passed", "")

            with patch.object(godmode, "run", side_effect=fake_run):
                result = godmode._forge_control_run(
                    root, "http://127.0.0.1:8545", "attack", entry, spec, {}
                )

            self.assertEqual(result["backend"], "forge-state-diff")
            self.assertEqual(result["trace_schema_version"], 1)
            self.assertEqual(result["trace_events"][0]["kind"], "Call")
            self.assertEqual(result["trace_events"][0]["selector"], "0x12345678")
            self.assertEqual(result["trace_events"][0]["source_backend"], "forge-state-diff")
            self.assertEqual(result["metric"], 100)
            self.assertEqual(result["metric_kind"], "forge_account_balance_delta_without_eoa_gas")
            self.assertFalse(result["gas_verified"])
            self.assertFalse(result["transaction_envelope_verified"])
            self.assertIsNone(result["tx_hash"])
            self.assertFalse(result["target_authenticity_verified"])
            self.assertEqual(result["fidelity_label"], "simulated_caller")
            self.assertEqual(result["derived_storage_slots"][0]["address"], target)
            self.assertTrue(result["derived_storage_slots"][0]["prestate_value"].endswith("05"))

    def test_forge_archive_verification_checks_pinned_header_code_and_trace_storage(self):
        from unittest.mock import patch
        target = "0x" + "1" * 40
        from lowkey.forge_state_diff import normalize_forge_state_diff

        normalized = normalize_forge_state_diff(
            self._forge_artifact(), expected_target=target
        )
        parent_hash = "0x" + "b" * 64
        target_hash = normalized["target_code_hash"]
        block_hash = "0x" + "c" * 64
        state_root = "0x" + "d" * 64
        block = {
            "hash": block_hash, "parentHash": parent_hash,
            "stateRoot": state_root, "timestamp": "0x1234",
        }
        storage_value = "0x" + "0" * 63 + "5"

        def fake_rpc(url, method, params, timeout=20):
            if method == "eth_chainId":
                return "0x1"
            if method == "eth_getBlockByNumber":
                return ({"hash": parent_hash} if params[0] == hex(19_999_999) else block)
            if method == "eth_getCode":
                return "0x6000"
            if method == "eth_getBalance":
                return hex(1000)
            if method == "eth_getTransactionCount":
                return "0x1"
            if method == "eth_getProof":
                return {"codeHash": target_hash}
            if method == "eth_getStorageAt":
                return storage_value
            raise AssertionError("Unexpected RPC method: " + method)

        with patch.object(godmode, "rpc", side_effect=fake_rpc):
            verified = godmode._forge_source_verification(
                "https://archive.example", "http://127.0.0.1:8545",
                normalized, {"source_addresses": [target]},
            )
        self.assertFalse(verified["verified"], verified)
        self.assertTrue(verified["archive_state_verified"], verified)
        self.assertFalse(verified["identity_verified"])
        self.assertEqual(verified["fork_block"], 20_000_000)
        self.assertEqual(verified["checked_addresses"][0]["address"], target)
        self.assertEqual(len(verified["checked_storage_slots"]), 1)

        def mismatched_rpc(url, method, params, timeout=20):
            result = fake_rpc(url, method, params, timeout)
            # Mutate only the independent archive response. If both RPCs are
            # changed identically, the test no longer exercises a fork/archive mismatch.
            if (urlparse(url).hostname == "archive.example" and
                method == "eth_getBlockByNumber" and
                params[0] == hex(20_000_000)):
                return {**block, "stateRoot": "0x" + "e" * 64}
            return result

        with patch.object(godmode, "rpc", side_effect=mismatched_rpc):
            rejected = godmode._forge_source_verification(
                "https://archive.example", "http://127.0.0.1:8545",
                normalized, {"source_addresses": [target]},
            )
        self.assertFalse(rejected["verified"])
        self.assertFalse(rejected["archive_state_verified"])
        self.assertIn("stateRoot differs", rejected["reason"])

    def test_fork_identity_requires_exact_sourcify_and_resolves_eip1967_implementation(self):
        from unittest.mock import patch
        from lowkey.forge_state_diff import normalize_forge_state_diff

        target = "0x" + "1" * 40
        implementation = "0x" + "4" * 40
        raw = self._forge_artifact()
        impl_access = {
            "kind": 1, "account": implementation, "accessor": target,
            "depth": 2, "value": 0, "data": "0x12345678",
            "old_balance": 0, "new_balance": 0,
            "old_nonce": 1, "new_nonce": 1, "code_hash": "0x" + "e" * 64,
            "reverted": False, "storage_accesses": [],
        }
        raw["accesses"].append(impl_access)
        normalized = normalize_forge_state_diff(raw, expected_target=target)

        parent_hash = "0x" + "b" * 64
        target_hash = normalized["target_code_hash"]
        block = {
            "hash": "0x" + "c" * 64, "parentHash": parent_hash,
            "stateRoot": "0x" + "d" * 64, "timestamp": "0x1234",
        }
        implementation_slot = godmode.EIP1967["implementation"]
        beacon_slot = godmode.EIP1967["beacon"]
        implementation_word = "0x" + "0" * 24 + implementation[2:]
        storage_value = "0x" + "0" * 63 + "5"

        def fake_rpc(url, method, params, timeout=20):
            if method == "eth_chainId":
                return "0x1"
            if method == "eth_getBlockByNumber":
                return {"hash": parent_hash} if params[0] == hex(19_999_999) else block
            if method == "eth_getCode":
                address, tag = params
                block_no = int(tag, 16)
                if address == target and block_no == 19_999_999:
                    return "0x"
                if address == implementation and block_no == 18_999_999:
                    return "0x"
                if address in {target, implementation}:
                    return "0x6000"
                return "0x"
            if method == "eth_getBalance":
                return hex(1000)
            if method == "eth_getTransactionCount":
                return "0x1"
            if method == "eth_getProof":
                return {"codeHash": ("0x" + "e" * 64) if params[0] == implementation else target_hash}
            if method == "eth_getStorageAt":
                address, slot, tag = params
                if address == target and slot == implementation_slot:
                    return implementation_word
                if address == target and slot == beacon_slot:
                    return "0x" + "0" * 64
                return storage_value
            raise AssertionError("Unexpected RPC method: " + method)

        def exact_sourcify(chain_id, address):
            is_target = address == target
            return {
                "chainId": str(chain_id), "address": address,
                "match": "exact_match", "runtimeMatch": "exact_match",
                "creationMatch": "exact_match", "verifiedAt": "2026-11-05T00:00:00Z",
                "matchId": "123",
                "deployment": {
                    "blockNumber": "20000000" if is_target else "19000000",
                },
                "sources": {
                    "src/Proxy.sol" if is_target else "src/Logic.sol": {
                        "content": "contract Proxy {}" if is_target else "contract Logic {}"
                    }
                },
                "proxyResolution": (
                    {
                        "isProxy": True, "proxyType": "EIP1967Proxy",
                        "implementations": [{"address": implementation, "name": "Logic"}],
                    } if is_target else
                    {"isProxy": False, "proxyType": None, "implementations": []}
                ),
            }

        spec = {
            "source_addresses": [target],
            "target_authenticity": "forked_deployment",
            "target_identity": {
                "source_provider": "sourcify",
                "deployment_block": 20_000_000,
                "proxy": {
                    "type": "eip1967",
                    "implementation_address": implementation,
                    "implementation_deployment_block": 19_000_000,
                },
            },
        }
        with patch.object(godmode, "rpc", side_effect=fake_rpc), \
             patch.object(godmode, "_sourcify_contract_identity", side_effect=exact_sourcify):
            verified = godmode._forge_source_verification(
                "https://archive.example", "http://127.0.0.1:8545", normalized, spec
            )
        self.assertTrue(verified["archive_state_verified"], verified)
        self.assertTrue(verified["identity_verified"], verified)
        self.assertTrue(verified["verified"], verified)
        self.assertEqual(verified["identity"]["target"]["deployment_block"], 20_000_000)
        self.assertEqual(
            verified["identity"]["proxy"]["implementation_address"], implementation
        )
        self.assertEqual(
            verified["identity"]["proxy"]["runtime_match"], "exact_match"
        )
        self.assertEqual(verified["identity"]["target"]["source_file_count"], 1)
        self.assertEqual(len(verified["identity"]["target"]["source_bundle_sha256"]), 64)
        self.assertEqual(
            verified["identity"]["proxy"]["source_file_hashes"]["src/Logic.sol"],
            hashlib.sha256(b"contract Logic {}").hexdigest(),
        )

    def test_fork_identity_fails_closed_when_sourcify_is_not_exact(self):
        from unittest.mock import patch
        from lowkey.forge_state_diff import normalize_forge_state_diff

        target = "0x" + "1" * 40
        normalized = normalize_forge_state_diff(
            self._forge_artifact(), expected_target=target
        )
        parent_hash = "0x" + "b" * 64
        target_hash = normalized["target_code_hash"]
        block = {
            "hash": "0x" + "c" * 64, "parentHash": parent_hash,
            "stateRoot": "0x" + "d" * 64, "timestamp": "0x1234",
        }

        def fake_rpc(url, method, params, timeout=20):
            if method == "eth_chainId":
                return "0x1"
            if method == "eth_getBlockByNumber":
                return {"hash": parent_hash} if params[0] == hex(19_999_999) else block
            if method == "eth_getCode":
                if int(params[1], 16) == 19_999_999:
                    return "0x"
                return "0x6000"
            if method == "eth_getBalance":
                return hex(1000)
            if method == "eth_getTransactionCount":
                return "0x1"
            if method == "eth_getProof":
                return {"codeHash": target_hash}
            if method == "eth_getStorageAt":
                return "0x" + "0" * 63 + "5"
            raise AssertionError("Unexpected RPC method: " + method)

        def partial_sourcify(chain_id, address):
            return {
                "chainId": str(chain_id), "address": address,
                "match": "match", "runtimeMatch": "exact_match",
                "creationMatch": "exact_match",
            }

        spec = {
            "source_addresses": [target],
            "target_authenticity": "forked_deployment",
            "target_identity": {"source_provider": "sourcify", "deployment_block": 20_000_000},
        }
        with patch.object(godmode, "rpc", side_effect=fake_rpc), \
             patch.object(godmode, "_sourcify_contract_identity", side_effect=partial_sourcify):
            rejected = godmode._forge_source_verification(
                "https://archive.example", "http://127.0.0.1:8545", normalized, spec
            )
        self.assertTrue(rejected["archive_state_verified"], rejected)
        self.assertFalse(rejected["identity_verified"])
        self.assertFalse(rejected["verified"])
        self.assertIn("exact", rejected["reason"].lower())


if __name__ == "__main__":
    unittest.main()
