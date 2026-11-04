import importlib.util
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
import io
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "godmode.py"
SPEC = importlib.util.spec_from_file_location("lowkey_godmode_tested", MODULE)
godmode = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = godmode
SPEC.loader.exec_module(godmode)


class GodmodeTests(unittest.TestCase):
    def test_registry_covers_all_44_numbered_capabilities(self):
        self.assertEqual(len(godmode.CAPABILITIES), 44)
        self.assertEqual([row[0] for row in godmode.CAPABILITIES], list(range(1, 45)))
        self.assertEqual(len({row[1] for row in godmode.CAPABILITIES}), 44)

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
            "control": {"argv": [sys.executable, "-c", "pass"]},
            "attack": {"argv": [sys.executable, "-c", "pass"]},
        }
        (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
        return manifest, target, sender, wrapper

    def _mock_trace_rpc(self, target, sender, wrapper, attack_calldata="0x12345678", control_gain=5, attack_gain=15, external_state=None, attack_tx_fields=None):
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
                return {"status": "0x1", "blockNumber": "0x65", "transactionIndex": "0x0"}
            if method == "eth_getBalance":
                if params[1] == "0x65":
                    gain = control_gain if state["tx_hash"] == "0x" + "a" * 64 else attack_gain
                    if params[0] == sender:
                        return hex(0x100 - 1)
                    if params[0] == wrapper:
                        return hex(0x100 + gain + 1)
                return "0x100"
            if method == "eth_getTransactionCount":
                return "0x1"
            if method == "eth_getCode":
                return "0x6000" if params[0] == wrapper else "0x"
            if method == "eth_getStorageAt":
                if params[0] == wrapper and params[1] == "0x0" and params[2] == "latest":
                    return state["scenario_slot"]
                return "0x" + "0" * 63 + "1"
            if method == "debug_traceTransaction":
                return {
                    "type": "CALL",
                    "from": sender,
                    "to": wrapper,
                    "input": state["input"],
                    "value": "0x0",
                    "calls": [{
                        "type": "CALL",
                        "from": wrapper,
                        "to": target,
                        "input": "0xdeadbeef",
                        "value": "0x0",
                    }],
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
                output = f"LOWKEY_TRACE_TX_HASH {hashes[i]}\\n"
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(target, sender, wrapper)), \\
                 patch.object(godmode, "run", side_effect=fake_run), \\
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 0)
            self.assertEqual(saved["status"], "BREAK")
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
                output = f"LOWKEY_TRACE_TX_HASH {hashes[i]}\\n"
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(target, sender, wrapper, "0xaabbccdd")), \\
                 patch.object(godmode, "run", side_effect=fake_run), \\
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "OBSERVED")
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
            self.assertEqual(saved["status"], "OBSERVED")
            self.assertTrue(saved["same_entry_call_verified"])
            self.assertFalse(saved["same_transaction_envelope_verified"])
            self.assertTrue(saved["same_prestate_verified"])
            self.assertIn("transaction nonce/gas/fee/type/access-list envelope differs", saved["reasons"])

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
            tx_hashes = iter(["0x" + "a" * 64, "0x" + "b" * 64])
            gain_by_tx = {"0x" + "a" * 64: 5, "0x" + "b" * 64: 15}

            def fake_run(argv, cwd, timeout=300, env=None):
                if argv[0] == "prepare":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                tx_hash = next(tx_hashes)
                return subprocess.CompletedProcess(argv, 0, f"LOWKEY_TRACE_TX_HASH {tx_hash}\n", "")

            rpc_state = {"tx_hash": None, "input": None, "scenario_slot": "0x" + "0" * 64}
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
            self.assertEqual(result, 0)
            self.assertEqual(saved["status"], "BREAK")
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
            calls = []
            def fake_run(argv, cwd, timeout=300, env=None):
                calls.append(argv)
                if argv[0] == "prepare":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                return subprocess.CompletedProcess(argv, 0, "LOWKEY_TRACE_TX_HASH " + "0x" + "a" * 64 + "\n", "")

            with patch.object(godmode, "rpc", side_effect=self._mock_trace_rpc(target, sender, wrapper)), \
                 patch.object(godmode, "run", side_effect=fake_run), \
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "OBSERVED")
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
            self.assertEqual(saved["status"], "OBSERVED")
            self.assertTrue(saved["same_entry_call_verified"])
            self.assertFalse(saved["same_transaction_envelope_verified"])
            self.assertTrue(saved["same_prestate_verified"])
            self.assertIn("transaction nonce/gas/fee/type/access-list envelope differs", saved["reasons"])

    def test_control_rejects_script_supplied_hashes_without_a_mined_trace(self):
        from unittest.mock import patch
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._control_manifest(root)

            def fake_run(argv, cwd, timeout=300, env=None):
                output = "LOWKEY_CALL_SEQUENCE_SHA256 " + "a" * 64
                return subprocess.CompletedProcess(argv, 0, output, "")

            with patch.object(godmode, "run", side_effect=fake_run), \\
                 redirect_stdout(io.StringIO()):
                result = godmode.run_control([
                    "control.json", "--root", str(root), "--rpc-url", "http://127.0.0.1:8545"
                ])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "OBSERVED")
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
                    return {"type": "CALL", "from": sender, "to": target, "input": "0x12345678",
                            "value": "0x0", "calls": []}
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
            self.assertEqual(saved["status"], "OBSERVED")
            self.assertEqual(saved["control_delta"], 0)

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


if __name__ == "__main__":
    unittest.main()
