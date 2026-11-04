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

    def test_control_requires_positive_attack_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest = {
                "same_calls_id": "same-sequence-1",
                "metric_name": "attacker_gain",
                "control_metric_regex": "CONTROL_GAIN ([0-9]+)",
                "attack_metric_regex": "ATTACK_GAIN ([0-9]+)",
                "control": {"argv": [sys.executable, "-c", "print('CONTROL_GAIN 5'); print('LOWKEY_CALL_SEQUENCE_SHA256 ' + 'a'*64); print('LOWKEY_PRECONDITION_SHA256 ' + 'b'*64)"]},
                "attack": {"argv": [sys.executable, "-c", "print('ATTACK_GAIN 15'); print('LOWKEY_CALL_SEQUENCE_SHA256 ' + 'a'*64); print('LOWKEY_PRECONDITION_SHA256 ' + 'b'*64)"]},
            }
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                result = godmode.run_control(["control.json", "--root", str(root)])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 0)
            self.assertEqual(saved["status"], "BREAK")
            self.assertEqual(saved["control_delta"], 10)

    def test_control_rejects_mismatched_call_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest = {
                "same_calls_id": "same-sequence-1",
                "control_metric_regex": "CONTROL_GAIN ([0-9]+)",
                "attack_metric_regex": "ATTACK_GAIN ([0-9]+)",
                "control": {"argv": [sys.executable, "-c", "print('CONTROL_GAIN 2'); print('LOWKEY_CALL_SEQUENCE_SHA256 ' + 'a'*64); print('LOWKEY_PRECONDITION_SHA256 ' + 'b'*64)"]},
                "attack": {"argv": [sys.executable, "-c", "print('ATTACK_GAIN 9'); print('LOWKEY_CALL_SEQUENCE_SHA256 ' + 'c'*64); print('LOWKEY_PRECONDITION_SHA256 ' + 'b'*64)"]},
            }
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                result = godmode.run_control(["control.json", "--root", str(root)])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "OBSERVED")
            self.assertFalse(saved["same_calls_verified"])

    def test_control_requires_runtime_digests_not_only_declared_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest = {
                "same_calls_id": "same-sequence-1",
                "control_metric_regex": "CONTROL_GAIN ([0-9]+)",
                "attack_metric_regex": "ATTACK_GAIN ([0-9]+)",
                "control": {"argv": [sys.executable, "-c", "print('CONTROL_GAIN 2')"]},
                "attack": {"argv": [sys.executable, "-c", "print('ATTACK_GAIN 9')"]},
            }
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                result = godmode.run_control(["control.json", "--root", str(root)])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "OBSERVED")
            self.assertFalse(saved["same_calls_verified"])

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

    def test_control_rejects_non_positive_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest = {
                "same_calls_id": "same-sequence-1",
                "control_metric_regex": "CONTROL_GAIN ([0-9]+)",
                "attack_metric_regex": "ATTACK_GAIN ([0-9]+)",
                "control": {"argv": [sys.executable, "-c", "print('CONTROL_GAIN 15'); print('LOWKEY_CALL_SEQUENCE_SHA256 ' + 'a'*64); print('LOWKEY_PRECONDITION_SHA256 ' + 'b'*64)"]},
                "attack": {"argv": [sys.executable, "-c", "print('ATTACK_GAIN 15'); print('LOWKEY_CALL_SEQUENCE_SHA256 ' + 'a'*64); print('LOWKEY_PRECONDITION_SHA256 ' + 'b'*64)"]},
            }
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                result = godmode.run_control(["control.json", "--root", str(root)])
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
