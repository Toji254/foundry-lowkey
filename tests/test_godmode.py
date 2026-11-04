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
                "control": {"argv": [sys.executable, "-c", "print('CONTROL_GAIN 5')"]},
                "attack": {"argv": [sys.executable, "-c", "print('ATTACK_GAIN 15')"]},
            }
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                result = godmode.run_control(["control.json", "--root", str(root)])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 0)
            self.assertEqual(saved["status"], "BREAK")
            self.assertEqual(saved["control_delta"], 10)

    def test_control_rejects_non_positive_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest = {
                "same_calls_id": "same-sequence-1",
                "control_metric_regex": "CONTROL_GAIN ([0-9]+)",
                "attack_metric_regex": "ATTACK_GAIN ([0-9]+)",
                "control": {"argv": [sys.executable, "-c", "print('CONTROL_GAIN 15')"]},
                "attack": {"argv": [sys.executable, "-c", "print('ATTACK_GAIN 15')"]},
            }
            (root / "control.json").write_text(json.dumps(manifest), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                result = godmode.run_control(["control.json", "--root", str(root)])
            saved = json.loads((root / ".audit/godmode/control.json").read_text())
            self.assertEqual(result, 1)
            self.assertEqual(saved["status"], "OBSERVED")
            self.assertEqual(saved["control_delta"], 0)


if __name__ == "__main__":
    unittest.main()
