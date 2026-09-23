import importlib.util
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "slither_tools.py"

spec = importlib.util.spec_from_file_location("slither_tools", MODULE)
slither_tools = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = slither_tools
spec.loader.exec_module(slither_tools)


class LowkeySlitherTests(unittest.TestCase):
    def test_foundry_project_root_walks_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
            nested = root / "src" / "nested"
            nested.mkdir(parents=True)
            self.assertEqual(slither_tools.foundry_project_root(nested), root)

    def test_summary_counts_impacts(self):
        payload = {
            "results": {
                "detectors": [
                    {"check": "reentrancy-eth", "impact": "High", "confidence": "High", "description": "external call"},
                    {"check": "tx-origin", "impact": "Medium", "confidence": "Medium", "description": "tx.origin"},
                    {"check": "naming-convention", "impact": "Informational", "confidence": "High", "description": "name"},
                ]
            }
        }
        with patch("builtins.print") as printer:
            slither_tools._summary(payload)
        rendered = "\n".join(str(call.args[0]) for call in printer.call_args_list)
        self.assertIn("Findings: 3", rendered)
        self.assertIn("High", rendered)
        self.assertIn("Medium", rendered)
        self.assertIn("Informational", rendered)

    def test_human_report_explains_finding(self):
        payload = {
            "results": {
                "detectors": [{
                    "check": "low-level-calls",
                    "impact": "Informational",
                    "confidence": "High",
                    "description": "Low level call in Escrow.release()",
                    "elements": [{
                        "type": "function",
                        "name": "release",
                        "source_mapping": {
                            "filename_short": "src/EthEscrow.sol",
                            "lines": [61, 69],
                        },
                    }],
                }]
            }
        }
        output = io.StringIO()
        with patch("sys.stdout", output):
            slither_tools._summary(payload)
        rendered = output.getvalue()
        self.assertIn("Issue       : Low-level external call", rendered)
        self.assertIn("Impact      : Informational", rendered)
        self.assertIn("Confidence  : High", rendered)
        self.assertIn("Where       : src/EthEscrow.sol:61-69", rendered)
        self.assertIn("Why it matters:", rendered)
        self.assertIn("Next audit move:", rendered)
        self.assertNotIn("[Informational/High]", rendered)


    @patch("slither_tools.slither_path", return_value="/usr/bin/slither")
    @patch("slither_tools.subprocess.run")
    def test_default_scan_writes_and_summarizes_evidence(self, run, _path):
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            evidence = root / ".audit" / "slither"
            evidence.mkdir(parents=True)
            payload = {"results": {"detectors": []}}
            (evidence / "latest.json").write_text(json.dumps(payload), encoding="utf-8")
            with patch("slither_tools._default_paths", return_value=(evidence / "latest.json", evidence / "latest.sarif")):
                result = slither_tools.run_default(root)
        self.assertEqual(result, 0)
        command = run.call_args.args[0]
        self.assertIn("--exclude-dependencies", command)
        self.assertIn("--fail-none", command)
        self.assertIn("--json", command)
        self.assertIn("--sarif", command)

    @patch("slither_tools.slither_path", return_value="/usr/bin/slither")
    @patch("slither_tools.subprocess.run")
    def test_option_first_command_auto_targets_project(self, run, _path):
        run.return_value.returncode = 0
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            with patch.object(slither_tools.Path, "cwd", return_value=root):
                result = slither_tools.main(["--detect", "tx-origin"])
        self.assertEqual(result, 0)
        self.assertEqual(run.call_args.args[0][1:4], [str(root), "--detect", "tx-origin"])


    @patch("slither_tools.slither_path", return_value=None)
    def test_missing_slither_is_clean_failure(self, _path):
        self.assertEqual(slither_tools.run_default(pathlib.Path(".")), 1)


if __name__ == "__main__":
    unittest.main()
