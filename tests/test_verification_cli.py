import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey.verification_adapters import CapabilityRegistry, EngineCapability, ExecutableAdapter
from lowkey import verification_cli


class VerificationCliTests(unittest.TestCase):
    def test_engine_inventory_exposes_installation_and_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
            with patch("lowkey.verification_adapters.shutil.which", return_value="/usr/bin/tool"):
                report = verification_cli.engine_inventory(root)
        forge = next(item for item in report["engines"] if item["name"] == "forge")
        self.assertTrue(forge["available"])
        self.assertIn("unit", forge["supported_test_kinds"])
        self.assertIn("fuzz", forge["supported_test_kinds"])
        slither = next(item for item in report["engines"] if item["name"] == "slither")
        self.assertEqual(tuple(slither["test_kinds"]), ())

    def test_campaign_manifest_executes_and_saves_native_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
            manifest = root / "campaign.json"
            manifest.write_text(json.dumps({
                "test_kind": "unit",
                "profile": "light",
                "request": {"argv_by_engine": {"fake": ["-c", "print('native output')"]}},
                "budget": {"timeout_seconds": 5},
            }), encoding="utf-8")
            adapter = ExecutableAdapter(EngineCapability(
                "fake", sys.executable, ("unit",), ("solidity",), ("foundry",),
                ("foundry.toml",), memory_class="low",
            ))
            registry = CapabilityRegistry([adapter])
            with patch("lowkey.verification_cli.default_registry", return_value=registry):
                report = verification_cli.run_campaign_manifest(
                    manifest, project_root=root,
                    output_path=".audit/verification/campaign.json",
                )
            saved = json.loads((root / ".audit/verification/campaign.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["execution_mode"], "serial")
        self.assertGreaterEqual(report["duration_seconds"], 0)
        self.assertGreaterEqual(report["engine_duration_seconds"], 0)
        self.assertIn("native output", report["results"][0]["result"]["raw_stdout"])
        self.assertEqual(saved["report_path"], report["report_path"])


if __name__ == "__main__":
    unittest.main()
