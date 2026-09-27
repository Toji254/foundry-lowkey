import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "project_detection.py"

spec = importlib.util.spec_from_file_location("project_detection", MODULE)
project_detection = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(project_detection)


class ProjectDetectionTests(unittest.TestCase):
    def test_cairo_manifest_wins_over_nested_solidity_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "Scarb.toml").write_text("[package]\nname = \"demo\"\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "lib.cairo").write_text("fn main() {}\n", encoding="utf-8")
            nested = root / "workspace" / "apps" / "staking" / "L1" / "starkware" / "solidity"
            nested.mkdir(parents=True)
            (nested / "ProxySupport.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")

            info = project_detection.detect_project(root)

            self.assertEqual(info["backend"], "cairo-starknet")
            self.assertIn("cairo-starknet", info["stacks"])
            self.assertEqual(info["languages"]["solidity"], 1)
            self.assertEqual(info["languages"]["cairo"], 1)

    def test_vyper_project_detected_without_foundry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\ndependencies = [\"vyper>=0.4.0\"]\n",
                encoding="utf-8",
            )
            (root / "contracts").mkdir()
            (root / "contracts" / "Vault.vy").write_text(
                "@external\ndef ping():\n    pass\n",
                encoding="utf-8",
            )

            info = project_detection.detect_project(root)

            self.assertEqual(info["backend"], "vyper")
            self.assertEqual(info["kind"], "vyper")
            self.assertEqual(info["languages"]["vyper"], 1)

    def test_foundry_manifest_selects_foundry_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")

            info = project_detection.detect_project(root)

            self.assertEqual(info["backend"], "foundry")
            self.assertEqual(info["kind"], "foundry")

    def test_dependency_and_build_directories_do_not_affect_language_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Vault.vy").write_text("# project source\n", encoding="utf-8")
            ignored = root / "lib" / "vendor"
            ignored.mkdir(parents=True)
            (ignored / "Fake.sol").write_text("contract Fake {}\n", encoding="utf-8")

            info = project_detection.detect_project(root)

            self.assertNotIn("solidity", info["languages"])
            self.assertEqual(info["languages"]["vyper"], 1)


if __name__ == "__main__":
    unittest.main()
