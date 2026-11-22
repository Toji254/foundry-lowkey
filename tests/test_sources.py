import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast_sources", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class SoliditySourcesCommandTests(unittest.TestCase):
    def write(self, root, relative, content):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def run_sources(self, args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = lk.run_sources(args)
        return code, output.getvalue()

    def fixture(self, root):
        self.write(root, "foundry.toml", "[profile.default]\n")
        self.write(root, "contracts/core/Vault.sol", "pragma solidity ^0.8.20;\ncontract Vault {}\n")
        self.write(root, "contracts/core/OrderBook.sol", "contract OrderBook {}\n")
        self.write(root, "contracts/interfaces/IVault.sol", "interface IVault {}\n")
        self.write(root, "test/Vault.t.sol", "contract VaultTest {}\n")
        self.write(root, "scripts/Deploy.sol", "contract Deploy {}\n")

    def test_default_lists_solidity_files_grouped_by_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)

            code, output = self.run_sources([str(root)])

            self.assertEqual(code, 0)
            self.assertIn("LOWKEY // SOLIDITY SOURCE INVENTORY", output)
            self.assertIn("contracts/core (2 file(s))", output)
            self.assertIn("contracts/core/Vault.sol", output)
            self.assertIn("contracts/interfaces/IVault.sol", output)
            self.assertIn("test/Vault.t.sol", output)
            self.assertIn("scripts/Deploy.sol", output)
            self.assertIn("Coverage     : COMPLETE", output)

    def test_application_scope_excludes_support_and_support_scope_keeps_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)

            code, application = self.run_sources([str(root), "--scope", "application"])
            self.assertEqual(code, 0)
            self.assertIn("contracts/core/Vault.sol", application)
            self.assertNotIn("test/Vault.t.sol", application)
            self.assertNotIn("scripts/Deploy.sol", application)

            code, support = self.run_sources([str(root), "--scope", "support"])
            self.assertEqual(code, 0)
            self.assertNotIn("contracts/core/Vault.sol", support)
            self.assertIn("test/Vault.t.sol", support)
            self.assertIn("scripts/Deploy.sol", support)

    def test_type_group_and_filter_match_solidity_declarations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)

            code, output = self.run_sources([str(root), "--group", "type", "--filter", "OrderBook"])

            self.assertEqual(code, 0)
            self.assertIn("contracts (1 file(s))", output)
            self.assertIn("contracts/core/OrderBook.sol", output)
            self.assertNotIn("contracts/core/Vault.sol", output)

    def test_json_mode_is_machine_readable_and_preserves_inventory_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)

            code, output = self.run_sources([str(root), "--json"])
            payload = json.loads(output)

            self.assertEqual(code, 0)
            self.assertTrue(payload["complete"])
            self.assertEqual(payload["files_discovered"], 5)
            self.assertEqual(payload["files_displayed"], 5)
            self.assertEqual(payload["scope"], "all")
            self.assertEqual(payload["group"], "directory")
            self.assertTrue(any(
                item["path"] == "contracts/core/Vault.sol"
                for group in payload["groups"]
                for item in group["files"]
            ))

    def test_invalid_options_and_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)

            code, output = self.run_sources([str(root), "--unknown"])
            self.assertEqual(code, 2)
            self.assertIn("unknown lk sources option", output)

            code, output = self.run_sources([str(root), "--group", "function"])
            self.assertEqual(code, 2)
            self.assertIn("--group must be", output)

    def test_incomplete_inventory_is_reported_and_returns_two(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            blocked = root / "contracts" / "private"
            blocked.mkdir(parents=True)
            self.write(root, "contracts/Vault.sol", "contract Vault {}\n")
            real_scandir = lk.project_tools.os.scandir

            def failing_scandir(path):
                if pathlib.Path(path).resolve() == blocked.resolve():
                    raise PermissionError("permission denied for test")
                return real_scandir(path)

            with patch.object(lk.project_tools.os, "scandir", side_effect=failing_scandir):
                code, output = self.run_sources([str(root)])

            self.assertEqual(code, 2)
            self.assertIn("Coverage     : INCOMPLETE", output)
            self.assertIn("contracts/private [enumerate]", output)
            self.assertIn("permission denied for test", output)


if __name__ == "__main__":
    unittest.main()
