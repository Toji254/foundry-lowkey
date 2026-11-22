import importlib.util
import io
import os
import pathlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY_DIR = ROOT / "lowkey"
if str(LOWKEY_DIR) not in sys.path:
    sys.path.insert(0, str(LOWKEY_DIR))

import project_tools

LK_MODULE = LOWKEY_DIR / "lk.py"
spec = importlib.util.spec_from_file_location("lowkeycast_project_verbosity", LK_MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class ProjectVerbosityTests(unittest.TestCase):
    def write(self, root, relative, content):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def fixture(self, root):
        self.write(root, "foundry.toml", '[profile.default]\\nsrc = "src"\\n')
        self.write(
            root,
            "src/IRepository.sol",
            "pragma solidity ^0.8.20;\\ninterface IRepository {}\\n",
        )
        self.write(
            root,
            "src/Repository.sol",
            'pragma solidity ^0.8.20;\\nimport "./IRepository.sol";\\ncontract Repository is IRepository {}\\n',
        )
        self.write(
            root,
            "src/Coordinator.sol",
            'pragma solidity ^0.8.20;\\nimport "./IRepository.sol";\\ncontract Coordinator {}\\n',
        )
        self.write(
            root,
            "src/Worker.sol",
            'pragma solidity ^0.8.20;\\nimport "./Coordinator.sol";\\ncontract Worker is Coordinator {}\\n',
        )

    def overview(self, root, verbosity=0):
        map_output = io.StringIO()
        with redirect_stdout(map_output):
            result = project_tools.render_project_map(root)
        output = io.StringIO()
        with redirect_stdout(output):
            project_tools.render_project_overview(result, verbosity=verbosity)
        return result, output.getvalue()

    def run_cli(self, root, args):
        previous = os.getcwd()
        output = io.StringIO()
        try:
            os.chdir(root)
            with patch.object(lk, "workspace_context", return_value=None), \\
                 patch.object(lk.audit_context, "foundry_project_root", return_value=root), \\
                 patch.object(lk, "_sync_security_patterns"), \\
                 patch.object(
                     lk,
                     "_security_pattern_summary",
                     return_value={"total": 0, "reviews": 0, "confirmed": 0, "candidates": 0},
                 ), \\
                 redirect_stdout(output):
                code = lk.run_project_map({}, args)
        finally:
            os.chdir(previous)
        return code, output.getvalue()

    def test_default_overview_is_short_and_derived_from_generic_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)
            result, output = self.overview(root)

            self.assertIn("LOWKEY PROJECT OVERVIEW", output)
            self.assertIn("STRUCTURAL NAVIGATION", output)
            self.assertIn("Coordinator", output)
            self.assertIn("Repository", output)
            self.assertIn("IRepository", output)
            self.assertIn("not a risk ranking", output)
            self.assertNotIn("LOWKEY PROJECT MAP", output)
            self.assertNotIn("GMX", output)
            self.assertGreater(result["graph"]["summary"]["imports"], 0)

    def test_verbose_overview_adds_relationships_without_dumping_full_graph(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)
            _result, output = self.overview(root, verbosity=1)

            self.assertIn("RELATIONSHIP DETAIL", output)
            self.assertIn("Referenced by:", output)
            self.assertIn("->", output)
            self.assertNotIn("1. WHAT IS THE PROTOCOL?", output)

    def test_very_verbose_cli_preserves_the_legacy_full_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)
            code, output = self.run_cli(root, ["-vv"])

            self.assertEqual(code, 0)
            self.assertIn("LOWKEY PROJECT MAP", output)
            self.assertIn("1. WHAT IS THE PROTOCOL?", output)
            self.assertIn("2. HOW DOES IT DEPEND ON OTHER CODE?", output)

    def test_cli_default_and_single_verbose_select_the_expected_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)

            code, compact = self.run_cli(root, [])
            self.assertEqual(code, 0)
            self.assertIn("LOWKEY PROJECT OVERVIEW", compact)
            self.assertNotIn("LOWKEY PROJECT MAP", compact)

            code, expanded = self.run_cli(root, ["-v"])
            self.assertEqual(code, 0)
            self.assertIn("LOWKEY PROJECT OVERVIEW", expanded)
            self.assertIn("RELATIONSHIP DETAIL", expanded)
            self.assertNotIn("LOWKEY PROJECT MAP", expanded)

    def test_json_remains_complete_json_even_with_verbosity_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)
            code, output = self.run_cli(root, ["-vv", "--json"])

            import json
            payload = json.loads(output)
            self.assertEqual(code, 0)
            self.assertIn("graph", payload)
            self.assertIn("human", payload)
            self.assertIn("security_patterns", payload)

    def test_non_solidity_projects_get_a_language_neutral_overview(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Scarb.toml", '[package]\\nname = "sample"\\nversion = "0.1.0"\\n')
            self.write(root, "src/lib.cairo", "fn greet() {}\\n")
            _result, output = self.overview(root)

            self.assertIn("LOWKEY PROJECT OVERVIEW", output)
            self.assertIn("cairo", output.lower())
            self.assertNotIn("Solidity source files", output)
            self.assertNotIn("Vault", output)

    def test_unknown_project_option_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.fixture(root)
            code, output = self.run_cli(root, ["--not-a-project-option"])

            self.assertEqual(code, 2)
            self.assertIn("unknown lk project option", output.lower())


if __name__ == "__main__":
    unittest.main()
