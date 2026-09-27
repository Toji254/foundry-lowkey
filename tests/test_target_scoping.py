import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkey_lk", MODULE)
lk = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(lk)


class TargetScopingTests(unittest.TestCase):
    def test_target_aliases_ignore_targets_owned_by_other_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            current_root = pathlib.Path(tmp) / "curve"
            other_root = pathlib.Path(tmp) / "bounty"
            current_root.mkdir()
            other_root.mkdir()

            config = {
                "aliases": {
                    "curve": "0x1111111111111111111111111111111111111111",
                    "bounty": "0x2222222222222222222222222222222222222222",
                },
                "targets": {},
                "project_roots": {
                    "0x1111111111111111111111111111111111111111": str(current_root),
                    "0x2222222222222222222222222222222222222222": str(other_root),
                },
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=current_root):
                aliases = lk.target_aliases(config, current_root)

            self.assertEqual(
                aliases,
                {"curve": "0x1111111111111111111111111111111111111111"},
            )

    def test_numeric_target_resolution_is_project_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            current_root = pathlib.Path(tmp) / "curve"
            other_root = pathlib.Path(tmp) / "bounty"
            current_root.mkdir()
            other_root.mkdir()

            config = {
                "aliases": {
                    "bounty": "0x2222222222222222222222222222222222222222",
                    "curve": "0x1111111111111111111111111111111111111111",
                },
                "targets": {},
                "project_roots": {
                    "0x1111111111111111111111111111111111111111": str(current_root),
                    "0x2222222222222222222222222222222222222222": str(other_root),
                },
            }

            self.assertEqual(
                lk.resolve_target_ref(config, "1", current_root),
                "0x1111111111111111111111111111111111111111",
            )

    def test_interactive_targets_selects_current_project_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            current_root = pathlib.Path(tmp) / "curve"
            current_root.mkdir()
            address = "0x1111111111111111111111111111111111111111"
            config = {
                "target": None,
                "target_contract": None,
                "aliases": {"curve": address},
                "targets": {},
                "project_roots": {address: str(current_root)},
                "abi_paths": {},
            }

            with patch.object(lk.audit_context, "foundry_project_root", return_value=current_root), \
                 patch.object(lk, "project_context_target", return_value=None), \
                 patch.object(lk, "discover_deployments", return_value=[]), \
                 patch.object(lk, "save_config"), \
                 patch.object(lk.audit_context, "set_target"), \
                 patch("builtins.input", return_value="1"):
                code = lk.run_targets(config, interactive=True)

            self.assertEqual(code, 0)
            self.assertEqual(config["target"], address)
            self.assertEqual(config["target_contract"], "curve")


if __name__ == "__main__":
    unittest.main()
