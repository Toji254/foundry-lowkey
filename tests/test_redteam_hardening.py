import contextlib
import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

import analysis_adapters


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, LOWKEY / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


forge_tools = load_module("redteam_forge_tools", "forge_tools.py")
generator = load_module("redteam_generator", "generator.py")
lk = load_module("redteam_lk", "lk.py")


class RedTeamHardeningTests(unittest.TestCase):
    def test_string_masking_handles_solidity_and_vyper(self):
        solidity = 'contract C { function x() external { target.delegatecall(""); returnBytes("selfdestruct(bytes)"); } }'
        vyper = "message: String[64] = 'raw_call(msg.sender, b"", value=1)'\nraw_call(msg.sender, b"", value=1)"
        sm = analysis_adapters._strip_comments(solidity, "solidity", mask_strings=True)
        vm = analysis_adapters._strip_comments(vyper, "vyper", mask_strings=True)
        self.assertNotIn("selfdestruct(bytes)", sm)
        self.assertIn("delegatecall", sm)
        self.assertEqual(vm.count("raw_call("), 1)

    def test_broken_hardhat_dependency_forces_partial_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "hardhat.config.js").write_text("module.exports = {}\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"devDependencies": {"hardhat": "^3.0.0", "@nomicfoundation/hardhat-toolbox": "^6.0.0"}}),
                encoding="utf-8",
            )
            (root / "node_modules").mkdir()
            (root / "contracts").mkdir()
            (root / "contracts" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault {}\n",
                encoding="utf-8",
            )
            info = analysis_adapters.inspect_repository(root)
            self.assertEqual(info["backend"], "hardhat")
            self.assertEqual(info["coverage"], "partial")
            self.assertEqual(info["dependency_health"]["hardhat"]["status"], "broken")
            self.assertIn("hardhat", info["dependency_health"]["hardhat"]["missing"])

    def test_fresh_hardhat_without_node_modules_is_not_called_broken(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "hardhat.config.js").write_text("module.exports = {}\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"devDependencies": {"hardhat": "^3.0.0"}}),
                encoding="utf-8",
            )
            (root / "contracts").mkdir()
            (root / "contracts" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault {}\n",
                encoding="utf-8",
            )
            info = analysis_adapters.inspect_repository(root)
            self.assertEqual(info["dependency_health"]["hardhat"]["status"], "not-installed")

    def test_generated_diagnostics_are_filtered_without_hiding_project_errors(self):
        generated = """error: generated failure
   ╰─> script/LowkeyPoC_Vault.s.sol:24:32

Error: solar reported 1 error; see the diagnostics printed above
"""
        visible, filtered = forge_tools._filter_generated_diagnostics(generated)
        self.assertEqual(visible, "")
        self.assertEqual(filtered, 1)

        mixed = """error: combined failure
   ╰─> script/LowkeyPoC_Vault.s.sol:24:32
   ╰─> src/Vault.sol:9:5
"""
        visible, filtered = forge_tools._filter_generated_diagnostics(mixed)
        self.assertEqual(filtered, 0)
        self.assertIn("src/Vault.sol:9:5", visible)

    def test_forge_timeout_is_clamped_and_watch_is_explicit(self):
        with patch.dict(os.environ, {"LOWKEY_FORGE_TIMEOUT": "1"}):
            self.assertEqual(lk._bounded_forge_timeout([]), 30)
            self.assertEqual(forge_tools._forge_timeout([]), 30)
        with patch.dict(os.environ, {"LOWKEY_FORGE_TIMEOUT": "99999"}):
            self.assertEqual(lk._bounded_forge_timeout([]), 7200)
            self.assertEqual(forge_tools._forge_timeout([]), 7200)
        self.assertIsNone(lk._bounded_forge_timeout(["--watch"]))
        self.assertIsNone(forge_tools._forge_timeout(["--watch"]))

    def test_actor_reset_mode_1_clears_active_actor_but_keeps_profile(self):
        config = lk.fresh_config()
        config["actor"] = "Alice"
        config["wallets"]["Alice"] = {
            "source": "anvil-default",
            "anvil_index": 1,
            "address": "0x1111111111111111111111111111111111111111",
        }
        config["labels"]["0x1111111111111111111111111111111111111111"] = "Alice"

        with patch.object(lk, "save_config"):
            code = lk.dispatch_command("actor", ["reset", "1"], config)

        self.assertEqual(code, 0)
        self.assertIsNone(config["actor"])
        self.assertIn("Alice", config["wallets"])
        self.assertIn(
            "0x1111111111111111111111111111111111111111",
            config["labels"],
        )

    def test_actor_reset_mode_2_clears_active_actor_and_profiles(self):
        config = lk.fresh_config()
        config["actor"] = "Alice"
        config["wallets"]["Alice"] = {
            "source": "anvil-default",
            "anvil_index": 1,
            "address": "0x1111111111111111111111111111111111111111",
        }
        config["wallets"]["lab-deployer"] = {
            "source": "anvil-default",
            "anvil_index": 0,
            "address": "0x2222222222222222222222222222222222222222",
            "internal": True,
        }
        config["labels"]["0x1111111111111111111111111111111111111111"] = "Alice"

        with patch.object(lk, "save_config"):
            code = lk.dispatch_command("actor", ["reset", "2"], config)

        self.assertEqual(code, 0)
        self.assertIsNone(config["actor"])
        self.assertNotIn("Alice", config["wallets"])
        self.assertNotIn(
            "0x1111111111111111111111111111111111111111",
            config["labels"],
        )
        self.assertIn("lab-deployer", config["wallets"])

    def test_actor_list_does_not_replace_actor_identity_with_contract_identity(self):
        config = lk.fresh_config()
        config["actor"] = "lab-deployer"
        config["wallets"]["lab-deployer"] = {
            "source": "anvil-default",
            "anvil_index": 0,
            "address": "0x2222222222222222222222222222222222222222",
            "internal": True,
        }

        with patch.object(
            lk,
            "anvil_rpc_info",
            return_value={
                "url": "http://127.0.0.1:8545",
                "accounts": [
                    "0x2222222222222222222222222222222222222222"
                ],
            },
        ), patch.object(lk, "_contract_identity", return_value={
            "address": "0x2222222222222222222222222222222222222222",
            "contract": True,
            "name": "LOKI",
            "symbol": "LK",
            "kind": "token",
        }), patch.object(lk, "save_config"):

            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = lk.dispatch_command("actors", [], config)

        rendered = output.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("lab-deployer", rendered)
        self.assertIn("Contract   : LOKI (LK)", rendered)

    def test_scan_rejects_unknown_flag_instead_of_treating_it_as_a_path(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = lk.run_scan(["--json"])
        self.assertEqual(code, 2)
        self.assertIn("Unknown lk scan option", err.getvalue())

    def test_use_unknown_target_exits_nonzero(self):
        config = lk.fresh_config()
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(lk, "activate_project_target"), \
                 patch.object(lk, "save_config"), \
                 patch.object(lk, "resolve_target_ref", return_value=None), \
                 patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path(tmp)), \
                 contextlib.redirect_stderr(err):
                code = lk.dispatch_command("use", ["definitely-not-a-target"], config)
        self.assertEqual(code, 2)
        self.assertIn("Unknown target for project", err.getvalue())

    def test_unknown_command_is_rejected_before_cast(self):
        with patch.object(lk, "run_cast", side_effect=AssertionError("cast fallback reached")):
            self.assertEqual(lk.dispatch_command("not-a-command", [], {}), 2)

    def test_generator_gate_does_not_create_forge_std_scaffold_without_dependency(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            with patch.object(generator.shutil, "which", return_value=None):
                self.assertFalse(generator._forge_std_available(root))
            self.assertFalse((root / "script").exists())


if __name__ == "__main__":
    unittest.main()
