import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

ROOT = Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

import analysis_adapters


class AnalysisAdapterTests(unittest.TestCase):
    def test_empty_project_is_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = analysis_adapters.inspect_repository(tmp)
            self.assertEqual(info["coverage"], "none")
            self.assertEqual(info["analysis_status"], "no-application-source")
            self.assertEqual(info["source_file_count"], 0)
            self.assertTrue(info["capabilities"]["project_detection"])

    def test_single_file_scope_does_not_expand_to_entire_repository(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            first = root / "src" / "A.sol"
            second = root / "src" / "B.sol"
            first.write_text("pragma solidity ^0.8.20; contract A { function x() external { tx.origin; } }\n", encoding="utf-8")
            second.write_text("pragma solidity ^0.8.20; contract B { function y() external { tx.origin; } }\n", encoding="utf-8")
            info = analysis_adapters.inspect_repository(first)
            self.assertEqual(info["scope_type"], "single-file")
            self.assertEqual(info["source_file_count"], 1)
            self.assertEqual(info["source_files"], ["A.sol"])

    def test_workspace_scope_is_never_reported_as_full(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["a", "b"]\n',
                encoding="utf-8",
            )
            (root / "a" / "src").mkdir(parents=True)
            (root / "b" / "src").mkdir(parents=True)
            (root / "a" / "src" / "lib.rs").write_text("pub fn a() {}\n", encoding="utf-8")
            (root / "b" / "src" / "lib.rs").write_text("pub fn b() {}\n", encoding="utf-8")
            info = analysis_adapters.inspect_repository(root)
            self.assertTrue(info["workspace"])
            self.assertEqual(info["scope_type"], "workspace")
            self.assertEqual(info["coverage"], "partial")
            self.assertEqual(info["analysis_status"], "workspace-aggregate")

    def test_cargo_workspace_regex_is_strict_and_does_not_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "fixture"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                "pub fn ok() { let _ = 1u64; }\n",
                encoding="utf-8",
            )
            info = analysis_adapters.inspect_repository(root)
            self.assertEqual(info["backend"], "cargo")
            self.assertFalse(info["workspace"])

    def test_cosmwasm_is_distinguished_from_generic_cargo(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "cw-demo"\nversion = "0.1.0"\n'
                '[dependencies]\ncosmwasm-std = "2"\n',
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "contract.rs").write_text(
                "pub fn execute() { let _ = cosmwasm_std::Addr::unchecked(\"x\"); }\n",
                encoding="utf-8",
            )
            info = analysis_adapters.inspect_repository(root)
            self.assertIn("cosmwasm", info["stacks"])
            self.assertEqual(info["backend"], "cosmwasm")
            self.assertIn("cosmwasm", info["adapters"])
            self.assertEqual(info["coverage"], "partial")

    def test_anchor_rust_sources_are_analyzed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Anchor.toml").write_text("[provider]\ncluster = \"localnet\"\n", encoding="utf-8")
            (root / "programs" / "demo" / "src").mkdir(parents=True)
            source = root / "programs" / "demo" / "src" / "lib.rs"
            source.write_text(
                "pub fn dangerous() { unsafe { let _ = 1u64; } invoke_signed(); }\n",
                encoding="utf-8",
            )
            result = analysis_adapters.source_triage(root)
            self.assertEqual(result["files_scanned"], 1)
            labels = {item["label"] for item in result["markers"]}
            self.assertIn("UNSAFE", labels)
            self.assertIn("RAW_SYSCALL", labels)

    def test_first_party_lib_source_is_included(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lib").mkdir()
            source = root / "lib" / "Protocol.sol"
            source.write_text(
                "pragma solidity ^0.8.20; contract Protocol { function x() external { tx.origin; } }\n",
                encoding="utf-8",
            )
            result = analysis_adapters.source_triage(root)
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual(result["project"]["source_files"], ["lib/Protocol.sol"])

    def test_lib_dependency_from_remapping_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "lib" / "openzeppelin-contracts" / "contracts").mkdir(parents=True)
            (root / "remappings.txt").write_text(
                "@openzeppelin/=lib/openzeppelin-contracts/contracts/\n",
                encoding="utf-8",
            )
            dependency = root / "lib" / "openzeppelin-contracts" / "contracts" / "Ownable.sol"
            dependency.write_text(
                "pragma solidity ^0.8.20; abstract contract Ownable {}\n",
                encoding="utf-8",
            )
            (root / "src").mkdir()
            app = root / "src" / "Vault.sol"
            app.write_text(
                "pragma solidity ^0.8.20; contract Vault {}\n",
                encoding="utf-8",
            )
            result = analysis_adapters.source_triage(root)
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual(result["project"]["source_files"], ["src/Vault.sol"])

    def test_mixed_cairo_and_solidity_scope_keeps_both_adapters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Scarb.toml").write_text('[package]\nname = "bridge"\n', encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "bridge.cairo").write_text(
                "fn bridge_call() { deploy_syscall(); }\n", encoding="utf-8"
            )
            solidity_dir = root / "contracts" / "solidity"
            solidity_dir.mkdir(parents=True)
            (solidity_dir / "Bridge.sol").write_text(
                "pragma solidity ^0.8.20; contract Bridge { function x() external { assembly {} } }\n",
                encoding="utf-8",
            )
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_bridge.py").write_text(
                "def test_bridge(): pass\n", encoding="utf-8"
            )

            info = analysis_adapters.inspect_repository(root)

            self.assertEqual(info["backend"], "multi")
            self.assertIn("cairo-starknet", info["stacks"])
            self.assertIn("evm-source", info["stacks"])
            self.assertIn("solidity", info["languages"])
            self.assertIn("cairo", info["languages"])
            self.assertEqual(info["source_file_count"], 2)

    def test_source_only_solidity_gets_evm_source_adapter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "contracts").mkdir()
            (root / "contracts" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault {}\n",
                encoding="utf-8",
            )
            info = analysis_adapters.inspect_repository(root)
            self.assertEqual(info["backend"], "evm-source")
            self.assertIn("evm-source", info["stacks"])

    def test_security_plan_uses_installed_native_analyzers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            info = {
                "root": str(root),
                "backend": "cargo",
                "stacks": ["cargo"],
                "languages": {"rust": 1},
            }
            with patch.object(
                analysis_adapters.shutil,
                "which",
                side_effect=lambda name: f"/usr/bin/{name}" if name in {"cargo-audit", "cargo-geiger"} else None,
            ):
                plan = analysis_adapters.security_analysis_plan(info)
            names = {item["name"] for item in plan}
            self.assertEqual(names, {"cargo-audit", "cargo-geiger"})

    def test_security_runner_records_native_tool_results(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            info = {
                "root": str(root),
                "backend": "cargo",
                "stacks": ["cargo"],
                "languages": {"rust": 1},
            }
            completed = SimpleNamespace(returncode=0, stdout="audit ok", stderr="")
            with patch.object(
                analysis_adapters.shutil,
                "which",
                side_effect=lambda name: f"/usr/bin/{name}" if name == "cargo-audit" else None,
            ), patch.object(analysis_adapters.subprocess, "run", return_value=completed) as run:
                result = analysis_adapters.run_security_analysis(info)
            self.assertEqual(result["tools_available"], ["cargo-audit"])
            self.assertEqual(result["results"][0]["status"], "passed")
            self.assertIn(["cargo", "audit", "--json"], [call.args[0] for call in run.call_args_list])

    def test_scan_returns_review_exit_for_partial_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                '[package]\nname = "demo"\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text("pub fn execute() {}\n", encoding="utf-8")
            with patch.object(analysis_adapters, "run_security_analysis", return_value={"results": []}):
                code = analysis_adapters.scan_repository(root)
            self.assertEqual(code, 2)

    def test_support_and_audit_paths_are_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "test").mkdir()
            (root / "certora").mkdir()
            (root / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function x() external { tx.origin; } }\n",
                encoding="utf-8",
            )
            (root / "test" / "Fake.sol").write_text(
                "pragma solidity ^0.8.20; contract Fake { function x() external { tx.origin; } }\n",
                encoding="utf-8",
            )
            (root / "certora" / "Harness.sol").write_text(
                "pragma solidity ^0.8.20; contract Harness { function x() external { tx.origin; } }\n",
                encoding="utf-8",
            )
            result = analysis_adapters.source_triage(root)
            self.assertEqual(result["files_scanned"], 1)
            self.assertEqual(result["markers"][0]["file"], "src/Vault.sol")

    def test_hardhat_marker_without_config_does_not_create_fake_stack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(json.dumps({"scripts": {"test": "hardhat test"}}), encoding="utf-8")
            (root / "contracts").mkdir()
            (root / "contracts" / "A.sol").write_text("pragma solidity ^0.8.20; contract A {}\n", encoding="utf-8")
            info = analysis_adapters.inspect_repository(root)
            self.assertIn("hardhat", info["stacks"])
            self.assertEqual(info["backend"], "hardhat")

    def test_render_scope_calls_partial_analysis_out_explicitly(self):
        info = {
            "root": "/tmp/x",
            "backend": "rust",
            "stacks": ["cargo"],
            "languages": {"rust": 1},
            "source_file_count": 1,
            "coverage": "partial",
            "analysis_status": "ready",
            "adapters": ["cargo"],
            "capabilities": {"build": True, "tests": True, "coverage": False, "slither": False, "live_evm": False},
            "unsupported_languages": [],
        }
        rendered = analysis_adapters.render_scope(info)
        self.assertIn("Coverage   : partial", rendered)
        self.assertIn("analysis is partial", rendered.lower())


if __name__ == "__main__":
    unittest.main()
