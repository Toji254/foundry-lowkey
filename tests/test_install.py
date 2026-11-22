import json
import os
import shutil
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALL = ROOT / "install.sh"


class InstallSmokeTests(unittest.TestCase):
    def test_install_publishes_current_runtime_and_manifest(self):
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HOME"] = home
            env["XDG_CONFIG_HOME"] = str(pathlib.Path(home) / ".config")
            env["XDG_DATA_HOME"] = str(pathlib.Path(home) / ".local" / "share")
            env["XDG_STATE_HOME"] = str(pathlib.Path(home) / ".local" / "state")

            result = subprocess.run(
                ["bash", str(INSTALL)],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            installed_lk = pathlib.Path(home) / ".foundry" / "bin" / "lk"
            manifest = pathlib.Path(home) / ".lowkey" / "install-manifest.json"
            self.assertTrue(installed_lk.exists())
            self.assertTrue(manifest.exists())
            question_engine = pathlib.Path(home) / ".lowkey" / "question_engine.py"
            self.assertTrue(question_engine.exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "fixture_context.py").exists())
            shared_context = pathlib.Path(home) / ".lowkey" / "shared_context.py"
            self.assertTrue(shared_context.exists())
            cheatsheet = pathlib.Path(home) / ".lowkey" / "solidity_cheatsheet.py"
            self.assertTrue(cheatsheet.exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "ai_harness.py").exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "experience_memory.py").exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "trace_evidence.py").exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "attack_engine.py").exists())
            trace_import = subprocess.run(
                ["python3", "-c", "import forge_state_diff, godmode, attack_engine; print('TRACE_IMPORT_OK')"],
                cwd=ROOT,
                env={**env, "PYTHONPATH": str(pathlib.Path(home) / ".lowkey")},
                capture_output=True,
                text=True,
            )
            self.assertEqual(trace_import.returncode, 0, trace_import.stdout + trace_import.stderr)
            self.assertIn("TRACE_IMPORT_OK", trace_import.stdout)

            attack_inventory = subprocess.run(
                [str(installed_lk), "attack", "engines", "--json"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(attack_inventory.returncode, 0, attack_inventory.stdout + attack_inventory.stderr)
            self.assertEqual(len(json.loads(attack_inventory.stdout)["families"]), 15)

            archetype_dir = pathlib.Path(home) / ".lowkey" / "archetypes"
            self.assertTrue((archetype_dir / "__init__.py").is_file())
            self.assertTrue((archetype_dir / "_index.py").is_file())
            pack_paths = sorted(archetype_dir.glob("*.json"))
            self.assertEqual(len(pack_paths), 10)
            install_manifest = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertIn(str(shared_context), install_manifest["files"])
            for installed_path in [archetype_dir / "__init__.py", archetype_dir / "_index.py", *pack_paths]:
                self.assertIn(str(installed_path), install_manifest["files"])
            fixture_source = ROOT / "tests" / "fixtures" / "acceptance" / "p3-genericity" / "vault"
            fixture_project = pathlib.Path(home) / "p3-vault"
            shutil.copytree(fixture_source, fixture_project)
            p3_classification = subprocess.run(
                [str(installed_lk), "archetype", "classify", "--root", str(fixture_project), "--json"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(p3_classification.returncode, 0, p3_classification.stdout + p3_classification.stderr)
            self.assertEqual(json.loads(p3_classification.stdout)["archetype"], "vault4626")
            assumption_check = subprocess.run(
                [str(installed_lk), "assumptions", "--root", str(fixture_project)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(assumption_check.returncode, 0, assumption_check.stdout + assumption_check.stderr)
            self.assertIn("Citation verification: OBSERVED", assumption_check.stdout)
            capability_view = subprocess.run(
                [str(installed_lk), "capability", "--root", str(fixture_project)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(capability_view.returncode, 0, capability_view.stdout + capability_view.stderr)
            self.assertIn("Capability negotiation:", capability_view.stdout)

            source_index = pathlib.Path(home) / ".lowkey" / "source_index.py"
            source_link = pathlib.Path(home) / ".lowkey" / "source_link.py"
            self.assertTrue(source_index.is_file())
            self.assertTrue(source_link.is_file())
            self.assertIn(str(source_index), install_manifest["files"])
            self.assertIn(str(source_link), install_manifest["files"])

            source_fixture = pathlib.Path(home) / "source-link-fixture"
            (source_fixture / "src").mkdir(parents=True)
            (source_fixture / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\n',
                encoding="utf-8",
            )
            (source_fixture / "src" / "FlowVault.sol").write_text(
                """
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.20;
                contract FlowVault {
                    mapping(address => uint256) public balances;
                    function deposit() external payable {
                        balances[msg.sender] += msg.value;
                    }
                    function withdraw(uint256 amount) external {
                        balances[msg.sender] -= amount;
                        (bool ok,) = msg.sender.call{value: amount}("");
                        require(ok);
                    }
                }
                """,
                encoding="utf-8",
            )
            linked_function = subprocess.run(
                [str(installed_lk), "link", "FlowVault.withdraw(uint256)", "--root", str(source_fixture)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(linked_function.returncode, 0, linked_function.stdout + linked_function.stderr)
            self.assertIn("LOWKEY // SOURCE LINK", linked_function.stdout)
            self.assertIn("FlowVault.withdraw(uint256)", linked_function.stdout)
            self.assertIn("TRANSFER ATTEMPT", linked_function.stdout)
            self.assertIn("ORIGIN    FIRST-PARTY", linked_function.stdout)

            linked_mapping = subprocess.run(
                [str(installed_lk), "link", "FlowVault.balances", "--root", str(source_fixture)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(linked_mapping.returncode, 0, linked_mapping.stdout + linked_mapping.stderr)
            self.assertIn("balances[msg.sender]", linked_mapping.stdout)
            self.assertIn("WRITTEN BY", linked_mapping.stdout)

            flow_filter = subprocess.run(
                [str(installed_lk), "fn", "--flow", "out", "--asset", "eth", "--root", str(source_fixture)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(flow_filter.returncode, 0, flow_filter.stdout + flow_filter.stderr)
            self.assertIn("FlowVault.withdraw(uint256)", flow_filter.stdout)
            self.assertIn("ETH", flow_filter.stdout)
            self.assertIn("OUT", flow_filter.stdout)

            version = subprocess.run(
                [str(installed_lk), "--version"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(version.returncode, 0, version.stdout + version.stderr)
            self.assertIn("LowkeyCast 2.1", version.stdout)
            self.assertIn("Runtime: OK", version.stdout)

            help_result = subprocess.run(
                [str(installed_lk), "--help"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(help_result.returncode, 0, help_result.stderr)
            self.assertIn("lk slither", help_result.stdout)
            self.assertIn("lk audit --checks", help_result.stdout)
            self.assertIn("lk q", help_result.stdout)
            self.assertIn("lk questions", help_result.stdout)
            self.assertIn("lk cheat", help_result.stdout)
            self.assertIn("lk ai status", help_result.stdout)
            self.assertIn("lk memory status", help_result.stdout)
            self.assertIn("lk link Vault", help_result.stdout)
            self.assertIn("lk fn --flow", help_result.stdout)

            link_help = subprocess.run(
                [str(installed_lk), "link", "--help"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(link_help.returncode, 0, link_help.stdout + link_help.stderr)
            self.assertIn("lk link", link_help.stdout)
            self.assertIn("--depth", link_help.stdout)
            self.assertIn("--only", link_help.stdout)

            flow_help = subprocess.run(
                [str(installed_lk), "fn", "--flow", "--help"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(flow_help.returncode, 0, flow_help.stdout + flow_help.stderr)
            self.assertIn("--asset", flow_help.stdout)
            self.assertIn("erc20", flow_help.stdout)

            ai_status = subprocess.run(
                [str(installed_lk), "ai", "status", "--json"], cwd=ROOT, env=env,
                capture_output=True, text=True,
            )
            self.assertEqual(ai_status.returncode, 0, ai_status.stdout + ai_status.stderr)
            self.assertFalse(json.loads(ai_status.stdout)["enabled"])

            memory_status = subprocess.run(
                [str(installed_lk), "memory", "status"], cwd=ROOT, env=env,
                capture_output=True, text=True,
            )
            self.assertEqual(memory_status.returncode, 0, memory_status.stdout + memory_status.stderr)
            self.assertIn('"global_approved": 0', memory_status.stdout)
            for command in ("forge", "slither"):
                contextual_help = subprocess.run(
                    [str(installed_lk), command, "--h"],
                    cwd=ROOT,
                    env=env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(contextual_help.returncode, 0, contextual_help.stderr)
                self.assertIn(f"lk {command}", contextual_help.stdout)
                self.assertNotIn("LOWKEY SLITHER", contextual_help.stdout)



if __name__ == "__main__":
    unittest.main()
