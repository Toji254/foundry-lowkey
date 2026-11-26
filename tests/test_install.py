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
    def test_install_script_is_executable(self):
        self.assertTrue(INSTALL.is_file(), "install.sh must exist in the repository checkout")
        self.assertTrue(
            os.access(INSTALL, os.X_OK),
            "install.sh must retain its executable bit because CI and users invoke ./install.sh",
        )

    def test_hardhat_test_prepares_dependencies_before_native_test_router(self):
        with tempfile.TemporaryDirectory() as home:
            lowkey_dir = pathlib.Path(home) / ".lowkey"
            lowkey_dir.mkdir()
            (lowkey_dir / "hardhat_tools.py").write_text(
                "print('HARDHAT_PREPARE')\n",
                encoding="utf-8",
            )
            (lowkey_dir / "lk.py").write_text(
                "import sys\nprint('NATIVE_TEST', *sys.argv[1:])\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["HOME"] = home

            result = subprocess.run(
                ["bash", str(ROOT / "bin" / "lk"), "test", "--match-test", "testFoo"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertLess(
                result.stdout.index("HARDHAT_PREPARE"),
                result.stdout.index("NATIVE_TEST"),
            )
            self.assertIn("NATIVE_TEST test --match-test testFoo", result.stdout)

    def test_non_hardhat_test_keeps_existing_native_router(self):
        with tempfile.TemporaryDirectory() as home:
            lowkey_dir = pathlib.Path(home) / ".lowkey"
            lowkey_dir.mkdir()
            (lowkey_dir / "hardhat_tools.py").write_text(
                "raise SystemExit(3)\n",
                encoding="utf-8",
            )
            (lowkey_dir / "lk.py").write_text(
                "import sys\nprint('NATIVE_TEST', *sys.argv[1:])\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["HOME"] = home

            result = subprocess.run(
                ["bash", str(ROOT / "bin" / "lk"), "test", "--match-test", "testFoo"],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("NATIVE_TEST test --match-test testFoo", result.stdout)



    def test_clean_help_is_routed_to_lowkey_before_native_clean_adapter(self):
        with tempfile.TemporaryDirectory() as home:
            lowkey_dir = pathlib.Path(home) / ".lowkey"
            lowkey_dir.mkdir()
            (lowkey_dir / "lk.py").write_text(
                "import sys\nprint('LOWKEY_HELP_ROUTED', *sys.argv[1:])\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env["HOME"] = home

            for flag in ("--h", "--help", "-h", "help"):
                with self.subTest(flag=flag):
                    result = subprocess.run(
                        ["bash", str(ROOT / "bin" / "lk"), "clean", flag],
                        cwd=ROOT,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn(f"LOWKEY_HELP_ROUTED clean {flag}", result.stdout)
                    self.assertNotIn("forge clean", result.stdout + result.stderr)


    def test_install_publishes_current_runtime_and_manifest(self):
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HOME"] = home
            env["XDG_CONFIG_HOME"] = str(pathlib.Path(home) / ".config")
            env["XDG_DATA_HOME"] = str(pathlib.Path(home) / ".local" / "share")
            env["XDG_STATE_HOME"] = str(pathlib.Path(home) / ".local" / "state")

            result = subprocess.run(
                [str(INSTALL)],
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
            proxy_engine_module = pathlib.Path(home) / ".lowkey" / "proxy_engine.py"
            self.assertTrue(proxy_engine_module.is_file())
            library_linker_module = pathlib.Path(home) / ".lowkey" / "library_linker.py"
            network_manager_module = pathlib.Path(home) / ".lowkey" / "network_manager.py"
            runtime_verification_module = pathlib.Path(home) / ".lowkey" / "runtime_verification.py"
            for runtime_module in (library_linker_module, network_manager_module, runtime_verification_module):
                with self.subTest(runtime_module=runtime_module.name):
                    self.assertTrue(runtime_module.is_file())
            lab_target_scope = pathlib.Path(home) / ".lowkey" / "lab_target_scope.py"
            self.assertTrue(lab_target_scope.is_file())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "fixture_context.py").exists())
            shared_context = pathlib.Path(home) / ".lowkey" / "shared_context.py"
            self.assertTrue(shared_context.exists())
            cheatsheet = pathlib.Path(home) / ".lowkey" / "solidity_cheatsheet.py"
            self.assertTrue(cheatsheet.exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "ai_harness.py").exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "experience_memory.py").exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "trace_evidence.py").exists())
            self.assertTrue((pathlib.Path(home) / ".lowkey" / "attack_engine.py").exists())
            target_scope_import = subprocess.run(
                ["python3", "-c", "import lab_target_scope; print('TARGET_SCOPE_IMPORT_OK')"],
                cwd=ROOT,
                env={**env, "PYTHONPATH": str(pathlib.Path(home) / ".lowkey")},
                capture_output=True,
                text=True,
            )
            self.assertEqual(target_scope_import.returncode, 0, target_scope_import.stdout + target_scope_import.stderr)
            self.assertIn("TARGET_SCOPE_IMPORT_OK", target_scope_import.stdout)

            proxy_import = subprocess.run(
                ["python3", "-c", "import proxy_engine; print('PROXY_ENGINE_IMPORT_OK')"],
                cwd=ROOT,
                env={**env, "PYTHONPATH": str(pathlib.Path(home) / ".lowkey")},
                capture_output=True,
                text=True,
            )
            self.assertEqual(proxy_import.returncode, 0, proxy_import.stdout + proxy_import.stderr)
            self.assertIn("PROXY_ENGINE_IMPORT_OK", proxy_import.stdout)

            proxy_help = subprocess.run(
                [str(installed_lk), "proxy", "audit", "--h"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(proxy_help.returncode, 0, proxy_help.stdout + proxy_help.stderr)
            self.assertIn("COMMAND VARIATIONS", proxy_help.stdout)

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
            self.assertIn(str(proxy_engine_module), install_manifest["files"])
            self.assertIn(str(library_linker_module), install_manifest["files"])
            self.assertIn(str(network_manager_module), install_manifest["files"])
            self.assertIn(str(runtime_verification_module), install_manifest["files"])
            self.assertIn(str(lab_target_scope), install_manifest["files"])
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
            source_ast = pathlib.Path(home) / ".lowkey" / "source_ast.py"
            source_link = pathlib.Path(home) / ".lowkey" / "source_link.py"
            eth_flow = pathlib.Path(home) / ".lowkey" / "eth_flow.py"
            self.assertTrue(source_index.is_file())
            self.assertTrue(source_ast.is_file())
            self.assertTrue(source_link.is_file())
            self.assertTrue(eth_flow.is_file())
            self.assertIn(str(source_index), install_manifest["files"])
            self.assertIn(str(source_ast), install_manifest["files"])
            self.assertIn(str(source_link), install_manifest["files"])
            self.assertIn(str(eth_flow), install_manifest["files"])

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
            self.assertIn("LOWKEY // SOURCE TRACE", linked_function.stdout)
            self.assertIn("FlowVault.withdraw(uint256)", linked_function.stdout)
            self.assertIn("EXTERNAL BOUNDARIES", linked_function.stdout)
            self.assertIn("ETH OUT", linked_function.stdout)
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

            eth_flow_recon = subprocess.run(
                [str(installed_lk), "flow", "eth", "--root", str(source_fixture)],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(eth_flow_recon.returncode, 0, eth_flow_recon.stdout + eth_flow_recon.stderr)
            self.assertIn("LOWKEY / ETH FLOW", eth_flow_recon.stdout)
            self.assertIn("FLOW SNAPSHOT", eth_flow_recon.stdout)
            self.assertIn("SOURCE ROUTES TO ETH EXITS", eth_flow_recon.stdout)
            self.assertIn("FlowVault.withdraw", eth_flow_recon.stdout)

            eth_flow_detail = subprocess.run(
                [str(installed_lk), "flow", "eth", "--root", str(source_fixture), "--detail"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(eth_flow_detail.returncode, 0, eth_flow_detail.stdout + eth_flow_detail.stderr)
            self.assertIn("LOWKEY / ETH FLOW  ·  FORENSIC VIEW", eth_flow_detail.stdout)
            self.assertIn("ETH EXIT SITES", eth_flow_detail.stdout)

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
            self.assertIn("--only calls|storage|reads|writes|imports|assets", help_result.stdout)
            self.assertIn("lk fn --flow", help_result.stdout)
            self.assertIn("lk flow eth", help_result.stdout)
            self.assertIn("lk trace source --help", help_result.stdout)
            self.assertIn("lk fn --flow --help", help_result.stdout)

            link_help = subprocess.run(
                [str(installed_lk), "link", "--help"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(link_help.returncode, 0, link_help.stdout + link_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk link", link_help.stdout)
            for item in ("What it does:", "When to use:", "COMMAND VARIATIONS", "OPTIONS / MODES", "--depth <N>", "--only <FILTER>", "--detail <VIEW>", "--search <TEXT>", "--type <KIND>", "--page <N>", "--all", "--json"):
                self.assertIn(item, link_help.stdout)

            flow_help = subprocess.run(
                [str(installed_lk), "fn", "--flow", "both", "--help"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(flow_help.returncode, 0, flow_help.stdout + flow_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk fn --flow", flow_help.stdout)
            self.assertIn("--flow <in|out|both>", flow_help.stdout)
            self.assertIn("--asset <eth|erc20|all>", flow_help.stdout)
            self.assertIn("does not prove that a transfer happened", flow_help.stdout)

            trace_source_help = subprocess.run(
                [str(installed_lk), "trace", "source", "--h"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(trace_source_help.returncode, 0, trace_source_help.stdout + trace_source_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk trace source", trace_source_help.stdout)
            self.assertIn("not the same as 'lk trace <TX>'", trace_source_help.stdout)

            eth_flow_help = subprocess.run(
                [str(installed_lk), "flow", "eth", "--h"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(eth_flow_help.returncode, 0, eth_flow_help.stdout + eth_flow_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk flow eth", eth_flow_help.stdout)
            self.assertIn("OPTIONS / MODES", eth_flow_help.stdout)

            ast_help = subprocess.run(
                [str(installed_lk), "ast", "--h"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(ast_help.returncode, 0, ast_help.stdout + ast_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk ast", ast_help.stdout)
            self.assertIn("COMMAND VARIATIONS", ast_help.stdout)

            clean_help = subprocess.run(
                [str(installed_lk), "clean", "--h"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(clean_help.returncode, 0, clean_help.stdout + clean_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk clean", clean_help.stdout)
            self.assertIn("generated artifacts/cache", clean_help.stdout)

            hardhat_doctor_help = subprocess.run(
                [str(installed_lk), "hardhat", "doctor", "--h"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(hardhat_doctor_help.returncode, 0, hardhat_doctor_help.stdout + hardhat_doctor_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk hardhat doctor", hardhat_doctor_help.stdout)
            self.assertIn("read-only", hardhat_doctor_help.stdout)

            build_help = subprocess.run(
                [str(installed_lk), "build", "--h"],
                cwd=ROOT, env=env, capture_output=True, text=True,
            )
            self.assertEqual(build_help.returncode, 0, build_help.stdout + build_help.stderr)
            self.assertIn("LOWKEY HELP  •  lk build", build_help.stdout)
            self.assertIn("--low-memory", build_help.stdout)

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
