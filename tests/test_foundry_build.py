from __future__ import annotations

import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import foundry_build
import project_detection


class FoundryBuildPlannerTests(unittest.TestCase):
    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_collect_resources_reads_ram_swap_zram_psi_and_cgroup(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            proc = base / "proc"
            sysfs = base / "sys"
            self.write(proc, "meminfo", "MemTotal:       8192000 kB\nMemAvailable:   6144000 kB\nSwapTotal:      7340032 kB\nSwapFree:       5242880 kB\n")
            self.write(proc, "swaps", "Filename Type Size Used Priority\n/dev/zram0 partition 7340032 2097152 100\n")
            self.write(proc, "pressure/memory", "some avg10=2.00 avg60=1.00 avg300=0.50 total=100\nfull avg10=0.25 avg60=0.10 avg300=0.05 total=10\n")
            self.write(sysfs, "block/zram0/mm_stat", "1000000 500000 300000 0 0 0 0\n")
            self.write(sysfs, "fs/cgroup/memory.max", str(7 * 1024 ** 3))
            self.write(sysfs, "fs/cgroup/memory.current", str(2 * 1024 ** 3))

            snapshot = foundry_build.collect_resources(proc, sysfs, cpu_count=8)

            self.assertEqual(snapshot["memory_total_bytes"], 7 * 1024 ** 3)
            self.assertEqual(snapshot["memory_available_bytes"], 5 * 1024 ** 3)
            self.assertEqual(snapshot["swap_used_bytes"], 2 * 1024 ** 3)
            self.assertEqual(snapshot["zram_used_bytes"], 300000)
            self.assertEqual(snapshot["memory_psi_full_avg10"], 0.25)
            self.assertGreaterEqual(snapshot["cpu_count"], 1)

    def test_thread_selection_is_deterministic_and_conservative(self):
        small = {
            "memory_total_bytes": 8 * 1024 ** 3,
            "memory_available_bytes": 6 * 1024 ** 3,
            "cpu_count": 16,
            "swap_total_bytes": 8 * 1024 ** 3,
            "swap_used_bytes": 0,
            "memory_psi_full_avg10": 0.0,
        }
        self.assertEqual(foundry_build.select_threads(small)[0], 1)
        self.assertEqual(foundry_build.select_threads(small, low_memory=True)[0], 1)
        self.assertEqual(foundry_build.select_threads(small, explicit=5)[0], 5)
        self.assertTrue(foundry_build.select_threads(small, explicit=5)[2])

        large = {
            "memory_total_bytes": 32 * 1024 ** 3,
            "memory_available_bytes": 12 * 1024 ** 3,
            "cpu_count": 8,
            "swap_total_bytes": 0,
            "swap_used_bytes": 0,
            "memory_psi_full_avg10": 0.0,
        }
        self.assertEqual(foundry_build.select_threads(large)[0], 4)

    def test_build_plan_production_scope_uses_package_config_and_import_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "foundry.toml",
                '[profile.default]\nsrc = "contracts"\ntest = "spec"\nscript = "deploy"\nsolc = "0.8.35"\noptimizer = true\noptimizer_runs = 200\nvia_ir = true\n',
            )
            self.write(root, "contracts/Vault.sol", "pragma solidity ^0.8.20; contract Vault {}")
            self.write(root, "spec/Vault.t.sol", "contract VaultTest {}")
            self.write(root, "deploy/Deploy.s.sol", "contract Deploy {}")
            with patch.object(foundry_build, "load_foundry_config", return_value=({
                "src": "contracts", "test": "spec", "script": "deploy",
                "solc": "0.8.35", "optimizer": True, "optimizer_runs": 200, "via_ir": True,
            }, "effective test config")), patch.object(foundry_build, "collect_resources", return_value={
                "memory_total_bytes": 8 * 1024 ** 3,
                "memory_available_bytes": 6 * 1024 ** 3,
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
                "zram_used_bytes": 0,
                "cpu_count": 8,
                "memory_psi_some_avg10": 0.0,
                "memory_psi_full_avg10": 0.0,
            }):
                plan = foundry_build.build_plan(root, scope="production")

            self.assertEqual(plan["config_file"], str(root / "foundry.toml"))
            self.assertEqual(plan["config_source"], "effective test config")
            self.assertEqual(plan["scope_paths"], ["contracts"])
            self.assertIn("contracts", plan["forge_args"])
            self.assertIn("--threads", plan["forge_args"])
            self.assertEqual(plan["threads"], 1)
            self.assertTrue(plan["via_ir"])
            self.assertFalse(plan["side_effects"]["deploy"])
            self.assertFalse(plan["side_effects"]["cache_delete"])

    def test_build_plan_honors_cli_config_path_over_environment_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
            self.write(root, "foundry-env.toml", '[profile.default]\nsrc = "env-src"\n')
            self.write(root, "foundry-cli.toml", '[profile.default]\nsrc = "contracts"\n')
            self.write(root, "src/Default.sol", "contract Default {}")
            self.write(root, "env-src/Environment.sol", "contract Environment {}")
            self.write(root, "contracts/Cli.sol", "contract Cli {}")
            resources = {
                "memory_total_bytes": 16 * 1024 ** 3,
                "memory_available_bytes": 12 * 1024 ** 3,
                "swap_total_bytes": 0,
                "swap_used_bytes": 0,
                "zram_used_bytes": 0,
                "cpu_count": 8,
                "memory_psi_some_avg10": 0.0,
                "memory_psi_full_avg10": 0.0,
            }
            with patch.dict(foundry_build.os.environ, {"FOUNDRY_CONFIG": "foundry-env.toml"}), \
                 patch.object(foundry_build.forge_tools, "forge_path", return_value=None), \
                 patch.object(foundry_build, "collect_resources", return_value=resources):
                plan = foundry_build.build_plan(
                    root,
                    scope="production",
                    forge_args=["--config-path", "foundry-cli.toml"],
                )

            self.assertEqual(plan["config_file"], str((root / "foundry-cli.toml").resolve()))
            self.assertEqual(plan["scope_paths"], ["contracts"])

    def test_large_scope_warns_when_one_compiler_worker_may_still_be_risky(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
            for index in range(181):
                self.write(root, f"src/Contract{index}.sol", f"contract Contract{index} {{}}")

            resources = {
                "memory_total_bytes": 8 * 1024 ** 3,
                "memory_available_bytes": 6 * 1024 ** 3,
                "swap_total_bytes": 7 * 1024 ** 3,
                "swap_used_bytes": 2 * 1024 ** 3,
                "zram_used_bytes": 2 * 1024 ** 3,
                "cpu_count": 8,
                "memory_psi_some_avg10": 0.0,
                "memory_psi_full_avg10": 0.0,
            }
            with patch.object(foundry_build.forge_tools, "forge_path", return_value=None), \
                 patch.object(foundry_build, "collect_resources", return_value=resources):
                plan = foundry_build.build_plan(root, scope="production")

            self.assertEqual(plan["source_file_count"], 181)
            self.assertEqual(plan["threads"], 1)
            self.assertTrue(any(
                "may exceed available memory even with one compiler worker" in warning
                for warning in plan["warnings"]
            ))
            self.assertTrue(any(
                "no validated per-compiler memory estimate" in warning
                for warning in plan["warnings"]
            ))

    def test_target_contract_name_resolves_only_in_configured_source_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\ntest = "test"\n')
            self.write(root, "src/TrancheVault.sol", "contract TrancheVault {}")
            self.write(root, "test/TrancheVault.t.sol", "contract TrancheVaultTest {}")
            self.assertEqual(
                foundry_build._resolve_target(root, "TrancheVault", {"src": "src"}),
                "src/TrancheVault.sol",
            )

    def test_build_failure_classifier_separates_oom_from_solidity_errors(self):
        oom = foundry_build.classify_build_failure("error: out of memory while allocating", 1)
        killed = foundry_build.classify_build_failure("", -9)
        solidity = foundry_build.classify_build_failure("Error (7576): Undeclared identifier", 1)
        timeout = foundry_build.classify_build_failure("", 124, timed_out=True)
        self.assertEqual(oom["category"], "resource_exhaustion")
        self.assertEqual(killed["category"], "process_terminated")
        self.assertIn("not prove", killed["reason"])
        self.assertEqual(solidity["category"], "compiler_or_source_error")
        self.assertEqual(timeout["category"], "timeout")

    def test_child_package_overrides_stale_workspace_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private": true, "workspaces": ["packages/*"]}')
            self.write(root, "packages/perps/foundry.toml", "[profile.default]\n")
            self.write(root, "packages/perps/src/Vault.sol", "contract Vault {}")
            self.write(root, "packages/spot/foundry.toml", "[profile.default]\n")
            self.write(root, "packages/spot/src/Spot.sol", "contract Spot {}")
            project_detection.set_workspace_selection(root, root / "packages/spot")

            selected, error = foundry_build._resolve_project_root(root / "packages/perps/src")

            self.assertIsNone(error)
            self.assertEqual(selected, root / "packages/perps")

    def test_workspace_root_requires_selection_when_multiple_foundry_members_exist(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private": true, "workspaces": ["packages/*"]}')
            self.write(root, "packages/perps/foundry.toml", "[profile.default]\n")
            self.write(root, "packages/spot/foundry.toml", "[profile.default]\n")

            selected, error = foundry_build._resolve_project_root(root)

            self.assertIsNone(selected)
            self.assertIn("multiple Foundry members", error)
            self.assertIn("lk workspace select", error)

    def test_workspace_root_config_does_not_hide_nested_foundry_members(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private": true, "workspaces": ["packages/*"]}')
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "root-src"\n')
            self.write(root, "packages/perps/foundry.toml", '[profile.default]\nsrc = "src"\n')
            self.write(root, "packages/spot/foundry.toml", '[profile.default]\nsrc = "src"\n')

            selected, error = foundry_build._resolve_project_root(root)

            self.assertIsNone(selected)
            self.assertIn("multiple Foundry members", error)
            self.assertTrue(project_detection.set_workspace_selection(root, root / "packages/spot"))

            selected, error = foundry_build._resolve_project_root(root)

            self.assertIsNone(error)
            self.assertEqual(selected, root / "packages/spot")

    def test_workspace_root_with_one_nested_foundry_member_selects_the_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private": true, "workspaces": ["packages/*"]}')
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "root-src"\n')
            self.write(root, "packages/perps/foundry.toml", '[profile.default]\nsrc = "src"\n')

            selected, error = foundry_build._resolve_project_root(root)

            self.assertIsNone(error)
            self.assertEqual(selected, root / "packages/perps")

    def test_child_non_foundry_member_does_not_inherit_workspace_foundry_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private": true, "workspaces": ["packages/*"]}')
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
            self.write(root, "packages/frontend/package.json", '{"name":"frontend","scripts":{"build":"vite build"}}')

            selected, error = foundry_build._resolve_project_root(root / "packages/frontend")

            self.assertIsNone(error)
            self.assertIsNone(selected)

    def test_build_plan_honors_explicit_foundry_config_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\ntest = "test"\n')
            self.write(root, "foundry-ci.toml", '[profile.default]\nsrc = "contracts"\ntest = "spec"\n')
            self.write(root, "src/Vault.sol", "contract Vault {}")
            self.write(root, "contracts/Vault.sol", "contract Vault {}")
            with patch.dict(foundry_build.os.environ, {"FOUNDRY_CONFIG": "foundry-ci.toml"}), \
                 patch.object(foundry_build.forge_tools, "forge_path", return_value=None), \
                 patch.object(foundry_build, "collect_resources", return_value={
                     "memory_total_bytes": 8 * 1024 ** 3,
                     "memory_available_bytes": 6 * 1024 ** 3,
                     "swap_total_bytes": 0,
                     "swap_used_bytes": 0,
                     "zram_used_bytes": 0,
                     "cpu_count": 8,
                     "memory_psi_some_avg10": 0.0,
                     "memory_psi_full_avg10": 0.0,
                 }):
                plan = foundry_build.build_plan(root, scope="production")

            self.assertEqual(plan["config_file"], str((root / "foundry-ci.toml").resolve()))
            self.assertEqual(plan["scope_paths"], ["contracts"])
            self.assertIn("foundry-ci.toml", plan["config_source"])


if __name__ == "__main__":
    unittest.main()
