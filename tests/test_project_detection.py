import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "project_detection.py"

spec = importlib.util.spec_from_file_location("project_detection", MODULE)
project_detection = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(project_detection)


class ProjectDetectionTests(unittest.TestCase):
    def test_detect_project_never_bootstraps_submodules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".gitmodules").write_text(
                '[submodule "nested"]\n\tpath = nested\n\turl = https://example.com/nested.git\n',
                encoding="utf-8",
            )
            nested = root / "nested"
            nested.mkdir()
            (nested / "pyproject.toml").write_text("[project]\nname = \"nested\"\n", encoding="utf-8")
            with patch.object(project_detection, "_bootstrap_step", side_effect=AssertionError("detection must not bootstrap")):
                info = project_detection.detect_project(root)
            self.assertEqual(info["backend"], "generic")

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

    def test_bootstrap_initializes_submodules_and_uv_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / ".gitmodules").write_text(
                '[submodule "vendor"]\n\tpath = vendor\n\turl = https://example.com/vendor.git\n',
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                "[project]\nname = \"demo\"\ndependencies = [\"vyper>=0.4.0\"]\n",
                encoding="utf-8",
            )
            calls = []

            def fake_run(command, cwd):
                calls.append((list(command), cwd))
                return 0, "ok"

            with patch.object(project_detection.shutil, "which", side_effect=lambda name: name in {"git", "uv"}), \
                 patch.object(project_detection, "_run", side_effect=fake_run):
                code = project_detection.bootstrap_project(project_detection.detect_project(root))

            self.assertEqual(code, 0)
            self.assertEqual(
                calls,
                [
                    (
                        ["git", "submodule", "update", "--init", "--recursive", "--depth", "1"],
                        root,
                    ),
                    (["uv", "sync", "--all-extras", "--dev"], root),
                ],
            )

    def test_bootstrap_syncs_python_submodule_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            submodule = root / "vendor" / "scrvusd"
            submodule.mkdir(parents=True)
            (root / ".gitmodules").write_text(
                '[submodule "scrvusd"]\n\tpath = vendor/scrvusd\n\turl = https://example.com/scrvusd.git\n',
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text("[project]\nname = \"root-demo\"\n", encoding="utf-8")
            (submodule / "pyproject.toml").write_text("[project]\nname = \"nested-demo\"\n", encoding="utf-8")
            calls = []

            def fake_run(command, cwd):
                calls.append((list(command), cwd))
                return 0, "ok"

            with patch.object(project_detection.shutil, "which", side_effect=lambda name: name in {"git", "uv"}), \\
                 patch.object(project_detection, "_run", side_effect=fake_run):
                code = project_detection.bootstrap_project(project_detection.detect_project(root))

            self.assertEqual(code, 0)
            self.assertEqual(calls[-1], (["uv", "sync", "--all-extras", "--dev"], submodule))

    def test_bootstrap_does_not_sync_manifestless_submodule(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            submodule = root / "contracts" / "xdao"
            (submodule / "tests").mkdir(parents=True)
            (submodule / "tests" / "test_dummy.py").write_text("def test_dummy(): pass\n", encoding="utf-8")
            (root / ".gitmodules").write_text(
                '[submodule "xdao"]\n\tpath = contracts/xdao\n\turl = https://example.com/xdao.git\n',
                encoding="utf-8",
            )
            calls = []

            def fake_run(command, cwd):
                calls.append((list(command), cwd))
                return 0, "ok"

            with patch.object(project_detection.shutil, "which", side_effect=lambda name: name in {"git", "uv"}), \\
                 patch.object(project_detection, "_run", side_effect=fake_run):
                code = project_detection.bootstrap_project(project_detection.detect_project(root))

            self.assertEqual(code, 0)
            self.assertEqual(calls, [
                (["git", "submodule", "update", "--init", "--recursive", "--depth", "1"], root),
            ])

    def test_bootstrap_uses_lockfile_aware_node_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text('{"private":true}\n', encoding="utf-8")
            (root / "package-lock.json").write_text("{}\n", encoding="utf-8")
            calls = []

            def fake_run(command, cwd):
                calls.append(list(command))
                return 0, "ok"

            with patch.object(project_detection.shutil, "which", side_effect=lambda name: name == "npm"), \
                 patch.object(project_detection, "_run", side_effect=fake_run):
                code = project_detection.bootstrap_project(project_detection.detect_project(root))

            self.assertEqual(code, 0)
            self.assertEqual(calls, [["npm", "ci"]])

    def test_project_python_runner_prefers_uv_over_global_pytest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\nname = \"demo\"\n",
                encoding="utf-8",
            )
            with patch.object(project_detection.shutil, "which", side_effect=lambda name: "uv" if name == "uv" else None):
                self.assertEqual(
                    project_detection._project_python_runner(root, "pytest", "-q"),
                    ["uv", "run", "pytest", "-q"],
                )

    def test_native_vyper_runs_nested_python_submodule_tests_from_submodule_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            nested = root / "tests" / "scrvusd" / "contracts" / "scrvusd"
            (root / ".gitmodules").write_text(
                '[submodule "scrvusd"]\n\tpath = tests/scrvusd/contracts/scrvusd\n\turl = https://example.com/scrvusd.git\n',
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text("[project]\nname = \"root-demo\"\n", encoding="utf-8")
            (root / "test_root.py").write_text("def test_root(): pass\n", encoding="utf-8")
            (nested / "tests").mkdir(parents=True)
            (nested / "tests" / "test_nested.py").write_text("def test_nested(): pass\n", encoding="utf-8")
            calls = []

            def fake_run(command, cwd):
                calls.append((list(command), cwd))
                return 0, ""

            with patch.object(project_detection, "bootstrap_project", return_value=0), \\
                 patch.object(project_detection.shutil, "which", side_effect=lambda name: name in {"uv", "pytest"}), \\
                 patch.object(project_detection, "_run", side_effect=fake_run):
                code = project_detection.run_native_audit(
                    {"root": str(root), "backend": "vyper", "native": {"pytest": True}}
                )

            self.assertEqual(code, 0)
            self.assertEqual(calls[0], (["uv", "run", "pytest", "-q", "--ignore", "tests/scrvusd/contracts/scrvusd/tests"], root))
            self.assertEqual(
                calls[1],
                (["uv", "run", "--project", str(root), "pytest", "-q"], nested),
            )

    def test_native_vyper_tests_use_project_python_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\nname = \"demo\"\n",
                encoding="utf-8",
            )
            (root / "contracts").mkdir()\n            (root / "contracts" / "Ping.vy").write_text("@external\\ndef ping():\\n    pass\\n", encoding="utf-8")\n            (root / "test_ping.py").write_text("def test_ping(): pass\n", encoding="utf-8")
            calls = []

            def fake_run(command, cwd):
                calls.append(list(command))
                return 0, ""

            with patch.object(project_detection, "bootstrap_project", return_value=0), \
                 patch.object(project_detection.shutil, "which", side_effect=lambda name: name in {"uv", "pytest"}), \
                 patch.object(project_detection, "_run", side_effect=fake_run):
                code = project_detection.run_native_audit(
                    {
                        "root": str(root),
                        "backend": "vyper",
                        "native": {"pytest": True},
                    }
                )

            self.assertEqual(code, 0)
            self.assertEqual(calls, [["uv", "run", "pytest", "-q"]])


if __name__ == "__main__":
    unittest.main()
