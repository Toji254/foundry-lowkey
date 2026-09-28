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
    def test_workspace_selection_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            nested = root / "packages" / "app"
            nested.mkdir(parents=True)

            self.assertTrue(project_detection.set_workspace_selection(root, nested))
            self.assertEqual(project_detection.workspace_selection(root).resolve(), nested.resolve())

            project_detection.clear_workspace_selection(root)
            self.assertIsNone(project_detection.workspace_selection(root))

    def test_workspace_metadata_includes_description_and_sibling_usage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )

            shared = root / "packages" / "shared"
            app = root / "packages" / "app"
            for project in (shared, app):
                (project / "src").mkdir(parents=True)
                (project / "src" / "main.sol").write_text("contract Main {}\n", encoding="utf-8")

            (shared / "package.json").write_text(
                '{"name":"@demo/shared","description":"Shared protocol utilities"}\n',
                encoding="utf-8",
            )
            (app / "package.json").write_text(
                '{"name":"@demo/app","dependencies":{"@demo/shared":"workspace:*"}}\n',
                encoding="utf-8",
            )

            candidates = project_detection.discover_nested_projects(root)
            shared_info = next(item for item in candidates if item["root"] == str(shared))

            self.assertEqual(shared_info["description"], "Shared protocol utilities")
            self.assertEqual(shared_info["used_by_siblings"], 1)
            self.assertEqual(shared_info["scope_hint"], "shared dependency")

    def test_workspace_with_one_nested_project_resolves_to_nested_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            nested = root / "packages" / "app"
            nested.mkdir(parents=True)
            (nested / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (nested / "src").mkdir()
            (nested / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")

            info = project_detection.detect_project(root)

            self.assertEqual(pathlib.Path(info["root"]).resolve(), nested.resolve())
            self.assertEqual(info["backend"], "foundry")

    def test_workspace_with_multiple_nested_projects_stays_at_workspace_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            for name, marker in (("evm", "foundry.toml"), ("python", "pyproject.toml"), ("rust", "Cargo.toml")):
                nested = root / "packages" / name
                nested.mkdir(parents=True)
                (nested / marker).write_text("", encoding="utf-8")

            candidates = project_detection.discover_nested_projects(root)
            self.assertEqual(
                {item["relative"] for item in candidates},
                {"packages/evm", "packages/python", "packages/rust"},
            )
            self.assertEqual(project_detection.project_root(root).resolve(), root.resolve())

    def test_nested_detection_is_language_agnostic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name, marker, source_name in (
                ("python-app", "pyproject.toml", "app.py"),
                ("rust-app", "Cargo.toml", "main.rs"),
                ("go-app", "go.mod", "main.go"),
                ("solidity-app", "foundry.toml", "Vault.sol"),
            ):
                nested = root / name
                nested.mkdir(parents=True)
                (nested / marker).write_text("", encoding="utf-8")
                source_dir = nested / "src"
                source_dir.mkdir()
                (source_dir / source_name).write_text("", encoding="utf-8")

            candidates = project_detection.discover_nested_projects(root)
            self.assertEqual(
                {item["relative"] for item in candidates},
                {"python-app", "rust-app", "go-app", "solidity-app"},
            )

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

    def test_bootstrap_keeps_dependency_install_scoped_to_root_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            submodule = root / "vendor" / "scrvusd"
            submodule.mkdir(parents=True)
            (root / ".gitmodules").write_text(
                '[submodule "scrvusd"]\n\tpath = vendor/scrvusd\n\turl = https://example.com/scrvusd.git\n',
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                "[project]\nname = \"root-demo\"\n", encoding="utf-8"
            )
            (submodule / "pyproject.toml").write_text(
                "[project]\nname = \"nested-demo\"\n", encoding="utf-8"
            )
            calls = []

            def fake_run(command, cwd):
                calls.append((list(command), cwd))
                return 0, "ok"

            with patch.object(project_detection.shutil, "which", side_effect=lambda name: name in {"git", "uv"}), \\
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

    def test_native_vyper_ignores_test_submodules_in_parent_pytest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            nested = root / "tests" / "scrvusd" / "contracts" / "scrvusd"
            (root / ".gitmodules").write_text(
                '[submodule "scrvusd"]\n\tpath = tests/scrvusd/contracts/scrvusd\n\turl = https://example.com/scrvusd.git\n',
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text(
                "[project]\nname = \"root-demo\"\n",
                encoding="utf-8",
            )
            (root / "test_root.py").write_text(
                "def test_root(): pass\n",
                encoding="utf-8",
            )
            (nested / "tests").mkdir(parents=True)
            (nested / "tests" / "test_nested.py").write_text(
                "def test_nested(): pass\n",
                encoding="utf-8",
            )
            calls = []

            def fake_run(command, cwd):
                calls.append((list(command), cwd))
                return 0, ""

            with patch.object(project_detection, "bootstrap_project", return_value=0), \
                 patch.object(project_detection.shutil, "which", side_effect=lambda name: name in {"uv", "pytest"}), \
                 patch.object(project_detection, "_run", side_effect=fake_run):
                code = project_detection.run_native_audit(
                    {"root": str(root), "backend": "vyper", "native": {"pytest": True}}
                )

            self.assertEqual(code, 0)
            self.assertEqual(
                calls,
                [
                    (
                        ["uv", "run", "pytest", "-q", "--ignore", "tests/scrvusd/contracts/scrvusd"],
                        root,
                    )
                ],
            )

    def test_pytest_runner_uses_local_tests_namespace_shim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\nname = \"demo\"\n",
                encoding="utf-8",
            )
            (root / "tests").mkdir()

            command = project_detection._project_python_runner(root, "pytest", "-q")

            self.assertEqual(command[:4], ["uv", "run", "python", "-c"])
            self.assertIn("sys.modules['tests']", command[4])
            self.assertIn("pathlib.Path('tests').resolve()", command[4])
            self.assertEqual(command[-1], "-q")

    def test_native_vyper_tests_use_project_python_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "pyproject.toml").write_text(
                "[project]\nname = \"demo\"\n",
                encoding="utf-8",
            )
            (root / "contracts").mkdir()
            (root / "contracts" / "Ping.vy").write_text("@external\\ndef ping():\\n    pass\\n", encoding="utf-8")\n            (root / "test_ping.py").write_text("def test_ping(): pass\n", encoding="utf-8")
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
