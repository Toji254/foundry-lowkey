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
    def test_lowkey_source_checkout_is_not_detected_as_user_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "lowkey").mkdir()
            (root / "lowkey" / "lk.py").write_text("print('lowkey')\n", encoding="utf-8")
            (root / "lowkey" / "project_detection.py").write_text("print('lowkey')\n", encoding="utf-8")
            (root / "install.sh").write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            (root / "Makefile").write_text("all:\n\t@true\n", encoding="utf-8")
            info = project_detection.detect_project(root)
            self.assertEqual(info["kind"], "lowkey-source")
            self.assertEqual(project_detection.project_root(root), root)

    def test_lowkey_source_root_wins_over_single_nested_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "lowkey").mkdir()
            (root / "lowkey" / "lk.py").write_text("print('lowkey')\\n", encoding="utf-8")
            (root / "lowkey" / "project_detection.py").write_text("print('lowkey')\\n", encoding="utf-8")
            (root / "install.sh").write_text("#!/usr/bin/env bash\\n", encoding="utf-8")

            nested = root / "example-project"
            nested.mkdir()
            (nested / "foundry.toml").write_text("[profile.default]\\n", encoding="utf-8")
            (nested / "src").mkdir()
            (nested / "src" / "Example.sol").write_text("contract Example {}\\n", encoding="utf-8")

            self.assertEqual(project_detection.project_root(root).resolve(), root.resolve())
            self.assertEqual(project_detection.detect_project(root)["kind"], "lowkey-source")

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

    def test_active_workspace_project_is_used_from_child_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["packages/*"]}\n',
                encoding="utf-8",
            )
            nested = root / "packages" / "app"
            nested.mkdir(parents=True)
            (nested / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")

            self.assertTrue(project_detection.set_workspace_selection(root, nested))

            child = nested / "src"
            child.mkdir()
            self.assertEqual(project_detection.project_root(child).resolve(), nested.resolve())

            sibling_area = root / "pkg"
            sibling_area.mkdir()
            self.assertEqual(project_detection.project_root(sibling_area).resolve(), nested.resolve())

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

    def test_workspace_metadata_builds_audit_scope_roles_and_relationships(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "package.json").write_text(
                '{"private":true,"workspaces":["pkg/*"]}\n',
                encoding="utf-8",
            )
            app = root / "pkg" / "app"
            dep = root / "pkg" / "vault"
            support = root / "pkg" / "helpers"
            for project in (app, dep, support):
                (project / "src").mkdir(parents=True)

            (app / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (app / "package.json").write_text(
                '{"name":"@demo/app","dependencies":{"@demo/vault":"workspace:*"}}\n',
                encoding="utf-8",
            )
            (app / "script").mkdir()
            (app / "script" / "Deploy.s.sol").write_text("", encoding="utf-8")
            (app / "src" / "App.sol").write_text("contract App {}\n", encoding="utf-8")
            (app / "test").mkdir()
            (app / "test" / "App.t.sol").write_text("", encoding="utf-8")

            (dep / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (dep / "package.json").write_text(
                '{"name":"@demo/vault","description":"Core vault infrastructure"}\n',
                encoding="utf-8",
            )
            (dep / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")

            (support / "package.json").write_text(
                '{"name":"@demo/helpers","description":"Internal helpers"}\n',
                encoding="utf-8",
            )
            (support / "tools.ts").write_text("export const x = 1;\n", encoding="utf-8")

            candidates = project_detection.discover_nested_projects(root)
            app_info = next(item for item in candidates if item["root"] == str(app))
            dep_info = next(item for item in candidates if item["root"] == str(dep))
            support_info = next(item for item in candidates if item["root"] == str(support))

            self.assertEqual(app_info["scope_role"], "primary audit candidate")
            self.assertIn("vault", " ".join(app_info["depends_on"]))
            self.assertEqual(dep_info["scope_role"], "important dependency")
            self.assertIn("pkg/app", " ".join(dep_info["depended_on_by"]))
            self.assertEqual(support_info["scope_role"], "support / tooling")

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

    def test_cargo_workspace_manifest_is_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "Cargo.toml").write_text("[workspace]\nmembers = []\n", encoding="utf-8")
            self.assertTrue(project_detection.is_workspace_root(root))

    def test_inferred_workspace_detection_does_not_run_project_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for name in ("first", "second"):
                project = root / name
                project.mkdir()
                (project / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")

            with patch.object(project_detection, "detect_project", side_effect=AssertionError):
                self.assertTrue(project_detection.is_workspace_root(root))

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

    def test_hardhat_fork_spec_reads_pinned_network_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "hardhat.config.ts").write_text(
                'export const NETWORK = "arbitrumMain";\n', encoding="utf-8"
            )
            (root / "utils").mkdir()
            (root / "utils" / "forkConfig.ts").write_text(
                'import { vars } from "hardhat/config";\n'
                'const FORK_CONFIGS = {\n'
                '  arbitrumMain: {\n'
                '    url: vars.get("ARBITRUM_MAINNET_URL", "https://example.invalid/rpc"),\n'
                '    blockNumber: 289488417,\n'
                '  },\n'
                '};\n',
                encoding="utf-8",
            )

            with patch.dict(
                project_detection.os.environ,
                {"ARBITRUM_MAINNET_URL": "https://archive.example/rpc"},
                clear=False,
            ):
                self.assertEqual(
                    project_detection._hardhat_fork_spec(root),
                    ("https://archive.example/rpc", 289488417),
                )

    def test_historical_state_errors_are_classified_as_infrastructure(self):
        self.assertTrue(
            project_detection._historical_state_unavailable(
                "ProviderError: historical state c065 is not available"
            )
        )
        self.assertTrue(
            project_detection._historical_state_unavailable(
                "missing trie node c065 state 0xc065 is not available, not found"
            )
        )
        self.assertFalse(project_detection._historical_state_unavailable("AssertionError: value mismatch"))

    def test_hardhat_fork_fallback_defers_without_archive_rpc(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "hardhat.config.ts").write_text(
                'export const NETWORK = "arbitrumMain";\n', encoding="utf-8"
            )
            (root / "utils").mkdir()
            (root / "utils" / "forkConfig.ts").write_text(
                'const FORK_CONFIGS = { arbitrumMain: { url: "https://example.invalid/rpc", blockNumber: 289488417 } };\n',
                encoding="utf-8",
            )
            with patch.dict(project_detection.os.environ, {}, clear=False):
                project_detection.os.environ.pop("LOWKEY_ARCHIVE_RPC", None)
                result = project_detection._run_hardhat_fork_fallback(
                    root, root / "node_modules/.bin/hardhat", ["hardhat", "test"]
                )

            self.assertIsNotNone(result)
            self.assertEqual(result[2], "defer")
            self.assertIn("LOWKEY_ARCHIVE_RPC", result[1])

    def test_hardhat_fork_fallback_runs_tests_on_temporary_hardhat_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "hardhat.config.ts").write_text(
                'export const NETWORK = "arbitrumMain";\n', encoding="utf-8"
            )
            (root / "utils").mkdir()
            (root / "utils" / "forkConfig.ts").write_text(
                'const FORK_CONFIGS = { arbitrumMain: { url: "https://example.invalid/rpc", blockNumber: 289488417 } };\n',
                encoding="utf-8",
            )

            class DummyProcess:
                stdout = None

                def poll(self):
                    return None

                def terminate(self):
                    pass

                def wait(self, timeout=5):
                    return 0

            class DummySocket:
                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, tb):
                    return False

            calls = []

            def fake_run(command, cwd):
                calls.append(list(command))
                return 0, "all tests passed"

            with patch.dict(project_detection.os.environ, {"LOWKEY_ARCHIVE_RPC": "https://archive.example/rpc"}, clear=False), patch.object(project_detection.subprocess, "Popen", return_value=DummyProcess()) as popen, patch.object(project_detection.socket, "create_connection", return_value=DummySocket()), patch.object(project_detection, "_run", side_effect=fake_run):
                result = project_detection._run_hardhat_fork_fallback(
                    root, root / "node_modules/.bin/hardhat", ["hardhat", "test"]
                )

            self.assertEqual(result, (0, "all tests passed", "pass"))
            popen.assert_called_once()
            fork_command = popen.call_args.args[0]
            self.assertIn("--fork", fork_command)
            self.assertIn("https://archive.example/rpc", fork_command)
            self.assertIn("--fork-block-number", fork_command)
            self.assertIn("289488417", fork_command)
            self.assertEqual(calls, [[str(root / "node_modules/.bin/hardhat"), "--network", "localhost", "test"]])

    def test_bootstrap_delegates_to_shared_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            info = project_detection.detect_project(root)

            with patch.object(project_detection, "run_shared_bootstrap", return_value=0) as bootstrap:
                code = project_detection.bootstrap_project(info, reason="audit")

            self.assertEqual(code, 0)
            bootstrap.assert_called_once()
            args, kwargs = bootstrap.call_args
            self.assertEqual(args[0]["root"], str(root))
            self.assertEqual(kwargs["reason"], "audit")

    def test_bootstrap_status_comes_from_shared_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            info = project_detection.detect_project(root)
            expected = {"dependency_root": str(root), "ready": True}

            with patch.object(project_detection, "shared_bootstrap_status", return_value=expected):
                self.assertEqual(project_detection.bootstrap_status(info), expected)

    def test_native_multi_stack_audit_runs_each_protocol_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            calls = []

            info = {
                "root": str(root),
                "backend": "multi",
                "stacks": ["cairo-starknet", "evm-source"],
                "native": {"scarb": True, "snforge": True},
                "analysis": {
                    "root": str(root),
                    "backend": "multi",
                    "stacks": ["cairo-starknet", "evm-source"],
                    "languages": {"cairo": 1, "solidity": 1},
                },
                "_bootstrap_done": True,
            }

            def fake_child(parent, stack, args):
                calls.append((stack, dict(parent)))
                return 0

            with patch.object(project_detection, "_run_native_child", side_effect=fake_child) as child:
                code = project_detection.run_native_audit(info)

            self.assertEqual(code, 0)
            self.assertEqual(child.call_count, 2)
            self.assertEqual([item[0] for item in calls], ["cairo-starknet", "evm-source"])
            self.assertEqual(calls[0][1]["backend"], "multi")
            self.assertEqual(calls[1][1]["stacks"], ["cairo-starknet", "evm-source"])

    def test_native_timeout_is_bounded_and_configurable(self):
        with patch.dict(project_detection.os.environ, {"LOWKEY_NATIVE_TIMEOUT": "45"}, clear=False):
            self.assertEqual(project_detection._native_timeout(), 45)
        with patch.dict(project_detection.os.environ, {"LOWKEY_NATIVE_TIMEOUT": "99999"}, clear=False):
            self.assertEqual(project_detection._native_timeout(), 1800)

    def test_project_detection_exposes_non_evm_build_backend(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "Cargo.toml").write_text(
                "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n",
                encoding="utf-8",
            )
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text("pub fn ping() {}\n", encoding="utf-8")

            info = project_detection.detect_project(root)

            self.assertEqual(info["build_backend"], "cargo")
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
                        project_detection._project_python_runner(root, "pytest", "-q") + ["--ignore", "tests/scrvusd/contracts/scrvusd"],
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
            (root / "contracts" / "Ping.vy").write_text(
                "@external\ndef ping():\n    pass\n",
                encoding="utf-8",
            )
            (root / "test_ping.py").write_text(
                "def test_ping(): pass\n",
                encoding="utf-8",
            )
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
