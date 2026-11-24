import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "lowkey") not in sys.path:
    sys.path.insert(0, str(ROOT / "lowkey"))

import bootstrap
import hardhat_tools


class HardhatVersionTests(unittest.TestCase):
    def test_node_version_parser(self):
        self.assertEqual(hardhat_tools._parse_version("v24.22.1"), (24, 22, 1))
        self.assertEqual(hardhat_tools._parse_version("v22.13.0"), (22, 13, 0))
        self.assertIsNone(hardhat_tools._parse_version("not-a-version"))

    def test_old_node_is_rejected_before_initializer_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(
                hardhat_tools, "_node_context",
                return_value=(None, "Hardhat 3 requires Node.js 22.13.0 or newer"),
            ), patch.object(hardhat_tools.Path, "cwd", return_value=root), \
                 patch.object(hardhat_tools, "_command_prefix") as prefix:
                self.assertEqual(hardhat_tools.run_init([]), 2)
                prefix.assert_not_called()


class HardhatInitTests(unittest.TestCase):
    def test_init_uses_minimal_template_and_verifies_local_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "node_modules" / ".bin" / "hardhat"
            binary.parent.mkdir(parents=True)
            env = {"PATH": "/usr/bin"}
            calls = []

            def fake_run(command, **kwargs):
                calls.append((command, kwargs))
                (root / "hardhat.config.ts").write_text(
                    "export default {}\n", encoding="utf-8"
                )
                return SimpleNamespace(returncode=0, stdout="", stderr="")

            with patch.object(hardhat_tools, "_node_context", return_value=(env, None)), \
                 patch.object(
                     hardhat_tools, "_command_prefix",
                     return_value=(["npx", "--yes", "--package=hardhat@^3", "hardhat"], None),
                 ), patch.object(hardhat_tools, "_local_hardhat", return_value=binary), \
                 patch.object(hardhat_tools.subprocess, "run", side_effect=fake_run), \
                 patch.object(hardhat_tools.Path, "cwd", return_value=root):
                self.assertEqual(hardhat_tools.run_init([]), 0)

            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][0][-3:], ["--init", "--template", "minimal"])
            self.assertEqual(calls[0][1]["cwd"], str(root))

    def test_existing_commonjs_package_requires_explicit_esm_migration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"name": "demo", "type": "commonjs"}), encoding="utf-8"
            )
            with patch.object(
                hardhat_tools, "_node_context", return_value=({"PATH": "/usr/bin"}, None)
            ), patch.object(hardhat_tools.Path, "cwd", return_value=root), \
                 patch.object(hardhat_tools, "_command_prefix") as prefix:
                self.assertEqual(hardhat_tools.run_init([]), 2)
                prefix.assert_not_called()

    def test_esm_migration_preserves_original_package_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = '{"name":"demo","type":"commonjs"}\n'
            (root / "package.json").write_text(original, encoding="utf-8")
            changed, error = hardhat_tools._backup_and_enable_esm(root)
            self.assertTrue(changed)
            self.assertIsNone(error)
            self.assertEqual(
                (root / ".package.json.lowkey-pre-hardhat-esm").read_text(encoding="utf-8"),
                original,
            )
            self.assertEqual(
                json.loads((root / "package.json").read_text(encoding="utf-8"))["type"],
                "module",
            )

    def test_build_and_test_planners_use_project_local_hardhat(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hardhat.config.ts").write_text("export default {}\n", encoding="utf-8")
            (root / "package.json").write_text(
                json.dumps({"devDependencies": {"hardhat": "^3.0.0"}}),
                encoding="utf-8",
            )
            binary = root / "node_modules" / ".bin" / "hardhat"
            binary.parent.mkdir(parents=True)
            binary.write_text("", encoding="utf-8")
            info = {"root": str(root), "backend": "node", "stacks": ["hardhat"]}

            build = bootstrap.project_build_command(info, root)
            test = bootstrap.project_test_command(info, root)

            self.assertEqual(build[0], root)
            self.assertEqual(build[1], [str(binary), "compile"])
            self.assertEqual(test[0], root)
            self.assertEqual(test[1], [str(binary), "test"])


class HardhatReadinessTests(unittest.TestCase):
    def make_hardhat_project(self, root: Path, *, ignored: bool = True):
        (root / "hardhat.config.js").write_text(
            'const config = require("./env.json");\nmodule.exports = {};\n',
            encoding="utf-8",
        )
        (root / "env.example.json").write_text(
            '{"RPC_URL":"https://example.invalid","PRIVATE_KEY":"replace-me"}\n',
            encoding="utf-8",
        )
        hardhat_tools.subprocess.run(
            ["git", "init", "-q"], cwd=root, capture_output=True, text=True, check=True
        )
        if ignored:
            (root / ".gitignore").write_text("env.json\n", encoding="utf-8")

    def test_ignored_env_template_is_copied_atomically_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_hardhat_project(root)

            ready, findings = hardhat_tools._inspect_local_configuration(
                root, create_ignored_templates=True
            )

            self.assertTrue(ready)
            self.assertEqual([item["status"] for item in findings], ["copied"])
            self.assertEqual(
                json.loads((root / "env.json").read_text(encoding="utf-8"))["RPC_URL"],
                "https://example.invalid",
            )
            self.assertEqual((root / "env.json").stat().st_mode & 0o777, 0o600)

    def test_symlinked_config_template_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            self.make_hardhat_project(root)
            outside = base / "host-secret.json"
            outside.write_text('{"PRIVATE_KEY":"must-not-read"}\n', encoding="utf-8")
            template = root / "env.example.json"
            template.unlink()
            template.symlink_to(outside)

            ready, findings = hardhat_tools._inspect_local_configuration(
                root, create_ignored_templates=True
            )

            self.assertFalse(ready)
            self.assertEqual(findings[0]["status"], "missing")
            self.assertFalse((root / "env.json").exists())

    def test_existing_env_config_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_hardhat_project(root)
            original = '{"PRIVATE_KEY":"do-not-replace"}\n'
            (root / "env.json").write_text(original, encoding="utf-8")

            ready, findings = hardhat_tools._inspect_local_configuration(
                root, create_ignored_templates=True
            )

            self.assertTrue(ready)
            self.assertEqual(findings[0]["status"], "existing")
            self.assertEqual((root / "env.json").read_text(encoding="utf-8"), original)

    def test_config_template_is_not_copied_when_destination_is_not_git_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_hardhat_project(root, ignored=False)

            ready, findings = hardhat_tools._inspect_local_configuration(
                root, create_ignored_templates=True
            )

            self.assertFalse(ready)
            self.assertEqual(findings[0]["status"], "not_ignored")
            self.assertFalse((root / "env.json").exists())

    def test_missing_config_without_example_is_reported_before_hardhat_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hardhat.config.js").write_text(
                'require("./env.json");\nmodule.exports = {};\n',
                encoding="utf-8",
            )

            ready, findings = hardhat_tools._inspect_local_configuration(
                root, create_ignored_templates=True
            )

            self.assertFalse(ready)
            self.assertEqual(findings[0]["status"], "missing")

    def test_invalid_json_template_is_not_copied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_hardhat_project(root)
            (root / "env.example.json").write_text("{invalid json\n", encoding="utf-8")

            ready, findings = hardhat_tools._inspect_local_configuration(
                root, create_ignored_templates=True
            )

            self.assertFalse(ready)
            self.assertEqual(findings[0]["status"], "invalid_template")
            self.assertFalse((root / "env.json").exists())

    def test_hardhat_node_engine_mismatch_is_advisory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "node_modules" / "hardhat" / "package.json"
            package.parent.mkdir(parents=True)
            package.write_text(
                json.dumps({
                    "name": "hardhat",
                    "version": "2.12.0",
                    "engines": {"node": "^14.0.0 || ^16.0.0 || ^18.0.0"},
                }),
                encoding="utf-8",
            )
            binary = root / "node_modules" / ".bin" / "hardhat"
            binary.parent.mkdir(parents=True)
            binary.write_text("", encoding="utf-8")

            with patch.object(
                hardhat_tools.bootstrap, "runtime_environment",
                return_value=({"PATH": "/usr/bin"}, None),
            ), patch.object(
                hardhat_tools.shutil, "which", return_value="/usr/bin/node"
            ), patch.object(
                hardhat_tools.subprocess, "run",
                return_value=SimpleNamespace(returncode=0, stdout="v24.22.1", stderr=""),
            ):
                status = hardhat_tools._hardhat_runtime_status(root, binary)

            self.assertEqual(status["status"], "warning")
            self.assertIn("outside", status["message"])
            self.assertIn("will not downgrade", status["message"])

    def test_doctor_is_read_only_when_example_config_is_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_hardhat_project(root)
            info = {"root": str(root), "backend": "hardhat", "stacks": ["hardhat"]}
            with patch.object(
                hardhat_tools, "_selected_project", return_value=(root, info)
            ), patch.object(
                hardhat_tools, "_local_hardhat", return_value=None
            ), patch.object(
                hardhat_tools.bootstrap, "bootstrap_status",
                return_value={"actions": []},
            ):
                code = hardhat_tools.run_doctor([])

            self.assertEqual(code, 0)
            self.assertFalse((root / "env.json").exists())


class HardhatCleanTests(unittest.TestCase):
    def test_hardhat_clean_uses_project_local_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "node_modules" / ".bin" / "hardhat"
            binary.parent.mkdir(parents=True)
            binary.write_text("", encoding="utf-8")
            env = {"PATH": "/usr/bin"}
            with patch.object(
                hardhat_tools, "_selected_project",
                return_value=(root, {"root": str(root), "backend": "hardhat"}),
            ), patch.object(hardhat_tools.bootstrap, "_is_hardhat_scope", return_value=True), \
                 patch.object(hardhat_tools, "_local_hardhat", return_value=binary), \
                 patch.object(hardhat_tools, "_execution_environment", return_value=(env, None)), \
                 patch.object(hardhat_tools, "prepare_readiness", return_value=0) as readiness, \
                 patch.object(hardhat_tools, "_run", return_value=0) as runner:
                self.assertEqual(hardhat_tools.run_clean(["--help"]), 0)
            readiness.assert_called_once_with(root, binary)
            runner.assert_called_once_with([str(binary), "clean", "--help"], root, env)

    def test_foundry_clean_preserves_existing_forge_handler(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            with patch.object(
                hardhat_tools, "_selected_project",
                return_value=(root, {"root": str(root), "backend": "foundry"}),
            ), patch.object(hardhat_tools.forge_tools, "main", return_value=0) as forge_main:
                self.assertEqual(hardhat_tools.run_clean(["--root", "x"]), 0)
            forge_main.assert_called_once_with(["clean", "--root", "x"])

    def test_hardhat_clean_refuses_global_fallback_when_local_binary_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(
                hardhat_tools, "_selected_project",
                return_value=(root, {"root": str(root), "backend": "hardhat"}),
            ), patch.object(hardhat_tools.bootstrap, "_is_hardhat_scope", return_value=True), \
                 patch.object(hardhat_tools, "_local_hardhat", return_value=None), \
                 patch.object(hardhat_tools.forge_tools, "main") as forge_main:
                self.assertEqual(hardhat_tools.run_clean([]), 2)
                forge_main.assert_not_called()


if __name__ == "__main__":
    unittest.main()
