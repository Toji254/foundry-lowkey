import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "bootstrap.py"

spec = importlib.util.spec_from_file_location("bootstrap", MODULE)
bootstrap = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_dependency_boundary_follows_pnpm_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "pnpm-workspace.yaml",
                "packages:\n  - 'packages/*'\n",
            )
            self.write(root, "package.json", '{"private":true}\n')
            project = root / "packages" / "app"
            self.write(project, "package.json", '{"name":"app"}\n')

            self.assertEqual(
                bootstrap.dependency_boundary(project),
                root.resolve(),
            )

    def test_parent_package_json_is_not_promoted_without_workspace_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private":true}\n')
            project = root / "packages" / "app"
            self.write(project, "package.json", '{"name":"app"}\n')

            self.assertEqual(
                bootstrap.dependency_boundary(project),
                project.resolve(),
            )

    def test_pnpm_v6_lockfile_selects_compatible_pnpm_8(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private":true}\n')
            self.write(root, "pnpm-lock.yaml", "lockfileVersion: '6.0'\n")

            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda name: name == "corepack",
            ):
                plan = bootstrap.bootstrap_plan(
                    {"root": str(root), "backend": "hardhat", "languages": {}}
                )

            node_actions = [a for a in plan["actions"] if a["kind"] == "node"]
            self.assertEqual(len(node_actions), 1)
            self.assertEqual(
                node_actions[0]["command"],
                ["corepack", "pnpm@8", "install", "--frozen-lockfile"],
            )
            self.assertEqual(node_actions[0]["cwd"], root.resolve())

    def test_shared_plan_uses_repository_declared_rust_dependencies_only_for_rust_projects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Cargo.toml", "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n")
            self.write(root, "Cargo.lock", "")
            info = {"root": str(root), "backend": "cargo", "build_backend": "cargo", "languages": {"rust": 1}}

            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: name == "cargo"):
                plan = bootstrap.bootstrap_plan(info)

            cargo_actions = [a for a in plan["actions"] if a["kind"] == "cargo"]
            self.assertEqual(len(cargo_actions), 1)
            self.assertEqual(
                cargo_actions[0]["command"],
                ["cargo", "fetch", "--locked"],
            )

    def test_failure_classifier_does_not_turn_source_errors_into_dependency_repairs(self):
        dependency = bootstrap.classify_build_failure(
            "Error: source '@openzeppelin/contracts/token/ERC20.sol' not found",
            ["forge", "build"],
        )
        source = bootstrap.classify_build_failure(
            "Error: CompilerError: Stack too deep",
            ["forge", "build"],
        )
        missing_first_party = bootstrap.classify_build_failure(
            'Source "contracts/src/Missing.sol" not found',
            ["forge", "build"],
        )
        toolchain = bootstrap.classify_build_failure(
            "This project requires node >=18 but current version is 16",
            ["hardhat", "compile"],
        )

        self.assertEqual(dependency["category"], "dependency")
        self.assertTrue(dependency["repairable"])
        self.assertEqual(source["category"], "source_or_build_error")
        self.assertFalse(source["repairable"])
        self.assertEqual(missing_first_party["category"], "source_or_build_error")
        self.assertFalse(missing_first_party["repairable"])
        self.assertEqual(toolchain["category"], "toolchain_mismatch")
        self.assertFalse(toolchain["repairable"])

    def test_build_command_uses_workspace_level_hardhat_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"private":true,"workspaces":["packages/*"]}\n')
            self.write(root, "pnpm-workspace.yaml", "packages:\n  - packages/*\n")
            project = root / "packages" / "app"
            self.write(project, "hardhat.config.ts", "export default {}\n")
            self.write(project, "package.json", '{"name":"app"}\n')
            binary = root / "node_modules" / ".bin" / "hardhat"
            binary.parent.mkdir(parents=True)
            binary.write_text("", encoding="utf-8")

            info = {"root": str(project), "backend": "hardhat", "build_backend": "hardhat"}
            command = bootstrap.project_build_command(info)

            self.assertIsNotNone(command)
            cwd, argv, evidence = command
            self.assertEqual(cwd, project.resolve())
            self.assertEqual(argv, [str(binary), "compile"])
            self.assertEqual(evidence, "local Hardhat binary")

    def test_build_command_uses_local_hardhat_without_npx_downloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "hardhat.config.ts", "export default {}\n")
            binary = root / "node_modules" / ".bin" / "hardhat"
            binary.parent.mkdir(parents=True)
            binary.write_text("", encoding="utf-8")

            info = {"root": str(root), "backend": "hardhat", "build_backend": "hardhat"}

            command = bootstrap.project_build_command(info)

            self.assertIsNotNone(command)
            cwd, argv, evidence = command
            self.assertEqual(cwd, root.resolve())
            self.assertEqual(argv, [str(binary), "compile"])
            self.assertEqual(evidence, "local Hardhat binary")
            self.assertNotIn("npx", argv)

    def test_build_command_supports_aptos_move(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Move.toml", "[package]\nname=\"demo\"\nversion=\"1.0.0\"\n")
            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: name == "aptos"):
                command = bootstrap.project_build_command(
                    {"root": str(root), "backend": "move", "build_backend": "move"}
                )
            self.assertEqual(command[1], ["aptos", "move", "compile"])
            self.assertEqual(command[2], "Aptos Move.toml")

    def test_build_command_supports_cargo_and_go(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Cargo.toml", "[package]\nname=\"demo\"\nversion=\"0.1.0\"\n")
            self.write(root, "go.mod", "module example.com/demo\n\ngo 1.22\n")

            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda name: name in {"cargo", "go"},
            ):
                cargo = bootstrap.project_build_command(
                    {"root": str(root), "backend": "cargo", "build_backend": "cargo"}
                )
                go = bootstrap.project_build_command(
                    {"root": str(root), "backend": "go", "build_backend": "go"}
                )

            self.assertEqual(cargo[1][0], "cargo")
            self.assertIn("build", cargo[1])
            self.assertEqual(go[1], ["go", "build", "./..."])


if __name__ == "__main__":
    unittest.main()
