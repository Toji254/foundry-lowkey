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

    def test_partial_node_modules_triggers_hardhat_dependency_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "package.json",
                '{"private":true,"devDependencies":{"hardhat":"^2.22.0"}}\n',
            )
            (root / "node_modules").mkdir()

            info = {
                "root": str(root),
                "backend": "multi",
                "stacks": ["foundry", "hardhat"],
                "languages": {"solidity": 1, "typescript": 1},
            }

            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda name: name == "npm",
            ):
                plan = bootstrap.bootstrap_plan(info, reason="audit")

            node_actions = [a for a in plan["actions"] if a["kind"] == "node"]
            self.assertEqual(len(node_actions), 1)
            self.assertEqual(node_actions[0]["command"], ["npm", "install"])
            self.assertIn("Hardhat binary missing", node_actions[0]["evidence"])

    def test_node_runtime_pin_prefers_matching_installed_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, ".nvmrc", "18.18.0\n")
            with patch.object(bootstrap.shutil, "which", return_value="/usr/bin/node"), patch.object(
                bootstrap.subprocess,
                "run",
                side_effect=lambda command, **kwargs: type(
                    "Result",
                    (),
                    {
                        "returncode": 0,
                        "stdout": "v26.8.1\n" if command[0] == "/usr/bin/node" else "v18.18.0\n",
                        "stderr": "",
                    },
                )(),
            ):
                with patch.object(bootstrap.Path, "home", return_value=pathlib.Path(tmp)):
                    nvm_runtime = pathlib.Path(tmp) / ".nvm" / "versions" / "node" / "v18.18.0" / "bin"
                    nvm_runtime.mkdir(parents=True)
                    nvm_node = nvm_runtime / "node"
                    nvm_node.write_text("#!/bin/sh\nprintf 'v18.18.0\n'\n", encoding="utf-8")
                    nvm_node.chmod(0o755)
                    env, pin = bootstrap.runtime_environment(root)

            self.assertEqual(pin, "18.18.0")
            self.assertEqual(env["PATH"].split(bootstrap.os.pathsep)[0], str(nvm_runtime))

    def test_node_runtime_pin_prefers_concrete_asdf_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, ".nvmrc", "18.18.0\n")
            runtime = pathlib.Path(tmp) / "nodejs" / "18.18.0" / "bin"
            runtime.mkdir(parents=True)
            node = runtime / "node"
            node.write_text("", encoding="utf-8")
            node.chmod(0o755)

            def fake_which(name):
                return {
                    "node": "/home/rogue/.asdf/shims/node",
                    "asdf": "/usr/bin/asdf",
                    "bash": "/bin/bash",
                }.get(name)

            def fake_run(command, **kwargs):
                if command[:2] == ["/home/rogue/.asdf/shims/node", "--version"]:
                    return type("Result", (), {"returncode": 0, "stdout": "v26.8.1\n", "stderr": ""})()
                if command[:4] == ["/usr/bin/asdf", "where", "nodejs", "18.18.0"]:
                    return type("Result", (), {"returncode": 0, "stdout": str(runtime.parent) + "\n", "stderr": ""})()
                if command[:2] == [str(node), "--version"]:
                    return type("Result", (), {"returncode": 0, "stdout": "v18.18.0\n", "stderr": ""})()
                raise AssertionError(f"unexpected command: {command}")

            with patch.object(bootstrap.shutil, "which", side_effect=fake_which), patch.object(
                bootstrap.subprocess, "run", side_effect=fake_run
            ):
                env, pin = bootstrap.runtime_environment(root)

            self.assertEqual(pin, "18.18.0")
            self.assertEqual(env["PATH"].split(bootstrap.os.pathsep)[0], str(runtime))

    def test_native_node_addon_failure_retries_without_scripts(self):
        action = {
            "kind": "node",
            "cwd": pathlib.Path("/tmp/lowkey-bootstrap-test"),
            "command": ["corepack", "pnpm@8", "install", "--frozen-lockfile"],
            "evidence": "pnpm-lockfile",
        }
        calls = []

        class Result:
            def __init__(self, code, stdout="", stderr=""):
                self.returncode = code
                self.stdout = stdout
                self.stderr = stderr

        def fake_run(command, **kwargs):
            calls.append(command)
            if len(calls) == 1:
                return Result(
                    1,
                    stderr="node-gyp ERR! build error\n"
                    "fatal error: libusb.h: No such file or directory\n",
                )
            return Result(0, stdout="Lockfile is up to date\n")

        with patch.object(bootstrap.subprocess, "run", side_effect=fake_run):
            code = bootstrap.run_bootstrap(
                {
                    "root": str(action["cwd"]),
                    "stacks": ["foundry", "hardhat"],
                }
            )

        self.assertEqual(code, 0)
        self.assertEqual(calls[1], [*action["command"], "--ignore-scripts"])

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

    def test_failure_classifier_marks_package_solver_conflicts_as_hard_dependency_conflicts(self):
        conflict = bootstrap.classify_build_failure(
            "error: version solving failed: staking depends on snforge_std >=0.64.0, <0.65.0 "
            "and starkware_utils_testing depends on snforge_std >=0.34.0, <0.35.0; "
            "staking is forbidden.",
            ["scarb", "build"],
        )

        self.assertEqual(conflict["category"], "dependency_conflict")
        self.assertFalse(conflict["repairable"])
        self.assertIn("mutually incompatible", conflict["reason"])

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
