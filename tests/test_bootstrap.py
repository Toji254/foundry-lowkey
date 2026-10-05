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

        plan = {
            "project_root": str(action["cwd"]),
            "workspace_root": str(action["cwd"]),
            "dependency_root": str(action["cwd"]),
            "runtime_requirements": {},
            "actions": [action],
        }
        with patch.object(bootstrap, "bootstrap_plan", return_value=plan),              patch.object(bootstrap.subprocess, "run", side_effect=fake_run):
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

    def test_build_command_uses_vyper_compiler_for_single_vyper_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "contracts/Vault.vy", "# pragma version 0.4.3\n")
            info = {"root": str(root), "backend": "vyper", "kind": "vyper"}
            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda name: "/usr/bin/vyper" if name == "vyper" else None,
            ), patch.object(
                bootstrap.subprocess,
                "run",
                return_value=type(
                    "Result",
                    (),
                    {"returncode": 0, "stdout": "0.4.3+commit.test\n", "stderr": ""},
                )(),
            ):
                result = bootstrap.project_build_command(info)
            self.assertEqual(
                result,
                (root.resolve(), ["vyper", "contracts/Vault.vy"], "Vyper compiler (0.4.3+commit.test)"),
            )


    def test_build_command_uses_vyper_compiler_for_multiple_vyper_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "contracts/Vault.vy", "# pragma version 0.4.3\n")
            self.write(root, "contracts/Token.vy", "# pragma version 0.4.3\n")
            self.write(root, "contracts/interfaces/IVault.vyi", "interface IVault:\n    def ping(): view\n")

            info = {"root": str(root), "backend": "vyper", "kind": "vyper"}
            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda name: "/usr/bin/vyper" if name == "vyper" else None,
            ), patch.object(
                bootstrap.subprocess,
                "run",
                return_value=type(
                    "Result",
                    (),
                    {"returncode": 0, "stdout": "0.4.3+commit.test\n", "stderr": ""},
                )(),
            ):
                result = bootstrap.project_build_command(info)

            self.assertEqual(
                result,
                (
                    root.resolve(),
                    ["vyper", "contracts/Token.vy", "contracts/Vault.vy"],
                    "Vyper compiler (0.4.3+commit.test)",
                ),
            )

    def test_build_command_rejects_multiple_vyper_compiler_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "contracts/legacy.vy", "# pragma version 0.3.10\n")
            self.write(root, "contracts/current.vy", "# pragma version ^0.4.0\n")
            info = {"root": str(root), "backend": "vyper", "kind": "vyper"}

            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda name: "/usr/bin/vyper" if name == "vyper" else None,
            ), patch.object(
                bootstrap.subprocess,
                "run",
                return_value=type(
                    "Result",
                    (),
                    {"returncode": 0, "stdout": "0.4.3+commit.test\n", "stderr": ""},
                )(),
            ):
                self.assertIsNone(bootstrap.project_build_command(info))

    def test_build_command_rejects_incompatible_vyper_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "contracts/legacy.vy", "# pragma version 0.3.10\n")
            info = {"root": str(root), "backend": "vyper", "kind": "vyper"}

            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda name: "/usr/bin/vyper" if name == "vyper" else None,
            ), patch.object(
                bootstrap.subprocess,
                "run",
                return_value=type(
                    "Result",
                    (),
                    {"returncode": 0, "stdout": "0.4.3+commit.test\n", "stderr": ""},
                )(),
            ):
                self.assertIsNone(bootstrap.project_build_command(info))

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
            self.write(
                root,
                "Move.toml",
                "[package]\nname=\"demo\"\nversion=\"1.0.0\"\n\n[dependencies]\n"
                "AptosFramework = { git = \"https://github.com/aptos-labs/aptos-core.git\" }\n",
            )
            with patch.object(bootstrap.shutil, "which", side_effect=lambda name: name == "aptos"):
                command = bootstrap.project_build_command(
                    {"root": str(root), "backend": "move", "build_backend": "move"}
                )
            self.assertEqual(command[1], ["aptos", "move", "compile"])
            self.assertEqual(command[2], "Move.toml declares Aptos")

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


class NativeRoutingSafetyRegressionTests(unittest.TestCase):
    """Regression tests for unsafe native-command routing on unfamiliar repos.

    Each test encodes an invariant: a repository that does not actually declare
    a toolchain must never have that toolchain's command invented for it, and an
    unavailable local toolchain must produce REVIEW NEEDED (None) rather than a
    global/`npx` fallback.
    """

    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def local_binary(self, root, name="hardhat"):
        binary = root / "node_modules" / ".bin" / name
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_text("#!/bin/sh\n", encoding="utf-8")
        return binary

    def test_stray_hardhat_config_does_not_hijack_cargo_build_or_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Cargo.toml", '[package]\nname="demo"\nversion="0.1.0"\n')
            self.write(root, "src/lib.rs", "pub fn x() {}\n")
            self.write(root, "hardhat.config.ts", "export default {}\n")
            info = {"root": str(root), "backend": "cargo", "build_backend": "cargo", "stacks": ["cargo"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/cargo" if n == "cargo" else None):
                build = bootstrap.project_build_command(info)
                test = bootstrap.project_test_command(info, root)
            self.assertIsNotNone(build)
            self.assertEqual(build[1][0], "cargo")
            self.assertIsNotNone(test)
            self.assertEqual(test[1][:2], ["cargo", "test"])

    def test_stray_hardhat_config_does_not_hijack_cairo_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Scarb.toml", '[package]\nname="demo"\nversion="0.1.0"\n')
            self.write(root, "src/lib.cairo", "fn x() {}\n")
            self.write(root, "hardhat.config.js", "module.exports = {}\n")
            info = {"root": str(root), "backend": "cairo-starknet", "stacks": ["cairo-starknet"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/scarb" if n == "scarb" else None):
                build = bootstrap.project_build_command(info)
            self.assertIsNotNone(build)
            self.assertEqual(build[1], ["scarb", "build"])

    def test_hardhat_missing_local_binary_returns_review_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "hardhat.config.ts", "export default {}\n")
            self.write(
                root,
                "package.json",
                '{"name":"hh","devDependencies":{"hardhat":"^2"},'
                '"scripts":{"build":"hardhat compile","test":"hardhat test"}}\n',
            )
            # node_modules exists, but the local Hardhat binary does not.
            (root / "node_modules").mkdir()
            info = {"root": str(root), "backend": "hardhat", "stacks": ["hardhat"]}
            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda n: "/usr/bin/npm" if n == "npm" else None,
            ):
                self.assertIsNone(bootstrap.project_build_command(info))
                self.assertIsNone(bootstrap.project_test_command(info, root))

    def test_hardhat_uses_repository_local_binary_and_never_npx(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "hardhat.config.ts", "export default {}\n")
            self.write(
                root,
                "package.json",
                '{"name":"hh","devDependencies":{"hardhat":"^2"}}\n',
            )
            binary = self.local_binary(root)
            info = {"root": str(root), "backend": "hardhat", "stacks": ["hardhat"]}
            with patch.object(
                bootstrap.shutil,
                "which",
                side_effect=lambda n: "/usr/bin/npm" if n == "npm" else None,
            ):
                build = bootstrap.project_build_command(info)
                test = bootstrap.project_test_command(info, root)
            self.assertEqual(build[1], [str(binary), "compile"])
            self.assertEqual(test[1], [str(binary), "test"])
            self.assertNotIn("npx", build[1] + test[1])

    def test_pnpm_lockfile_never_falls_back_to_npm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"name":"app","scripts":{"test":"hardhat test"}}\n')
            self.write(root, "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
            info = {"root": str(root), "backend": "hardhat", "stacks": ["hardhat"]}
            # Corepack and pnpm are unavailable; only npm is installed.
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/npm" if n == "npm" else None):
                self.assertIsNone(bootstrap.project_test_command(info, root))
                plan = bootstrap.bootstrap_plan(info, root)
            node_actions = [a for a in plan["actions"] if a["kind"] == "node"]
            self.assertEqual(node_actions, [])
            self.assertNotIn("npm", " ".join(a["command"] for a in plan["actions"]))

    def test_yarn_lockfile_never_falls_back_to_npm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"name":"app","scripts":{"test":"hardhat test"}}\n')
            self.write(root, "yarn.lock", "# yarn lockfile v1\n")
            info = {"root": str(root), "backend": "hardhat", "stacks": ["hardhat"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/npm" if n == "npm" else None):
                self.assertIsNone(bootstrap.project_test_command(info, root))

    def test_declared_pnpm_without_corepack_does_not_use_global_pnpm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "package.json",
                '{"name":"app","packageManager":"pnpm@9.0.0","scripts":{"test":"hardhat test"}}\n',
            )
            info = {"root": str(root), "backend": "hardhat", "stacks": ["hardhat"]}
            # A random global pnpm must not be used to satisfy a declared pin.
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/" + n if n in {"pnpm", "npm"} else None):
                self.assertIsNone(bootstrap.project_test_command(info, root))
                plan = bootstrap.bootstrap_plan(info, root)
            self.assertEqual([a for a in plan["actions"] if a["kind"] == "node"], [])

    def test_sui_move_project_is_not_routed_to_aptos(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "Move.toml",
                '[package]\nname="s"\n\n[dependencies]\n'
                'Sui = { git = "https://github.com/MystenLabs/sui.git" }\n',
            )
            info = {"root": str(root), "backend": "move", "stacks": ["move"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/" + n if n in {"aptos", "sui"} else None):
                build = bootstrap.project_build_command(info)
                test = bootstrap.project_test_command(info, root)
            self.assertEqual(build[1], ["sui", "move", "build"])
            self.assertEqual(test[1], ["sui", "move", "test"])

    def test_ambiguous_move_project_is_review_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Move.toml", '[package]\nname="demo"\nversion="0.0.1"\n')
            info = {"root": str(root), "backend": "move", "stacks": ["move"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/" + n if n in {"aptos", "sui"} else None):
                self.assertIsNone(bootstrap.project_build_command(info))
                self.assertIsNone(bootstrap.project_test_command(info, root))

    def test_move_framework_mismatch_is_review_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "Move.toml",
                '[dependencies]\nAptosFramework = { git = "https://github.com/aptos-labs/aptos-core.git" }\n',
            )
            info = {"root": str(root), "backend": "move", "stacks": ["move"]}
            # The declared framework is Aptos, but only Sui is installed.
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/sui" if n == "sui" else None):
                self.assertIsNone(bootstrap.project_build_command(info))

    def test_tests_dir_without_python_files_does_not_select_pytest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "Anchor.toml", '[provider]\ncluster = "localnet"\n')
            self.write(root, "Cargo.toml", '[package]\nname="demo"\nversion="0.1.0"\n')
            self.write(root, "tests/demo.ts", "describe('x', () => {});\n")
            info = {"root": str(root), "backend": "multi", "stacks": ["solana-anchor", "cargo"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/" + n if n in {"pytest", "cargo", "anchor"} else None):
                self.assertIsNone(bootstrap.project_test_command(info, root))

    def test_python_tests_directory_with_python_file_selects_pytest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "tests/test_smoke.py", "def test_smoke(): pass\n")
            info = {"root": str(root), "backend": "python", "stacks": ["python"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/pytest" if n == "pytest" else None):
                result = bootstrap.project_test_command(info, root)
            self.assertEqual(result[1], ["pytest"])

    def test_go_project_selects_go_native_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
            self.write(root, "main.go", "package main\n\nfunc main() {}\n")
            info = {"root": str(root), "backend": "go", "build_backend": "go", "stacks": ["go"]}
            with patch.object(bootstrap.shutil, "which", side_effect=lambda n: "/usr/bin/go" if n == "go" else None):
                build = bootstrap.project_build_command(info)
                test = bootstrap.project_test_command(info, root)
            self.assertEqual(build[1], ["go", "build", "./..."])
            self.assertEqual(test[1], ["go", "test", "./..."])

    def test_node_satisfies_handles_ranges(self):
        cases = (
            ("26.8.1", ">=20", True),
            ("18.18.0", "18.18.0", True),
            ("16.0.0", "18.18.0", False),
            ("18.5.0", "18.x", True),
            ("18.5.0", "^18.0.0", True),
            ("26.8.1", ">=18 <21", False),
            ("20.1.0", ">=18 <21", True),
        )
        for version, spec, expected in cases:
            with self.subTest(version=version, spec=spec):
                self.assertEqual(bootstrap._node_satisfies(version, spec), expected)

    def test_node_engines_range_is_collected_as_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"engines":{"node":">=18 <21"}}\n')
            self.assertEqual(bootstrap._node_runtime_requirement(root), ">=18 <21")

    def test_node_tool_versions_pin_is_collected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, ".tool-versions", "nodejs 18.18.0\n")
            self.assertEqual(bootstrap._node_runtime_requirement(root), "18.18.0")

    def test_node_runtime_status_flags_unsatisfied_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, ".nvmrc", "18.18.0\n")
            with patch.object(bootstrap.shutil, "which", return_value="/usr/bin/node"), patch.object(
                bootstrap.subprocess,
                "run",
                return_value=type("R", (), {"returncode": 0, "stdout": "v26.8.1\n", "stderr": ""})(),
            ), patch.object(bootstrap.Path, "home", return_value=pathlib.Path(tmp)):
                status = bootstrap.node_runtime_status(root)
            self.assertEqual(status["required"], "18.18.0")
            self.assertFalse(status["matched"])
            self.assertIsNone(status["path"])

    def test_node_runtime_status_matches_satisfied_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "package.json", '{"engines":{"node":">=18"}}\n')
            with patch.object(bootstrap.shutil, "which", return_value="/usr/bin/node"), patch.object(
                bootstrap.subprocess,
                "run",
                return_value=type("R", (), {"returncode": 0, "stdout": "v26.8.1\n", "stderr": ""})(),
            ):
                status = bootstrap.node_runtime_status(root)
            self.assertEqual(status["required"], ">=18")
            self.assertTrue(status["matched"])


if __name__ == "__main__":
    unittest.main()
