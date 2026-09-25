import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "project_tools.py"

spec = importlib.util.spec_from_file_location("project_tools", MODULE)
project_tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(project_tools)


class ProjectToolsTests(unittest.TestCase):
    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_detects_foundry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "foundry.toml", "[profile.default]\nsrc = 'src'\n")
            self.write(root, "src/Vault.sol", "pragma solidity ^0.8.20; contract Vault {}")
            project = project_tools.detect_project(root)
            self.assertEqual(project["kind"], "foundry")
            self.assertIn("solidity", project["languages"])
            self.assertEqual(project["sources"]["solidity"], 1)

    def test_detects_vyper_uv_from_pyproject_without_src(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "pyproject.toml",
                """
[project]
name = "storage-proofs"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["vyper>=0.4.0", "snekmate==0.1.0"]
""",
            )
            self.write(root, "uv.lock", "version = 1\n")
            self.write(root, "contracts/oracle.vy", "@external\ndef price() -> uint256: return 1\n")
            project = project_tools.detect_project(root)
            self.assertIn(project["kind"], {"vyper-uv", "vyper"})
            self.assertIn("vyper", project["languages"])
            self.assertIn("contracts", project["source_roots"])
            self.assertEqual(project["sources"]["vyper"], 1)

    def test_detects_mixed_foundry_vyper(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "foundry.toml", "[profile.default]\n")
            self.write(root, "pyproject.toml", '[project]\\ndependencies = ["vyper>=0.4.0"]\\n')
            self.write(root, "src/Vault.sol", "pragma solidity ^0.8.20; contract Vault {}")
            self.write(root, "contracts/Vault.vy", "@external\ndef ping(): pass\n")
            project = project_tools.detect_project(root)
            self.assertEqual(project["kind"], "mixed-foundry-vyper")
            self.assertEqual(project["sources"]["solidity"], 1)
            self.assertEqual(project["sources"]["vyper"], 1)

    def test_dependency_graph_connects_local_solidity_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "src/Factory.sol",
                'pragma solidity ^0.8.20; import "./Pool.sol"; contract Factory is Pool {}',
            )
            self.write(root, "src/Pool.sol", "pragma solidity ^0.8.20; contract Pool {}")
            graph = project_tools.build_dependency_graph(root)
            resolved = [
                edge for edge in graph["edges"]
                if edge["kind"] == "import" and edge["to"] == "src/Pool.sol"
            ]
            self.assertEqual(len(resolved), 1)
            self.assertTrue(resolved[0]["resolved"])

    def test_dependency_graph_understands_vyper_imports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "contracts/main.vy",
                "from interfaces.pool import IPool\\n@external\\ndef ping():\\n    pass\\n",
            )
            self.write(
                root,
                "contracts/interfaces/pool.vyi",
                "interface IPool:\\n    def ping(): nonpayable\\n",
            )
            graph = project_tools.build_dependency_graph(root)
            self.assertEqual(graph["summary"]["imports"], 1)
            self.assertEqual(graph["summary"]["unresolved_imports"], 0)
            edge = graph["edges"][0]
            self.assertEqual(edge["to"], "contracts/interfaces/pool.vyi")
            self.assertTrue(edge["resolved"])

    def test_dependency_graph_marks_installed_vyper_package_as_external_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "contracts/main.vy",
                "from snekmate.auth import access_control\n",
            )
            package = root / ".venv/lib/python3.12/site-packages/snekmate"
            package.mkdir(parents=True)

            graph = project_tools.build_dependency_graph(root)

            self.assertEqual(graph["summary"]["unresolved_imports"], 0)
            self.assertEqual(graph["summary"]["external_imports"], 1)
            edge = graph["edges"][0]
            self.assertTrue(edge["external"])
            self.assertTrue(edge["resolved"])

    def test_dependency_graph_resolves_vyper_package_style_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "contracts/scrvusd/oracles/ScrvusdOracleV2.vy",
                "@external\ndef price() -> uint256:\n    return 1\n",
            )
            self.write(
                root,
                "tests/scrvusd/contracts/ScrvusdOracleMock.vy",
                "from contracts.scrvusd.oracles import ScrvusdOracleV2\n",
            )

            graph = project_tools.build_dependency_graph(root)

            self.assertEqual(graph["summary"]["unresolved_imports"], 0)
            edge = next(edge for edge in graph["edges"] if edge["from"].startswith("tests/"))
            self.assertEqual(
                edge["to"],
                "contracts/scrvusd/oracles/ScrvusdOracleV2.vy",
            )
            self.assertTrue(edge["resolved"])
            self.assertFalse(edge["external"])

    def test_dependency_graph_resolves_common_node_modules_solidity_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "contracts/Verifier.sol",
                'pragma solidity ^0.8.20; import "hamdiallam/Solidity-RLP@2.0.7/contracts/RLPReader.sol"; contract Verifier {}\n',
            )
            self.write(
                root,
                "node_modules/solidity-rlp/contracts/RLPReader.sol",
                "pragma solidity ^0.8.20; library RLPReader {}\n",
            )

            graph = project_tools.build_dependency_graph(root)

            edge = graph["edges"][0]
            self.assertTrue(edge["resolved"])
            self.assertTrue(edge["external"])
            self.assertEqual(
                pathlib.Path(edge["to"]).as_posix(),
                "node_modules/solidity-rlp/contracts/RLPReader.sol",
            )
            self.assertEqual(graph["summary"]["unresolved_imports"], 0)

    def test_detect_project_reports_solidity_compiler_versions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                "contracts/Verifier.sol",
                "pragma solidity ^0.8.18; contract Verifier {}\n",
            )
            self.write(
                root,
                "scripts/deploy.py",
                'compiler_args = {"solc_version": "0.8.18"}\n',
            )

            project = project_tools.detect_project(root)

            self.assertEqual(project["solidity_compilers"], ["0.8.18"])

    def test_detect_project_treats_git_only_submodule_directory_as_uninitialized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                ".gitmodules",
                "[submodule \"contracts/xdao\"]\n"
                "\tpath = contracts/xdao\n"
                "\turl = https://example.com/xdao.git\n",
            )
            submodule = root / "contracts/xdao"
            submodule.mkdir(parents=True)
            (submodule / ".git").mkdir()

            project = project_tools.detect_project(root)

            self.assertTrue(project["submodules"][0]["present"])
            self.assertFalse(project["submodules"][0]["initialized"])

    def test_detect_project_reports_python_version_and_submodules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(
                root,
                ".python-version",
                "3.12\n",
            )
            self.write(
                root,
                ".gitmodules",
                "[submodule \"contracts/xdao\"]\n"
                "\tpath = contracts/xdao\n"
                "\turl = https://example.com/xdao.git\n",
            )
            submodule = root / "contracts/xdao"
            submodule.mkdir(parents=True)
            self.write(root, "contracts/xdao/README.md", "initialized")

            project = project_tools.detect_project(root)

            self.assertEqual(project["python"]["version_file"], "3.12")
            self.assertEqual(len(project["submodules"]), 1)
            self.assertTrue(project["submodules"][0]["initialized"])

    def test_source_inventory_excludes_audit_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "contracts/Oracle.vy", "@external\ndef ping(): pass\n")
            self.write(root, ".audit/evidence/fake.vy", "garbage")
            files = project_tools.project_source_files(root)
            self.assertEqual([p.relative_to(root).as_posix() for p in files], ["contracts/Oracle.vy"])


if __name__ == "__main__":
    unittest.main()
