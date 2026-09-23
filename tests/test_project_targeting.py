import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast_project_targeting", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class ProjectTargetingTests(unittest.TestCase):
    def _root(self, tmp):
        root = pathlib.Path(tmp) / "project"
        root.mkdir()
        (root / "foundry.toml").write_text("[profile.default]\nsrc = \"src\"\n", encoding="utf-8")
        return root

    def test_stale_global_target_does_not_leak_into_current_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            old_root = pathlib.Path(tmp) / "old-project"
            old_root.mkdir()
            config = {
                "target": "0x" + "1" * 40,
                "target_contract": "EthEscrow",
                "abi_paths": {"0x" + "1" * 40: str(old_root / "out" / "EthEscrow.json")},
                "project_roots": {"0x" + "1" * 40: str(old_root)},
            }

            synced = lk._sync_audit_context(config, root)

            self.assertIsNone(synced["target"]["address"])
            self.assertIsNone(lk.active_project_target(config, root))
            self.assertIsNone(lk.activate_project_target(config, root))
            self.assertIsNone(config["target"])

    def test_project_target_overrides_global_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            artifact = root / "out" / "ConfidencePoolFactory.sol" / "ConfidencePoolFactory.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("{}", encoding="utf-8")
            project_target = "0x" + "2" * 40
            global_target = "0x" + "1" * 40

            lk.audit_context.set_target(
                root,
                address=project_target,
                contract="ConfidencePoolFactory",
                artifact=str(artifact),
                source="manual",
            )
            config = {
                "target": global_target,
                "target_contract": "EthEscrow",
                "abi_paths": {global_target: str(pathlib.Path(tmp) / "old" / "Escrow.json")},
                "project_roots": {global_target: str(pathlib.Path(tmp) / "old")},
            }

            self.assertEqual(lk.active_project_target(config, root), project_target)
            lk.activate_project_target(config, root)
            self.assertEqual(config["target"], project_target)
            self.assertEqual(config["target_contract"], "ConfidencePoolFactory")
            self.assertEqual(config["abi_paths"][project_target], str(artifact))


    def test_ask_uses_current_build_artifacts_without_live_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            artifact = root / "out" / "ConfidencePoolFactory.sol" / "ConfidencePoolFactory.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps(
                    {
                        "contractName": "ConfidencePoolFactory",
                        "abi": [
                            {
                                "type": "function",
                                "name": "createPool",
                                "stateMutability": "nonpayable",
                                "inputs": [
                                    {"name": "agreement", "type": "address"},
                                    {"name": "stakeToken", "type": "address"},
                                ],
                                "outputs": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            config = {"target": None}
            output = io.StringIO()
            with patch_cwd(root), redirect_stdout(output):
                result = lk.dispatch_command("ask", ["createPool"], config)

            self.assertEqual(result, 0)
            rendered = output.getvalue()
            self.assertIn("LOWKEY BUILD FUNCTION", rendered)
            self.assertIn("Found:   ConfidencePoolFactory::createPool(address,address)", rendered)

    def test_discover_audit_target_contract_prefers_higher_impact_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            for contract in ("Factory", "Helper"):
                artifact = root / "out" / f"{contract}.sol" / f"{contract}.json"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text(
                    json.dumps(
                        {
                            "contractName": contract,
                            "bytecode": {"object": "0x6000"},
                            "abi": [],
                        }
                    ),
                    encoding="utf-8",
                )
            lk.audit_context.add_signal(
                {
                    "id": "HIGH-TEST",
                    "title": "High issue",
                    "tool": "test",
                    "impact": "High",
                    "confidence": "High",
                    "file": "src/Factory.sol",
                    "line": 10,
                    "status": "open",
                },
                root,
            )
            lk.audit_context.add_signal(
                {
                    "id": "LOW-TEST",
                    "title": "Low issue",
                    "tool": "test",
                    "impact": "Low",
                    "confidence": "High",
                    "file": "src/Helper.sol",
                    "line": 10,
                    "status": "open",
                },
                root,
            )
            self.assertEqual(lk.discover_audit_target_contract(root), "Factory")

    def test_repo_clone_helpers(self):
        self.assertEqual(
            lk.repo_clone_url("CodeHawks-Contests/2026-07-bc-confidence-pools"),
            "https://github.com/CodeHawks-Contests/2026-07-bc-confidence-pools.git",
        )
        self.assertEqual(
            lk.repo_clone_name("https://github.com/Toji254/foundry-lowkey.git"),
            "foundry-lowkey",
        )
        self.assertEqual(
            lk.repo_clone_name("git@github.com:Toji254/foundry-lowkey.git"),
            "foundry-lowkey",
        )

    def test_clone_requires_only_repo(self):
        original = lk.run_clone
        calls = []

        def fake_run_clone(config, args):
            calls.append((config, args))
            return 0

        lk.run_clone = fake_run_clone
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = self._root(tmp)
                config = {"target": None}
                with patch_cwd(root):
                    result = lk.dispatch_command(
                        "clone",
                        ["https://example.com/repo.git"],
                        config,
                    )
        finally:
            lk.run_clone = original

        self.assertEqual(result, 0)
        self.assertEqual(calls[0][1], ["https://example.com/repo.git"])

    def test_upgradeable_artifact_has_initializer(self):
        artifact = {
            "abi": [
                {"type": "constructor", "inputs": []},
                {"type": "function", "name": "initialize", "inputs": [], "outputs": []},
            ],
            "bytecode": {"object": "0x6000"},
        }
        self.assertTrue(
            any(
                item.get("name") == "initialize"
                for item in artifact["abi"]
                if isinstance(item, dict)
            )
        )

    def test_parse_deployed_address(self):
        self.assertEqual(
            lk.parse_deployed_address("Deployed to: 0x" + "b" * 40),
            "0x" + "b" * 40,
        )
        self.assertEqual(
            lk.parse_deployed_address("Deployed to: 0x" + "b" * 40 + " (ConfidencePoolFactory)"),
            "0x" + "b" * 40,
        )
        self.assertEqual(
            lk.parse_deployed_address("Contract Address: 0x" + "c" * 40),
            "0x" + "c" * 40,
        )
        self.assertEqual(
            lk.parse_deployed_address('{"deployedTo":"0x' + "d" * 40 + '"}'),
            "0x" + "d" * 40,
        )
        self.assertIsNone(lk.parse_deployed_address("deployment complete"))

    def test_artifact_constructor_inputs(self):
        artifact = {
            "abi": [
                {
                    "type": "constructor",
                    "inputs": [
                        {"name": "owner", "type": "address"},
                        {"name": "limit", "type": "uint256"},
                    ],
                }
            ]
        }
        self.assertEqual(
            lk.artifact_constructor_inputs(artifact),
            [
                {"name": "owner", "type": "address"},
                {"name": "limit", "type": "uint256"},
            ],
        )

    def test_run_foundry_capture_combines_stdout_and_stderr(self):
        class Completed:
            returncode = 0
            stdout = "compile warning"
            stderr = "Deployed to: 0x" + "e" * 40

        class FakeSubprocess:
            @staticmethod
            def run(*args, **kwargs):
                return Completed()

        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            original_subprocess = lk.subprocess
            original_tool_path = lk.tool_path
            lk.subprocess = FakeSubprocess
            lk.tool_path = lambda name: "/usr/bin/forge" if name == "forge" else None
            try:
                with patch_cwd(root):
                    result = lk.run_foundry(["create", "src/Test.sol:Test"], capture=True)
            finally:
                lk.subprocess = original_subprocess
                lk.tool_path = original_tool_path

        self.assertEqual(result.code, 0)
        self.assertIn("compile warning", result.text)
        self.assertIn("Deployed to: 0x" + "e" * 40, result.text)

    def test_parse_lab_marker(self):
        self.assertEqual(
            lk.parse_lab_marker("LOWKEY_TARGET 0x" + "a" * 40),
            "0x" + "a" * 40,
        )
        self.assertIsNone(lk.parse_lab_marker("LOWKEY_TARGET not-an-address"))

    def test_discover_local_lab_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            script_dir = root / "script"
            script_dir.mkdir()
            local_script = script_dir / "LocalAudit.s.sol"
            local_script.write_text("// local lab", encoding="utf-8")
            self.assertEqual(lk.discover_local_lab_script(root), str(local_script))

    def test_fn_searches_current_build_artifacts_without_live_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            artifact = root / "out" / "ConfidencePoolFactory.sol" / "ConfidencePoolFactory.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text(
                json.dumps(
                    {
                        "contractName": "ConfidencePoolFactory",
                        "abi": [
                            {
                                "type": "function",
                                "name": "createPool",
                                "stateMutability": "nonpayable",
                                "inputs": [
                                    {"name": "agreement", "type": "address"},
                                    {"name": "stakeToken", "type": "address"},
                                    {"name": "expiry", "type": "uint256"},
                                    {"name": "minStake", "type": "uint256"},
                                    {"name": "recoveryAddress", "type": "address"},
                                    {"name": "accounts", "type": "address[]"},
                                ],
                                "outputs": [{"name": "pool", "type": "address"}],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            config = {"target": None}
            with patch_cwd(root):
                output = io.StringIO()
                with redirect_stdout(output):
                    result = lk.run_functions(
                        config,
                        "createPool(address,address,uint256,uint256,address,address[])",
                    )

            self.assertEqual(result, 0)
            rendered = output.getvalue()
            self.assertIn("LOWKEY BUILD FUNCTION", rendered)
            self.assertIn("Found:   ConfidencePoolFactory::createPool(address,address,uint256,uint256,address,address[])", rendered)
            self.assertIn("Other:   IConfidencePoolFactory (interface), MockConfidencePoolFactoryV2 (test mock)", rendered)
            self.assertIn("Live:    none", rendered)


class patch_cwd:
    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.old = None

    def __enter__(self):
        self.old = pathlib.Path.cwd()
        import os
        os.chdir(self.path)
        return self

    def __exit__(self, exc_type, exc, tb):
        import os
        os.chdir(self.old)


if __name__ == "__main__":
    unittest.main()
