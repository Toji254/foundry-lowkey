import io
import json
import importlib.util
import unittest
import os
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "lowkey"))
SPEC = importlib.util.spec_from_file_location("audit_engine", ROOT / "lowkey" / "audit_engine.py")
audit_engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_engine)


class AuditEngineTests(unittest.TestCase):
    def test_project_solc_env_prefers_lowkey_pinned_binary(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            toolchain = root / ".audit" / "toolchain" / "bin"
            toolchain.mkdir(parents=True)
            solc = toolchain / "solc"
            solc.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            solc.chmod(0o755)

            env = audit_engine._project_solc_env(
                str(root),
                {"solidity_compilers": ["0.8.18"]},
            )

            self.assertEqual(env["SOLC_VERSION"], "0.8.18")
            self.assertEqual(env["PATH"].split(os.pathsep)[0], str(toolchain))

    def test_clone_declared_git_dependency_uses_recursive_shallow_clone(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            with patch.object(
                audit_engine,
                "run_command",
                return_value=(0, "cloned", ""),
            ) as run:
                code, stdout, stderr = audit_engine._clone_declared_git_dependency(
                    str(root),
                    "deps/example",
                    "https://example.com/example.git",
                )

            self.assertEqual(code, 0)
            self.assertEqual(stdout, "cloned")
            self.assertEqual(stderr, "")
            command = run.call_args.args[0]
            self.assertEqual(
                command,
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--recurse-submodules",
                    "https://example.com/example.git",
                    str(root / "deps/example"),
                ],
            )

    def test_vyper_build_skips_submodule_sources(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            contracts = root / "contracts"
            contracts.mkdir()
            (contracts / "Oracle.vy").write_text(
                "@external\ndef ping() -> uint256:\n    return 1\n",
                encoding="utf-8",
            )
            dependency = root / "deps" / "legacy"
            dependency.mkdir(parents=True)
            (dependency / "Legacy.vy").write_text(
                "# @version 0.3.10\n",
                encoding="utf-8",
            )

            with patch.object(
                audit_engine,
                "project_source_files",
                return_value=[contracts / "Oracle.vy", dependency / "Legacy.vy"],
            ), patch.object(
                audit_engine,
                "run_command",
                return_value=(0, "ok", ""),
            ):
                code, stdout, stderr, files = audit_engine._run_vyper_build(
                    str(root),
                    {"submodules": [{"path": "deps/legacy"}]},
                )

            self.assertEqual(code, 0)
            self.assertEqual(
                [item["file"] for item in files],
                ["contracts/Oracle.vy"],
            )

    def test_parse_slither_payload_normalizes_detector(self):
        payload = {
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "candidate",
                        "elements": [
                            {
                                "name": "withdraw()",
                                "type": "function",
                                "source_mapping": {
                                    "filename_relative": "src/Vault.sol",
                                    "lines": [42, 48],
                                },
                            }
                        ],
                    }
                ]
            }
        }
        findings = audit_engine.parse_slither_payload(payload)
        self.assertEqual(findings[0]["check"], "reentrancy-eth")
        self.assertEqual(findings[0]["impact"], "high")
        self.assertEqual(findings[0]["confidence"], "medium")
        self.assertEqual(findings[0]["locations"][0]["source"], "src/Vault.sol")
        self.assertEqual(findings[0]["locations"][0]["start"], 42)

    def test_project_test_command_uses_uv_active_environment(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "tests").mkdir()
            dependency = root / "tests" / "vendor"
            dependency.mkdir(parents=True)
            project = {"submodules": [{"path": "tests/vendor"}]}

            command = audit_engine._project_test_command(str(root), project)

            self.assertEqual(command[:4], ["uv", "run", "--active", "pytest"])
            self.assertEqual(command[4], "tests")
            self.assertEqual(command[5:], ["--ignore", "tests/vendor"])


    def test_slither_command_does_not_fail_on_findings_by_default(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "contracts" / "Verifier.sol"
            source.parent.mkdir(parents=True)
            source.write_text(
                "pragma solidity ^0.8.18;\ncontract Verifier {}\n",
                encoding="utf-8",
            )
            project = {"solidity_compilers": ["0.8.18"], "submodules": []}

            with patch.object(audit_engine, "slither_available", return_value=True), \
                 patch.object(audit_engine, "project_source_files", return_value=[source]), \
                 patch.object(
                     audit_engine,
                     "run_command",
                     return_value=(0, "", ""),
                 ) as run:
                code = audit_engine.run_slither_project(str(root), project)

            self.assertEqual(code, 0)
            command = run.call_args.args[0]
            self.assertIn("--fail-none", command)

    def test_github_release_solc_rejects_invalid_cached_binary(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            cache = root / ".audit" / "toolchain" / "cache"
            cache.mkdir(parents=True)
            binary = cache / "solc-0.8.18"
            binary.write_text("not-a-solc", encoding="utf-8")
            binary.chmod(0o755)

            with patch(
                "audit_engine.urllib.request.urlopen",
                side_effect=OSError("offline"),
            ):
                code, stdout, stderr, executable = audit_engine._github_release_solc(
                    str(root), "0.8.18"
                )

            self.assertNotEqual(code, 0)
            self.assertIsNone(executable)
            self.assertIn("offline", stderr)

    def test_generate_poc_uses_slither_evidence_and_matrix(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            lowkey = root / ".lowkey"
            lowkey.mkdir()
            (lowkey / "config.json").write_text(
                json.dumps(
                    {
                        "target": "0x1111111111111111111111111111111111111111",
                        "rpc": "http://127.0.0.1:8545",
                        "last_tx": "0x" + "a" * 64,
                        "abi_paths": {},
                    }
                )
            )
            evidence = root / ".audit" / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "slither.json").write_text(
                json.dumps(
                    {
                        "data": {
                            "findings": [
                                {
                                    "check": "reentrancy-eth",
                                    "impact": "high",
                                    "confidence": "high",
                                    "description": "External call before effects.",
                                    "locations": [
                                        {
                                            "name": "withdraw()",
                                            "source": "src/Vault.sol",
                                            "start": 42,
                                            "end": 48,
                                        }
                                    ],
                                }
                            ]
                        }
                    }
                )
            )

            with patch.dict("os.environ", {"HOME": str(root)}, clear=False):
                code, files = audit_engine.generate_poc(str(root))

            self.assertEqual(code, 0)
            self.assertEqual(len(files), 2)
            solidity = (root / "test" / "Poc_reentrancy_eth.t.sol").read_text()
            self.assertIn("PocAttacker", solidity)
            self.assertIn("reentrancy-eth", solidity)
            brief = json.loads((root / ".audit" / "poc" / "Poc_reentrancy_eth.json").read_text())
            self.assertEqual(brief["candidate"]["mode"], "reentrancy")
            self.assertEqual(brief["candidate"]["impact"], "high")
            self.assertEqual(brief["poc_file"], "test/Poc_reentrancy_eth.t.sol")

    def test_generate_poc_detects_vyper_project_without_slither(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "pyproject.toml").write_text(
                """
[project]
name = "fixture"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["vyper>=0.4.0"]
""",
                encoding="utf-8",
            )
            contracts = root / "contracts"
            contracts.mkdir()
            (contracts / "Oracle.vy").write_text(
                "@external\ndef price() -> uint256:\n    return block.timestamp\n",
                encoding="utf-8",
            )

            with patch.dict("os.environ", {"HOME": str(root)}, clear=False):
                code, files = audit_engine.generate_poc(str(root))

            self.assertEqual(code, 0)
            self.assertEqual(len(files), 2)
            self.assertTrue((root / "tests" / "poc_audit_candidate.py").exists())
            brief = list((root / ".audit" / "poc").glob("Poc_*.json"))
            self.assertEqual(len(brief), 1)
            payload = json.loads(brief[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["project_type"], "vyper")

    def test_run_source_triage_handles_relative_root(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            src = root / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function f() external { tx.origin; } }",
                encoding="utf-8",
            )
            with patch.object(audit_engine, "record_evidence") as record:
                self.assertEqual(audit_engine.run_source_triage(str(root)), 0)
                payload = record.call_args.args[1]
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["markers"][0]["label"], "TX.ORIGIN")

    def test_render_audit_dashboard_is_human_readable(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            evidence = root / ".audit" / "evidence"
            evidence.mkdir(parents=True)
            records = {
                "context": {"target": "0x" + "1" * 40, "rpc": "http://127.0.0.1:8545", "git_sha": "abc123", "git_branch": "audit"},
                "build": {"exit_code": 0, "stdout": "Compiler run successful", "stderr": ""},
                "tests": {"exit_code": 0, "stdout": "Suite result: ok. 3 passed", "stderr": ""},
                "coverage": {"exit_code": 0, "stdout": "Total coverage: 91.2%", "stderr": ""},
                "slither": {
                    "available": False,
                    "exit_code": 127,
                    "reason": "slither not found on PATH",
                    "finding_count": 0,
                    "findings": [],
                },
                "source_triage": {"count": 19, "markers": []},
            }
            for name, data in records.items():
                (evidence / f"{name}.json").write_text(
                    json.dumps({"data": data}),
                    encoding="utf-8",
                )
            (evidence / "manifest.json").write_text(
                json.dumps({"pipeline": {"completed_at": "2026-09-24T00:00:00"}}),
                encoding="utf-8",
            )

            output = io.StringIO()
            with patch.object(audit_engine, "_config", return_value={"target": records["context"]["target"], "rpc": records["context"]["rpc"]}):
                with redirect_stdout(output):
                    code = audit_engine.render_audit_dashboard(str(root), 0)

        self.assertEqual(code, 0)
        rendered = output.getvalue()
        self.assertIn("LOWKEY AUDIT DASHBOARD", rendered)
        self.assertIn("Forge build", rendered)
        self.assertIn("PASS", rendered)
        self.assertIn("Slither", rendered)
        self.assertIn("SKIPPED", rendered)
        self.assertIn("19 review markers", rendered)
        self.assertIn("Heuristic findings are review leads", rendered)

    def test_run_rg_treats_no_match_as_success(self):
        with patch.object(audit_engine, "rg_available", return_value=True), patch.object(
            audit_engine, "run_command", return_value=(1, "", "")
        ):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as raw:
                root = Path(raw)
                self.assertEqual(audit_engine.run_rg("does-not-exist", root=str(root)), 0)
                evidence = json.loads((root / ".audit" / "evidence" / "rg.json").read_text())
                self.assertEqual(evidence["data"]["hits"], [])


if __name__ == "__main__":
    unittest.main()
