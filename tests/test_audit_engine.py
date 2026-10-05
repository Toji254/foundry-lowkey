import io
import pathlib
import json
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
# audit_engine imports sibling modules. This test loads it directly through
# importlib, so keep the module directory on sys.path independent of test order.
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))
SPEC = importlib.util.spec_from_file_location("audit_engine", ROOT / "lowkey" / "audit_engine.py")
audit_engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_engine)


class AuditEngineTests(unittest.TestCase):
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

    def test_generate_poc_safe_address_literal(self):
        target = "0xa51c1fc2f0d1a1b8494ed1fe312d7c3a78ed91c0"
        rendered = audit_engine._solidity_address_literal(target)
        self.assertEqual(
            rendered,
            "address(uint160(0x00a51c1fc2f0d1a1b8494ed1fe312d7c3a78ed91c0))",
        )

    def test_source_triage_excludes_generated_test_and_script_files(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "src").mkdir()
            (root / "test").mkdir()
            (root / "script").mkdir()
            (root / "audits" / "Certora").mkdir(parents=True)
            (root / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function f() external { block.timestamp; } }",
                encoding="utf-8",
            )
            (root / "test" / "Poc.sol").write_text(
                "contract Poc { function f() external { block.timestamp; } }",
                encoding="utf-8",
            )
            (root / "script" / "Replay.sol").write_text(
                "contract Replay { function f() external { block.timestamp; } }",
                encoding="utf-8",
            )
            (root / "audits" / "Certora" / "Harness.sol").write_text(
                "contract Harness { function f() external { block.timestamp; } }",
                encoding="utf-8",
            )
            with patch.object(audit_engine, "record_evidence") as record:
                self.assertEqual(audit_engine.run_source_triage(str(root)), 0)
                payload = record.call_args.args[1]
            self.assertEqual(payload["files_scanned"], 1)
            self.assertEqual(payload["markers"][0]["file"], "src/Vault.sol")

    def test_source_triage_ignores_commented_markers(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            src = root / "src"
            src.mkdir()
            (src / "Vault.sol").write_text(
                "// block.timestamp should NOT count\n"
                "/* delegatecall should NOT count */\n"
                "contract Vault {\n"
                "    function f() external {\n"
                "        uint256 x = block.timestamp;\n"
                "    }\n"
                "}\n",
                encoding="utf-8",
            )
            with patch.object(audit_engine, "record_evidence") as record:
                self.assertEqual(audit_engine.run_source_triage(str(root)), 0)
                payload = record.call_args.args[1]
            labels = [item["label"] for item in payload["markers"]]
            self.assertIn("TIMESTAMP", labels)
            self.assertNotIn("DELEGATECALL", labels)

    def test_generic_poc_template_uses_named_import_and_lint_safe_call(self):
        rendered = audit_engine._body("generic")
        self.assertIn("NEXT STEP:", rendered)
        self.assertNotIn("TODO:", rendered)
        self.assertIn("forge-lint: disable-next-line low-level-calls", rendered)

    def test_source_triage_returns_success_for_completed_source_only_evm_scope(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text(
                "pragma solidity ^0.8.20; contract Vault { function f() external { tx.origin; } }",
                encoding="utf-8",
            )
            with patch.object(audit_engine, "record_evidence"):
                self.assertEqual(audit_engine.run_source_triage(str(root)), 0)

    def test_source_triage_returns_review_code_for_partial_native_scope(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text(
                "pub fn execute() {}\n",
                encoding="utf-8",
            )
            with patch.object(audit_engine, "record_evidence"):
                self.assertEqual(audit_engine.run_source_triage(str(root)), 2)

    def test_project_config_does_not_inherit_global_target_when_context_has_none(self):
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as raw:
            root = pathlib.Path(raw)
            (root / ".audit").mkdir()
            (root / ".audit" / "context.json").write_text(
                json.dumps({"target": {"address": None, "contract": None}}),
                encoding="utf-8",
            )
            with patch.object(audit_engine, "_config", return_value={"target": "0x" + "1" * 40}):
                config = audit_engine._project_config(root)
        self.assertIsNone(config.get("target"))

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
        self.assertIn("Build", rendered)
        self.assertIn("Tests", rendered)
        self.assertIn("PASS", rendered)
        self.assertIn("Slither", rendered)
        self.assertIn("SKIPPED", rendered)
        self.assertIn("19 review markers", rendered)
        self.assertIn("Security patterns", rendered)
        self.assertIn("0 signals", rendered)
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


    def test_finalize_pipeline_marks_missing_slither_for_solidity_as_inconclusive(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            with patch.object(audit_engine, "_evidence_data", side_effect=lambda _root, name: {
                "context": {
                    "project": {
                        "sources": {"solidity": 1}
                    }
                },
            }.get(name, {})):
                with patch.object(audit_engine, "read_json", return_value={}):
                    with patch.object(audit_engine, "write_json"):
                        with patch.object(audit_engine, "generate_poc"):
                            with patch.object(audit_engine, "render_audit_dashboard") as render_dashboard:
                                code = audit_engine._finalize_pipeline(
                                    str(root),
                                    [
                                        {"label": "build", "code": 0},
                                        {"label": "tests", "code": 0},
                                        {"label": "coverage", "code": 0},
                                        {"label": "slither", "code": 127},
                                    ],
                                    0,
                                    False,
                                )
            self.assertEqual(code, 2)
            render_dashboard.assert_called_once_with(str(root), pipeline_code=2)

    def test_finalize_pipeline_marks_analyzer_failure_as_failed(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            with patch.object(audit_engine, "_evidence_data", side_effect=lambda _root, name: {
                "context": {
                    "project": {
                        "sources": {"solidity": 1}
                    }
                },
                "tests": {
                    "stdout": "Suite result: ok. 3 passed",
                    "stderr": "",
                },
            }.get(name, {})):
                with patch.object(audit_engine, "read_json", return_value={}):
                    with patch.object(audit_engine, "write_json"):
                        with patch.object(audit_engine, "generate_poc"):
                            with patch.object(audit_engine, "render_audit_dashboard") as render_dashboard:
                                code = audit_engine._finalize_pipeline(
                                    str(root),
                                    [
                                        {"label": "build", "code": 0},
                                        {"label": "tests", "code": 0},
                                        {"label": "coverage", "code": 0},
                                        {"label": "slither", "code": 1},
                                    ],
                                    0,
                                    False,
                                )
            self.assertEqual(code, 1)
            render_dashboard.assert_called_once_with(str(root), pipeline_code=1)

    def test_finalize_pipeline_marks_missing_tests_as_inconclusive(self):
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as raw:
            root = Path(raw)
            with patch.object(audit_engine, "_evidence_data", side_effect=lambda _root, name: {
                "context": {
                    "project": {
                        "sources": {"solidity": 1}
                    }
                },
                "tests": {
                    "stdout": "Warning: No tests found in project!",
                    "stderr": "",
                },
            }.get(name, {})):
                with patch.object(audit_engine, "read_json", return_value={}):
                    with patch.object(audit_engine, "write_json"):
                        with patch.object(audit_engine, "generate_poc"):
                            with patch.object(audit_engine, "render_audit_dashboard"):
                                code = audit_engine._finalize_pipeline(
                                    str(root),
                                    [
                                        {"label": "build", "code": 0},
                                        {"label": "tests", "code": 0},
                                        {"label": "coverage", "code": 0},
                                        {"label": "slither", "code": 0},
                                    ],
                                    0,
                                    False,
                                )
            self.assertEqual(code, 2)

if __name__ == "__main__":
    unittest.main()
