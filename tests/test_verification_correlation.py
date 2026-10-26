import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from lowkey import audit_context, lk as lowkey_cli, verification_cli


class VerificationCorrelationTests(unittest.TestCase):
    def _project(self, parent):
        root = pathlib.Path(parent)
        (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text(
            "pragma solidity ^0.8.20; contract Vault { function withdraw() external {} }\n",
            encoding="utf-8",
        )
        return root

    def _campaign(self, root, report_path, *, investigation=None, test_kind="invariant"):
        report = {
            "profile": "balanced",
            "test_kind": test_kind,
            "project": {"root": str(root), "languages": ["solidity"], "build_systems": ["foundry"]},
            "manifest": str(root / "campaign.json"),
            "manifest_sha256": "a" * 64,
            "investigation": investigation or {},
            "results": [
                {
                    "selection": {"engine": "echidna", "status": "selected"},
                    "result": {
                        "engine": "echidna",
                        "status": "failed",
                        "exit_code": 1,
                        "summary": "Campaign property failed",
                        "metadata": {"result_semantics": "echidna_json_campaign_failure"},
                        "raw_stdout": "counterexample seed 42",
                        "raw_stderr": "",
                        "duration_seconds": 2.5,
                        "artifacts": ["corpus/repro.json"],
                    },
                },
                {
                    "selection": {"engine": "halmos", "status": "selected"},
                    "result": {
                        "engine": "halmos",
                        "status": "passed",
                        "exit_code": 0,
                        "summary": "Symbolic test passed",
                        "metadata": {"result_semantics": "halmos_pass_marker_detected"},
                        "raw_stdout": "[PASS] check_withdrawal",
                        "raw_stderr": "",
                        "duration_seconds": 1.2,
                        "artifacts": [],
                    },
                },
            ],
        }
        report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        return report

    def test_correlate_attaches_repeat_safe_evidence_without_confirming_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            signal = audit_context.add_signal({
                "tool": "slither",
                "check": "reentrancy-eth",
                "title": "Potential reentrancy",
                "impact": "High",
                "confidence": "Medium",
                "file": "src/Vault.sol",
                "line": 1,
                "function": "withdraw()",
            }, root)
            report_path = root / ".audit" / "verification" / "campaign.json"
            report_path.parent.mkdir(parents=True)
            self._campaign(
                root, report_path,
                investigation={"signal_ids": [signal["id"]], "property_id": "withdrawal-solvency"},
            )

            first = verification_cli.correlate_campaign(report_path, project_root=root)
            second = verification_cli.correlate_campaign(report_path, project_root=root)
            stored = audit_context.signals(root)[0]
            evidence = stored.get("evidence", [])

            self.assertEqual(first["attached_signal_ids"], [signal["id"]])
            self.assertEqual(second["attached_signal_ids"], [signal["id"]])
            self.assertEqual(len(evidence), 1)
            self.assertFalse(first["summary"]["security_finding_confirmed"])
            self.assertEqual(first["summary"]["reported_test_or_property_failures"], 1)
            by_engine = {item["engine"]: item for item in first["engine_results"]}
            self.assertEqual(
                by_engine["echidna"]["interpretation"],
                "property_or_counterexample_failure_requires_review",
            )
            self.assertIn("not_a_security_verdict", by_engine["halmos"]["interpretation"])

    def test_explicit_source_and_function_match_only_one_existing_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            signal = audit_context.add_signal({
                "tool": "slither",
                "check": "external-call",
                "title": "External call review",
                "file": "src/Vault.sol",
                "line": 1,
                "function": "withdraw()",
            }, root)
            report_path = root / "campaign.json"
            self._campaign(
                root, report_path,
                investigation={"source_file": "src/Vault.sol", "function": "withdraw()"},
            )
            result = verification_cli.correlate_campaign(report_path, project_root=root)
            self.assertEqual(result["attached_signal_ids"], [signal["id"]])

    def test_missing_signal_is_reported_and_never_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            report_path = root / "campaign.json"
            self._campaign(root, report_path, investigation={"signal_ids": ["SLITHER-MISSING"]})
            result = verification_cli.correlate_campaign(report_path, project_root=root)
            self.assertEqual(result["missing_signal_ids"], ["SLITHER-MISSING"])
            self.assertEqual(audit_context.signals(root), [])
            self.assertTrue(any("no replacement signals" in note for note in result["notes"]))

    def test_cli_correlate_parses_signal_and_output_options(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            signal = audit_context.add_signal({
                "tool": "slither",
                "check": "access-control",
                "title": "Access control review",
                "file": "src/Vault.sol",
                "line": 1,
                "function": "withdraw()",
            }, root)
            report_path = root / "campaign.json"
            self._campaign(root, report_path)
            output_path = root / "correlation.json"
            rendered = StringIO()
            with patch("lowkey.verification_cli._project_root", return_value=root):
                with redirect_stdout(rendered):
                    code = verification_cli.run_cli([
                        "correlate", str(report_path), "--signal", signal["id"],
                        "--output", str(output_path),
                    ])

            self.assertEqual(code, 0)
            self.assertTrue(output_path.is_file())
            self.assertIn("LOWKEY VERIFICATION CORRELATION", rendered.getvalue())
            saved = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["attached_signal_ids"], [signal["id"]])

    def test_findings_renderer_displays_engine_outcomes_and_skipped_tools(self):
        output = StringIO()
        signal = {
            "evidence": [{
                "kind": "verification-correlation",
                "correlation_id": "property:withdrawal-solvency",
                "campaign_report": ".audit/verification/campaign.json",
                "campaign_report_sha256": "a" * 64,
                "coverage_status": "engine_results_available",
                "security_finding_confirmed": False,
                "engine_results": [
                    {
                        "engine": "echidna",
                        "status": "failed",
                        "summary": "Property failed with counterexample",
                        "interpretation": "property_or_counterexample_failure_requires_review",
                    },
                    {
                        "engine": "halmos",
                        "status": "passed",
                        "summary": "Symbolic check passed",
                        "interpretation": "engine_completed_without_reported_failure_not_a_security_verdict",
                    },
                ],
                "engine_selection": [
                    {"engine": "medusa", "status": "missing_configuration", "reason": "medusa.json is missing"},
                ],
            }],
        }
        with redirect_stdout(output):
            lowkey_cli._render_signal_evidence(signal)

        rendered = output.getvalue()
        self.assertIn("Echidna: FAILED — property_or_counterexample_failure_requires_review", rendered)
        self.assertIn("Halmos: PASSED — engine_completed_without_reported_failure_not_a_security_verdict", rendered)
        self.assertIn("Not run      : medusa (missing_configuration)", rendered)
        self.assertIn("not confirmed; review evidence before disposition", rendered)
        self.assertNotIn("Storage     : no changed slots", rendered)

    def test_empty_campaign_is_reported_as_coverage_gap_and_cli_fails_closed(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            report_path = root / "empty-campaign.json"
            report = self._campaign(root, report_path)
            report["results"] = []
            report["considered_engines"] = [
                {
                    "engine": "echidna",
                    "status": "missing_configuration",
                    "test_kind": "invariant",
                    "memory_class": "medium",
                    "reason": "An explicit harness is required",
                }
            ]
            report["selection_summary"] = {
                "selected": 0,
                "unsupported": 0,
                "missing_configuration": 1,
                "profile_excluded": 0,
                "adapter_error": 0,
            }
            report_path.write_text(json.dumps(report), encoding="utf-8")
            output_path = root / "correlation.json"
            rendered = StringIO()
            with patch("lowkey.verification_cli._project_root", return_value=root):
                with redirect_stdout(rendered):
                    code = verification_cli.run_cli([
                        "correlate", str(report_path), "--output", str(output_path),
                    ])

            self.assertEqual(code, 2)
            self.assertIn("verification coverage gap", rendered.getvalue().lower())
            saved = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["coverage_status"], "no_engine_results")
            self.assertEqual(saved["engine_selection"][0]["status"], "missing_configuration")
            self.assertFalse(saved["summary"]["security_finding_confirmed"])


    def test_report_for_another_project_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            root_a = self._project(tmp_a)
            root_b = self._project(tmp_b)
            report_path = root_a / "campaign.json"
            self._campaign(root_a, report_path)
            with self.assertRaisesRegex(ValueError, "different project root"):
                verification_cli.correlate_campaign(report_path, project_root=root_b)

    def test_manifest_preserves_hash_and_explicit_investigation_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(tmp)
            manifest = root / "campaign.json"
            manifest.write_text(json.dumps({
                "test_kind": "unit",
                "profile": "light",
                "investigation": {
                    "signal_id": "SLITHER-EXPLICIT",
                    "property_id": "vault-withdrawal-access",
                    "source_file": "src/Vault.sol",
                    "function": "withdraw()",
                },
                "request": {
                    "argv_by_engine": {
                        "fake": ["-c", "print('campaign smoke')"],
                    },
                },
                "budget": {"timeout_seconds": 5},
            }), encoding="utf-8")

            from lowkey.verification_adapters import CapabilityRegistry, EngineCapability, ExecutableAdapter
            import sys
            from unittest.mock import patch

            adapter = ExecutableAdapter(EngineCapability(
                "fake", sys.executable, ("unit",), ("solidity",), ("foundry",),
                ("foundry.toml",), memory_class="low",
            ))
            with patch("lowkey.verification_cli.default_registry", return_value=CapabilityRegistry([adapter])):
                report = verification_cli.run_campaign_manifest(
                    manifest,
                    project_root=root,
                    output_path=root / ".audit" / "verification" / "campaign.json",
                )

            self.assertEqual(report["investigation"]["signal_ids"], ["SLITHER-EXPLICIT"])
            self.assertEqual(len(report["manifest_sha256"]), 64)
            self.assertEqual(report["summary"]["passed"], 1)


if __name__ == "__main__":
    unittest.main()
