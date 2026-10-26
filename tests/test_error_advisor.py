import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import error_advisor, error_context


class ErrorAdvisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(Path(self.tmp.name) / "config"),
            "XDG_STATE_HOME": str(Path(self.tmp.name) / "state"),
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_last_error_is_private_redacted_and_truncated(self):
        secret = "AIza" + "A" * 30
        record = error_context.record_last_error(
            command="lk test", error=f"Request failed key={secret}\nConnection timed out",
            exit_code=1, project_root=self.tmp.name,
        )
        self.assertNotIn(secret, error_context.last_error_path().read_text())
        self.assertEqual(error_context.last_error_path().stat().st_mode & 0o777, 0o600)
        self.assertIn("[REDACTED", record["error"])
        self.assertEqual(error_context.read_last_error()["command"], "lk test")

    def test_deterministic_hints_are_concrete_and_read_only_first(self):
        hints = error_advisor.deterministic_hints("failed to retrieve chain ID: connection timed out", "lk test")
        self.assertTrue(any("read-only request" in item["why"] for item in hints))
        self.assertTrue(any("chainId" in item["command"] for item in hints))

    def test_diagnosis_requires_structured_actionable_schema(self):
        record = {"error": "RPC connection timed out", "command": "lk test", "exit_code": 1}
        good = {
            "summary": "The RPC endpoint did not answer.",
            "likely_cause": "The configured RPC endpoint is unreachable from this host.",
            "confidence": "high",
            "checks": [{"what": "Check reachability", "command": "lk rpc", "why": "Confirm the configured endpoint."}],
            "fixes": [{"title": "Use a reachable endpoint", "commands": ["lk rpc"], "why": "Check current RPC first.", "verify": "Retry a read-only chain ID request.", "risk": "read-only"}],
            "caveats": [],
        }
        with patch.object(error_advisor.ai_harness, "request_structured", return_value=good):
            result = error_advisor.diagnose_record(record)
        self.assertEqual(result["fixes"][0]["risk"], "read-only")
        self.assertEqual(result["execution_policy"], "No suggested command was executed.")

    def test_malformed_diagnosis_is_rejected(self):
        with patch.object(error_advisor.ai_harness, "request_structured", return_value={"summary": "x"}):
            with self.assertRaises(error_advisor.ErrorAdvisorError):
                error_advisor.diagnose_record({"error": "something failed"})

    def test_model_cannot_label_destructive_command_read_only(self):
        result = {
            "summary": "A suggested command was supplied.",
            "likely_cause": "Unknown.",
            "confidence": "low",
            "checks": [],
            "fixes": [{
                "title": "Cleanup",
                "commands": ["git reset --hard"],
                "why": "A destructive command should be reviewed.",
                "verify": "",
                "risk": "read-only",
            }],
            "caveats": [],
        }
        validated = error_advisor._validate(result)
        self.assertEqual(validated["fixes"][0]["risk"], "review")

    def test_full_project_path_is_not_sent_to_provider(self):
        project_path = "/home/private-user/secret-project"
        observed = {}
        response = {
            "summary": "An RPC request timed out.",
            "likely_cause": "The endpoint is not reachable.",
            "confidence": "medium",
            "checks": [],
            "fixes": [],
            "caveats": [],
        }
        def capture_request(**kwargs):
            observed.update(kwargs)
            return response
        with patch.object(error_advisor.ai_harness, "request_structured", side_effect=capture_request):
            error_advisor.diagnose_record({
                "error": "connection timed out", "command": "test",
                "project_label": "project", "project_root": project_path,
            })
        self.assertNotIn(project_path, json.dumps(observed))

    def test_last_error_missing_is_actionable(self):
        with self.assertRaisesRegex(RuntimeError, "No saved Lowkey error"):
            error_context.read_last_error()


if __name__ == "__main__":
    unittest.main()
