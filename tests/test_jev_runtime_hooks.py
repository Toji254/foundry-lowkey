import contextlib
import io
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from lowkey import lk


class JevRuntimeHookTests(unittest.TestCase):
    def test_success_triggers_are_selective_and_failures_remain_diagnostic(self):
        self.assertTrue(lk._jev_command_eligible("build", [], 0))
        self.assertTrue(lk._jev_command_eligible("verification", ["run", "campaign.json"], 0))
        self.assertTrue(lk._jev_command_eligible("matrix", ["test"], 0))
        self.assertTrue(lk._jev_command_eligible("clone", ["https://example.invalid/project"], 0))
        self.assertFalse(lk._jev_command_eligible("read", ["balanceOf"], 0))
        self.assertFalse(lk._jev_command_eligible("verification", ["engines", "--json"], 0))
        self.assertFalse(lk._jev_command_eligible("matrix", ["list"], 0))
        self.assertFalse(lk._jev_command_eligible("ai", ["jev", "status"], 1))
        self.assertTrue(lk._jev_command_eligible("read", ["balanceOf"], 1))

    def test_jev_triage_receives_only_completed_command_evidence_and_never_executes_actions(self):
        captured = {}
        ai = SimpleNamespace(
            autonomy_budget_status=lambda: {"free_tier_guard": True, "remaining": 2},
        )
        jev = SimpleNamespace(
            status=lambda: {"configured": True},
            classify_command=lambda **kwargs: captured.update(kwargs) or {
                "outcome": "actionable_failure",
            },
            render_classification=lambda report, command: "JEV TEST TRIAGE: " + report["outcome"],
        )
        output = io.StringIO()
        with patch.object(lk, "_ai_status_safely", return_value={"jev_autonomous": True}), \
             patch.dict(sys.modules, {"ai_harness": ai, "jev_engine": jev}), \
             contextlib.redirect_stdout(output):
            lk._print_jev_command_classification(
                "build", ["--profile", "default"], 1, "Compiler failed: missing import"
            )
        self.assertEqual(captured["command"], "lk build")
        self.assertEqual(captured["arguments"], ["--profile", "default"])
        self.assertEqual(captured["exit_code"], 1)
        self.assertIn("missing import", captured["command_output"])
        self.assertIn("JEV TEST TRIAGE", output.getvalue())

    def test_runtime_delegates_provider_quota_and_cache_policy_to_jev_engine(self):
        captured = {}
        jev = SimpleNamespace(
            status=lambda: {
                "configured": True,
                "provider": "typesafe",
                "local": False,
            },
            classify_command=lambda **kwargs: captured.update(kwargs) or {
                "outcome": "cached_or_engine_classified",
            },
            render_classification=lambda report, command:
                "JEV TEST TRIAGE: " + report["outcome"],
        )
        output = io.StringIO()
        with patch.object(lk, "_ai_status_safely", return_value={"jev_autonomous": True}), \
             patch.dict(sys.modules, {"jev_engine": jev}), \
             contextlib.redirect_stdout(output):
            lk._print_jev_command_classification("build", [], 0, "Build succeeded")

        self.assertEqual(captured["command"], "lk build")
        self.assertIn("JEV TEST TRIAGE: cached_or_engine_classified", output.getvalue())

    def test_jev_eligibility_prevents_generic_auto_guidance_from_preempting_triage(self):
        self.assertTrue(lk._jev_should_classify("build", [], 0, True))
        self.assertTrue(lk._jev_should_classify("test", [], 0, True))
        self.assertFalse(lk._jev_should_classify("build", [], 0, False))
        self.assertFalse(lk._jev_should_classify("read", ["balanceOf"], 0, True))
        self.assertTrue(lk._jev_should_classify("read", ["balanceOf"], 1, True))

    def test_local_jevos_classifies_when_hosted_budget_is_exhausted(self):
        captured = {}
        ai = SimpleNamespace(
            autonomy_budget_status=lambda: self.fail(
                "local Jevos must not consult the hosted request allowance"
            ),
        )
        jev = SimpleNamespace(
            status=lambda: {
                "configured": True,
                "provider": "jevos",
                "local": True,
            },
            classify_command=lambda **kwargs: captured.update(kwargs) or {
                "outcome": "local_classification",
            },
            render_classification=lambda report, command:
                "JEV TEST TRIAGE: " + report["outcome"],
        )
        output = io.StringIO()
        with patch.object(lk, "_ai_status_safely", return_value={"jev_autonomous": True}), \
             patch.dict(sys.modules, {"ai_harness": ai, "jev_engine": jev}), \
             contextlib.redirect_stdout(output):
            lk._print_jev_command_classification("build", [], 0, "Build succeeded")

        self.assertEqual(captured["command"], "lk build")
        self.assertEqual(captured["exit_code"], 0)
        self.assertIn("JEV TEST TRIAGE: local_classification", output.getvalue())

    def test_automatic_text_guidance_budget_skip_is_not_counted_as_a_run(self):
        workflow = SimpleNamespace(
            guide_command=lambda **kwargs: self.fail(
                "the exhausted budget must prevent a text-AI request"
            ),
            render_guidance=lambda report: "unexpected guidance",
        )
        output = io.StringIO()
        with patch.object(
            lk, "_ai_status_safely",
            return_value={"jev_free_tier_mode": True, "jev_calls_remaining": 0},
        ), patch.dict(sys.modules, {"ai_workflow": workflow}), \
             contextlib.redirect_stdout(output):
            attempted = lk._print_ai_command_guidance(
                "build", [], 0, {}, "Build succeeded", automatic=True
            )

        self.assertFalse(attempted)
        self.assertEqual(output.getvalue(), "")

    def test_jev_engine_error_detail_is_reported_without_changing_native_result(self):
        jev = SimpleNamespace(
            JevError=RuntimeError,
            status=lambda: {"configured": True, "local": True},
            classify_command=lambda **kwargs: (_ for _ in ()).throw(
                RuntimeError("Could not reach local Jevos-v5 at 127.0.0.1:8017.")
            ),
        )
        stderr = io.StringIO()
        with patch.object(
            lk, "_ai_status_safely", return_value={"jev_autonomous": True}
        ), patch.dict(sys.modules, {"jev_engine": jev}), \
             contextlib.redirect_stderr(stderr):
            lk._print_jev_command_classification(
                "build", [], 0, "Compiler run successful"
            )

        self.assertIn("JEV TRIAGE UNAVAILABLE (RuntimeError)", stderr.getvalue())
        self.assertIn("Could not reach local Jevos-v5", stderr.getvalue())
        self.assertIn("native command kept its original result", stderr.getvalue())

    def test_disabled_jev_returns_without_importing_provider_modules(self):
        with patch.object(lk, "_ai_status_safely", return_value={"jev_autonomous": False}):
            lk._print_jev_command_classification("build", [], 0, "Build succeeded")


if __name__ == "__main__":
    unittest.main()
