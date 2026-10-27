import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import ai_workflow as workflow
from lowkey import evidence_ledger


class AIWorkflowTests(unittest.TestCase):
    def test_universal_flag_is_removed_for_native_commands_only(self):
        self.assertEqual(
            workflow.extract_universal_ai_flag(["status", "--ai"]),
            (True, ["status"]),
        )
        self.assertEqual(
            workflow.extract_universal_ai_flag(["read", "isAgreementValid", "--ai", "arg"]),
            (True, ["read", "isAgreementValid", "arg"]),
        )
        self.assertEqual(
            workflow.extract_universal_ai_flag(["ai", "run", "goal", "--ai"]),
            (False, ["ai", "run", "goal", "--ai"]),
        )
        self.assertEqual(
            workflow.extract_universal_ai_flag(["status"]),
            (False, ["status"]),
        )

    def test_auto_mode_guides_eligible_workflows_and_avoids_duplicate_error_help(self):
        active = {
            "enabled": True,
            "usable": True,
            "auto_assist": True,
            "auto_explain_errors": False,
        }
        self.assertTrue(workflow.should_auto_guide("test", [], 0, active))
        # Existing auto mode keeps its original scope; Jev opts into wider coverage.
        self.assertFalse(workflow.should_auto_guide("build", [], 0, active))
        self.assertFalse(workflow.should_auto_guide("doctor", [], 0, active))
        self.assertFalse(workflow.should_auto_guide("trace", [], 0, active))
        jev_active = {**active, "jev_autonomous": True}
        self.assertTrue(workflow.should_auto_guide("build", [], 0, jev_active))
        self.assertTrue(workflow.should_auto_guide("doctor", [], 0, jev_active))
        self.assertTrue(workflow.should_auto_guide("trace", [], 0, jev_active))
        self.assertFalse(workflow.should_auto_guide("read", ["balanceOf"], 0, active))
        self.assertTrue(workflow.should_auto_guide("read", ["balanceOf"], 1, active))
        self.assertTrue(workflow.should_auto_guide("audit", ["run"], 0, active))
        self.assertTrue(workflow.should_auto_guide("verification", ["run", "campaign.json"], 0, active))
        self.assertTrue(workflow.should_auto_guide("verification", ["investigate", "F-123"], 0, active))
        self.assertFalse(workflow.should_auto_guide("verification", ["engines", "--json"], 0, active))
        self.assertFalse(workflow.should_auto_guide("verification", ["correlate", "campaign.json"], 0, active))
        no_double_error = {**active, "auto_explain_errors": True}
        self.assertFalse(workflow.should_auto_guide("read", ["balanceOf"], 1, no_double_error))
        self.assertFalse(workflow.should_auto_guide("test", [], 0, {**active, "auto_assist": False}))
        self.assertFalse(workflow.should_auto_guide("test", [], 0, {**active, "usable": False}))

    def test_read_only_task_allowlist_rejects_state_changes_and_shell_syntax(self):
        for command in (
            "lk functions",
            "lk fn withdraw",
            "lk ask withdraw",
            "lk read isAgreementValid",
            "lk logs",
            "lk proxy",
            "lk recon",
            "lk questions",
        ):
            with self.subTest(command=command):
                self.assertEqual(workflow._safe_task_command(command), command)

        for command in (
            "lk status",
            "lk changes withdraw",
            "lk q",
            "lk findings",
            "lk send withdraw 1",
            "lk deploy Vault",
            "lk test",
            "lk build",
            "forge test",
            "lk status; forge test",
            "lk read isAgreementValid --rpc-url http://example.invalid",
            "lk target 0x1111111111111111111111111111111111111111",
            "lk read \"withdraw\"",
        ):
            with self.subTest(command=command):
                self.assertIsNone(workflow._safe_task_command(command))

    def test_plan_validation_filters_unsafe_and_ungrounded_steps(self):
        context = {
            "source_files": [{
                "path": "src/Vault.sol",
                "source_excerpt": "function withdraw() external { totalAssets -= amount; }",
            }]
        }
        result = {
            "summary": "Inspect the withdrawal path.",
            "steps": [
                {
                    "title": "Inspect withdrawal",
                    "why": "Confirm the function's interface and source before testing.",
                    "command": "lk fn withdraw",
                    "source": {"path": "src/Vault.sol", "symbol": "withdraw"},
                },
                {
                    "title": "Send a transaction",
                    "why": "Try withdrawing automatically.",
                    "command": "lk send withdraw 1",
                    "source": {"path": "src/Vault.sol", "symbol": "withdraw"},
                },
                {
                    "title": "Read unsupported source",
                    "why": "No corresponding source citation.",
                    "command": "lk read balanceOf",
                    "source": {"path": "src/Other.sol", "symbol": "balanceOf"},
                },
            ],
        }
        plan = workflow._validate_plan(result, context)
        self.assertEqual([step["command"] for step in plan["steps"]], ["lk fn withdraw"])
        self.assertEqual(plan["blocked_steps"], 2)
        self.assertEqual(plan["status"], "plan-only")

    def test_command_guidance_redacts_secrets_and_never_receives_rpc_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_context = {
                "project_label": root.name,
                "requested_contract": "Vault",
                "source_files": [{
                    "path": "src/Vault.sol",
                    "source_excerpt": "contract Vault { uint256 public totalAssets; }",
                }],
                "source_files_included": 1,
            }
            answer = {
                "summary": "\x1b[31mThe status command completed, but the selected target still needs review.\x1b[0m",
                "observations": ["The native command exited successfully."],
                "risks": ["Confirm that the selected network is the intended one."],
                "missing_information": ["No transaction trace was supplied."],
                "next_steps": ["Inspect the target with lk recon."],
                "suggested_command": "lk recon",
            }
            with patch.object(workflow.ai, "_source_context", return_value=source_context), \
                 patch.object(workflow.ai, "request_structured", return_value=answer) as request:
                report = workflow.guide_command(
                    root=root,
                    command="lk status",
                    arguments=["--private-key", "SENSITIVE-CLI-KEY"],
                    exit_code=0,
                    command_output=(
                        "private_key=SENSITIVE-OUTPUT-KEY "
                        "rpc_url=https://user:RPC-PASSWORD@rpc.example.invalid/?token=RPC-TOKEN"
                    ),
                    project_config={
                        "target": "0x" + "1" * 40,
                        "target_contract": "Vault",
                        "actor": "Alice",
                        "rpc": "https://user:RPC-PASSWORD@rpc.example.invalid/?token=RPC-TOKEN",
                    },
                )

            sent_context = request.call_args.kwargs["context"]
            serialized = repr(sent_context)
            for secret in (
                "SENSITIVE-CLI-KEY",
                "SENSITIVE-OUTPUT-KEY",
                "RPC-PASSWORD",
                "RPC-TOKEN",
                "rpc.example.invalid",
            ):
                with self.subTest(secret=secret):
                    self.assertNotIn(secret, serialized)
            self.assertEqual(sent_context["native_arguments"], ["--private-key", "[REDACTED]"])
            self.assertEqual(sent_context["project_state"]["network_kind"], "remote RPC (endpoint omitted)")
            self.assertNotIn("rpc", sent_context["project_state"])
            self.assertFalse(report["executed_by_ai"])
            self.assertEqual(report["status"], "unverified")
            rendered = workflow.render_guidance(report)
            self.assertIn("AI COMMAND GUIDANCE — UNVERIFIED", rendered)
            self.assertIn("SUGGESTED COMMAND (NOT RUN)", rendered)
            self.assertIn("lk recon", rendered)
            self.assertNotIn("\x1b", rendered)

    def test_prior_project_evidence_is_bounded_and_marked_historical(self):
        with tempfile.TemporaryDirectory() as temporary:
            findings = [
                {
                    "finding_id": f"F-{index:02d}",
                    "title": f"Finding {index} https://user:LEDGER-PASSWORD@rpc.example.invalid/?token=LEDGER-TOKEN",
                    "category": "access-control",
                    "severity": "medium",
                    "location": "src/Vault.sol:withdraw",
                    "status": "candidate",
                    "verified": False,
                    "test_runs": [{
                        "test_path": "test/Vault.t.sol",
                        "test_name": "testWithdraw",
                        "status": "passed",
                        "exit_code": 0,
                    }],
                    "disposition": {"disposition": "needs-review", "reason": "private reviewer note"},
                }
                for index in range(10)
            ]
            with patch.dict(sys.modules, {"evidence_ledger": evidence_ledger}), patch.object(
                evidence_ledger,
                "summary",
                return_value={"event_count": 10, "findings": findings},
            ), patch.object(
                evidence_ledger,
                "historical_feedback_context",
                return_value=[{
                    "kind": "lesson",
                    "summary": "Recheck withdrawal accounting against current source.",
                    "evidence_note": "Historical evidence only.",
                    "finding_id": "F-01",
                    "created_at": "2026-10-01T00:00:00Z",
                }],
            ):
                context = workflow._prior_evidence_context(Path(temporary))

        self.assertEqual(context["event_count"], 10)
        self.assertEqual(len(context["candidate_findings"]), 8)
        self.assertEqual(len(context["candidate_findings"][0]["recent_test_runs"]), 1)
        self.assertEqual(context["candidate_findings"][0]["human_disposition"], "needs-review")
        self.assertIn("historical", context["trust_boundary"].lower())
        rendered = repr(context)
        self.assertNotIn("LEDGER-PASSWORD", rendered)
        self.assertNotIn("LEDGER-TOKEN", rendered)
        self.assertNotIn("private reviewer note", rendered)
        self.assertIn("historical feedback only", rendered)

    def test_run_plan_only_never_executes_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            plan = {
                "summary": "Inspect the target with read-only commands.",
                "steps": [{
                    "title": "Inspect status",
                    "why": "Establish current selection.",
                    "command": "lk status",
                    "source": "src/Vault.sol",
                    "symbol": "totalAssets",
                }],
                "blocked_steps": 0,
            }
            output = io.StringIO()
            with patch.object(workflow, "_make_plan", return_value=plan), \
                 patch.object(workflow.subprocess, "run") as run_command, \
                 contextlib.redirect_stdout(output):
                result = workflow.run_task(Path(temporary), "investigate target", plan_only=True)
            self.assertEqual(result, 0)
            run_command.assert_not_called()
            self.assertIn("Plan only: no commands were run.", output.getvalue())


if __name__ == "__main__":
    unittest.main()
