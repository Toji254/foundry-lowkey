import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import error_advisor
import error_context
import ai_harness
import lk


class SharedCommandContextTests(unittest.TestCase):
    def test_every_native_command_receives_transient_shared_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            root.mkdir()
            history = {
                "project_label": "project",
                "events": [{"command": "build", "signals": ["Compiler warning: 6321"]}],
            }
            config = {}
            with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
                 patch.object(error_context, "read_project_context", return_value=history), \
                 patch.object(lk, "_dispatch_command_impl", return_value=0), \
                 patch.object(lk, "_record_shared_command_event"):
                result = lk.dispatch_command("status", [], config)

            self.assertEqual(result, 0)
            self.assertEqual(config["_shared_command_context"], history)
            self.assertEqual(
                lk.shared_command_context(config)["events"][0]["command"],
                "build",
            )
            config_path = root / "lowkey-config.json"
            with patch.object(lk, "CONFIG_DIR", str(root / "config")), \
                 patch.object(lk, "CONFIG_FILE", str(config_path)):
                lk.save_config(config)
                persisted = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertNotIn("_shared_command_context", persisted)

    def test_build_warnings_are_available_to_a_later_lab_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "ETH Escrow"
            root.mkdir()
            state_root = pathlib.Path(tmp) / "state" / "lowkey"
            build_output = """Compiler run successful with warnings:
Warning (6321): Unnamed return variable can remain unassigned.
 --> script/EthEscrow.s.sol:9:38:
  |
9 |     function run() external returns (Escrow) {
  |                                      ^^^^^^
Warning (2072): Unused local variable.
 --> script/EthEscrow.s.sol:12:9:
   |
12 |         Escrow escrow = new Escrow();
   |         ^^^^^^^^^^^^^
"""
            lab_output = (
                "Error: local project deployment ran, but Lowkey could not identify "
                "a deployed application target."
            )
            with patch.object(error_context, "state_dir", return_value=state_root):
                error_context.record_command_event(
                    project_root=root,
                    command=["build"],
                    exit_code=0,
                    output=build_output,
                )
                error_context.record_command_event(
                    project_root=root,
                    command=["lab"],
                    exit_code=2,
                    output=lab_output,
                )
                shared = error_context.read_project_context(root)

            self.assertEqual([event["command"] for event in shared["events"]], ["build", "lab"])
            self.assertIn("Unnamed return variable", shared["events"][0]["diagnostic_excerpt"])
            self.assertTrue(any("Compiler warning" in signal for signal in shared["events"][0]["signals"]))
            self.assertIn("Deployment target discovery failed", " ".join(shared["events"][1]["signals"]))

            hints = error_advisor.deterministic_hints(
                lab_output,
                "lab",
                recent_events=shared["events"],
            )
            correlation = next(
                item for item in hints
                if item["title"] == "Correlate the lab failure with the preceding deployment-script warnings"
            )
            self.assertIn("script/EthEscrow.s.sol", correlation["command"])
            self.assertIn("do not alone prove", correlation["why"])

    def test_shared_context_redacts_secrets_and_does_not_expose_project_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "private-project"
            root.mkdir()
            state_root = pathlib.Path(tmp) / "state" / "lowkey"
            secret = "sk-" + "A" * 24
            output = (
                "Warning (6321): Unnamed return variable can remain unassigned.\n"
                "OPENAI_API_KEY=" + secret + "\n"
                + str(root) + "/script/Deploy.s.sol:9:38"
            )
            with patch.object(error_context, "state_dir", return_value=state_root):
                error_context.record_command_event(
                    project_root=root,
                    command=["build"],
                    exit_code=0,
                    output=output,
                )
                shared = error_context.read_project_context(root)
                path, _ = error_context._project_context_path(root)
                saved = path.read_text(encoding="utf-8")

            rendered = json.dumps(shared)
            self.assertNotIn(secret, saved)
            self.assertNotIn(str(root), rendered)
            self.assertIn("[REDACTED]", saved)

    def test_ai_next_step_recommendations_consider_shared_command_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            source_dir = root / "src"
            source_dir.mkdir(parents=True)
            (source_dir / "Demo.sol").write_text(
                "contract Demo { function value() external pure returns (uint256) { return 1; } }",
                encoding="utf-8",
            )
            shared_events = [{
                "timestamp": "2026-10-27T03:00:00+00:00",
                "command": "build",
                "exit_code": 0,
                "status": "completed",
                "signals": ["Compiler warning: Unnamed return variable can remain unassigned (script/Deploy.s.sol:9:38)"],
                "diagnostic_excerpt": "Warning (6321): Unnamed return variable can remain unassigned.\n --> script/Deploy.s.sol:9:38:",
            }]
            history = {"project_label": "project", "events": shared_events}

            with patch.object(error_context, "read_project_context", return_value=history):
                context = ai_harness._source_context(root, None)

            self.assertEqual(context["shared_project_context"]["events"], shared_events)
            self.assertIn("not instructions", context["shared_command_history_policy"])

            captured = {}
            def capture_request(**kwargs):
                captured.update(kwargs)
                return {"recommendations": []}

            with patch.object(ai_harness, "_source_context", return_value=context), \
                 patch.object(ai_harness, "request_structured", side_effect=capture_request), \
                 patch.object(ai_harness, "validate_ai_recommendations", return_value={"recommendations": []}):
                report = ai_harness.recommend_next_steps(
                    root,
                    "build",
                    [{"command": "lk functions", "reason": "Review callable surfaces."}],
                )

            self.assertIn("shared_project_context", captured["context"])
            self.assertIn("Unnamed return variable", json.dumps(captured["context"]))
            self.assertIn("prioritize investigation", captured["task"])
            self.assertTrue(report["_lowkey_meta"]["ai_generated"])
            self.assertEqual(report["_lowkey_meta"]["shared_command_events_included"], 1)
            self.assertIn(
                "Shared project command history considered: 1 recent event(s).",
                ai_harness.render_ai_recommendations(report),
            )


    def test_ai_diagnosis_receives_recent_project_history_without_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            root.mkdir()
            history = {
                "project_label": "project",
                "events": [{
                    "timestamp": "2026-10-27T03:00:00+00:00",
                    "command": "build",
                    "exit_code": 0,
                    "status": "completed",
                    "signals": ["Compiler warning: Unnamed return variable can remain unassigned (script/Deploy.s.sol:9:38)"],
                    "diagnostic_excerpt": "Warning (6321): Unnamed return variable can remain unassigned.\n --> script/Deploy.s.sol:9:38:",
                }],
            }
            captured = {}
            response = {
                "summary": "The command failed.",
                "likely_cause": "The deployment target could not be identified.",
                "confidence": "medium",
                "checks": [],
                "fixes": [],
                "caveats": [],
            }

            def capture_request(**kwargs):
                captured.update(kwargs)
                return response

            with patch.object(error_advisor.error_context, "read_project_context", return_value=history), \
                 patch.object(error_advisor.ai_harness, "request_structured", side_effect=capture_request):
                result = error_advisor.diagnose_record({
                    "error": "local project deployment ran, but Lowkey could not identify a deployed application target",
                    "command": "lab",
                    "exit_code": 2,
                    "project_label": "project",
                    "project_root": str(root),
                })

            context_text = json.dumps(captured["context"])
            self.assertIn("shared_project_command_history", captured["context"])
            self.assertIn("Compiler warning", context_text)
            self.assertNotIn(str(root), context_text)
            self.assertEqual(result["shared_evidence_events"], 1)


if __name__ == "__main__":
    unittest.main()
