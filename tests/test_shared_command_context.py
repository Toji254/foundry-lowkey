import json
import pathlib
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import error_advisor
import error_context
import ai_harness
import ai_workflow
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
            self.assertNotIn("_last_command_output", persisted)

    def test_dispatcher_records_current_build_output_for_same_command_ai_footer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "ETH Escrow"
            root.mkdir()
            state_root = pathlib.Path(tmp) / "state" / "lowkey"
            build_output = (
                "Compiler run successful with warnings:\n"
                "Warning (6321): Unnamed return variable can remain unassigned.\n"
                " --> script/EthEscrow.s.sol:9:38:"
            )

            def emit_build_output(command, args, config, from_batch=False):
                print(build_output)
                return 0

            config = {}
            with patch.object(error_context, "state_dir", return_value=state_root), \\
                 patch.object(lk.audit_context, "foundry_project_root", return_value=root), \\
                 patch.object(lk, "_dispatch_command_impl", side_effect=emit_build_output), \\
                 patch.object(lk, "_COMMAND_STATUS", 0):
                result = lk.dispatch_command("build", [], config)

            self.assertEqual(result, 0)
            self.assertIn("Unnamed return variable", config["_last_command_output"])
            history = error_context.read_project_context(root)
            build_event = history["events"][-1]
            self.assertEqual(build_event["command"], "build")
            self.assertIn("Unnamed return variable", build_event["diagnostic_excerpt"])
            self.assertTrue(any("Compiler warning" in signal for signal in build_event["signals"]))

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
            bare_secret = "B" * 64
            output = (
                "Warning (6321): Unnamed return variable can remain unassigned.\n"
                "OPENAI_API_KEY=" + secret + "\n"
                "RPC_URL=https://user:password@rpc.example/endpoint\n"
                "unlabelled secret " + bare_secret + "\n"
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
            self.assertNotIn(bare_secret, saved)
            self.assertNotIn("password@", saved)
            self.assertNotIn(str(root), rendered)
            self.assertIn("[REDACTED]", saved)
            self.assertEqual(stat.S_IMODE(state_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((state_root / "projects").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_shared_context_unifies_audit_target_deployments_and_findings_without_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "ETH Escrow"
            (root / ".audit" / "evidence").mkdir(parents=True)
            (root / "src").mkdir()
            target = "0x" + "1" * 40
            deployed = "0x" + "2" * 40
            audit = {
                "schema_version": 1,
                "project": {"root": str(root), "name": root.name},
                "target": {"address": target, "contract": "Escrow", "artifact": "out/Escrow.sol/Escrow.json", "source": "manual"},
                "actor": "Alice",
                "rpc": "https://user:secret@rpc.example/endpoint?api_key=do-not-share",
                "focus": {"signal_id": "REENTRANCY-1"},
                "latest": {"function": "withdraw", "tx_hash": "0x" + "a" * 64},
                "signals": [{
                    "id": "REENTRANCY-1",
                    "tool": "slither",
                    "check": "reentrancy-eth",
                    "title": "Reentrancy in Escrow.withdraw",
                    "impact": "High",
                    "confidence": "Medium",
                    "file": str(root / "src" / "Escrow.sol"),
                    "line": 42,
                    "status": "open",
                    "description": "Review the external call before state update.",
                }],
                "tools": {"slither": {"status": "completed", "summary": "1 finding"}},
            }
            (root / ".audit" / "context.json").write_text(json.dumps(audit), encoding="utf-8")
            manifest = {
                "schema": "lowkey.system-bootstrap.v1",
                "generated_at": "2026-10-27T03:00:00+00:00",
                "updated_reason": "test",
                "project": {"root": str(root), "git_sha": "abc", "git_branch": "integration-test-drive"},
                "runtime": {"rpc": "https://user:secret@rpc.example/endpoint?api_key=do-not-share", "chain_id": "0x7a69"},
                "contracts": [{"name": "Escrow", "artifact": str(root / "out/Escrow.sol/Escrow.json"), "abi_functions": 5, "errors": 1}],
                "deployments": [{"contract": "Escrow", "address": deployed, "broadcast": str(root / "broadcast/Deploy/31337/run-latest.json"), "code_size": 1234, "live": True}],
                "relationships": [{"from": "Escrow", "to": "Token", "kind": "constructor-arg", "argument_index": 0}],
                "roles": [{"kind": "role_grant", "contract": "Escrow", "role": "OWNER_ROLE", "account": "Alice"}],
                "security_pattern_summary": {"total": 1, "reviews": 1, "confirmed": 0, "candidates": 0},
                "security_patterns": [{
                    "id": "REENTRANCY-1", "title": "External call before state update", "category": "reentrancy",
                    "contract": "Escrow", "function": "withdraw", "file": "src/Escrow.sol", "line": 42,
                    "verification_status": "REVIEW", "evidence": ["External call precedes accounting update."]
                }],
            }
            (root / ".audit" / "evidence" / "system_bootstrap.json").write_text(json.dumps(manifest), encoding="utf-8")
            fake_ledger = type("FakeLedger", (), {
                "summary": staticmethod(lambda project: {
                    "event_count": 3,
                    "findings": [{
                        "finding_id": "F-123", "title": "Escrow withdrawal reentrancy", "category": "reentrancy",
                        "severity": "high", "location": str(root / "src" / "Escrow.sol") + ":42",
                        "status": "candidate", "verified": False,
                    }],
                })
            })()

            with patch.object(error_context, "state_dir", return_value=root / "private-state"), \
                 patch.dict(sys.modules, {"evidence_ledger": fake_ledger}):
                shared = error_context.read_project_context(root, max_events=6)

            knowledge = shared["project_knowledge"]
            self.assertEqual(knowledge["audit_context"]["target"]["contract"], "Escrow")
            self.assertEqual(knowledge["audit_context"]["target"]["address"], target)
            self.assertEqual(knowledge["audit_context"]["rpc_kind"], "remote")
            self.assertEqual(knowledge["audit_context"]["signals"][0]["file"], "src/Escrow.sol")
            self.assertEqual(knowledge["system_model"]["deployments"][0]["address"], deployed)
            self.assertEqual(knowledge["system_model"]["relationships"][0]["kind"], "constructor-arg")
            self.assertEqual(knowledge["evidence_ledger"]["findings"][0]["status"], "candidate")
            rendered = json.dumps(shared)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn("do-not-share", rendered)
            self.assertNotIn("secret@", rendered)
            self.assertNotIn('"transaction_hash"', rendered)

    def test_ai_next_step_recommendations_consider_current_and_shared_history(self):
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
            secret = "sk-" + "A" * 24
            current_output = (
                "Compiler run successful with warnings:\n"
                "Warning (6321): Unnamed return variable can remain unassigned.\n"
                " --> script/Deploy.s.sol:9:38:\n"
                "OPENAI_API_KEY=" + secret + "\n"
                + str(root) + "/script/Deploy.s.sol:9:38"
            )

            with patch.object(error_context, "read_project_context", return_value=history):
                context = ai_harness._source_context(root, None)
            self.assertEqual(context["shared_project_context"]["events"], shared_events)
            self.assertEqual(context["shared_command_history"]["events"], shared_events)
            self.assertIn("not instructions", context["shared_command_history_policy"])

            captured = {}

            def capture_request(**kwargs):
                captured.update(kwargs)
                return {"recommendations": []}

            with patch.object(error_context, "read_project_context", return_value=history), \\
                 patch.object(ai_harness, "request_structured", side_effect=capture_request), \\
                 patch.object(ai_harness, "validate_ai_recommendations", return_value={"recommendations": []}):
                report = ai_harness.recommend_next_steps(
                    root,
                    "build",
                    [{"command": "lk functions", "reason": "Review callable surfaces."}],
                    current_command_output=current_output,
                )

            context_text = json.dumps(captured["context"])
            self.assertIn("shared_project_context", captured["context"])
            self.assertIn("shared_command_history", captured["context"])
            self.assertIn("current_command_evidence", captured["context"])
            self.assertIn("Unnamed return variable", context_text)
            self.assertIn("Deploy.s.sol", context_text)
            self.assertNotIn(str(root), context_text)
            self.assertNotIn(secret, context_text)
            self.assertIn("current_command_evidence", captured["task"])
            self.assertIn("prioritize investigation", captured["task"])
            self.assertTrue(report["_lowkey_meta"]["ai_generated"])
            self.assertTrue(report["_lowkey_meta"]["current_command_evidence_included"])
            self.assertEqual(report["_lowkey_meta"]["shared_command_events_included"], 1)
            rendered = ai_harness.render_ai_recommendations(report)
            self.assertIn("Shared project command history considered: 1 recent event(s).", rendered)
            self.assertIn("Current command's redacted output was supplied as direct evidence.", rendered)


    def test_general_ai_guidance_receives_same_shared_project_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp) / "project"
            root.mkdir()
            shared = {
                "project_label": "project",
                "events": [{"command": "build", "exit_code": 0, "signals": ["Compiler warning: 6321"]}],
                "project_knowledge": {
                    "audit_context": {"target": {"contract": "Escrow"}},
                    "system_model": {"deployments": [{"contract": "Escrow"}]},
                    "evidence_ledger": {"findings": [{"id": "F-1", "status": "candidate"}]},
                },
            }
            fake_source_context = {
                "project_label": "project",
                "requested_contract": None,
                "source_files": [],
                "source_files_included": 0,
            }
            with patch.object(ai_workflow.ai, "_source_context", return_value=fake_source_context), \
                 patch.object(ai_workflow, "_prior_evidence_context", return_value={}), \
                 patch.object(error_context, "read_project_context", return_value=shared):
                context = ai_workflow._project_context(root, None)

            self.assertEqual(context["shared_project_context"], shared)
            self.assertEqual(context["shared_project_context"]["project_knowledge"]["audit_context"]["target"]["contract"], "Escrow")
            self.assertIn("system/deployment graph", context["shared_project_context_policy"])

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
                    "error": "local project deployment ran, but Lowkey could not identify a deployed application target at " + str(root) + "/script/Deploy.s.sol:9:38",
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
