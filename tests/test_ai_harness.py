import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import ai_harness as ai
from lowkey import experience_memory as memory


class AIHarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(Path(self.tmp.name) / "config"),
            "XDG_DATA_HOME": str(Path(self.tmp.name) / "data"),
            "XDG_STATE_HOME": str(Path(self.tmp.name) / "state"),
        })
        env.start()
        self.addCleanup(env.stop)

    def test_top_level_help_is_compact_and_lists_commands_variations_and_flags(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["--help"]), 0)
        help_text = output.getvalue()
        self.assertTrue(help_text.startswith("LOWKEY HELP  •  lk ai"))
        self.assertIn("What it does:", help_text)
        self.assertIn("When to use:", help_text)
        self.assertIn("lk ai security-review", help_text)
        self.assertNotIn("usage: lk ai", help_text)
        for command in (
            "status", "preview", "mode", "setup", "enable", "disable", "test",
            "keys", "list", "add", "remove", "clear", "explain-error",
            "errors", "project", "test-plan", "security-review", "ledger", "verify",
            "disposition", "runtime", "recommendations",
        ):
            with self.subTest(command=command):
                self.assertIn(command, help_text)
        for flag in (
            "--json", "--root", "--contract", "--show-context", "--provider",
            "--model", "--base-url", "--api-key-env", "--timeout",
            "--max-output-tokens", "--slot", "--last", "--text", "--command",
            "--test", "--match-test", "--run", "--status", "--reviewer",
            "--reason", "--evidence-id",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, help_text)
        self.assertIn("COMMAND FORMS & OPTIONS", help_text)
        self.assertIn("lk ai keys add --help", help_text)
        self.assertIn("lk ai recommendations auto", help_text)
        self.assertIn("--h, --help, -h, and help", help_text)
        self.assertLess(len(help_text), 8500)
        self.assertNotIn("COMPLETE COMMAND REFERENCE", help_text)
        self.assertNotIn("Key failover:", help_text)

    def test_help_alias_and_command_specific_help_include_examples(self):
        for alias in (["help"], ["--h"], ["-h"]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(ai.main(alias), 0)
            self.assertIn("COMMAND FORMS & OPTIONS", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as help_exit:
                ai.main(["setup", "--help"])
        self.assertEqual(help_exit.exception.code, 0)
        self.assertIn("--api-key-env", output.getvalue())
        self.assertIn("WHEN:", output.getvalue())
        self.assertIn("lk ai setup --provider gemini", output.getvalue())

    def test_ai_help_is_grouped_and_explains_independent_auto_settings(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["--help"]), 0)
        help_text = output.getvalue()
        for expected in (
            "SETUP & CONNECTION",
            "KEY MANAGEMENT",
            "REVIEW & EVIDENCE",
            "AUTOMATION SETTINGS",
            "WHAT DOES \"AUTO\" MEAN?",
            "lk ai mode auto",
            "lk ai recommendations auto",
            "lk ai errors auto",
            "auto is a value after a setting command",
            "AI INSIDE EXISTING LK WORKFLOWS",
            "lk lab Vault --ai-review",
            "Use --json only on commands that list it",
        ):
            self.assertIn(expected, help_text)

    def test_top_level_help_makes_lab_ai_review_flag_discoverable(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["--h"]), 0)
        rendered = output.getvalue()
        self.assertIn("AI INSIDE EXISTING LK WORKFLOWS", rendered)
        self.assertIn("lk lab Vault --ai-review", rendered)
        self.assertIn("lk ai mode manual", rendered)
        self.assertIn("lk ai mode auto", rendered)
        self.assertIn("It does not choose", rendered)

    def test_auto_is_not_a_top_level_command_and_help_alias_does_not_hide_the_error(self):
        for args in (["auto", "--h"], ["auto", "--help"]):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                self.assertEqual(ai.main(args), 2)
            message = output.getvalue()
            self.assertIn("not a standalone 'lk ai' command", message)
            self.assertIn("lk ai recommendations auto", message)
            self.assertNotIn("invalid choice", message)
            self.assertNotIn("usage: lk ai", message)

    def test_unknown_root_option_gets_lowkey_style_guidance(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(ai.main(["--auto", "--help"]), 2)
        message = output.getvalue()
        self.assertIn("unknown 'lk ai' option '--auto'", message)
        self.assertIn("lk ai --help", message)
        self.assertNotIn("usage: lk ai", message)

    def test_bare_setting_groups_show_current_value_and_exact_commands(self):
        expectations = {
            "mode": ("lk ai mode manual", "lk ai mode auto"),
            "recommendations": ("lk ai recommendations status", "lk ai recommendations auto"),
            "errors": ("lk ai errors status", "lk ai errors auto"),
        }
        for action, expected_commands in expectations.items():
            output = io.StringIO()
            with self.subTest(action=action), contextlib.redirect_stdout(output):
                self.assertEqual(ai.main([action]), 0)
            rendered = output.getvalue()
            expected_heading = {
                "mode": "LOWKEY AI PROTOCOL REVIEW MODE",
                "recommendations": "LOWKEY AI NEXT-COMMAND RECOMMENDATIONS",
                "errors": "LOWKEY AI AUTOMATIC ERROR EXPLANATIONS",
            }[action]
            self.assertIn(expected_heading, rendered)
            self.assertNotIn("LOWKEY AI AI", rendered)
            self.assertIn("Current setting: MANUAL / OFF", rendered)
            for command in expected_commands:
                self.assertIn(command, rendered)
            self.assertNotIn("usage: lk ai", rendered)

    def test_malformed_nested_command_reports_human_readable_help_hint(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(ai.main(["errors", "sometimes"]), 2)
        rendered = output.getvalue()
        self.assertIn("Error:", rendered)
        self.assertIn("lk ai errors --help", rendered)
        self.assertNotIn("usage: lk ai", rendered)

    def test_command_help_exposes_each_command_flag_and_nested_variation(self):
        cases = [
            (["status", "--help"], ["--json"]),
            (["preview", "--help"], ["--root", "--contract", "--show-context", "--json-context"]),
            (["setup", "--help"], ["--provider", "--model", "--base-url", "--api-key-env", "--timeout", "--max-output-tokens"]),
            (["recommendations", "--help"], ["status", "auto", "manual", "--json"]),
            (["keys", "--help"], ["list", "add", "remove", "clear"]),
            (["keys", "list", "--help"], ["--provider", "--json"]),
            (["keys", "add", "--help"], ["--provider", "--slot"]),
            (["keys", "remove", "--help"], ["--provider", "--slot"]),
            (["keys", "clear", "--help"], ["--provider"]),
            (["explain-error", "--help"], ["--last", "--text", "--command"]),
            (["errors", "--help"], ["auto", "manual", "status", "--json"]),
            (["project", "--help"], ["--root", "--contract", "--json", "does not start a local lab"]),
            (["test-plan", "--help"], ["--root", "--contract", "--json"]),
            (["security-review", "--help"], ["--root", "--contract", "--json"]),
            (["ledger", "--help"], ["--root", "--json"]),
            (["verify", "--help"], ["--root", "--test", "--match-test", "--run", "--json"]),
            (["disposition", "--help"], ["--root", "--status", "--reviewer", "--reason", "--evidence-id", "--json"]),
            (["runtime", "--help"], ["--json"]),
        ]
        for args, expected in cases:
            output = io.StringIO()
            with self.subTest(args=args):
                with contextlib.redirect_stdout(output):
                    with self.assertRaises(SystemExit) as help_exit:
                        ai.main(args)
                self.assertEqual(help_exit.exception.code, 0)
                rendered = output.getvalue()
                normalized = " ".join(rendered.split())
                for flag in expected:
                    with self.subTest(expected=flag):
                        self.assertIn(" ".join(flag.split()), normalized)

    def test_project_help_uses_stable_lowkey_renderer_and_spaced_options(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as help_exit:
                ai.main(["project", "--help"])
        self.assertEqual(help_exit.exception.code, 0)
        rendered = output.getvalue()
        normalized = " ".join(rendered.split())
        self.assertTrue(rendered.startswith("LOWKEY HELP  •  lk ai project"))
        self.assertIn("--root ROOT", rendered)
        self.assertIn("--contract CONTRACT", rendered)
        self.assertIn("--json", rendered)
        self.assertIn("does not start a local lab", normalized)
        self.assertNotIn("usage: lk ai project", rendered.lower())

    def test_project_review_is_standalone_and_does_not_start_lab(self):
        project_root = self.tmp.name
        review = {
            "summary": "Factory creates deterministic pools and relies on agreement ownership.",
            "contract_roles": [{
                "name": "ConfidencePoolFactory",
                "purpose": "Creates confidence-pool instances.",
                "evidence": "src/ConfidencePoolFactory.sol:createPool",
            }],
            "invariants": [{
                "statement": "Only an authorized agreement owner can create a pool.",
                "rationale": "Pool creation is restricted to an agreement owner.",
                "source": "src/ConfidencePoolFactory.sol:createPool",
            }],
            "open_questions": ["Does the registry reject invalid agreements consistently?"],
            "deployment_considerations": ["Confirm the registry address for each network."],
            "ai_generated": True,
            "origin": "configured-model",
            "_lowkey_meta": {"source_files_included": 3, "context_sha256": "abc123"},
        }
        output = io.StringIO()
        with patch.object(ai, "review_project_protocol", return_value=review) as request:
            with contextlib.redirect_stdout(output):
                self.assertEqual(ai.main(["project", "--root", project_root, "--contract", "Vault"]), 0)
        request.assert_called_once_with(Path(project_root), "Vault")
        rendered = output.getvalue()
        self.assertIn("PROJECT PROTOCOL REVIEW (UNVERIFIED)", rendered)
        self.assertIn("Factory creates deterministic pools", rendered)
        self.assertIn("Candidate invariants:", rendered)
        self.assertIn("No local lab was started", rendered)

    def test_project_review_escapes_terminal_control_characters(self):
        rendered = ai.render_project_protocol_review({
            "summary": "before\x1b[31mred\x1b[0m",
            "contract_roles": [],
            "invariants": [],
            "open_questions": [],
            "deployment_considerations": [],
            "_lowkey_meta": {"source_files_included": 1},
        })
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"\x1b[31m", rendered)

    def test_project_review_supports_json_output(self):
        review = {
            "summary": "Project summary",
            "contract_roles": [],
            "invariants": [],
            "open_questions": [],
            "deployment_considerations": [],
            "_lowkey_meta": {"source_files_included": 1},
        }
        output = io.StringIO()
        with patch.object(ai, "review_project_protocol", return_value=review) as request:
            with contextlib.redirect_stdout(output):
                self.assertEqual(ai.main(["project", "--root", self.tmp.name, "--json"]), 0)
        request.assert_called_once()
        self.assertEqual(json.loads(output.getvalue())["summary"], "Project summary")

    def test_ai_recommendations_are_off_by_default_and_setting_is_independent(self):
        value = ai.status()
        self.assertFalse(value["auto_recommendations"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["recommendations", "auto"]), 0)
        self.assertTrue(ai.load_config()["auto_recommendations"])
        self.assertIn("native next-command list stays separate", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["recommendations", "manual"]), 0)
        self.assertIn("native next-command suggestions.", output.getvalue())
        self.assertIn("No automatic AI recommendation requests will be made.", output.getvalue())
        self.assertFalse(ai.load_config()["auto_recommendations"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["recommendations", "status", "--json"]), 0)
        self.assertIn('"automatic_ai_recommendations": false', output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["recommendations", "status"]), 0)
        self.assertIn("MANUAL / OFF", output.getvalue())

    def test_ai_recommendations_keep_only_source_grounded_read_only_commands(self):
        context = {
            "source_files": [{
                "path": "src/Vault.sol",
                "source_excerpt": "contract Vault { function withdraw(uint256 amount) external {} function owner() external view returns(address) {} }",
            }]
        }
        raw = {
            "recommendations": [
                {
                    "title": "Check the owner gate",
                    "why": "The withdrawal path should be compared with the owner authorization rule.",
                    "command": "lk read owner",
                    "source": {"path": "src/Vault.sol", "symbol": "withdraw"},
                },
                {
                    "title": "Submit a transaction",
                    "why": "Try sending a transaction.",
                    "command": "lk send withdraw 1",
                    "source": {"path": "src/Vault.sol", "symbol": "withdraw"},
                },
                {
                    "title": "Run a shell chain",
                    "why": "This is unsafe.",
                    "command": "lk read owner; rm -rf .",
                    "source": {"path": "src/Vault.sol", "symbol": "owner"},
                },
                {
                    "title": "Unknown source claim",
                    "why": "It is not in the reviewed excerpt.",
                    "command": "lk read balanceOf [account]",
                    "source": {"path": "src/Missing.sol", "symbol": "balanceOf"},
                },
                {
                    "title": "Unsupported command target",
                    "why": "The command target is not present in the cited source.",
                    "command": "lk read balanceOf",
                    "source": {"path": "src/Vault.sol", "symbol": "withdraw"},
                },
            ]
        }
        result = ai.validate_ai_recommendations(raw, context, [{"command": "lk read owner", "reason": "native"}])
        self.assertEqual(result["recommendations"], [])
        raw["recommendations"] = [raw["recommendations"][0], raw["recommendations"][4]]
        result = ai.validate_ai_recommendations(raw, context, [])
        self.assertEqual(len(result["recommendations"]), 1)
        self.assertEqual(result["recommendations"][0]["command"], "lk read owner")
        # candidate_count is the model's raw count before validation; one of
        # the two suggestions is accepted and one is discarded by the checks.
        self.assertEqual(result["candidate_count"], 2)
        self.assertEqual(result["discarded_count"], 1)
        self.assertTrue(result["ai_generated"])
        self.assertEqual(result["origin"], "configured-model")
        self.assertEqual(result["recommendations"][0]["source"]["symbol"], "withdraw")

    def test_recommend_next_steps_requests_a_concrete_source_grounded_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Registry.sol").write_text(
                "contract Registry { "
                "function isAgreementValid(address agreement) external view returns (bool) { return true; } "
                "function owner() external view returns (address) { return msg.sender; } "
                "}",
                encoding="utf-8",
            )
            model_result = {
                "recommendations": [{
                    "title": "Inspect the agreement validity check",
                    "why": "See the function signature and review the validity rule before relying on it.",
                    "command": "lk fn isAgreementValid",
                    "source": {"path": "src/Registry.sol", "symbol": "isAgreementValid"},
                }]
            }
            with patch.object(ai, "request_structured", return_value=model_result) as request:
                report = ai.recommend_next_steps(
                    root,
                    command="status",
                    native_recommendations=[{"command": "lk functions", "reason": "List ABI functions."}],
                    contract_name="Registry",
                )
            self.assertEqual(len(report["recommendations"]), 1)
            self.assertEqual(report["recommendations"][0]["command"], "lk fn isAgreementValid")
            context = request.call_args.kwargs["context"]
            self.assertEqual(context["active_contract"], "Registry")
            self.assertIn("Do not abstain merely because a function needs input values", request.call_args.kwargs["task"])
            self.assertTrue(report["ai_generated"])

    def test_empty_ai_recommendations_explain_abstention_or_filtered_candidates(self):
        no_candidates = ai.render_ai_recommendations({"recommendations": [], "candidate_count": 0, "discarded_count": 0})
        filtered = ai.render_ai_recommendations({"recommendations": [], "candidate_count": 2, "discarded_count": 2})
        self.assertIn("no extra command", no_candidates)
        self.assertIn("none passed Lowkey's source and command checks", filtered)
        self.assertIn("No rejected command was shown", filtered)

    def test_model_derived_text_renderers_have_visible_ai_watermarks(self):
        from lowkey import error_advisor, security_review, test_planner

        plan_text = test_planner.render_test_plan({"summary": "Candidate test idea", "test_cases": []})
        review_text = security_review.render_review({"summary": "Candidate review", "candidate_findings": []})
        error_text = error_advisor.render({
            "summary": "Check the RPC endpoint",
            "likely_cause": "The endpoint is unreachable",
            "confidence": "medium",
            "checks": [],
            "fixes": [],
            "caveats": [],
        })
        self.assertTrue(plan_text.startswith("@ AI OUTPUT — TEST IDEAS"))
        self.assertTrue(review_text.startswith("@ AI OUTPUT — SECURITY REVIEW"))
        self.assertTrue(error_text.startswith("@ AI OUTPUT — ERROR DIAGNOSIS"))

    def test_disabled_and_unconfigured_by_default(self):
        value = ai.status()
        self.assertFalse(value["enabled"])
        self.assertFalse(value["configured"])
        self.assertFalse(value["usable"])

    def test_status_is_plain_language_by_default_and_json_is_opt_in(self):
        ai.configure(
            provider="openai-compatible",
            model="demo-model",
            base_url="https://provider.example/v1",
            api_key="test-key",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["status"]), 0)
        rendered = output.getvalue()
        self.assertIn("LOWKEY AI STATUS", rendered)
        self.assertIn("READY TO TRY", rendered)
        self.assertIn("Connection: Not checked", rendered)
        self.assertNotIn('"key_slots_configured"', rendered)
        self.assertNotIn("https://provider.example/v1", rendered)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["status", "--json"]), 0)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["usable"])
        self.assertEqual(payload["key_slots_configured"], 1)

    def test_error_help_status_is_human_readable_by_default(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["errors", "status"]), 0)
        self.assertIn("LOWKEY AI ERROR HELP", output.getvalue())
        self.assertIn("suggested commands are shown only", output.getvalue().lower())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["errors", "status", "--json"]), 0)
        self.assertFalse(json.loads(output.getvalue())["suggested_commands_are_executed"])

    def test_ledger_human_output_explains_empty_results_without_claiming_security(self):
        rendered = ai.render_ledger({
            "event_count": 2,
            "ledger_path": ".audit/ai-review/ledger.jsonl",
            "findings": [],
        })
        self.assertIn("LOWKEY REVIEW HISTORY", rendered)
        self.assertIn("did not list a specific possible vulnerability", rendered)
        self.assertIn("does NOT mean the contracts are secure", rendered)
        self.assertNotIn("Model confidence never sets verification status", rendered)

    def test_mode_is_manual_by_default_and_can_be_switched(self):
        self.assertEqual(ai.status()["mode"], "manual")
        self.assertFalse(ai.status()["auto_assist"])
        with patch("builtins.print"):
            self.assertEqual(ai.main(["mode", "auto"]), 0)
        self.assertEqual(ai.status()["mode"], "auto")
        self.assertTrue(ai.status()["auto_assist"])
        with patch("builtins.print"):
            self.assertEqual(ai.main(["mode", "manual"]), 0)
        self.assertEqual(ai.status()["mode"], "manual")

    def test_automatic_review_decision_requires_auto_mode_and_usable_provider(self):
        with patch.object(ai, "auto_review_reason", return_value="proxy/factory composition") as complexity:
            self.assertIsNone(ai.automatic_review_reason(
                Path(self.tmp.name), current_status={"usable": True, "auto_assist": False}
            ))
            complexity.assert_not_called()
            self.assertIsNone(ai.automatic_review_reason(
                Path(self.tmp.name), current_status={"usable": False, "auto_assist": True}
            ))
            complexity.assert_not_called()
            self.assertEqual(
                ai.automatic_review_reason(
                    Path(self.tmp.name), current_status={"usable": True, "auto_assist": True}
                ),
                "proxy/factory composition",
            )
            complexity.assert_called_once()

    def test_complexity_heuristic_only_triggers_for_multi_contract_composition(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
            self.assertIsNone(ai.auto_review_reason(root))
            (root / "src" / "Factory.sol").write_text(
                "contract Factory { address public implementation; }", encoding="utf-8"
            )
            (root / "src" / "Proxy.sol").write_text(
                "contract Proxy { address public implementation; }", encoding="utf-8"
            )
            reason = ai.auto_review_reason(root)
            self.assertIsNotNone(reason)
            self.assertIn("protocol-composition", reason)

    def test_api_key_is_separate_and_permissions_are_private(self):
        ai.configure(provider="deepseek", model="deepseek-flash", api_key="example-secret")
        self.assertNotIn("example-secret", ai.config_path().read_text(encoding="utf-8"))
        self.assertEqual(json.loads(ai.credentials_path().read_text(encoding="utf-8"))["keys"]["deepseek"]["1"], "example-secret")
        self.assertEqual(ai.credentials_path().stat().st_mode & 0o777, 0o600)

    def test_three_key_slots_fail_over_after_quota_and_never_log_key_values(self):
        from lowkey import provider_adapters

        ai.configure(
            provider="openai-compatible", model="fixture-model",
            base_url="https://provider.example/v1", api_key="first-secret-key",
        )
        ai.set_api_key_slot("openai-compatible", 2, "second-secret-key")
        ai.set_api_key_slot("openai-compatible", 3, "third-secret-key")
        adapter = provider_adapters.get_provider_adapter("openai-compatible")
        used_keys = []
        response = json.dumps({
            "choices": [{"message": {"content": json.dumps({"facts": [], "hypotheses": ["ok"]})}}]
        }).encode("utf-8")

        def send(**kwargs):
            used_keys.append(kwargs["api_key"])
            if kwargs["api_key"] in {"first-secret-key", "second-secret-key"}:
                raise provider_adapters.ProviderAdapterError("quota", "quota")
            return response

        with patch.object(adapter, "send", side_effect=send):
            result = ai.request_structured(
                purpose="protocol_analysis", task="test failover",
                context={"safe": True}, required_fields=("facts", "hypotheses"),
            )
        self.assertEqual(used_keys, ["first-secret-key", "second-secret-key", "third-secret-key"])
        self.assertEqual(result["hypotheses"], ["ok"])
        self.assertEqual(ai.status()["key_slots_configured"], 3)
        log = (ai._state_home() / "ai-events.jsonl").read_text(encoding="utf-8")
        record = json.loads(log.splitlines()[-1])
        self.assertEqual(record["key_slot"], "3")
        self.assertEqual(record["failover_attempts"], 2)
        for secret in ("first-secret-key", "second-secret-key", "third-secret-key"):
            self.assertNotIn(secret, log)
            self.assertNotIn(secret, ai.config_path().read_text(encoding="utf-8"))

    def test_key_status_displays_credential_provider_id_for_compatible_endpoints(self):
        ai.configure(
            provider="openai-compatible",
            model="gemini-3.5-flash-lite",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai",
            api_key="key-status-test-secret",
        )
        rendered = ai.render_key_pool_status(ai.key_pool_status())
        self.assertIn("Gemini API (OpenAI-compatible connection)", rendered)
        self.assertIn(
            "Credential provider ID (use with --provider): openai-compatible",
            rendered,
        )
        self.assertIn("Saved key slots: 1", rendered)
        self.assertNotIn("key-status-test-secret", rendered)

    def test_key_slots_reject_more_than_three_by_interface(self):
        ai.configure(provider="deepseek", model="fixture", api_key="slot-one")
        ai.set_api_key_slot("deepseek", 2, "slot-two")
        ai.set_api_key_slot("deepseek", 3, "slot-three")
        with self.assertRaises(ai.AIHarnessError):
            ai.set_api_key_slot("deepseek", 4, "slot-four")

    def test_public_plain_http_endpoint_is_rejected(self):
        with self.assertRaises(ai.AIHarnessError):
            ai.configure(provider="openai-compatible", model="demo", base_url="http://public.example/v1", api_key="secret")

    def test_credentials_in_url_are_rejected(self):
        with self.assertRaises(ai.AIHarnessError):
            ai.configure(provider="deepseek", model="deepseek-flash", base_url="https://user:pass@example.com/v1", api_key="secret")

    def test_provider_url_query_and_fragment_are_rejected(self):
        with self.assertRaises(ai.AIHarnessError):
            ai.configure(
                provider="openai-compatible", model="demo",
                base_url="https://provider.example/v1?token=should-not-be-here",
                api_key="secret",
            )
        with self.assertRaises(ai.AIHarnessError):
            ai.configure(
                provider="openai-compatible", model="demo",
                base_url="https://provider.example/v1#credentials",
                api_key="secret",
            )

    def test_missing_required_model_fields_are_rejected(self):
        ai.configure(provider="deepseek", model="deepseek-flash", api_key="secret")
        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return json.dumps({"choices": [{"message": {"content": '{"summary": "incomplete"}'}}]}).encode()
        with patch.object(ai, "urlopen", return_value=FakeResponse()):
            with self.assertRaises(ai.AIHarnessError):
                ai.request_structured(
                    purpose="protocol_analysis", task="inspect", context={},
                    required_fields=("facts", "hypotheses"),
                )

    def test_disabled_ai_blocks_request(self):
        ai.configure(provider="deepseek", model="deepseek-flash", api_key="secret")
        cfg = ai.load_config()
        cfg["enabled"] = False
        ai.save_config(cfg)
        with self.assertRaises(ai.AIUnavailable):
            ai.request_structured(purpose="protocol_analysis", task="inspect", context={})

    def test_general_chat_is_rejected(self):
        with self.assertRaises(ai.AIHarnessError):
            ai.request_structured(purpose="chat", task="hello", context={})

    def test_context_size_is_bounded(self):
        ai.configure(provider="deepseek", model="deepseek-flash", api_key="secret")
        with self.assertRaises(ai.AIHarnessError):
            ai.request_structured(purpose="protocol_analysis", task="inspect", context={"source": "X" * (ai.MAX_CONTEXT_BYTES + 10)})

    def test_json_output_and_metadata_only_event_log(self):
        ai.configure(provider="deepseek", model="deepseek-flash", api_key="test-secret")
        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return json.dumps({"choices": [{"message": {"content": '{"facts": [], "hypotheses": ["test"]}'}}]}).encode()
        with patch.object(ai, "urlopen", return_value=FakeResponse()):
            result = ai.request_structured(
                purpose="protocol_analysis", task="inspect private context",
                context={"project_source_marker": "VERY_PRIVATE_SOURCE"},
                required_fields=("facts", "hypotheses"),
            )
        self.assertEqual(result["hypotheses"], ["test"])
        log = (ai._state_home() / "ai-events.jsonl").read_text(encoding="utf-8")
        self.assertIn("protocol_analysis", log)
        self.assertNotIn("VERY_PRIVATE_SOURCE", log)
        self.assertNotIn("inspect private context", log)
        self.assertNotIn("test-secret", log)

    def test_invalid_json_response_is_rejected(self):
        ai.configure(provider="deepseek", model="deepseek-flash", api_key="secret")
        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self, limit):
                return json.dumps({"choices": [{"message": {"content": "not JSON"}}]}).encode()
        with patch.object(ai, "urlopen", return_value=FakeResponse()):
            with self.assertRaises(ai.AIHarnessError):
                ai.request_structured(purpose="protocol_analysis", task="inspect", context={})

    def test_explicit_protocol_review_receives_only_approved_memory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text(
                "contract Vault { function withdraw() external {} } // factory registry",
                encoding="utf-8",
            )
            approved = memory.propose_lesson(
                kind="test-procedure", title="Assert the factory registry",
                lesson="Check the event and the registry mapping.",
                root=root,
            )
            memory.approve_lesson(
                approved["id"], validation_kind="test",
                validation="The local Foundry regression test passes with the factory fixture.",
                root=root,
            )
            pending = memory.propose_lesson(
                kind="protocol-pattern", title="Unverified reentrancy hypothesis",
                lesson="Investigate whether callbacks can re-enter the withdrawal path.",
                root=root,
            )
            response = {
                "summary": "A small vault contract.",
                "contract_roles": [],
                "invariants": [],
                "open_questions": [],
                "deployment_considerations": [],
            }
            with patch.object(ai, "request_structured", return_value=response) as request:
                result = ai.review_project_protocol(root)
            context = request.call_args.kwargs["context"]
            experience = context["approved_experience"]
            self.assertEqual([item["id"] for item in experience], [approved["id"]])
            self.assertNotIn(pending["title"], json.dumps(experience))
            self.assertEqual(result["summary"], response["summary"])

    def test_protocol_review_accepts_valid_nested_schema(self):
        result = {
            "summary": "The vault tracks balances and exposes a withdrawal path.",
            "contract_roles": [{
                "name": "Vault",
                "purpose": "Holds user deposits.",
                "evidence": "src/Vault.sol: deposit and withdraw functions.",
            }],
            "invariants": [{
                "statement": "Total liabilities must not exceed tracked assets.",
                "rationale": "Withdrawals must remain fully backed.",
                "source": "src/Vault.sol: accounting state and withdrawal logic.",
            }],
            "open_questions": ["Is there a trusted price source?"],
            "deployment_considerations": ["Confirm the initialization sequence."],
        }
        ai._validate_protocol_review_output(result)

    def test_protocol_review_rejects_malformed_nested_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
            malformed = {
                "summary": "Review complete.",
                "contract_roles": [{"name": "Vault", "purpose": "Stores balances"}],
                "invariants": [],
                "open_questions": [],
                "deployment_considerations": [],
            }
            with patch.object(ai, "request_structured", return_value=malformed):
                with self.assertRaisesRegex(ai.AIHarnessError, "non-empty 'evidence'"):
                    ai.review_project_protocol(root)

    def test_protocol_review_rejects_unbounded_list_output(self):
        malformed = {
            "summary": "Review complete.",
            "contract_roles": [],
            "invariants": [],
            "open_questions": ["question"] * 129,
            "deployment_considerations": [],
        }
        with self.assertRaisesRegex(ai.AIHarnessError, "exceeds 128 entries"):
            ai._validate_protocol_review_output(malformed)

    def test_source_context_excludes_tests_dependencies_and_symlinks_but_includes_deploy_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("src", "test", "scripts", "lib", "vendor"):
                (root / name).mkdir()
            (root / "src" / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
            (root / "test" / "Vault.t.sol").write_text("contract LeakTest { string constant SECRET = 'test-only'; }", encoding="utf-8")
            (root / "scripts" / "Deploy.sol").write_text("contract Deploy { }", encoding="utf-8")
            (root / "lib" / "Dependency.sol").write_text("contract Dependency { }", encoding="utf-8")
            (root / "vendor" / "Vendor.sol").write_text("contract Vendor { }", encoding="utf-8")
            outside = root.parent / (root.name + "-outside.sol")
            outside.write_text("contract ExternalSecret { }", encoding="utf-8")
            self.addCleanup(lambda: outside.unlink(missing_ok=True))
            try:
                (root / "src" / "Linked.sol").symlink_to(outside)
            except (OSError, NotImplementedError):
                pass
            context = ai._source_context(root, "Vault")
            serialized = json.dumps(context)
            self.assertIn("Vault.sol", serialized)
            self.assertIn("Deploy.sol", serialized)
            self.assertNotIn("SECRET", serialized)
            self.assertNotIn("Dependency.sol", serialized)
            self.assertNotIn("Vendor.sol", serialized)
            self.assertNotIn("ExternalSecret", serialized)

    def test_large_source_and_approved_memory_fit_context_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
            (root / "src").mkdir()
            for index in range(18):
                (root / "src" / f"Vault{index}.sol").write_text(
                    "contract Vault" + str(index) + " { mapping(address => address) public registry; "
                    + "// factory registry "
                    + ("uint256 public value; " * 420) + " }",
                    encoding="utf-8",
                )
            for index in range(8):
                proposal = memory.propose_lesson(
                    kind="test-procedure",
                    title=f"Factory registry procedure {index}",
                    lesson=("Assert the factory registry after the state transition and emitted event. " * 10),
                    tags=["factory", "registry"],
                    root=root,
                )
                memory.approve_lesson(
                    proposal["id"], validation_kind="manual-review",
                    validation="Reviewed against reproducible fixture evidence and source paths.",
                    root=root,
                )
            response = {
                "summary": "Fixture protocol review",
                "contract_roles": [],
                "invariants": [],
                "open_questions": [],
                "deployment_considerations": [],
            }
            with patch.object(ai, "request_structured", return_value=response) as request:
                ai.review_project_protocol(root)
            context = request.call_args.kwargs["context"]
            total_bytes = len(json.dumps(context, ensure_ascii=False).encode("utf-8"))
            self.assertLessEqual(total_bytes, ai.MAX_CONTEXT_BYTES)
            self.assertTrue(context["approved_experience"])

    def test_openai_provider_uses_safe_default_endpoint(self):
        cfg = ai.configure(provider="openai", model="example-model", api_key="test-key")
        self.assertEqual(cfg["base_url"], "https://api.openai.com/v1")
        self.assertTrue(ai.status()["usable"])
        self.assertNotIn("test-key", ai.config_path().read_text(encoding="utf-8"))

    def test_local_ollama_needs_no_key(self):
        ai.configure(provider="ollama", model="qwen2.5-coder")
        self.assertTrue(ai.status()["usable"])

    def test_source_context_redacts_secret_assignments_and_pem_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text(
                'contract Vault { string private apiKey = "API_SECRET_DO_NOT_SEND"; '
                'string private password = "PASSWORD_DO_NOT_SEND"; }',
                encoding="utf-8",
            )
            (root / "src" / "KeyHolder.sol").write_text(
                'contract KeyHolder { string privateKey = "PRIVATE_KEY_DO_NOT_SEND"; }',
                encoding="utf-8",
            )
            (root / "src" / "Signer.sol").write_text(
                "contract Signer { string constant KEY = "
                '"-----BEGIN PRIVATE KEY-----\\nPEM_SECRET_DO_NOT_SEND\\n-----END PRIVATE KEY-----"; }',
                encoding="utf-8",
            )
            context = ai._source_context(root, None)
            rendered = json.dumps(context)
            for secret in ("API_SECRET_DO_NOT_SEND", "PASSWORD_DO_NOT_SEND", "PRIVATE_KEY_DO_NOT_SEND", "PEM_SECRET_DO_NOT_SEND"):
                self.assertNotIn(secret, rendered)
            self.assertIn("[REDACTED]", rendered)
            self.assertIn("[REDACTED PRIVATE KEY BLOCK]", rendered)

    def test_source_context_excludes_build_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "Vault.sol").write_text("contract Vault { function withdraw() external {} }", encoding="utf-8")
            (root / "out").mkdir()
            (root / "out" / "Generated.sol").write_text("contract Secret { }", encoding="utf-8")
            context = ai._source_context(root, "Vault")
            self.assertEqual(context["source_files_included"], 1)
            self.assertIn("Vault.sol", context["source_files"][0]["path"])
            self.assertNotIn("Secret", json.dumps(context))


    def test_ai_context_preview_is_local_and_shows_redacted_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\\nsrc='src'\\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "test").mkdir()
            (root / "src" / "Vault.sol").write_text(
                'contract Vault { string private apiKey = "PREVIEW_SECRET_DO_NOT_SEND"; }',
                encoding="utf-8",
            )
            (root / "test" / "Vault.t.sol").write_text(
                "contract TestVault { string constant IGNORE_ME = 'TEST_ONLY'; }", encoding="utf-8"
            )

            summary = io.StringIO()
            with patch.object(ai, "urlopen", side_effect=AssertionError("preview must not contact a provider")) as send:
                with contextlib.redirect_stdout(summary):
                    self.assertEqual(ai.main(["preview", "--root", str(root)]), 0)
                send.assert_not_called()
            self.assertIn("no provider request made", summary.getvalue())
            self.assertIn("Vault.sol", summary.getvalue())
            self.assertNotIn("PREVIEW_SECRET_DO_NOT_SEND", summary.getvalue())
            self.assertNotIn("Vault.t.sol", summary.getvalue())

            full = io.StringIO()
            with patch.object(ai, "urlopen", side_effect=AssertionError("preview must not contact a provider")) as send:
                with contextlib.redirect_stdout(full):
                    self.assertEqual(ai.main(["preview", "--root", str(root), "--show-context"]), 0)
                send.assert_not_called()
            readable = full.getvalue()
            self.assertIn("HUMAN-READABLE", readable)
            self.assertIn("Provider request: NOT SENT", readable)
            self.assertIn("Vault.sol", readable)
            self.assertIn("Source excerpt", readable)
            self.assertIn("[REDACTED]", readable)
            self.assertNotIn("PREVIEW_SECRET_DO_NOT_SEND", readable)
            self.assertNotIn("TEST_ONLY", readable)
            self.assertNotIn('"context": {', readable)

            structured = io.StringIO()
            with patch.object(ai, "urlopen", side_effect=AssertionError("preview must not contact a provider")) as send:
                with contextlib.redirect_stdout(structured):
                    self.assertEqual(ai.main(["preview", "--root", str(root), "--json-context"]), 0)
                send.assert_not_called()
            payload = json.loads(structured.getvalue())
            self.assertTrue(payload["preview_only"])
            self.assertFalse(payload["provider_request_made"])
            serialized = json.dumps(payload["context"])
            self.assertNotIn("PREVIEW_SECRET_DO_NOT_SEND", serialized)
            self.assertNotIn("TEST_ONLY", serialized)
            self.assertIn("[REDACTED]", serialized)
            self.assertLessEqual(payload["context_bytes"], ai.MAX_CONTEXT_BYTES)


    def test_human_context_preview_escapes_terminal_control_characters(self):
        rendered = "\n".join(
            ai._human_context_lines("source_excerpt", "before\x1b[31mred\x1b[0m")
        )
        self.assertNotIn("\x1b", rendered)
        self.assertIn(r"\x1b[31m", rendered)


if __name__ == "__main__":
    unittest.main()
