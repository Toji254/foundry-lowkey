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

    def test_top_level_help_is_complete_and_documents_all_ai_flags(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["--help"]), 0)
        help_text = output.getvalue()
        for command in (
            "status", "preview", "mode", "setup", "enable", "disable", "test",
            "keys list", "keys add", "keys remove", "keys clear", "explain-error",
            "errors", "test-plan", "security-review", "ledger", "verify",
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
        self.assertIn("Why / when", help_text)
        self.assertIn("Examples:", help_text)
        self.assertIn(
            "Examples:\n  lk ai status\n  lk ai security-review --contract Vault\n  lk ai test-plan --contract Vault",
            help_text,
        )
        self.assertIn("does NOT write Solidity test code", help_text)
        self.assertIn("preview never makes a provider request", help_text)

    def test_help_alias_and_command_specific_help_include_examples(self):
        for alias in (["help"], ["--h"], ["-h"]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(ai.main(alias), 0)
            self.assertIn("COMPLETE COMMAND REFERENCE", output.getvalue())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as help_exit:
                ai.main(["setup", "--help"])
        self.assertEqual(help_exit.exception.code, 0)
        self.assertIn("--api-key-env", output.getvalue())
        self.assertIn("WHEN:", output.getvalue())
        self.assertIn("lk ai setup --provider gemini", output.getvalue())

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
            ]
        }
        result = ai.validate_ai_recommendations(raw, context, [{"command": "lk read owner", "reason": "native"}])
        self.assertEqual(result["recommendations"], [])
        raw["recommendations"] = [raw["recommendations"][0]]
        result = ai.validate_ai_recommendations(raw, context, [])
        self.assertEqual(len(result["recommendations"]), 1)
        self.assertEqual(result["recommendations"][0]["command"], "lk read owner")
        self.assertTrue(result["ai_generated"])
        self.assertEqual(result["origin"], "configured-model")

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
            payload = json.loads(full.getvalue())
            self.assertTrue(payload["preview_only"])
            self.assertFalse(payload["provider_request_made"])
            serialized = json.dumps(payload["context"])
            self.assertNotIn("PREVIEW_SECRET_DO_NOT_SEND", serialized)
            self.assertNotIn("TEST_ONLY", serialized)
            self.assertIn("[REDACTED]", serialized)
            self.assertLessEqual(payload["context_bytes"], ai.MAX_CONTEXT_BYTES)


if __name__ == "__main__":
    unittest.main()
