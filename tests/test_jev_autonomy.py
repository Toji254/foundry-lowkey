import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import ai_harness as ai
from lowkey import jev_engine


class JevAutonomyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(Path(self.tmp.name) / "config"),
            "XDG_DATA_HOME": str(Path(self.tmp.name) / "data"),
            "XDG_STATE_HOME": str(Path(self.tmp.name) / "state"),
            "TYPESAFE_API_KEY": "",
        })
        env.start()
        self.addCleanup(env.stop)

    def _configure_local_provider(self):
        # Preserve the separate text-AI configuration while using a fake local
        # Jev credential; no network request is made by setup/status tests.
        ai.configure(
            provider="ollama",
            model="test-model",
            base_url="http://127.0.0.1:11434/v1",
        )
        jev_engine.configure(
            api_key="typesafe_test_key_0123456789",
            model="jev-latest",
        )
        return ai.load_config()

    def test_help_exposes_jev_switch_and_tier_controls(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["--help"]), 0)
        help_text = output.getvalue()
        self.assertIn("JEV AUTONOMY & LOCAL BUDGET GUARD", help_text)
        self.assertIn("lk ai jev on", help_text)
        self.assertIn("lk ai jev status", help_text)
        self.assertIn("lk ai jev off", help_text)
        self.assertIn("--daily-limit", help_text)

    def test_legacy_config_gets_new_defaults_without_schema_migration(self):
        ai.save_config({
            "schema_version": ai.SCHEMA_VERSION,
            "enabled": True,
            "auto_assist": False,
            "auto_explain_errors": False,
            "provider": "ollama",
            "model": "test-model",
            "base_url": "http://127.0.0.1:11434/v1",
            "timeout_seconds": 45,
            "max_output_tokens": 1800,
        })
        value = ai.load_config()
        self.assertFalse(value["jev_autonomous"])
        self.assertFalse(value["jev_free_tier_mode"])
        self.assertEqual(value["jev_daily_call_limit"], 5)

    def test_jev_setup_uses_hidden_prompt_and_makes_no_network_request(self):
        output = io.StringIO()
        with patch("lowkey.ai_harness.getpass.getpass", return_value="typesafe_test_key_0123456789") as prompt:
            with contextlib.redirect_stdout(output):
                self.assertEqual(ai.main(["jev", "setup"]), 0)
        prompt.assert_called_once()
        self.assertTrue(jev_engine.status()["configured"])
        self.assertTrue(ai.load_config()["jev_free_tier_mode"])
        self.assertIn("No request was sent", output.getvalue())

    def test_jev_cannot_enable_autonomy_without_a_type_safe_key(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(ai.main(["jev", "on"]), 2)
        self.assertFalse(ai.load_config()["jev_autonomous"])
        self.assertIn("Configure Jev first", output.getvalue())

    def test_jev_on_enables_existing_automation_and_free_tier_guard(self):
        self._configure_local_provider()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["jev", "on"]), 0)
        cfg = ai.load_config()
        self.assertTrue(cfg["enabled"])
        self.assertTrue(cfg["jev_autonomous"])
        self.assertTrue(cfg["jev_free_tier_mode"])
        # Jev's typed classifier is separate from the text-LLM automation toggles.
        self.assertFalse(cfg["auto_assist"])
        self.assertFalse(cfg["auto_explain_errors"])
        self.assertFalse(cfg["auto_recommendations"])
        self.assertIn("8 provider attempts", output.getvalue())
        self.assertIn("TypeSafe charges for input tokens", output.getvalue())

    def test_jev_off_disables_automatic_features_but_preserves_manual_ai_and_guard(self):
        self._configure_local_provider()
        self.assertEqual(ai.main(["jev", "on"]), 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["jev", "off"]), 0)
        cfg = ai.load_config()
        self.assertTrue(cfg["enabled"])
        self.assertFalse(cfg["jev_autonomous"])
        self.assertFalse(cfg["auto_assist"])
        self.assertFalse(cfg["auto_explain_errors"])
        self.assertFalse(cfg["auto_recommendations"])
        self.assertTrue(cfg["jev_free_tier_mode"])
        self.assertIn("Other Lowkey AI settings and native commands are unchanged", output.getvalue())

    def test_jev_status_is_local_and_reports_budget(self):
        self._configure_local_provider()
        self.assertEqual(ai.main(["jev", "on", "--daily-limit", "3"]), 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["jev", "status", "--json"]), 0)
        value = json.loads(output.getvalue())
        self.assertTrue(value["autonomous_mode"])
        self.assertTrue(value["jev"]["configured"])
        self.assertEqual(value["local_budget_guard"]["daily_limit"], 3)
        self.assertEqual(value["local_budget_guard"]["remaining"], 3)

    def test_invalid_daily_limit_does_not_change_existing_settings(self):
        self._configure_local_provider()
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(ai.main(["jev", "on", "--daily-limit", "25"]), 2)
        self.assertFalse(ai.load_config()["jev_autonomous"])
        self.assertIn("--daily-limit must be from 1 to 24", output.getvalue())

    def test_free_tier_request_budget_and_context_caps_apply_before_provider_call(self):
        self._configure_local_provider()
        cfg = ai.load_config()
        cfg["jev_free_tier_mode"] = True
        cfg["jev_daily_call_limit"] = 1
        cfg["jev_context_limit_bytes"] = 4096
        cfg["jev_max_output_tokens"] = 300
        ai.save_config(cfg)
        observed = {}

        def fake_send(**kwargs):
            observed.update(kwargs)
            return {"ok": True}

        with patch.object(ai, "_send", side_effect=fake_send) as send:
            result = ai.request_structured(
                purpose="error_diagnosis",
                task="Classify the provided diagnostic evidence.",
                context={"diagnostic": "x" * 20000},
                required_fields=("ok",),
            )
            self.assertEqual(result, {"ok": True})
            self.assertLessEqual(
                len(json.dumps(observed["context"], ensure_ascii=False).encode("utf-8")),
                4096,
            )
            self.assertEqual(observed["config"]["max_output_tokens"], 300)
            self.assertLessEqual(observed["config"]["timeout_seconds"], 30)
            with self.assertRaises(ai.AIUnavailable):
                ai.request_structured(
                    purpose="error_diagnosis",
                    task="Another diagnosis.",
                    context={"diagnostic": "short"},
                    required_fields=("ok",),
                )
            self.assertEqual(send.call_count, 1)
        budget = ai.autonomy_budget_status()
        self.assertEqual(budget["calls_today"], 1)
        self.assertEqual(budget["remaining"], 0)

    def test_exact_repeat_uses_private_response_cache_without_spending_budget_twice(self):
        self._configure_local_provider()
        cfg = ai.load_config()
        cfg["jev_free_tier_mode"] = True
        cfg["jev_daily_call_limit"] = 1
        ai.save_config(cfg)
        observed = []

        def fake_send(**kwargs):
            observed.append(kwargs)
            return {"ok": True, "summary": "Same exact context and task."}

        request = {
            "purpose": "error_diagnosis",
            "task": "Classify this exact diagnostic.",
            "context": {"command": "build", "error": "missing import"},
            "required_fields": ("ok", "summary"),
        }
        with patch.object(ai, "_send", side_effect=fake_send) as send:
            first = ai.request_structured(**request)
            second = ai.request_structured(**request)
        self.assertEqual(first, second)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(ai.autonomy_budget_status()["calls_today"], 1)
        cache_path = ai._jev_cache_path()
        self.assertTrue(cache_path.exists())
        cache_text = cache_path.read_text(encoding="utf-8")
        self.assertNotIn("missing import", cache_text)
        self.assertNotIn("api_key", cache_text.lower())

    def test_standard_tier_skips_local_free_tier_caps(self):
        self._configure_local_provider()
        cfg = ai.load_config()
        cfg["jev_free_tier_mode"] = False
        ai.save_config(cfg)

        def fake_send(**kwargs):
            return {"ok": True}

        with patch.object(ai, "_send", side_effect=fake_send) as send:
            self.assertEqual(ai.request_structured(
                purpose="error_diagnosis",
                task="Check the diagnostic.",
                context={"diagnostic": "x" * 20000},
                required_fields=("ok",),
            ), {"ok": True})
            self.assertEqual(send.call_count, 1)
        self.assertEqual(ai.autonomy_budget_status()["calls_today"], 0)


if __name__ == "__main__":
    unittest.main()
