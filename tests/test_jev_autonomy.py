import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import ai_harness as ai


class JevAutonomyTests(unittest.TestCase):
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

    def _configure_local_provider(self):
        return ai.configure(
            provider="ollama",
            model="test-model",
            base_url="http://127.0.0.1:11434/v1",
        )

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
        self.assertEqual(value["jev_daily_call_limit"], 8)

    def test_jev_on_enables_existing_automation_and_free_tier_guard(self):
        self._configure_local_provider()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["jev", "on"]), 0)
        cfg = ai.load_config()
        self.assertTrue(cfg["enabled"])
        self.assertTrue(cfg["jev_autonomous"])
        self.assertTrue(cfg["jev_free_tier_mode"])
        self.assertTrue(cfg["auto_assist"])
        self.assertTrue(cfg["auto_explain_errors"])
        self.assertTrue(cfg["auto_recommendations"])
        self.assertIn("8 AI requests", output.getvalue())

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
        self.assertIn("explicit 'lk ai ...' requests remain available", output.getvalue())

    def test_jev_status_is_local_and_reports_budget(self):
        self._configure_local_provider()
        self.assertEqual(ai.main(["jev", "on", "--daily-limit", "3"]), 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(ai.main(["jev", "status", "--json"]), 0)
        value = json.loads(output.getvalue())
        self.assertTrue(value["jev_autonomous"])
        self.assertEqual(value["jev_daily_call_limit"], 3)
        self.assertEqual(value["jev_calls_remaining"], 3)

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
