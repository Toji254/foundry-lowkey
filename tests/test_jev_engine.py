import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from urllib.error import HTTPError
from unittest.mock import patch

from lowkey import ai_harness
from lowkey import jev_engine


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.payload[:limit]


def classification_response():
    return {
        "model": "jev-1.14.0",
        "answers": {
            "outcome": {
                "type": "choice",
                "choice": "actionable_failure",
                "probabilities": {"actionable_failure": 0.8, "unknown": 0.2},
                "confidence": 0.82,
            },
            "attention": {
                "type": "choice",
                "choice": "review",
                "probabilities": {"review": 0.9, "routine": 0.1},
                "confidence": 0.9,
            },
            "needs_explanation": {"type": "noul", "noul": 0.96},
            "suggested_response": {
                "type": "choice",
                "choice": "explain_observation",
                "probabilities": {"explain_observation": 1.0},
                "confidence": 1.0,
            },
        },
        "usage": {"input_tokens": 500, "output_tokens": 42},
    }


class JevEngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(Path(self.tmp.name) / "config"),
            "XDG_DATA_HOME": str(Path(self.tmp.name) / "data"),
            "XDG_STATE_HOME": str(Path(self.tmp.name) / "state"),
            "TYPESAFE_API_KEY": "",
            "JEVMODEL_API_KEY": "",
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        jev_engine.configure(
            api_key="typesafe_test_key_0123456789",
            model="jev-latest",
            timeout_seconds=10,
        )

    def test_fresh_install_reports_missing_key_instead_of_invalid_credentials(self):
        jev_engine.clear_saved_key()
        self.assertFalse(jev_engine.credentials_path().exists())
        value = jev_engine.status()
        self.assertFalse(value["configured"])
        self.assertIsNone(value["key_source"])

    def test_setup_stores_key_in_private_file_and_status_never_exposes_it(self):
        key_path = jev_engine.credentials_path()
        self.assertTrue(key_path.is_file())
        stored = json.loads(key_path.read_text(encoding="utf-8"))
        self.assertNotIn("typesafe_test_key_0123456789", json.dumps(jev_engine.status()))
        self.assertEqual(stored["api_key"], "typesafe_test_key_0123456789")
        self.assertEqual(jev_engine.status()["key_source"], "private local credential file")

    def test_evaluate_posts_valid_typed_question_and_reports_actual_usage_cost(self):
        seen = {}

        def opener(request, timeout):
            seen["url"] = request.full_url
            seen["headers"] = dict(request.header_items())
            seen["timeout"] = timeout
            seen["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse({
                "model": "jev-1.14.0",
                "answers": {"probe": {"type": "noul", "noul": 0.99}},
                "usage": {"input_tokens": 1000, "output_tokens": 12},
            })

        result = jev_engine.evaluate(
            state={"message": "fixed connectivity probe"},
            questions={"probe": {
                "type": "noul",
                "instructions": "Does the state describe a connectivity probe?",
            }},
            opener=opener,
        )
        self.assertEqual(seen["url"], jev_engine.API_URL)
        self.assertEqual(seen["timeout"], 10)
        self.assertEqual(seen["body"]["model"], "jev-latest")
        self.assertIn("Bearer typesafe_test_key_0123456789", seen["headers"]["Authorization"])
        self.assertEqual(result["answers"]["probe"]["noul"], 0.99)
        self.assertEqual(result["usage"]["input_tokens"], 1000)
        self.assertAlmostEqual(result["usage"]["estimated_input_cost_usd"], 0.000042)

    def test_classify_command_uses_structured_answers_and_redacts_sensitive_output(self):
        seen = {}

        def opener(request, timeout):
            seen["body"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(classification_response())

        report = jev_engine.classify_command(
            command="lk build",
            arguments=["--api-key", "should-never-be-sent", "b" * 64],
            exit_code=1,
            command_output=(
                "build failed for https://example.invalid/v2/path-token-secret?api_key=ultra-secret "
                "Authorization: Bearer bearer-secret "
                "private key 0x" + "a" * 64 + " bare-secret " + "c" * 64
            ),
            opener=opener,
        )
        state_text = json.dumps(seen["body"]["state"])
        self.assertNotIn("should-never-be-sent", state_text)
        self.assertNotIn("b" * 64, state_text)
        self.assertNotIn("ultra-secret", state_text)
        self.assertNotIn("path-token-secret", state_text)
        self.assertNotIn("example.invalid", state_text)
        self.assertNotIn("bearer-secret", state_text)
        self.assertNotIn("0x" + "a" * 64, state_text)
        self.assertNotIn("c" * 64, state_text)
        self.assertEqual(report["outcome"], "actionable_failure")
        self.assertEqual(report["attention"], "review")
        self.assertTrue(report["needs_explanation"])
        self.assertEqual(report["suggested_response"], "explain_observation")
        self.assertEqual(report["usage"]["input_tokens"], 500)
        rendered = jev_engine.render_classification(report, "lk build")
        self.assertIn("JEV DECISION", rendered)
        self.assertIn("not a verdict", rendered.lower())
        self.assertIn("Estimated Jev input cost", rendered)

    def test_local_guard_counts_provider_failures_and_stops_after_daily_limit(self):
        config = ai_harness.load_config()
        config["jev_free_tier_mode"] = True
        config["jev_daily_call_limit"] = 1
        ai_harness.save_config(config)

        def rate_limited(request, timeout):
            raise HTTPError(jev_engine.API_URL, 429, "rate limited", {}, None)

        question = {
            "probe": {
                "type": "noul",
                "instructions": "Is this only a small connectivity probe?",
            }
        }
        with self.assertRaises(jev_engine.JevError) as failed:
            jev_engine.evaluate(state="small fixed probe", questions=question, opener=rate_limited)
        self.assertIn("429", str(failed.exception))
        budget = ai_harness.autonomy_budget_status()
        self.assertEqual(budget["calls_today"], 1)
        self.assertEqual(budget["remaining"], 0)
        with self.assertRaises(RuntimeError) as exhausted:
            jev_engine.evaluate(state="another probe", questions=question, opener=rate_limited)
        self.assertIn("cap has been reached", str(exhausted.exception))

    def test_exact_repeat_uses_private_cache_and_does_not_send_twice(self):
        config = ai_harness.load_config()
        config["jev_free_tier_mode"] = True
        config["jev_daily_call_limit"] = 1
        ai_harness.save_config(config)
        calls = []

        def opener(request, timeout):
            calls.append(request)
            return FakeResponse({
                "model": "jev-1.14.0",
                "answers": {"probe": {"type": "noul", "noul": 0.9}},
                "usage": {"input_tokens": 100, "output_tokens": 10},
            })

        request = {
            "state": {"probe": "fixed data"},
            "questions": {"probe": {
                "type": "noul",
                "instructions": "Does this describe fixed data?",
            }},
            "opener": opener,
        }
        first = jev_engine.evaluate(**request)
        second = jev_engine.evaluate(**request)
        self.assertEqual(first, second)
        self.assertEqual(len(calls), 1)
        budget = ai_harness.autonomy_budget_status()
        self.assertEqual(budget["calls_today"], 1)
        cached_text = jev_engine.cache_path().read_text(encoding="utf-8")
        self.assertNotIn("fixed data", cached_text)
        self.assertNotIn("typesafe_test_key_0123456789", cached_text)

    def test_cli_setup_preserves_active_provider_when_both_provider_keys_exist(self):
        output = io.StringIO()
        with patch.dict(os.environ, {
            "TYPESAFE_API_KEY": "typesafe_env_key_0123456789",
            "JEVMODEL_API_KEY": "jevmodel_env_key_0123456789",
        }):
            with contextlib.redirect_stdout(output):
                self.assertEqual(ai_harness.main(["jev", "setup"]), 0)
        self.assertEqual(jev_engine.load_settings()["provider"], "typesafe")
        self.assertIn("TypeSafe official API", output.getvalue())

    def test_ctrl_c_at_jev_setup_prompt_exits_without_traceback_or_writes(self):
        output = io.StringIO()
        with patch("getpass.getpass", side_effect=KeyboardInterrupt):
            with contextlib.redirect_stderr(output):
                self.assertEqual(ai_harness.main(["jev", "setup", "--provider", "jevmodel"]), 130)
        self.assertIn("Cancelled by user", output.getvalue())
        self.assertNotIn("Traceback", output.getvalue())
        self.assertFalse(jev_engine.credentials_path().exists())
        self.assertFalse(jev_engine.settings_path().exists())

    def test_cli_setup_defaults_to_jevmodel_when_no_existing_provider_is_configured(self):
        # Preserve old TypeSafe keys in real installations, but choose the advertised
        # starter-token endpoint for a brand-new profile.
        jev_engine.settings_path().unlink(missing_ok=True)
        jev_engine.credentials_path().unlink(missing_ok=True)
        output = io.StringIO()
        with patch("getpass.getpass", return_value="jevmodel_test_key_0123456789"):
            with contextlib.redirect_stdout(output):
                self.assertEqual(ai_harness.main(["jev", "setup"]), 0)
        self.assertEqual(jev_engine.load_settings()["provider"], "jevmodel")
        self.assertTrue(jev_engine.status()["configured"])
        self.assertIn("JevModel", output.getvalue())
        self.assertIn("100,000 starter input tokens", output.getvalue())
        # Setup configures locally and must not contact the provider.
        self.assertNotIn("CONNECTIVITY PROBE", output.getvalue())

    def test_fresh_install_defaults_to_jevmodel_starter_token_provider(self):
        # Simulate a genuinely fresh user profile with no old TypeSafe key to preserve.
        jev_engine.settings_path().unlink(missing_ok=True)
        jev_engine.credentials_path().unlink(missing_ok=True)
        settings = jev_engine.load_settings()
        self.assertEqual(settings["provider"], "jevmodel")
        self.assertEqual(
            jev_engine.status()["endpoint"],
            "https://jevmodel.app/api/v1/systemone",
        )
        self.assertFalse(jev_engine.status()["configured"])

    def test_jevmodel_uses_its_response_envelope_and_does_not_send_model_field(self):
        jev_engine.configure(
            api_key="jevmodel_test_key_0123456789",
            provider="jevmodel",
            model="jev-latest",
            timeout_seconds=10,
        )
        seen = {}

        def opener(request, timeout):
            seen["url"] = request.full_url
            seen["headers"] = dict(request.header_items())
            seen["body"] = json.loads(request.data.decode("utf-8"))
            seen["timeout"] = timeout
            return FakeResponse({
                "code": 0,
                "message": "ok",
                "data": {
                    "request_id": "fixture-request",
                    "model": "jev-1.13.0",
                    "answers": {
                        "probe": {
                            "type": "noul",
                            "noul": 0.92,
                        }
                    },
                    "usage": {"inputTokens": 142},
                },
            })

        result = jev_engine.evaluate(
            state={"probe": "short fixture"},
            questions={"probe": {
                "type": "noul",
                "instructions": "Does the state describe a short fixture?",
                "criteria": {
                    "true": "The state describes a short fixture.",
                    "false": "The state does not describe a short fixture.",
                },
            }},
            opener=opener,
        )
        self.assertEqual(seen["url"], jev_engine.JEVMODEL_API_URL)
        self.assertEqual(seen["timeout"], 10)
        self.assertNotIn("model", seen["body"])
        self.assertIn("Bearer jevmodel_test_key_0123456789", seen["headers"]["Authorization"])
        self.assertEqual(result["provider"], "jevmodel")
        self.assertEqual(result["answers"]["probe"]["noul"], 0.92)
        self.assertEqual(result["usage"]["input_tokens"], 142)
        self.assertIsNone(result["usage"]["estimated_input_cost_usd"])
        self.assertEqual(jev_engine.status()["provider"], "jevmodel")
        # Preserve the existing TypeSafe credential if the user switches provider.
        self.assertEqual(jev_engine._saved_key("typesafe"), "typesafe_test_key_0123456789")

    def test_jevmodel_rejects_unapproved_choice_and_invalid_noul_responses(self):
        jev_engine.configure(
            api_key="jevmodel_test_key_0123456789",
            provider="jevmodel",
            model="jev-latest",
            timeout_seconds=10,
        )
        questions = {"decision": {
            "type": "choice",
            "instructions": "Choose an allowed result based on the supplied fixture.",
            "criteria": {
                "safe": "The fixture supports a safe result.",
                "review": "The fixture needs a manual review.",
            },
        }}

        def bad_choice(request, timeout):
            return FakeResponse({
                "code": 0,
                "message": "ok",
                "data": {
                    "answers": {"decision": {"type": "choice", "choice": "unapproved"}},
                    "usage": {"inputTokens": 20},
                },
            })

        with self.assertRaises(jev_engine.JevError) as rejected:
            jev_engine.evaluate(state={"fixture": "small"}, questions=questions, opener=bad_choice)
        self.assertIn("unapproved Choice label", str(rejected.exception))

        def bad_noul(request, timeout):
            return FakeResponse({
                "code": 0,
                "message": "ok",
                "data": {
                    "answers": {"check": {"type": "noul", "noul": 1.7}},
                    "usage": {"inputTokens": 20},
                },
            })

        with self.assertRaises(jev_engine.JevError) as rejected_probability:
            jev_engine.evaluate(
                state={"fixture": "small"},
                questions={"check": {
                    "type": "noul",
                    "instructions": "Does the fixture support this bounded statement?",
                    "criteria": {
                        "true": "The fixture supports the statement.",
                        "false": "The fixture does not support the statement.",
                    },
                }},
                opener=bad_noul,
            )
        self.assertIn("invalid Noul probability", str(rejected_probability.exception))

    def test_jevmodel_question_and_choice_limits_are_rejected_before_network(self):
        def never_call(*args, **kwargs):
            self.fail("Invalid JevModel request must not make a provider request")

        with self.assertRaises(jev_engine.JevError):
            jev_engine.evaluate(
                state="test",
                questions={
                    f"q{i}": {"type": "noul", "instructions": "Is this a probe?"}
                    for i in range(9)
                },
                opener=never_call,
            )
        with self.assertRaises(jev_engine.JevError):
            jev_engine.evaluate(
                state="test",
                questions={"choice": {
                    "type": "choice",
                    "instructions": "Pick a label.",
                    "criteria": {"only-one": "An invalid single option."},
                }},
                opener=never_call,
            )

    def test_jevmodel_noul_requires_true_false_criteria_before_network(self):
        jev_engine.configure(
            api_key="jevmodel_test_key_0123456789",
            provider="jevmodel",
            model="jev-latest",
            timeout_seconds=10,
        )

        def never_call(*args, **kwargs):
            self.fail("Invalid JevModel Noul must not make a provider request")

        with self.assertRaisesRegex(jev_engine.JevError, "must define true and false descriptions"):
            jev_engine.evaluate(
                state="fixed probe",
                questions={"probe": {
                    "type": "noul",
                    "instructions": "Is this a test probe?",
                }},
                opener=never_call,
            )

    def test_bad_question_is_rejected_before_network_call(self):
        def never_call(*args, **kwargs):
            self.fail("Invalid question must not make a provider request")

        with self.assertRaises(jev_engine.JevError):
            jev_engine.evaluate(
                state="test",
                questions={"bad": {"type": "choice", "instructions": "pick"}},
                opener=never_call,
            )


if __name__ == "__main__":
    unittest.main()
