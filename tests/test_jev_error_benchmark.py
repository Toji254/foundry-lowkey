from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from lowkey import jev_error_benchmark as bench


class JevErrorBenchmarkTests(unittest.TestCase):
    def test_taxonomy_and_corpus_labels_are_valid(self):
        case_ids = [case["id"] for case in bench.CASES]
        self.assertEqual(len(case_ids), len(set(case_ids)))
        for case in bench.CASES:
            self.assertIn(case["expected_stage"], bench.STAGES)
            self.assertIn(case["expected_cause"], bench.ROOT_CAUSES)

    def test_taxonomy_separates_stage_from_root_cause(self):
        self.assertIn("dependency_resolution", bench.STAGES)
        self.assertIn("compilation", bench.STAGES)
        self.assertIn("missing_dependency_or_import", bench.ROOT_CAUSES)
        self.assertIn("solidity_compile_diagnostic", bench.ROOT_CAUSES)
        self.assertNotEqual(
            bench.STAGES["dependency_resolution"],
            bench.ROOT_CAUSES["missing_dependency_or_import"],
        )

    def test_rules_route_missing_import_even_when_test_command_was_run(self):
        result = bench.classify_rules(
            'forge test failed during compilation: Source "src/interfaces/IToken.sol" not found. Compilation failed.'
        )
        self.assertEqual(result, {
            "stage": "dependency_resolution",
            "root_cause": "missing_dependency_or_import",
        })

    def test_rules_classify_configuration_and_member_diagnostic(self):
        config = bench.classify_rules(
            'failed to parse foundry.toml: invalid type: string "true", expected a boolean'
        )
        compiler = bench.classify_rules(
            'CompilerError: Member "safeTransferFrom" not found in contract IERC20'
        )
        self.assertEqual(config["stage"], "configuration")
        self.assertEqual(config["root_cause"], "invalid_configuration")
        self.assertEqual(compiler["stage"], "compilation")
        self.assertEqual(compiler["root_cause"], "solidity_compile_diagnostic")

    def test_rules_classify_rpc_limit_before_test_or_script_name(self):
        result = bench.classify_rules(
            "forge script failed: RPC endpoint returned HTTP 429 Too Many Requests"
        )
        self.assertEqual(result, {
            "stage": "rpc_transport",
            "root_cause": "rpc_rate_limit_or_quota",
        })

    def test_unknown_fallback_does_not_force_a_supported_cause(self):
        result = bench.classify_rules(
            "Verification plugin returned internal diagnostic E-7F3A with no further explanation."
        )
        self.assertEqual(result, {"stage": "unknown", "root_cause": "unknown"})

    def test_parse_jev_response_accepts_typed_answers_and_filters_bad_probabilities(self):
        parsed = bench.parse_jev_response({
            "model": "jev-1.14.0",
            "answers": {
                "failure_stage": {
                    "type": "choice",
                    "choice": "dependency_resolution",
                    "probabilities": {
                        "dependency_resolution": 0.9,
                        "compilation": 0.1,
                        "made_up": 1.0,
                        "configuration": "not-a-number",
                    },
                    "confidence": 0.91,
                },
                "root_cause": {
                    "type": "choice",
                    "choice": "missing_dependency_or_import",
                    "probabilities": {"missing_dependency_or_import": 1.0},
                    "confidence": 0.99,
                },
            },
            "usage": {"input_tokens": 100, "output_tokens": 10},
        })
        self.assertEqual(parsed["stage"]["choice"], "dependency_resolution")
        self.assertEqual(
            parsed["stage"]["probabilities"],
            {"dependency_resolution": 0.9, "compilation": 0.1},
        )
        self.assertEqual(parsed["root_cause"]["choice"], "missing_dependency_or_import")
        self.assertEqual(parsed["usage"]["input_tokens"], 100)

    def test_parse_jev_response_rejects_missing_answer_object(self):
        with self.assertRaises(bench.JevRequestError):
            bench.parse_jev_response({"model": "jev-latest"})

    def test_call_jev_sends_key_in_header_not_json_state(self):
        captured = {}
        response_body = json.dumps({
            "model": "jev-1.14.0",
            "answers": {
                "failure_stage": {"type": "choice", "choice": "compilation", "probabilities": {"compilation": 1.0}},
                "root_cause": {"type": "choice", "choice": "solidity_compile_diagnostic", "probabilities": {"solidity_compile_diagnostic": 1.0}},
            },
            "usage": {"input_tokens": 20, "output_tokens": 5},
        }).encode("utf-8")

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size=-1):
                return response_body

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["body"] = request.data.decode("utf-8")
            captured["timeout"] = timeout
            return FakeResponse()

        result = bench.call_jev(
            "CompilerError: type mismatch",
            api_key="never-write-this-key",
            urlopen_fn=fake_urlopen,
        )
        self.assertEqual(captured["url"], bench.JEV_ENDPOINT)
        self.assertEqual(captured["authorization"], "Bearer never-write-this-key")
        self.assertNotIn("never-write-this-key", captured["body"])
        self.assertIn("failure_stage", captured["body"])
        self.assertEqual(result["stage"]["choice"], "compilation")
        self.assertGreaterEqual(result["latency_ms"], 0)

    def test_build_report_records_failed_provider_calls_without_losing_rules(self):
        def unavailable(_diagnostic, **_kwargs):
            raise bench.JevRequestError("rate-limit", "Rate-limited.")

        report = bench.build_report(
            cases=bench.CASES[:1],
            with_jev=True,
            jev_caller=unavailable,
        )
        self.assertEqual(report["summary"]["case_count"], 1)
        self.assertEqual(report["cases"][0]["rules_stage"], "dependency_resolution")
        self.assertEqual(report["cases"][0]["jev_error"]["category"], "rate-limit")
        self.assertEqual(report["summary"]["jev"]["request_errors"], 1)
        self.assertEqual(report["summary"]["jev"]["stage"]["accuracy"], 0.0)

    def test_build_report_uses_rules_without_a_jev_request(self):
        with patch.object(bench, "call_jev", side_effect=AssertionError("must not call provider")):
            report = bench.build_report(cases=bench.CASES[:2], with_jev=False)
        self.assertFalse(report["jev_enabled"])
        self.assertNotIn("jev", report["summary"])
        self.assertEqual(report["summary"]["rules"]["stage"]["total"], 2)


if __name__ == "__main__":
    unittest.main()
