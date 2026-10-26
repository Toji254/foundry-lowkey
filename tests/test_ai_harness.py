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

    def test_disabled_and_unconfigured_by_default(self):
        value = ai.status()
        self.assertFalse(value["enabled"])
        self.assertFalse(value["configured"])
        self.assertFalse(value["usable"])

    def test_api_key_is_separate_and_permissions_are_private(self):
        ai.configure(provider="deepseek", model="deepseek-flash", api_key="example-secret")
        self.assertNotIn("example-secret", ai.config_path().read_text(encoding="utf-8"))
        self.assertEqual(json.loads(ai.credentials_path().read_text(encoding="utf-8"))["deepseek"], "example-secret")
        self.assertEqual(ai.credentials_path().stat().st_mode & 0o777, 0o600)

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
                "contract Vault { function withdraw() external {} }", encoding="utf-8"
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

    def test_large_source_and_approved_memory_fit_context_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
            (root / "src").mkdir()
            for index in range(18):
                (root / "src" / f"Vault{index}.sol").write_text(
                    "contract Vault" + str(index) + " { " + ("uint256 public value; " * 420) + " }",
                    encoding="utf-8",
                )
            for index in range(8):
                proposal = memory.propose_lesson(
                    kind="test-procedure",
                    title=f"Validated procedure {index}",
                    lesson=("Assert the state transition and the relevant emitted event. " * 10),
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

    def test_local_ollama_needs_no_key(self):
        ai.configure(provider="ollama", model="qwen2.5-coder")
        self.assertTrue(ai.status()["usable"])

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


if __name__ == "__main__":
    unittest.main()
