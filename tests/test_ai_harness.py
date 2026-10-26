import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import ai_harness as ai


class AIHarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(Path(self.tmp.name) / "config"),
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
