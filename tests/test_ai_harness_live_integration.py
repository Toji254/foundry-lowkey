"""Loopback HTTP integration tests for the native AI review request path.

These tests exercise the real urllib request/response code against a local
OpenAI-compatible fixture. They never contact an external provider or incur
model charges.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from lowkey import ai_harness as ai


VALID_REVIEW = {
    "summary": "Vault tracks deposits and exposes a withdrawal path.",
    "contract_roles": [
        {
            "name": "Vault",
            "purpose": "Holds user balances.",
            "evidence": "src/Vault.sol: deposit and withdraw functions.",
        }
    ],
    "invariants": [
        {
            "statement": "A user cannot withdraw more than their credited balance.",
            "rationale": "Withdrawals must be bounded by recorded liabilities.",
            "source": "src/Vault.sol: balances mapping and withdraw function.",
        }
    ],
    "open_questions": ["Are token transfer return values checked?"],
    "deployment_considerations": ["Confirm the intended owner is assigned at deployment."],
}


def provider_envelope(review_content: str) -> bytes:
    """Wrap model JSON in the OpenAI-compatible chat-completions envelope."""
    return json.dumps({
        "choices": [{"message": {"content": review_content}}],
    }).encode("utf-8")


class ReviewHTTPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.server.received_path = self.path
        self.server.received_headers = {
            key.lower(): value for key, value in self.headers.items()
        }
        self.server.received_body = self.rfile.read(length)

        body = self.server.response_body
        self.send_response(self.server.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Keep request bodies/headers out of test output.
        return


class AIHarnessLiveRequestIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "project"
        for folder in ("src", "test", "lib/example/src"):
            (self.root / folder).mkdir(parents=True, exist_ok=True)

        self.env_patch = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(Path(self.tmp.name) / "config"),
            "XDG_DATA_HOME": str(Path(self.tmp.name) / "data"),
            "XDG_STATE_HOME": str(Path(self.tmp.name) / "state"),
        })
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

        (self.root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\nlibs = ["lib"]\n',
            encoding="utf-8",
        )
        (self.root / "src" / "Vault.sol").write_text(
            'pragma solidity ^0.8.20;\n'
            'contract Vault {\n'
            '    string private apiKey = "LIVE_REVIEW_SECRET_SENTINEL";\n'
            '    mapping(address => uint256) public balances;\n'
            '    function withdraw(uint256 amount) external {\n'
            '        require(amount <= balances[msg.sender]);\n'
            '    }\n'
            '}\n',
            encoding="utf-8",
        )
        (self.root / "test" / "Vault.t.sol").write_text(
            'contract TestVault { string constant MARKER = "LIVE_REVIEW_TEST_SENTINEL"; }\n',
            encoding="utf-8",
        )
        (self.root / "lib" / "example" / "src" / "Dependency.sol").write_text(
            'contract Dependency { string constant MARKER = "LIVE_REVIEW_DEPENDENCY_SENTINEL"; }\n',
            encoding="utf-8",
        )

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), ReviewHTTPHandler)
        self.server.daemon_threads = True
        self.server.response_status = 200
        self.server.response_body = provider_envelope(json.dumps(VALID_REVIEW))
        self.server.received_path = None
        self.server.received_headers = {}
        self.server.received_body = b""
        self.server_thread = threading.Thread(
            target=self.server.serve_forever, name="lowkey-ai-test-server", daemon=True
        )
        self.server_thread.start()
        self.addCleanup(self._stop_server)

    def _stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)

    def _configure_local_provider(self):
        base_url = f"http://127.0.0.1:{self.server.server_port}/v1"
        ai.configure(
            provider="openai-compatible",
            model="lowkey-fixture-model",
            base_url=base_url,
            api_key="fixture-key-never-real",
            timeout_seconds=5,
        )

    def test_real_http_round_trip_reviews_redacted_project_and_logs_metadata_only(self):
        self._configure_local_provider()

        result = ai.review_project_protocol(self.root, "Vault")

        self.assertEqual(result["summary"], VALID_REVIEW["summary"])
        self.assertEqual(result["contract_roles"][0]["name"], "Vault")
        self.assertEqual(result["invariants"][0]["statement"], VALID_REVIEW["invariants"][0]["statement"])
        self.assertFalse(result["_lowkey_meta"]["verified"])
        self.assertEqual(self.server.received_path, "/v1/chat/completions")
        self.assertEqual(
            self.server.received_headers.get("authorization"),
            "Bearer fixture-key-never-real",
        )

        request = json.loads(self.server.received_body.decode("utf-8"))
        self.assertEqual(request["model"], "lowkey-fixture-model")
        self.assertEqual(request["response_format"], {"type": "json_object"})
        self.assertFalse(request["stream"])
        user_message = json.loads(request["messages"][1]["content"])
        self.assertEqual(user_message["purpose"], "lab_protocol_review")
        context = user_message["context"]
        serialized_context = json.dumps(context, ensure_ascii=False)
        self.assertIn("[REDACTED]", serialized_context)
        self.assertNotIn("LIVE_REVIEW_SECRET_SENTINEL", serialized_context)
        self.assertNotIn("LIVE_REVIEW_TEST_SENTINEL", serialized_context)
        self.assertNotIn("LIVE_REVIEW_DEPENDENCY_SENTINEL", serialized_context)
        paths = [entry["path"] for entry in context["source_files"]]
        self.assertIn("src/Vault.sol", paths)
        self.assertFalse(any(path.startswith("test/") for path in paths))
        self.assertFalse(any(path.startswith("lib/") for path in paths))

        event_log = (ai._state_home() / "ai-events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"outcome": "completed"', event_log)
        self.assertIn("lab_protocol_review", event_log)
        for private_value in (
            "fixture-key-never-real",
            "LIVE_REVIEW_SECRET_SENTINEL",
            "LIVE_REVIEW_TEST_SENTINEL",
            "LIVE_REVIEW_DEPENDENCY_SENTINEL",
            "contract logic to help an auditor",
        ):
            self.assertNotIn(private_value, event_log)

    def test_live_http_auth_failure_is_actionable_without_leaking_key(self):
        self._configure_local_provider()
        self.server.response_status = 401
        self.server.response_body = b'{"error":"fixture-key-never-real must not be echoed"}'

        with self.assertRaises(ai.AIUnavailable) as caught:
            ai.request_structured(
                purpose="protocol_analysis",
                task="check provider failure handling",
                context={"fixture": True},
            )

        self.assertIn("authentication failed", str(caught.exception))
        self.assertNotIn("fixture-key-never-real", str(caught.exception))
        event_log = (ai._state_home() / "ai-events.jsonl").read_text(encoding="utf-8")
        self.assertIn('"outcome": "error"', event_log)
        self.assertNotIn("fixture-key-never-real", event_log)
        self.assertNotIn("fixture-key-never-real", ai.config_path().read_text(encoding="utf-8"))

    def test_live_http_response_with_invalid_nested_review_schema_is_rejected(self):
        self._configure_local_provider()
        malformed = {
            "summary": "Incomplete review.",
            "contract_roles": [{"name": "Vault", "purpose": "Stores balances"}],
            "invariants": [],
            "open_questions": [],
            "deployment_considerations": [],
        }
        self.server.response_body = provider_envelope(json.dumps(malformed))

        with self.assertRaisesRegex(ai.AIHarnessError, "non-empty 'evidence'"):
            ai.review_project_protocol(self.root, "Vault")


if __name__ == "__main__":
    unittest.main()
