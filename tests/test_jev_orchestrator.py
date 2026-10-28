import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from lowkey import jev_orchestrator as jev


class FakeMCP:
    def __init__(self, tools, response=None):
        self._tools = tools
        self.response = response or {"structuredContent": {"ok": True}}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def tools(self):
        return self._tools

    def call(self, name, arguments):
        self.calls.append((name, dict(arguments)))
        return self.response


class JevOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        env = patch.dict(os.environ, {
            "XDG_CONFIG_HOME": str(self.root / "config"),
            "XDG_STATE_HOME": str(self.root / "state"),
        })
        env.start()
        self.addCleanup(env.stop)

    def test_help_is_operational_and_mentions_optional_slash(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(jev.main(["help"]), 0)
        text = out.getvalue()
        self.assertIn("jev ask list my open Brave tabs", text)
        self.assertIn("Slash prefixes are optional", text)
        self.assertIn("jev autonomy on|off|status", text)

    def test_slash_prefix_is_optional_and_removed(self):
        self.assertEqual(jev._normalize_request("/list my tabs"), "list my tabs")
        self.assertEqual(jev._normalize_request("/// list files"), "list files")
        self.assertEqual(jev._normalize_request("list files"), "list files")

    def test_registry_lists_real_capability_groups(self):
        names = {item["name"] for item in jev.capability_registry()}
        self.assertTrue({"browser.tabs", "browser.navigate", "workspace.read", "lowkey.workflow"} <= names)

    def test_tab_request_selects_list_tool_and_returns_its_result(self):
        fake = FakeMCP(
            [{"name": "list_tabs", "description": "List all open browser tabs", "inputSchema": {"type": "object", "properties": {}, "required": []}}],
            {"structuredContent": {"tabs": [{"title": "Example", "url": "https://example.com"}]}},
        )
        with patch.object(jev, "_MCPStdioClient", return_value=fake):
            result = jev._route_request("list the currently open tabs in my normal Brave browser", explicit_yes=False)
        self.assertIn("list_tabs", result)
        self.assertIn("https://example.com", result)
        self.assertEqual(fake.calls, [("list_tabs", {})])

    def test_state_changing_browser_action_is_not_run_when_autonomy_is_off(self):
        fake = FakeMCP([{"name": "navigate_page", "description": "Navigate a tab to a URL", "inputSchema": {
            "type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]
        }}])
        with patch.object(jev, "_MCPStdioClient", return_value=fake) as client:
            result = jev._route_request("navigate to https://example.com", explicit_yes=False)
        self.assertIn("did not change your browser", result)
        client.assert_not_called()

    def test_explicit_approval_sends_url_to_registered_browser_tool(self):
        fake = FakeMCP([{"name": "navigate_page", "description": "Navigate a tab to a URL", "inputSchema": {
            "type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]
        }}])
        with patch.object(jev, "_MCPStdioClient", return_value=fake):
            result = jev._route_request("navigate to https://example.com/path", explicit_yes=True)
        self.assertIn("performed", result)
        self.assertEqual(fake.calls, [("navigate_page", {"url": "https://example.com/path"})])

    def test_workspace_list_and_read_stay_inside_project(self):
        (self.root / "src").mkdir()
        (self.root / "src" / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
        with patch.object(jev, "_safe_project_root", return_value=self.root):
            listing = jev._route_request("list files", explicit_yes=False)
            contents = jev._route_request("read file src/Vault.sol", explicit_yes=False)
        self.assertIn("Vault.sol", listing)
        self.assertIn("contract Vault", contents)

    def test_workspace_read_blocks_secrets_and_path_traversal(self):
        (self.root / ".env").write_text("SECRET=value", encoding="utf-8")
        (self.root.parent / "outside-jev-test.txt").write_text("outside", encoding="utf-8")
        with patch.object(jev, "_safe_project_root", return_value=self.root):
            with self.assertRaises(jev.JevOrchestratorError):
                jev._workspace_action("read file .env", "workspace.read")
            with self.assertRaises(jev.JevOrchestratorError):
                jev._resolve_workspace_file(self.root, "../outside-jev-test.txt")
        (self.root.parent / "outside-jev-test.txt").unlink()

    def test_search_is_case_insensitive_and_skips_sensitive_files(self):
        (self.root / "src").mkdir()
        (self.root / "src" / "Vault.sol").write_text("function withdraw() external onlyOwner {}", encoding="utf-8")
        (self.root / ".env").write_text("onlyOwner=secret", encoding="utf-8")
        with patch.object(jev, "_safe_project_root", return_value=self.root):
            result = jev._workspace_action("search files for 'ONLYOWNER'", "workspace.search")
        self.assertIn("Vault.sol:1", result)
        self.assertNotIn(".env", result)

    def test_native_workflow_needs_explicit_approval_by_default(self):
        with patch.object(jev.subprocess, "run") as run:
            result = jev._route_request("run the project tests", explicit_yes=False)
        self.assertIn("did not run it", result)
        run.assert_not_called()

    def test_approved_native_workflow_uses_argument_list_not_shell(self):
        fake_result = Mock(returncode=0, stdout="Ran 3 tests")
        with patch.object(jev.shutil, "which", return_value="/bin/true"):
            with patch.object(jev.subprocess, "run", return_value=fake_result) as run:
                result = jev._route_request("run the project tests", explicit_yes=True)
        self.assertIn("finished successfully", result)
        self.assertTrue(run.called)
        args, kwargs = run.call_args
        self.assertIsInstance(args[0], list)
        self.assertNotIn("shell", kwargs)
        self.assertIn("test", args[0])

    def test_high_risk_transaction_and_shell_requests_are_rejected(self):
        for request in ("deploy this contract", "sign transaction now", "run rm -rf ."):
            with self.subTest(request=request):
                with self.assertRaises(jev.JevOrchestratorError):
                    jev._route_request(request, explicit_yes=True)

    def test_autonomy_switch_is_persisted_and_independent(self):
        self.assertFalse(jev._read_config()["autonomy_enabled"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(jev.main(["autonomy", "on"]), 0)
        self.assertTrue(jev._read_config()["autonomy_enabled"])
        self.assertIn("is ON", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(jev.main(["autonomy", "off"]), 0)
        self.assertFalse(jev._read_config()["autonomy_enabled"])

    def test_url_extraction_rejects_embedded_credentials(self):
        self.assertEqual(jev._extract_url("go to https://example.com/path."), "https://example.com/path")
        self.assertIsNone(jev._extract_url("go to https://user:password@example.com"))


if __name__ == "__main__":
    unittest.main()
