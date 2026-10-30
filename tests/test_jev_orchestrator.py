import tempfile
import unittest
from pathlib import Path

from lowkey.jev_orchestrator import (
    is_browser_request,
    is_list_tabs_request,
    parse_click_request,
    parse_new_tab_request,
    urls_match,
    verify_click_effect,
    is_browser_change_tool,
    is_inspection_tool,
    resolve_workspace_path,
    validate_lk_argv,
)


class JevOrchestratorTests(unittest.TestCase):
    def test_browser_requests_are_detected(self):
        self.assertTrue(is_browser_request("list my open Brave tabs"))
        self.assertTrue(is_browser_request("open https://example.com"))
        self.assertFalse(is_browser_request("explain Solidity mappings"))

    def test_common_tab_list_requests_use_native_shortcut(self):
        self.assertTrue(is_list_tabs_request("list my open Brave tabs"))
        self.assertTrue(is_list_tabs_request("show the tabs"))
        self.assertTrue(is_list_tabs_request("what tabs are open?"))
        self.assertFalse(is_list_tabs_request("open a new tab"))

    def test_open_url_in_new_tab_is_parsed_safely(self):
        self.assertEqual(
            parse_new_tab_request("open https://example.com in a new tab"),
            "https://example.com",
        )
        self.assertEqual(
            parse_new_tab_request("visit https://example.com/docs in a new page"),
            "https://example.com/docs",
        )
        self.assertIsNone(
            parse_new_tab_request("do not open https://example.com in a new tab")
        )
        self.assertIsNone(parse_new_tab_request("open a new tab"))
        self.assertIsNone(
            parse_new_tab_request("open javascript:alert(1) in a new tab")
        )

    def test_url_verification_tolerates_trailing_slash(self):
        self.assertTrue(urls_match("https://example.com", "https://example.com/"))
        self.assertTrue(
            urls_match("https://example.com/docs/", "https://example.com/docs")
        )
        self.assertFalse(
            urls_match("https://example.com/a", "https://example.com/b")
        )

    def test_click_requests_parse_label_role_and_page(self):
        self.assertEqual(
            parse_click_request('click the "Show Sidebar" button on Venice'),
            ("Show Sidebar", "button", "Venice"),
        )
        self.assertEqual(
            parse_click_request("click Sign in button on Oracle tab"),
            ("Sign in", "button", "Oracle"),
        )
        self.assertEqual(
            parse_click_request('click "Use Classic Chat" link'),
            ("Use Classic Chat", "link", None),
        )
        self.assertIsNone(parse_click_request("do not click the Delete button"))
        self.assertIsNone(parse_click_request("open a new tab"))

    def test_sidebar_click_requires_sidebar_controls_to_be_visible(self):
        target = {"label": "Show Sidebar", "role": "button"}
        before = 'uid=1_4 button "Show Sidebar"'
        after = (
            'uid=1_15 dialog description="Toggle sidebar Search Agentic '
            'Chat Studio More API Folders Add folder Chats"\\n'
            'uid=1_17 button "Toggle sidebar"'
        )
        verified, message = verify_click_effect(
            target=target,
            before_snapshot=before,
            after_snapshot=after,
            before_pages_text="Pages\\n1: Venice (https://venice.ai/chat/agent) [selected]",
            after_pages_text="Pages\\n1: Venice (https://venice.ai/chat/agent) [selected]",
            before_title="Venice",
            before_url="https://venice.ai/chat/agent",
            after_title="Venice",
            after_url="https://venice.ai/chat/agent",
        )
        self.assertTrue(verified, message)
        self.assertIn("sidebar", message)

    def test_incidental_snapshot_change_does_not_confirm_generic_button(self):
        verified, message = verify_click_effect(
            target={"label": "Copy", "role": "button"},
            before_snapshot='uid=1_10 button "Copy"',
            after_snapshot='uid=1_10 button "Copy"\\nuid=1_11 status "Updated"',
            before_pages_text="Pages\\n1: Venice (https://venice.ai/chat/agent) [selected]",
            after_pages_text="Pages\\n1: Venice (https://venice.ai/chat/agent) [selected]",
            before_title="Venice",
            before_url="https://venice.ai/chat/agent",
            after_title="Venice",
            after_url="https://venice.ai/chat/agent",
        )
        self.assertFalse(verified)
        self.assertIn("no action-specific outcome", message)

    def test_link_navigation_is_confirmed_by_url_change(self):
        verified, message = verify_click_effect(
            target={"label": "Use Classic Chat", "role": "link",
                    "url": "https://venice.ai/chat/classic"},
            before_snapshot='uid=1_5 link "Use Classic Chat" url="https://venice.ai/chat/classic"',
            after_snapshot='RootWebArea "Classic Chat" url="https://venice.ai/chat/classic"',
            before_pages_text="Pages\\n1: Venice (https://venice.ai/chat/agent) [selected]",
            after_pages_text="Pages\\n1: Classic Chat (https://venice.ai/chat/classic) [selected]",
            before_title="Venice",
            before_url="https://venice.ai/chat/agent",
            after_title="Classic Chat",
            after_url="https://venice.ai/chat/classic",
        )
        self.assertTrue(verified, message)
        self.assertIn("URL changed", message)

    def test_path_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "workspace"
            root.mkdir()
            with self.assertRaises(ValueError):
                resolve_workspace_path(root, "../outside.txt")

    def test_secret_looking_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                resolve_workspace_path(root, ".env")
            with self.assertRaises(ValueError):
                resolve_workspace_path(root, "private/key.pem")

    def test_lk_tool_rejects_unsafe_commands(self):
        self.assertEqual(validate_lk_argv(["read", "balanceOf"]), ["read", "balanceOf"])
        with self.assertRaises(ValueError):
            validate_lk_argv(["send", "0x1234"])
        with self.assertRaises(ValueError):
            validate_lk_argv(["deploy", "Contract"])

    def test_browser_inspection_and_mutation_tools_are_distinguished(self):
        inspect_tool = {
            "name": "browser_list_tabs",
            "description": "List open browser tabs and their current URLs",
        }
        click_tool = {
            "name": "browser_click",
            "description": "Click an element in the current page",
        }
        self.assertTrue(is_inspection_tool(inspect_tool))
        self.assertFalse(is_inspection_tool(click_tool))
        self.assertTrue(is_browser_change_tool(click_tool))


if __name__ == "__main__":
    unittest.main()
