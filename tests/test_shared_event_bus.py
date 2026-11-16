import json
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import audit_context
import error_context
import lk


class SharedEventBusTests(unittest.TestCase):
    def _root(self, parent):
        root = pathlib.Path(parent) / "project"
        root.mkdir()
        (root / "foundry.toml").write_text("[profile.default]" + chr(10), encoding="utf-8")
        return root

    def test_read_events_returns_only_the_newest_bounded_records_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            for number in range(5):
                audit_context.emit(
                    "sample", root, tool="test", summary=str(number), data={"number": number}
                )

            records = audit_context.read_events(root, limit=2)

            self.assertEqual([item["data"]["number"] for item in records], [3, 4])
            self.assertEqual(audit_context.read_events(root, limit=0), [])

    def test_cli_completion_publishes_metadata_without_arguments_or_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            sensitive_argument = "https://user:password@example.invalid/private-rpc"
            sensitive_output = "PRIVATE_KEY=0x" + "a" * 64
            with patch.object(error_context, "record_command_event"):
                lk._record_shared_command_event(
                    root,
                    "send",
                    ["--rpc-url", sensitive_argument, "--private-key", sensitive_output],
                    0,
                    sensitive_output,
                )

            records = audit_context.read_events(root)
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["type"], "command-completed")
            self.assertEqual(records[0]["tool"], "cli")
            self.assertEqual(records[0]["status"], "completed")
            self.assertEqual(records[0]["data"], {"command": "send", "exit_code": 0})
            rendered = json.dumps(records)
            self.assertNotIn("password", rendered)
            self.assertNotIn("PRIVATE_KEY", rendered)
            self.assertNotIn("private-rpc", rendered)

    def test_help_only_commands_do_not_write_to_audit_event_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            with patch.object(error_context, "record_command_event"):
                lk._record_shared_command_event(root, "build", ["--help"], 0, "usage")
            self.assertEqual(audit_context.read_events(root), [])

    def test_shared_command_context_exposes_recent_audit_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._root(tmp)
            audit_context.emit("signal-added", root, tool="slither", summary="candidate")
            history = {"project_label": "project", "events": []}
            with patch.object(error_context, "read_project_context", return_value=history):
                context = lk._attach_shared_command_context({}, root)

            self.assertEqual(context["events"], [])
            self.assertEqual(context["audit_events"][-1]["type"], "signal-added")
            self.assertEqual(context["audit_events"][-1]["summary"], "candidate")


if __name__ == "__main__":
    unittest.main()
