import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "audit_context.py"

spec = importlib.util.spec_from_file_location("audit_context", MODULE)
audit_context = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit_context
spec.loader.exec_module(audit_context)


class AuditContextTests(unittest.TestCase):
    def test_load_creates_project_scoped_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            context = audit_context.load(root)
            self.assertEqual(context["project"]["root"], str(root))
            self.assertEqual(context["target"]["contract"], None)
            self.assertEqual(context["signals"], [])

    def test_source_link_preserves_relative_label_and_targets_exact_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            with patch.dict("os.environ", {"TERM_PROGRAM": "vscode"}):
                linked = audit_context.source_link(
                    "src/Vault.sol",
                    42,
                    7,
                    root,
                )
        self.assertIn("src/Vault.sol:42:7", linked)
        self.assertIn("vscode://file/", linked)
        self.assertIn(":42:7", linked)


    def test_update_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            audit_context.update(root, actor="attacker", rpc="http://127.0.0.1:8545")
            loaded = audit_context.load(root)
            self.assertEqual(loaded["actor"], "attacker")
            self.assertEqual(loaded["rpc"], "http://127.0.0.1:8545")

    def test_signal_is_stable_and_updates_without_losing_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            signal = {
                "tool": "slither",
                "check": "low-level-calls",
                "title": "Low-level external call",
                "impact": "Informational",
                "confidence": "High",
                "file": "src/Vault.sol",
                "line": 42,
            }
            first = audit_context.add_signal(signal, root)
            first_id = first["id"]
            self.assertTrue(first_id.startswith("SLITHER-"))

            context = audit_context.load(root)
            context["signals"][0]["status"] = "investigating"
            audit_context.save(context, root)

            second = audit_context.add_signal(signal, root)
            self.assertEqual(second["id"], first_id)
            self.assertEqual(len(audit_context.signals(root)), 1)
            self.assertEqual(second["status"], "investigating")

    def test_update_signal_status_records_triage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            signal = audit_context.add_signal({
                "tool": "slither",
                "check": "tx-origin",
                "title": "tx.origin used for authorization",
                "impact": "Medium",
                "confidence": "High",
                "file": "src/Auth.sol",
                "line": 20,
            }, root)
            updated = audit_context.update_signal_status(
                signal["id"],
                "investigating",
                root,
                note="Checking the caller boundary",
            )
            self.assertEqual(updated["status"], "investigating")
            self.assertEqual(updated["triage_note"], "Checking the caller boundary")
            events = audit_context.events_path(root).read_text(encoding="utf-8")
            self.assertIn("signal-status", events)


    def test_emit_creates_append_only_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            audit_context.emit("test-event", root, tool="test", summary="hello")
            lines = audit_context.events_path(root).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            event = json.loads(lines[0])
            self.assertEqual(event["type"], "test-event")
            self.assertEqual(event["tool"], "test")


if __name__ == "__main__":
    unittest.main()
