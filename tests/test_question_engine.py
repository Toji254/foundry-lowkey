import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "question_engine.py"

spec = importlib.util.spec_from_file_location("lowkeycast_questions", MODULE)
questions = importlib.util.module_from_spec(spec)
spec.loader.exec_module(questions)


class QuestionEngineTests(unittest.TestCase):
    def make_project(self, source="def main():\n    return 1\n", readme="# Demo\n"):
        temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(temp.name)
        (root / "src").mkdir()
        (root / "src" / "main.py").write_text(source, encoding="utf-8")
        if readme:
            (root / "README.md").write_text(readme, encoding="utf-8")
        return temp, root

    def test_stable_universe_is_bigger_than_visible_frontier(self):
        temp, root = self.make_project()
        self.addCleanup(temp.cleanup)
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            all_questions = questions.enabled_questions(root)
            visible = questions.rank_questions(root, limit=3)
        self.assertGreater(len(all_questions), 3)
        self.assertLessEqual(len(visible), 3)
        self.assertEqual(visible[0]["question"].id, "ARCH-001")

    def test_answering_current_question_moves_frontier(self):
        temp, root = self.make_project()
        self.addCleanup(temp.cleanup)
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root), \
             patch.object(questions.audit_context, "is_audit_project", return_value=True), \
             patch.object(questions.audit_context, "audit_dir", return_value=root / ".audit"), \
             patch.object(questions.audit_context, "events_path", return_value=root / ".audit" / "events.jsonl"), \
             patch.object(questions.audit_context, "load", return_value={"project": {"root": str(root)}, "target": {}, "latest": {}, "signals": [], "tools": {}}), \
             patch.object(questions.audit_context, "emit"):
            first = questions.current_question(root)
            self.assertEqual(first["question"].id, "ARCH-001")
            self.assertEqual(questions.answer_current("ANSWERED", note="read the README", root=root), 0)
            second = questions.current_question(root)
            self.assertNotEqual(second["question"].id, "ARCH-001")

    def test_blockchain_pack_requires_blockchain_evidence(self):
        temp, root = self.make_project(source="contract Demo { function withdraw() public {} }\n")
        self.addCleanup(temp.cleanup)
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            feature = questions.detect_features(root)
            self.assertFalse(feature["features"]["blockchain"])
        (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            feature = questions.detect_features(root)
            self.assertTrue(feature["features"]["blockchain"])

    def test_web_pack_is_contextual_not_always_on(self):
        temp, root = self.make_project(source="from fastapi import FastAPI\napp = FastAPI()\n")
        self.addCleanup(temp.cleanup)
        (root / "pyproject.toml").write_text("[project]\ndependencies=['fastapi']\n", encoding="utf-8")
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            enabled = {q.id for q in questions.enabled_questions(root)}
        self.assertIn("WEB-001", enabled)
        self.assertNotIn("BC-001", enabled)

    def test_question_help_state_is_evidence_driven(self):
        temp, root = self.make_project()
        self.addCleanup(temp.cleanup)
        (root / ".audit").mkdir()
        (root / ".audit" / "context.json").write_text(json.dumps({
            "project": {"root": str(root), "name": root.name},
            "target": {"address": None, "contract": None, "artifact": None},
            "latest": {"function": "withdraw", "tx_hash": "0x" + "1" * 64, "trace": "trace", "state_diff": "diff"},
            "signals": [{"id": "X", "title": "authorization review", "description": "check indirect authorization"}],
            "tools": {"trace": {"status": "completed"}},
        }), encoding="utf-8")
        (root / ".audit" / "events.jsonl").write_text(json.dumps({
            "tool": "lk", "type": "lk-command", "status": "completed",
            "data": {"command": "trace"},
        }) + "\n", encoding="utf-8")
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            first = questions.current_question(root)
            self.assertIsNotNone(first)
            self.assertIn("trace", " ".join(first["evidence"]).lower())

    def test_source_references_exist(self):
        for q in questions.QUESTION_CATALOG.values():
            for source in q.sources:
                self.assertIn(source, questions.SOURCES)

    def test_all_major_lowkey_commands_feed_the_evidence_bus(self):
        expected = {
            "project", "system", "functions", "read", "send", "probe", "changes",
            "state-diff", "trace", "logs", "findings", "focus", "slither", "scan",
            "risk", "seams", "rg", "audit", "walkthrough", "walkthrough test",
            "matrix", "test", "generate", "fuzz", "invariant", "mutate", "symbolic",
            "brutalize", "build", "script", "lab", "fork", "actor", "impersonate",
        }
        for command in expected:
            self.assertIn(command, questions.COMMAND_EVIDENCE_MAP)

    def test_question_is_deterministic_for_same_evidence(self):
        temp, root = self.make_project()
        self.addCleanup(temp.cleanup)
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            first = questions.rank_questions(root, limit=8)
            second = questions.rank_questions(root, limit=8)
        self.assertEqual(
            [row["question"].id for row in first],
            [row["question"].id for row in second],
        )
        self.assertEqual(
            [row["score"] for row in first],
            [row["score"] for row in second],
        )

    def test_recent_walkthrough_and_trace_evidence_can_push_proof_questions_forward(self):
        temp, root = self.make_project(
            source="contract Demo { function withdraw(uint256 amount) public {} }\n"
        )
        self.addCleanup(temp.cleanup)
        (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        (root / ".audit").mkdir()
        context = {
            "project": {"root": str(root), "name": root.name},
            "target": {"address": "0x" + "1" * 40, "contract": "Demo"},
            "latest": {"function": "withdraw", "tx_hash": "0x" + "1" * 64, "trace": "trace", "state_diff": "diff"},
            "signals": [],
            "tools": {"walkthrough": {"status": "completed"}, "trace": {"status": "completed"}},
        }
        (root / ".audit" / "context.json").write_text(json.dumps(context), encoding="utf-8")
        (root / ".audit" / "events.jsonl").write_text(
            json.dumps({"tool": "lk", "type": "lk-command", "status": "completed",
                        "data": {"command": "walkthrough"}}) + "\n"
            + json.dumps({"tool": "lk", "type": "lk-command", "status": "completed",
                          "data": {"command": "trace"}}) + "\n",
            encoding="utf-8",
        )
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            rows = questions.rank_questions(root, limit=8)
        ids = [row["question"].id for row in rows]
        self.assertTrue(any(qid.startswith("BC-") for qid in ids) or "PROOF-001" in ids)

    def test_focused_signal_changes_question_relevance_without_declaring_a_finding(self):
        temp, root = self.make_project()
        self.addCleanup(temp.cleanup)
        (root / ".audit").mkdir()
        context = {
            "project": {"root": str(root), "name": root.name},
            "target": {},
            "latest": {},
            "signals": [{
                "id": "SIG-AUTH",
                "title": "authorization boundary review",
                "description": "possible indirect authorization path",
                "function": "withdraw",
            }],
            "focus": {"signal_id": "SIG-AUTH"},
            "tools": {},
        }
        (root / ".audit" / "context.json").write_text(json.dumps(context), encoding="utf-8")
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            rows = questions.rank_questions(root, limit=12)
        auth_rows = [row for row in rows if row["question"].id in {"AUTH-002", "AUTH-003"}]
        self.assertTrue(auth_rows)
        self.assertTrue(any("overlaps the focused signal" in " ".join(row["reasons"]) for row in auth_rows))
        self.assertNotIn("VULNERABLE", " ".join(row["reasons"]).upper())

    def test_source_command_uses_current_question_without_changing_history(self):
        temp, root = self.make_project()
        self.addCleanup(temp.cleanup)
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            current = questions.current_question(root, record=True)
            before = questions._read_history(root)
            questions.render_source(current["question"].id, root)
            after = questions._read_history(root)
        self.assertEqual(len(before), len(after))

    def test_skip_is_stored_as_non_applicable_and_reset_keeps_audit_evidence(self):
        temp, root = self.make_project()
        self.addCleanup(temp.cleanup)
        (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root), \
             patch.object(questions.audit_context, "is_audit_project", return_value=True), \
             patch.object(questions.audit_context, "audit_dir", return_value=root / ".audit"), \
             patch.object(questions.audit_context, "events_path", return_value=root / ".audit" / "events.jsonl"), \
             patch.object(questions.audit_context, "emit"):
            current = questions.current_question(root)
            self.assertEqual(questions.answer_current("NOT_APPLICABLE", note="not relevant", root=root), 0)
            saved = questions.load_state(root)
            self.assertEqual(saved["answers"][current["question"].id]["status"], "NOT_APPLICABLE")
            self.assertEqual(questions.reset(root), 0)
            reset_state = questions.load_state(root)
            self.assertEqual(reset_state["answers"], {})

    def test_core_questions_apply_to_rust_project_without_blockchain_pack(self):
        temp, root = self.make_project(source='fn main() { println!("hello"); }\n')
        self.addCleanup(temp.cleanup)
        (root / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n", encoding="utf-8")
        (root / "src" / "main.rs").write_text('fn main() { println!("hello"); }\n', encoding="utf-8")
        with patch.object(questions.audit_context, "foundry_project_root", return_value=root):
            feature = questions.detect_features(root)
            enabled = {q.id for q in questions.enabled_questions(root)}
        self.assertTrue(feature["features"]["native"])
        self.assertIn("ARCH-001", enabled)
        self.assertIn("NATIVE-003", enabled)
        self.assertNotIn("BC-001", enabled)


if __name__ == "__main__":
    unittest.main()
