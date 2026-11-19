from __future__ import annotations
import contextlib, io, pathlib, sys, tempfile, unittest
from unittest.mock import patch
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))
import workflow_engine

class AuditorWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name).resolve()
        (self.root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        self.snapshot = {"commit": "a" * 40, "branch": "integration-test-drive",
                         "dirty_paths": [], "captured_at": "2026-11-19T00:00:00+00:00"}
        patches = [
            patch.object(workflow_engine.audit_context, "foundry_project_root",
                         side_effect=lambda hint=None: pathlib.Path(hint).resolve() if hint else self.root),
            patch.object(workflow_engine.audit_context, "is_audit_project", return_value=True),
            patch.object(workflow_engine, "_snapshot", return_value=dict(self.snapshot)),
            patch.object(workflow_engine.audit_context, "read_events", return_value=[]),
            patch.object(workflow_engine.audit_context, "emit"),
            patch.object(workflow_engine.question_engine, "rank_questions", return_value=[]),
        ]
        for p in patches: p.start(); self.addCleanup(p.stop)

    def test_workflow_help_overview_is_plain_english_and_lists_all_actions_and_flags(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(workflow_engine.main(["--h"]), 0)
        rendered = output.getvalue()
        for expected in (
            "LOWKEY HELP  •  lk workflow",
            "COMMAND VARIATIONS",
            "lk workflow start",
            "lk workflow status",
            "lk workflow next",
            "lk workflow note <text...> [--phase PHASE]",
            "lk workflow done [PHASE] --note",
            "lk workflow reset --yes",
            "--root ROOT",
            "--phase PHASE",
            "--note TEXT",
            "--yes",
            "THE FIVE AUDIT PHASES",
            "THIS IS NOT THE PROTOCOL WALKTHROUGH",
        ):
            self.assertIn(expected, rendered)

    def test_workflow_help_spellings_and_subcommand_pages(self):
        for flag in ("--h", "--help", "-h", "help"):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(workflow_engine.main([flag]), 0)
            self.assertIn("LOWKEY HELP  •  lk workflow", output.getvalue())

        pages = {
            "start": ("SCOPE BASELINE", "lk workflow start"),
            "status": ("AUTOMATIC EVIDENCE", "lk workflow status"),
            "next": ("AUTOMATIC EVIDENCE", "lk workflow status"),
            "note": ("NOTE VS DONE", "--phase PHASE"),
            "done": ("PREPARE is blocked", "--note TEXT"),
            "reset": ("WHAT IS PRESERVED", "--yes"),
        }
        for action, expected in pages.items():
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(workflow_engine.main([action, "--h"]), 0)
            for text_value in expected:
                self.assertIn(text_value, output.getvalue())

    def test_start_pins_scope_and_opens_prepare(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output): self.assertEqual(workflow_engine.main(["start"]), 0)
        state = workflow_engine._load(self.root)
        self.assertTrue(state["started"])
        self.assertEqual(state["baseline"]["commit"], "a" * 40)
        self.assertIn("NEXT • PREPARE", output.getvalue())

    def test_prepare_requires_real_current_build(self):
        workflow_engine.start(self.root)
        self.assertEqual(workflow_engine.done(self.root, None, "Scope and docs reviewed."), 2)
        self.assertNotIn("PREPARE", workflow_engine._load(self.root)["completed"])

    def test_successful_build_for_same_snapshot_unlocks_prepare(self):
        workflow_engine.start(self.root)
        workflow_engine.on_build_success(self.root, scope="production")
        self.assertEqual(workflow_engine.done(self.root, None, "Scope, dependencies and build reviewed."), 0)
        self.assertEqual(workflow_engine._current(workflow_engine._load(self.root))[0], "MAP")

    def test_source_change_makes_prior_build_stale(self):
        workflow_engine.start(self.root)
        workflow_engine.on_build_success(self.root)
        changed = {"commit": "b" * 40, "branch": "integration-test-drive",
                   "dirty_paths": [], "captured_at": "2026-11-19T00:01:00+00:00"}
        with patch.object(workflow_engine, "_snapshot", return_value=changed):
            self.assertFalse(workflow_engine._build_current(self.root, workflow_engine._load(self.root)))

    def test_dirty_file_content_hash_is_part_of_snapshot_match(self):
        before = {"commit": "a" * 40, "dirty_paths": ["src/Vault.sol"], "dirty_digest": "a" * 64}
        after = {"commit": "a" * 40, "dirty_paths": ["src/Vault.sol"], "dirty_digest": "b" * 64}
        self.assertFalse(workflow_engine._matches(before, after))

    def test_build_prompt_is_only_shown_once(self):
        first, second = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(first): workflow_engine.on_build_success(self.root)
        with contextlib.redirect_stdout(second): workflow_engine.on_build_success(self.root)
        self.assertIn("AUDIT WORKFLOW SUGGESTION", first.getvalue())
        self.assertEqual(second.getvalue(), "")

    def test_notes_are_tagged_to_a_phase(self):
        workflow_engine.start(self.root)
        self.assertEqual(workflow_engine.add_note(self.root, "Mapped withdrawal auth.", "MAP"), 0)
        self.assertEqual(workflow_engine._load(self.root)["notes"][-1]["phase"], "MAP")

    def test_reset_preserves_build_record_but_clears_checkpoints(self):
        workflow_engine.on_build_success(self.root)
        workflow_engine.start(self.root)
        workflow_engine.reset(self.root)
        state = workflow_engine._load(self.root)
        self.assertFalse(state["started"])
        self.assertTrue(state["build_tip_shown"])
        self.assertIsNotNone(state["last_build"])
        self.assertFalse(state["completed"])

    def test_suggested_commands_are_separate_not_shell_pipelines(self):
        workflow_engine.start(self.root)
        # Mark PREPARE using a current build so the MAP actions are displayed.
        workflow_engine.on_build_success(self.root)
        workflow_engine.done(self.root, None, "Scope, docs, dependencies and current build reviewed.")
        output = workflow_engine.render(self.root)
        self.assertIn("lk system\n  lk functions\n  lk deps\n  lk q", output)
        self.assertNotIn("lk system | lk functions", output)

    def test_phases_must_be_completed_in_order_and_have_notes(self):
        workflow_engine.start(self.root)
        self.assertEqual(workflow_engine.done(self.root, "MAP", "Mapped it."), 2)
        self.assertEqual(workflow_engine.done(self.root, None, "  "), 2)
        self.assertFalse(workflow_engine._load(self.root)["completed"])

if __name__ == "__main__": unittest.main()
