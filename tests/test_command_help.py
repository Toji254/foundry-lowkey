import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast_help", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class CommandHelpTests(unittest.TestCase):
    def capture_dispatch(self, command, *args):
        output = io.StringIO()
        with redirect_stdout(output):
            code = lk.dispatch_command(command, list(args), {})
        return code, output.getvalue()

    def test_walkthrough_help_lists_test_and_human_guidance(self):
        code, output = self.capture_dispatch("walkthrough", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk walkthrough", output)
        self.assertIn("NEXT COMMANDS", output)
        self.assertIn("lk walkthrough test", output)
        self.assertIn("What it does:", output)
        self.assertIn("When to use:", output)
        self.assertIn("Example", output)

    def test_walkthrough_seed_help_lists_seed_history_command(self):
        code, output = self.capture_dispatch("walkthrough", "--h")
        self.assertEqual(code, 0)
        self.assertIn("lk walkthrough seed", output)
        code, output = self.capture_dispatch("walkthrough", "seed", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk walkthrough seed", output)
        self.assertIn("previous walkthrough test seeds", output)

    def test_nested_walkthrough_test_help(self):
        code, output = self.capture_dispatch("walkthrough", "test", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk walkthrough test", output)
        self.assertIn("lk walkthrough test --cases 50", output)
        self.assertIn("Run randomized adversarial interactions", output)
        self.assertIn("OPTIONS / MODES", output)

    def test_help_spelling_variants_work(self):
        for flag in ("--h", "--help", "-h", "help"):
            code, output = self.capture_dispatch("walkthrough", flag)
            self.assertEqual(code, 0)
            self.assertIn("LOWKEY HELP  •  lk walkthrough", output)

    def test_nested_target_help(self):
        code, output = self.capture_dispatch("target", "list", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk target list", output)
        self.assertIn("List remembered targets", output)

    def test_leaf_help_has_parent_navigation(self):
        code, output = self.capture_dispatch("generate", "test", "--h")
        self.assertEqual(code, 0)
        self.assertIn("NAVIGATION", output)
        self.assertIn("lk generate --h", output)
        self.assertNotIn("Drill down: lk walkthrough test --h", output)

    def test_leaf_help_footer_points_to_actual_parent(self):
        code, output = self.capture_dispatch("generate", "test", "--h")
        self.assertEqual(code, 0)
        self.assertIn("Parent: lk generate --h", output)

    def test_canonical_command_is_not_mislabeled_as_alias(self):
        code, output = self.capture_dispatch("project", "--workspace", "--h")
        self.assertEqual(code, 0)
        self.assertNotIn("Alias:", output)

    def test_alias_help_explains_alias(self):
        code, output = self.capture_dispatch("walk", "--h")
        self.assertEqual(code, 0)
        self.assertIn("Alias:", output)
        self.assertIn("lk walkthrough", output)

    def test_unknown_nested_help_does_not_silently_fall_back(self):
        code, output = self.capture_dispatch("generate", "bogus", "--h")
        self.assertEqual(code, 2)
        self.assertIn("Unknown subcommand: 'bogus'", output)
        self.assertIn("Available next commands:", output)

    def test_nested_project_workspace_help(self):
        code, output = self.capture_dispatch("project", "--workspace", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk project --workspace", output)
        self.assertIn("larger workspace map", output)

    def test_generate_help_is_contextual(self):
        code, output = self.capture_dispatch("generate", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk generate", output)
        self.assertIn("lk generate test", output)

    def test_generate_help_is_forwarded_by_bin(self):
        script = (ROOT / "bin" / "lk").read_text(encoding="utf-8")
        block_start = script.index("    generate)")
        block_end = script.index("        ;;", block_start)
        block = script[block_start:block_end]
        self.assertIn('exec python3 "$HOME/.lowkey/lk.py" "$@"', block)

    def test_alias_help_resolves_to_canonical_command(self):
        code, output = self.capture_dispatch("walk", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk walkthrough", output)

    def test_help_does_not_activate_or_execute_command(self):
        called = []

        original = lk.activate_project_target
        try:
            lk.activate_project_target = lambda config: called.append(True)
            code, output = self.capture_dispatch("walkthrough", "--h")
        finally:
            lk.activate_project_target = original

        self.assertEqual(code, 0)
        self.assertEqual(called, [])
        self.assertIn("LOWKEY HELP  •  lk walkthrough", output)


if __name__ == "__main__":
    unittest.main()
