import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch


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

    def test_misspelled_help_suggests_the_correct_command(self):
        code, output = self.capture_dispatch("walet", "-h")
        self.assertEqual(code, 2)
        self.assertIn("No dedicated Lowkey help page matches 'walet'.", output)
        self.assertIn("lk wallet --h", output)
        self.assertIn("lk --h", output)

    def test_every_dispatch_root_command_has_help(self):
        import inspect
        import re

        source = inspect.getsource(lk.dispatch_command)
        expressions = re.findall(
            r"(?:if|elif) cmd(?:\s+in|\s*==)\s*(?:\{([^}]+)\}|\"([^\"]+)\"|\'([^\']+)\')",
            source,
        )
        commands = set()
        for group_set, double_quoted, single_quoted in expressions:
            if double_quoted or single_quoted:
                commands.add(double_quoted or single_quoted)
                continue
            commands.update(re.findall(r"[\"']([^\"']+)[\"']", group_set))

        commands.difference_update({"--version", "-V", "version"})
        commands = {
            command for command in commands
            if command not in {"try", "map", "walk", "graph", "signals", "signal",
                               "investigate", "investigation", "statediff", "state_diff",
                               "hotspots", "target-list", "actor-list", "erc20",
                               "resolve", "lookup", "decode-event", "decode-calldata",
                               "returns", "error", "cheats", "cheatsheet", "cheatcode"}
        }

        missing = []
        for command in sorted(commands):
            canonical = lk._canonical_help_command(command)
            if canonical not in lk.COMMAND_HELP:
                missing.append(command)

        self.assertEqual(missing, [])

    def test_nested_target_help(self):
        code, output = self.capture_dispatch("target", "list", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk target list", output)
        self.assertIn("List remembered targets", output)

    def test_wizard_help_explains_remix_workflow_and_modes(self):
        code, output = self.capture_dispatch("wizard", "--h")
        self.assertEqual(code, 0)
        self.assertIn("Remix-like contract interaction from the terminal", output)
        self.assertIn("lk wizard buyNft 5", output)
        self.assertIn("Simulate a read-only call with eth_call", output)
        self.assertIn("Send a state-changing transaction using the current actor", output)
        self.assertIn("Only build the ABI calldata", output)
        self.assertIn("Transactions use the current actor", output)
        self.assertIn("lk actor 0 Alice", output)
        self.assertIn("A target must already be selected", output)

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

    def test_native_test_help_is_not_forwarded_to_forge(self):
        script = (ROOT / "bin" / "lk").read_text(encoding="utf-8")
        self.assertIn("Friendly Lowkey help must be handled by the main router.", script)
        self.assertIn('exec python3 "$HOME/.lowkey/lk.py" "$@"', script)
        self.assertIn('exec python3 "$HOME/.lowkey/forge_tools.py" "$@"', script)

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


    def test_main_contextual_help_skips_project_sync(self):
        original_argv = lk.sys.argv
        lk.sys.argv = ["lk", "slither", "--h"]
        output = io.StringIO()
        try:
            with patch.object(lk, "_sync_audit_context", side_effect=AssertionError),                  patch.object(lk.audit_context, "foundry_project_root", side_effect=AssertionError),                  redirect_stdout(output), self.assertRaises(SystemExit) as raised:
                lk.main()
        finally:
            lk.sys.argv = original_argv

        self.assertEqual(raised.exception.code, 0)
        self.assertIn("LOWKEY HELP  •  lk slither", output.getvalue())

    def test_import_is_in_main_help(self):
        script = (ROOT / "lowkey" / "lk.py").read_text(encoding="utf-8")
        self.assertIn("lk import", script)
        self.assertIn("importable packages", script)

    def test_question_help_is_contextual(self):
        code, output = self.capture_dispatch("q", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk q", output)
        self.assertIn("lk q why", output)
        self.assertIn("lk q source", output)

    def test_questions_help_is_contextual(self):
        code, output = self.capture_dispatch("questions", "--h")
        self.assertEqual(code, 0)
        self.assertIn("LOWKEY HELP  •  lk questions", output)
        self.assertIn("lk questions --all", output)
        self.assertIn("lk q skip", output)
        self.assertIn("lk q reset", output)



if __name__ == "__main__":
    unittest.main()
