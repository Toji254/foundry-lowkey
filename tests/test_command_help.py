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
