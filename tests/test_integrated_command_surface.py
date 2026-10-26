import contextlib
import io
import unittest

from lowkey import lk


class IntegratedCommandSurfaceTests(unittest.TestCase):
    def test_help_exposes_newbie_path_and_integrated_commands(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            lk.print_help()
        help_text = stream.getvalue()
        required = (
            "START HERE",
            "FIRST 10 MINUTES",
            "lk lab",
            "lk lab --ai-review",
            "lk ai status",
            "lk memory status",
            "lk walkthrough --auto",
            "lk audit run",
            "lk benchmark",
            "lk poc",
            "lk project",
            "lk system",
            "lk rg",
            "lk slither",
            "lk generate deployment",
            "lk matrix init",
            "lk snapshot",
            "lk trace",
            "lk doctor",
        )
        for item in required:
            self.assertIn(item, help_text)

    def test_lab_ai_review_flag_has_a_native_help_path(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            result = lk.run_lab({}, ["--ai-review", "--help"])
        self.assertEqual(result, 0)
        self.assertIn("lk lab --ai-review", stream.getvalue())
        self.assertIn("native lab logic", stream.getvalue().lower())

    def test_legacy_test_gen_template_escapes_named_import(self):
        import inspect
        source = inspect.getsource(lk.run_test_gen)
        self.assertIn("import {{Test}}", source)

    def test_integrated_modules_are_importable(self):
        import lowkey.audit_engine  # noqa: F401
        import lowkey.project_tools  # noqa: F401
        import lowkey.system_model  # noqa: F401


if __name__ == "__main__":
    unittest.main()
