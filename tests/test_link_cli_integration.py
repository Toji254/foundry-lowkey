import contextlib
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))
import lk


class LinkCliIntegrationTests(unittest.TestCase):
    def test_link_help_has_target_forms_filters_and_static_evidence_boundary(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["link"])

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("lk link [TARGET] [options]", rendered)
        self.assertIn("--detail VIEW", rendered)
        self.assertIn("--only FILTER", rendered)
        self.assertIn("--search TEXT", rendered)
        self.assertIn("Static, not runtime", rendered)
        self.assertIn("do not prove", rendered)

    def test_trace_source_has_a_dedicated_child_help_page(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["trace", "source"])

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("lk trace source <Contract.function>", rendered)
        self.assertIn("--detail VIEW", rendered)
        self.assertIn("potential static relationships", rendered)
        self.assertIn("not a transaction replay", rendered)

    def test_transaction_trace_help_remains_separate(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["trace"])

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("lk trace [<transaction-hash>]", rendered)
        self.assertIn("--grep <TEXT>", rendered)
        self.assertIn("transaction", rendered.lower())

    def test_link_command_dispatches_to_source_relationship_engine(self):
        with patch.object(lk, "activate_project_context"), \
             patch.object(lk.source_link_engine, "run_link", return_value=0) as run_link:
            result = lk._dispatch_command_impl("link", ["Vault", "--detail", "all"], {})

        self.assertEqual(result, 0)
        run_link.assert_called_once_with(["Vault", "--detail", "all"])

    def test_trace_source_routes_to_source_graph_without_invoking_transaction_trace(self):
        with patch.object(lk, "activate_project_context"), \
             patch.object(lk.source_link_engine, "run_link", return_value=0) as run_link, \
             patch.object(lk, "run_trace") as transaction_trace:
            result = lk._dispatch_command_impl(
                "trace", ["source", "Vault.withdraw", "--detail", "storage"], {}
            )

        self.assertEqual(result, 0)
        run_link.assert_called_once_with(["Vault.withdraw", "--detail", "storage"])
        transaction_trace.assert_not_called()

    def test_trace_transaction_still_uses_the_transaction_tracer(self):
        with patch.object(lk, "activate_project_context"), \
             patch.object(lk, "run_trace", return_value=0) as transaction_trace:
            result = lk._dispatch_command_impl("trace", ["0x" + "1" * 64], {})

        self.assertEqual(result, 0)
        transaction_trace.assert_called_once_with({}, ["0x" + "1" * 64])


if __name__ == "__main__":
    unittest.main()
