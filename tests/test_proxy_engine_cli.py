import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
sys.path.insert(0, str(LOWKEY))
spec = importlib.util.spec_from_file_location("proxy_engine_cli_lk", LOWKEY / "lk.py")
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class ProxyEngineCliTests(unittest.TestCase):
    def test_proxy_command_routes_to_proxy_engine_and_preserves_legacy_field_commands(self):
        with patch.object(lk, "activate_project_context"), patch.object(
            lk.proxy_engine, "run_cli", return_value=7
        ) as engine:
            result = lk._dispatch_command_impl("proxy", ["audit", "0x" + "1" * 40], {})
        self.assertEqual(result, 7)
        args, kwargs = engine.call_args
        self.assertEqual(args[1], ["audit", "0x" + "1" * 40])
        self.assertIs(kwargs["rpc_resolver"], lk.effective_rpc)
        self.assertIs(kwargs["abi_resolver"], lk.load_abi)

    def test_proxy_help_exposes_auditor_workflow(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["proxy"])
        self.assertEqual(result, 0)
        self.assertIn("proxy audit", output.getvalue())

    def test_nested_proxy_audit_help_is_registered(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = lk._render_command_help(["proxy", "audit"])
        self.assertEqual(result, 0)
        self.assertIn("does not execute attacks", output.getvalue().lower())

    def test_json_proxy_commands_suppress_recommendation_footer(self):
        source = pathlib.Path(lk.__file__).read_text(encoding="utf-8")
        self.assertIn('_canonical_help_command(command) == "proxy"', source)
        self.assertIn('and "--json" in sys.argv[2:]', source)


if __name__ == "__main__":
    unittest.main()
