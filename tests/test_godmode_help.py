import ast
import contextlib
import io
import pathlib
import re
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY_RUNTIME = ROOT / "lowkey"
if str(LOWKEY_RUNTIME) not in sys.path:
    sys.path.insert(0, str(LOWKEY_RUNTIME))

# Match the installed runtime: lowkey/ is on sys.path and both modules are
# imported by their command names, so lk's root-help hook resolves godmode.
import godmode
import lk


GODMODE_SOURCE = LOWKEY_RUNTIME / "godmode.py"
LAUNCHER = ROOT / "bin" / "lk"


def _capture_help(command, spelling="--help"):
    output = io.StringIO()
    result = None
    with contextlib.redirect_stdout(output):
        try:
            result = godmode.main([command, spelling])
        except SystemExit as exc:
            result = exc.code if isinstance(exc.code, int) else 0
    return result, output.getvalue()


def _parser_arguments_from_source():
    """Read parser declarations so future flag additions are automatically tested."""
    tree = ast.parse(GODMODE_SOURCE.read_text(encoding="utf-8"))
    discovered = {}

    for function in (node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)):
        if function.name == "main":
            continue

        parser_variables = {}
        for node in ast.walk(function):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            function_name = (
                node.value.func.id if isinstance(node.value.func, ast.Name)
                else node.value.func.attr if isinstance(node.value.func, ast.Attribute)
                else ""
            )
            if not function_name.endswith("ArgumentParser"):
                continue
            prog = next(
                (item.value.value for item in node.value.keywords
                 if item.arg == "prog" and isinstance(item.value, ast.Constant)
                 and isinstance(item.value.value, str)),
                None,
            )
            if not prog or not prog.startswith("lk "):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    command = prog[3:].strip().split()[-1]
                    parser_variables[target.id] = command

        for node in ast.walk(function):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "add_argument" or not isinstance(node.func.value, ast.Name):
                continue
            command = parser_variables.get(node.func.value.id)
            if not command:
                continue
            for argument in node.args:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    value = argument.value
                    if value.startswith("-"):
                        discovered.setdefault(command, set()).add(value)

    # These parser families build their program name dynamically.
    for command in (
        "fallback-map", "oracle-map", "reentrancy-graph", "sig-matrix",
        "init-frontrun", "custody", "cross-vm", "cfg",
    ):
        discovered.setdefault(command, set()).add("--root")
    for command in ("proxy-resolve", "storage-infer", "selectors-full"):
        discovered.setdefault(command, set()).update({
            "--rpc-url", "--slots", "--no-resolve", "--key",
        })
    for command in ("invariant-forge", "archetype"):
        discovered.setdefault(command, set()).add("--root")

    # main() owns these three compact parser definitions directly.
    discovered["fidelity"] = {"--root", "--record", "--inspect", "--cheatcode", "--strength"}
    discovered["sandbox"] = {"--root", "--timeout"}
    discovered["time"] = {"--root", "--output"}
    return discovered


class GodmodeHelpCoverageTests(unittest.TestCase):
    def test_launcher_routes_and_help_catalog_are_the_same_command_set(self):
        launcher = LAUNCHER.read_text(encoding="utf-8")
        match = re.search(
            r'case "\$\{1:-\}" in\s*\n\s*([^\n]+)\n\s*exec python3 "\$HOME/\.lowkey/godmode\.py"',
            launcher,
        )
        self.assertIsNotNone(match, "Could not locate the Godmode route case in bin/lk.")
        launcher_commands = set(match.group(1).strip().split("|"))
        self.assertEqual(launcher_commands, set(godmode.ROUTED_COMMANDS))

        catalog = io.StringIO()
        with contextlib.redirect_stdout(catalog):
            godmode.print_command_catalog()
        rendered = catalog.getvalue()
        root_help = io.StringIO()
        with contextlib.redirect_stdout(root_help):
            lk.print_help()

        for command in sorted(launcher_commands):
            with self.subTest(command=command):
                self.assertIn(f"lk {command}", rendered)
                self.assertIn(f"lk {command}", root_help.getvalue())

    def test_every_routed_command_has_safe_help_for_all_spellings(self):
        for command in godmode.ROUTED_COMMANDS:
            for spelling in ("--h", "--help", "-h", "help"):
                with self.subTest(command=command, spelling=spelling):
                    result, output = _capture_help(command, spelling)
                    self.assertEqual(result, 0, output)
                    self.assertTrue(
                        "usage:" in output.lower()
                        or "LOWKEY GODMODE HELP" in output
                        or command == "capabilities",
                        output,
                    )
                    self.assertIn("lk " + command, output)

    def test_every_declared_godmode_option_is_visible_in_command_help(self):
        discovered = _parser_arguments_from_source()
        for command, flags in sorted(discovered.items()):
            if command not in godmode.ROUTED_COMMANDS or not flags:
                continue
            result, output = _capture_help(command)
            self.assertEqual(result, 0, output)
            for flag in sorted(flags):
                with self.subTest(command=command, flag=flag):
                    self.assertIn(flag, output)

    def test_new_p1_help_pages_explain_usage_examples_and_limitations(self):
        for command in ("control", "steps", "reprove", "godmode"):
            result, output = _capture_help(command)
            self.assertEqual(result, 0, output)
            for label in ("What it does:", "When to use:", "Example:", "Limitations:"):
                with self.subTest(command=command, label=label):
                    self.assertIn(label, output)
        for command, required in {
            "control": ("--freeze", "--validate", "--require-frozen", "--non-economic"),
            "steps": ("--root", "--output", "--refusal-output", "backend_unsupported"),
            "reprove": ("--prior-cost-wei", "--require-trace-storage", "--source-rpc-url"),
        }.items():
            result, output = _capture_help(command)
            self.assertEqual(result, 0, output)
            for token in required:
                self.assertIn(token, output)


if __name__ == "__main__":
    unittest.main()
