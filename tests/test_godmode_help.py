import ast
import contextlib
import io
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY_RUNTIME = ROOT / "lowkey"
if str(LOWKEY_RUNTIME) not in sys.path:
    sys.path.insert(0, str(LOWKEY_RUNTIME))

# Match the installed runtime: lowkey/ is on sys.path and Godmode is imported
# by its command name by the installed launcher.
import godmode


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


def _main_dispatch_commands():
    """Extract command names handled by godmode.main() from its actual AST."""
    tree = ast.parse(GODMODE_SOURCE.read_text(encoding="utf-8"))
    main = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    commands = set()
    for node in ast.walk(main):
        if not isinstance(node, ast.If):
            continue
        expression = node.test
        if not isinstance(expression, ast.Compare):
            continue
        if not isinstance(expression.left, ast.Name) or expression.left.id != "cmd":
            continue
        for operator, value in zip(expression.ops, expression.comparators):
            if not isinstance(operator, (ast.Eq, ast.In)):
                continue
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                commands.add(value.value)
            elif isinstance(value, (ast.Set, ast.Tuple, ast.List)):
                commands.update(
                    item.value for item in value.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                )
    return commands


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
    discovered.setdefault("proxy-resolve", set()).update({"--rpc-url", "--slots"})
    discovered.setdefault("storage-infer", set()).update({"--rpc-url", "--slots", "--no-resolve", "--key"})
    discovered.setdefault("selectors-full", set()).add("--rpc-url")
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
        launcher_commands = set(match.group(1).strip().rstrip(")").split("|"))
        registered_commands = set(godmode.ROUTED_COMMANDS)
        dispatch_commands = _main_dispatch_commands()
        # state-diff is intentionally owned by Lowkey's primary router: its
        # public lk state-diff syntax is distinct from this unused Godmode
        # helper, so the shell must not shadow it with the Godmode subcommand.
        dispatch_commands.discard("state-diff")
        self.assertEqual(dispatch_commands, registered_commands)
        self.assertEqual(launcher_commands, registered_commands)

        catalog = io.StringIO()
        with contextlib.redirect_stdout(catalog):
            godmode.print_command_catalog()
        rendered = catalog.getvalue()
        for command in sorted(launcher_commands):
            with self.subTest(command=command):
                self.assertIn(f"lk {command}", rendered)

    def test_every_routed_command_has_safe_help_for_all_spellings(self):
        for command in godmode.ROUTED_COMMANDS:
            for spelling in ("--h", "--help", "-h", "help"):
                with self.subTest(command=command, spelling=spelling):
                    result, output = _capture_help(command, spelling)
                    self.assertEqual(result, 0, output)
                    self.assertTrue(
                        "usage:" in output.lower()
                        or "LOWKEY GODMODE HELP" in output
                        or "LOWKEY HELP" in output
                        or command == "capabilities",
                        output,
                    )
                    expected_usage = "lk attack forge" if command == "attack-forge" else "lk " + command
                    self.assertIn(expected_usage, output)



    def test_every_godmode_help_page_uses_the_comprehensive_layout(self):
        required_sections = (
            "What it does:", "When to use:", "USAGE", "COMMAND VARIATIONS",
            "ARGUMENTS", "OPTIONS / MODES", "RECOMMENDED WORKFLOW",
            "OUTPUT / EVIDENCE", "SAFETY / LIMITATIONS", "RELATED COMMANDS",
            "HELP TIP",
        )
        self.assertEqual(set(godmode.GODMODE_HELP_GUIDES), set(godmode.ROUTED_COMMANDS))
        for command in godmode.ROUTED_COMMANDS:
            result, rendered = _capture_help(command)
            self.assertEqual(result, 0, rendered)
            for section in required_sections:
                with self.subTest(command=command, section=section):
                    self.assertIn(section, rendered)

    def test_godmode_help_is_a_real_quickstart_not_just_flag_inventory(self):
        result, output = _capture_help("godmode", "--h")
        self.assertEqual(result, 0, output)
        for expected in (
            "START HERE", "Source-only scan", "address or RPC URL",
            "--plan-only", "--attack", "local Anvil",
            "--control-manifest", "mutation", "coverage",
            ".audit/godmode/latest.json", "provenance.json",
            "<target-address>",
            "--root <folder>",
            "REVIEW_REQUIRED",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, output)

    def test_fidelity_help_explains_inspection_recording_and_strength(self):
        result, rendered = _capture_help("fidelity")
        self.assertEqual(result, 0, rendered)
        for token in ("--inspect", "--record", "--cheatcode", "--strength",
                      "heuristic", "simulated-funds", "reproduced-fork",
                      ".audit", "evidence ledger"):
            self.assertIn(token, rendered)

    def test_bundle_help_discloses_relay_data_sharing(self):
        result, rendered = _capture_help("bundle")
        self.assertEqual(result, 0, rendered)
        for token in ("--tx", "--target-block", "--relay-url", "--auth-signature",
                      "raw signed transactions", "relay URL", "simulation"):
            self.assertIn(token.lower(), rendered.lower())

    def test_root_help_in_launcher_appends_godmode_catalog(self):
        with tempfile.TemporaryDirectory() as temp_home:
            home = pathlib.Path(temp_home)
            lowkey_dir = home / ".lowkey"
            lowkey_dir.mkdir()
            (lowkey_dir / "lk.py").write_text(
                'print("BASE LOWKEY HELP")' + chr(10), encoding="utf-8"
            )
            (lowkey_dir / "godmode.py").write_text(
                'print("GODMODE CATALOG MARKER")' + chr(10), encoding="utf-8"
            )
            env = os.environ.copy()
            env["HOME"] = str(home)
            result = subprocess.run(
                ["bash", str(LAUNCHER), "--help"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("BASE LOWKEY HELP", result.stdout)
            self.assertIn("GODMODE CATALOG MARKER", result.stdout)

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
