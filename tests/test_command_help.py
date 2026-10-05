import importlib.util
import io
import pathlib
import unittest
from contextlib import redirect_stdout, redirect_stderr
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

    def test_accepted_nested_command_aliases_have_help(self):
        cases = (
            ("audit", "pipeline", "lk audit pipeline"),
            ("q", "next", "lk q next"),
            ("q", "not-applicable", "lk q not-applicable"),
        )
        for root, child, title in cases:
            code, output = self.capture_dispatch(root, child, "--h")
            self.assertEqual(code, 0)
            self.assertIn(f"LOWKEY HELP  •  {title}", output)
            self.assertNotIn("Unknown subcommand", output)
            self.assertIn("Example:", output)

    def test_every_help_variation_has_description_and_example(self):
        problems = lk._validate_help_variations(lk.COMMAND_HELP)
        self.assertEqual(problems, [])

    def test_every_help_entry_has_required_documentation_fields(self):
        def validate(entries, path="lk"):
            problems = []
            for name, entry in entries.items():
                current = f"{path} {name}"
                for field in ("summary", "usage", "example", "use"):
                    if not str(entry.get(field) or "").strip():
                        problems.append(f"{current}: missing {field}")
                children = entry.get("children") or {}
                if not isinstance(children, dict):
                    problems.append(f"{current}: children is not a mapping")
                    continue
                problems.extend(validate(children, current))
            return problems

        problems = validate(lk.COMMAND_HELP)
        self.assertEqual(problems, [])

    def test_launcher_routed_commands_also_have_lowkey_help(self):
        import re

        script = (ROOT / "bin" / "lk").read_text(encoding="utf-8")
        match = re.search(
            r"script\|inspect\|coverage\|lint\|geiger\|fmt\|lsp\|create\|"
            r"verify-contract\|verify-check\|verify-bytecode\|tree\|install\|"
            r"remove\|update\|init\|clean\|cache\|config\|remappings\|bind\|"
            r"bind-json\|doc\|compiler\|eip712\|soldeer\|completions\|flatten",
            script,
        )
        self.assertIsNotNone(match)
        native_commands = set(match.group(0).split("|"))
        native_commands.add("generate")

        missing = [
            command for command in sorted(native_commands)
            if lk._canonical_help_command(command) not in lk.COMMAND_HELP
        ]
        self.assertEqual(missing, [])

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



    def test_command_variations_are_explicit_in_help(self):
        cases = {
            "actor": (
                "lk actor reset",
                "Clear the active actor without deleting the saved profile.",
            ),
            "rpc": ("lk rpc reset", "Return to automatic RPC detection."),
            "abi": ("lk abi auto", "Auto-discover and load an ABI for the selected target."),
            "mapping": (
                "lk mapping <key_type> <slot> <key>",
                "Specify the mapping key type explicitly.",
            ),
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                code, output = self.capture_dispatch(command, "--h")
                self.assertEqual(code, 0)
                self.assertIn("COMMAND VARIATIONS", output)
                self.assertIn(expected[0], output)
                self.assertIn(expected[1], output)
                self.assertIn("Example:", output)

    def test_multiform_help_entries_have_variations_or_children(self):
        import re
        source = pathlib.Path(MODULE).read_text(encoding="utf-8")
        blocks = re.findall(
            r'^    "([^"]+)": _help_entry\(([\s\S]*?)(?=^    "[^"]+": _help_entry|\n\}\n\n)',
            source,
            flags=re.MULTILINE,
        )
        exempt = {"q", "send", "import", "wizard", "ens"}
        missing = []
        for name, block in blocks:
            usage_lines = [line for line in block.splitlines() if '"lk ' in line and '|' in line]
            if usage_lines and name not in exempt:
                if "children=" not in block and "forms=" not in block:
                    missing.append(name)
        self.assertEqual(missing, [])

    def test_recommended_next_commands_are_contextual(self):
        items = lk._recommended_next_commands("functions", [])
        commands = [command for command, _ in items]
        self.assertEqual(len(items), 4)
        self.assertIn("lk fn <function>", commands)
        self.assertIn("lk ask <function>", commands)
        self.assertIn("lk read <function> [args]", commands)
        self.assertIn("lk wizard <function> [values...]", commands)

        send_items = lk._recommended_next_commands("send", [])
        send_commands = [command for command, _ in send_items]
        self.assertIn("lk receipt", send_commands)
        self.assertIn("lk trace", send_commands)

    def test_read_recommendations_follow_abi_relationships(self):
        target = "0x" + "1" * 40
        owner = "0x" + "2" * 40
        abi = [
            {
                "type": "function",
                "name": "balanceOf",
                "stateMutability": "view",
                "inputs": [{"name": "account", "type": "address"}],
                "outputs": [{"name": "", "type": "uint256"}],
            },
            {
                "type": "function",
                "name": "ownerOf",
                "stateMutability": "view",
                "inputs": [{"name": "tokenId", "type": "uint256"}],
                "outputs": [{"name": "", "type": "address"}],
            },
            {
                "type": "function",
                "name": "getApproved",
                "stateMutability": "view",
                "inputs": [{"name": "tokenId", "type": "uint256"}],
                "outputs": [{"name": "", "type": "address"}],
            },
            {
                "type": "function",
                "name": "tokenURI",
                "stateMutability": "view",
                "inputs": [{"name": "tokenId", "type": "uint256"}],
                "outputs": [{"name": "", "type": "string"}],
            },
            {
                "type": "function",
                "name": "approve",
                "stateMutability": "nonpayable",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "tokenId", "type": "uint256"},
                ],
                "outputs": [],
            },
        ]
        config = {"target": target, "wallets": {}, "labels": {}}
        with patch.object(lk, "load_abi", return_value=abi):
            items = lk._recommended_next_commands("read", ["balanceOf", owner], config)

        commands = [command for command, _ in items]
        self.assertIn("lk read ownerOf <tokenId>", commands)
        self.assertIn("lk read getApproved <tokenId>", commands)
        self.assertIn("lk read tokenURI <tokenId>", commands)
        self.assertNotIn("lk send <function> [args] --preview", commands)
        self.assertNotIn("lk functions", commands)

    def test_write_function_recommendations_include_state_verification_reads(self):
        target = "0x" + "1" * 40
        abi = [
            {
                "type": "function",
                "name": "buyNft",
                "stateMutability": "nonpayable",
                "inputs": [{"name": "amount", "type": "uint256"}],
                "outputs": [],
            },
            {
                "type": "function",
                "name": "balanceOf",
                "stateMutability": "view",
                "inputs": [{"name": "account", "type": "address"}],
                "outputs": [{"name": "", "type": "uint256"}],
            },
        ]
        config = {"target": target, "wallets": {}, "labels": {}}
        with patch.object(lk, "load_abi", return_value=abi):
            items = lk._recommended_next_commands("send", ["buyNft", "5"], config)

        commands = [command for command, _ in items]
        self.assertIn("lk receipt", commands)
        self.assertIn("lk trace", commands)
        self.assertIn("lk read balanceOf <account>", commands)
        self.assertNotIn("lk send <function> [args] --preview", commands)

    def test_recommended_next_commands_use_function_query(self):
        items = lk._recommended_next_commands("fn", ["buyNft"])
        commands = [command for command, _ in items]
        self.assertIn("lk ask buyNft", commands)
        self.assertIn("lk read buyNft [args]", commands)
        self.assertIn("lk wizard buyNft [values...]", commands)

    def test_recommended_next_commands_skip_machine_output(self):
        self.assertEqual(lk._recommended_next_commands("benchmark", ["--json"]), [])
        self.assertEqual(lk._recommended_next_commands("project", ["json"]), [])

    def test_function_lookup_is_case_insensitive(self):
        abi = [
            {"type": "function", "name": "balanceOf", "inputs": [{"name": "account", "type": "address"}]}
        ]
        self.assertEqual(len(lk.matching_functions(abi, "balanceof")), 1)
        self.assertEqual(len(lk.matching_functions(abi, "BALANCEOF")), 1)
        self.assertEqual(len(lk.matching_functions(abi, "balanceOf(address)")), 1)

    def test_recommendation_footer_does_not_repeat_current_command_with_arguments(self):
        items = lk._recommended_next_commands("ask", ["balanceof"])
        commands = [command for command, _ in items]
        self.assertNotIn("lk ask balanceof", commands)
        self.assertNotIn("lk ask <function>", commands)

    def test_read_rejects_bare_target_address(self):
        output = io.StringIO()
        target = "0x" + "1" * 40
        with redirect_stdout(output), redirect_stderr(output):
            result = lk.dispatch_command("read", [target], {})
        self.assertEqual(result, 2)
        rendered = output.getvalue()
        self.assertIn("Usage: lk read <function> [args]", rendered)
        self.assertIn("A bare address is a contract target, not a function call.", rendered)

    def test_ask_rejects_extra_arguments(self):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            result = lk.dispatch_command("ask", ["balanceof", "0x" + "1" * 40], {})
        self.assertEqual(result, 2)
        self.assertIn("Usage: lk ask <function>", output.getvalue())

    def test_ask_reports_no_exact_match_instead_of_dumping_fuzzy_results(self):
        root = pathlib.Path(".")
        abi = [
            {"type": "function", "name": "balanceOf", "inputs": [{"name": "account", "type": "address"}]},
            {"type": "function", "name": "ownerOf", "inputs": [{"name": "tokenId", "type": "uint256"}]},
        ]
        with patch.object(lk.audit_context, "foundry_project_root", return_value=root), \
             patch.object(lk, "active_project_target", return_value="0x" + "2" * 40), \
             patch.object(lk, "load_abi", return_value=abi):
            output = io.StringIO()
            with redirect_stdout(output):
                result = lk.dispatch_command("ask", ["unknownFunction"], {})
        self.assertEqual(result, 2)
        rendered = output.getvalue()
        self.assertIn("No exact function match", rendered)
        self.assertIn("Did you mean:", rendered)
        self.assertIn("balanceOf(address)", rendered)

    def test_recommendations_require_a_curated_workflow(self):
        audit_commands = [command for command, _ in lk._recommended_next_commands("audit", [])]
        self.assertIn("lk findings", audit_commands)
        self.assertIn("lk checklist", audit_commands)
        self.assertNotIn("lk cheat", audit_commands)

        self.assertEqual(lk._recommended_next_commands("cheat", ["mapping"]), [])
        self.assertEqual(lk._recommended_next_commands("version", []), [])

    def test_recommendations_do_not_fall_back_to_help_related_commands(self):
        self.assertEqual(lk._recommended_next_commands("some-new-command", []), [])

    def test_recommendation_footer_skips_failed_commands(self):
        output = io.StringIO()
        with redirect_stdout(output):
            lk._print_recommended_next_commands("functions", [], result=1)
        self.assertEqual(output.getvalue(), "")

    def test_recommendation_footer_renders_for_successful_commands(self):
        previous_status = lk._COMMAND_STATUS
        lk._COMMAND_STATUS = 0
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                lk._print_recommended_next_commands("fn", ["buyNft"], result=0)
            rendered = output.getvalue()
        finally:
            lk._COMMAND_STATUS = previous_status
        self.assertIn("RECOMMENDED NEXT COMMANDS", rendered)
        self.assertIn("lk ask buyNft", rendered)
        self.assertIn("lk wizard buyNft [values...]", rendered)
        self.assertIn("Use it before read/send/changes when you are unsure what values a function expects.", rendered)

    def test_main_appends_recommendations_after_successful_command(self):
        original_argv = lk.sys.argv
        lk.sys.argv = ["lk", "fn", "buyNft"]
        output = io.StringIO()
        try:
            with patch.object(lk, "dispatch_command", return_value=0), \
                 patch.object(lk, "_sync_audit_context"), \
                 patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path(".")), \
                 patch.object(lk.audit_context, "emit"), \
                 redirect_stdout(output), \
                 self.assertRaises(SystemExit) as raised:
                lk.main()
            self.assertEqual(raised.exception.code, 0)
        finally:
            lk.sys.argv = original_argv

        rendered = output.getvalue()
        self.assertIn("RECOMMENDED NEXT COMMANDS", rendered)
        self.assertIn("lk ask buyNft", rendered)


if __name__ == "__main__":
    unittest.main()
