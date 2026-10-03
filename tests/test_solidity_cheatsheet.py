import importlib.util
import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "solidity_cheatsheet.py"
spec = importlib.util.spec_from_file_location("lowkey_solidity_cheatsheet", MODULE)
cheat = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cheat
spec.loader.exec_module(cheat)


class SolidityCheatsheetTests(unittest.TestCase):
    def render(self, *args):
        out = io.StringIO()
        with redirect_stdout(out):
            result = cheat.run(list(args))
        return result, out.getvalue()

    def test_help_is_read_only_lookup_help(self):
        result, output = self.render("--help")
        self.assertEqual(result, 0)
        self.assertIn("LOWKEY // SOLIDITY CHEATSHEET", output)
        self.assertIn("lk cheat mapping", output)
        self.assertIn("lk cheat fallback", output)

    def test_index_contains_requested_learning_topics(self):
        result, output = self.render()
        self.assertEqual(result, 0)
        for topic in (
            "mapping",
            "nested-mapping",
            "arrays-mappings",
            "arrays-structs",
            "require",
            "receive",
            "fallback",
            "interface",
            "calls",
            "symbols",
            "test",
            "test-cheatsheet",
            "script",
            "script-cheatsheet",
            "poc",
            "poc-cheatsheet",
            "vm-expect-call",
            "vm-mockcall",
            "vm-hoax",
        ):
            self.assertIn(topic, output)

    def test_mapping_detail_is_beginner_friendly(self):
        result, output = self.render("mapping")
        self.assertEqual(result, 0)
        self.assertIn("MENTAL MODEL", output)
        self.assertIn("SYNTAX", output)
        self.assertIn("REAL EXAMPLE", output)
        self.assertIn("STEP BY STEP", output)
        self.assertIn("mapping(address => uint256)", output)
        self.assertIn("balances[msg.sender]", output)

    def test_require_detail_explains_argument_order(self):
        result, output = self.render("require")
        self.assertEqual(result, 0)
        self.assertIn("First argument is the condition", output)
        self.assertIn("Second argument is optional failure information", output)

    def test_receive_and_fallback_are_separate_topics(self):
        for topic in ("receive", "fallback", "receive-vs-fallback"):
            result, output = self.render(topic)
            self.assertEqual(result, 0)
            self.assertIn("STEP BY STEP", output)
        result, output = self.render("receive-vs-fallback")
        self.assertIn("empty calldata", output)
        self.assertIn("fallback", output)

    def test_interface_detail_has_step_by_step_example(self):
        result, output = self.render("interface")
        self.assertEqual(result, 0)
        self.assertIn("restaurant menu", output)
        self.assertIn("interface IPriceFeed", output)
        self.assertIn("feed.latestAnswer()", output)

    def test_symbols_detail_contains_core_operators(self):
        result, output = self.render("symbols")
        self.assertEqual(result, 0)
        for token in ("=>", "[]", ".", "&&", "||", "==", "? :", "unchecked", "assembly"):
            self.assertIn(token, output)

    def test_search_finds_related_topics(self):
        result, output = self.render("search", "mapping")
        self.assertEqual(result, 0)
        self.assertIn("mapping", output)
        self.assertIn("nested-mapping", output)

    def test_foundry_test_script_poc_cheat_maps_are_detailed(self):
        for topic in ("test-cheatsheet", "script-cheatsheet", "poc-cheatsheet"):
            result, output = self.render(topic)
            self.assertEqual(result, 0)
            self.assertIn("MENTAL MODEL", output)
            self.assertIn("SYNTAX", output)
            self.assertIn("REAL EXAMPLE", output)
            self.assertIn("STEP BY STEP", output)

    def test_foundry_cheatcode_topics_show_usage(self):
        for topic, token in (
            ("vm-expect-call", "expectCall"),
            ("vm-mockcall", "mockCall"),
            ("vm-hoax", "hoax"),
        ):
            result, output = self.render(topic)
            self.assertEqual(result, 0)
            self.assertIn(token, output)

    def test_learning_extensions_cover_loops_globals_types_and_calldata(self):
        for topic in (
            "for",
            "while",
            "do-while",
            "for-each",
            "loop-comparison",
            "globals",
            "globals-map",
            "mapping-types",
            "struct-types",
            "types-table",
            "calldata-deep",
            "call-data-layout",
            "terminology",
            "ternary-deep",
            "parameter-vs-argument",
        ):
            result, output = self.render(topic)
            self.assertEqual(result, 0)
            self.assertIn("STEP BY STEP", output)

    def test_topic_view_menu_and_contract_mode(self):
        result, output = self.render("for")
        self.assertEqual(result, 0)
        self.assertIn("NEXT VIEW", output)
        self.assertIn("1  Contract Lab", output)
        self.assertIn("2  Walkthrough", output)
        self.assertIn("3  Term Decoder", output)
        self.assertIn("4  Audit Lens", output)

        result, output = self.render("for", "1")
        self.assertEqual(result, 0)
        self.assertIn("LOWKEY // CONTRACT LAB", output)
        self.assertIn("contract ForExample", output)
        self.assertIn("numbers.push(i)", output)

    def test_topic_detail_modes_are_selectable(self):
        for option, marker in (
            ("2", "LOWKEY // WALKTHROUGH"),
            ("3", "LOWKEY // TERM DECODER"),
            ("4", "LOWKEY // AUDIT LENS"),
        ):
            result, output = self.render("ternary", option)
            self.assertEqual(result, 0)
            self.assertIn(marker, output)

    def test_global_values_explain_call_context(self):
        result, output = self.render("globals")
        self.assertEqual(result, 0)
        for token in (
            "msg.sender",
            "msg.value",
            "msg.data",
            "msg.sig",
            "block.timestamp",
            "tx.origin",
            "address(this).balance",
        ):
            self.assertIn(token, output)
        self.assertIn("address(this).amount is not a Solidity global", output)

    def test_mapping_and_struct_tables_explain_key_and_value(self):
        result, output = self.render("mapping-types")
        self.assertEqual(result, 0)
        self.assertIn("balances[msg.sender]", output)
        self.assertIn("key", output.lower())
        self.assertIn("value", output.lower())

        result, output = self.render("struct-types")
        self.assertEqual(result, 0)
        self.assertIn("field type", output.lower())
        self.assertIn("actual value", output.lower())
        self.assertIn("amount: amount", output)

    def test_calldata_and_receive_fallback_are_connected(self):
        result, output = self.render("calldata-deep")
        self.assertEqual(result, 0)
        self.assertIn("raw byte payload", output)
        self.assertIn("first four bytes", output)
        self.assertIn("msg.data", output)
        self.assertIn("string calldata", output)

        result, output = self.render("receive-vs-fallback")
        self.assertEqual(result, 0)
        self.assertIn("Empty calldata", output)
        self.assertIn("fallback", output)
        self.assertIn("msg.data", output)

    def test_reference_format_and_contract_view(self):
        result, output = self.render("require")
        self.assertEqual(result, 0)
        self.assertIn("REQUIRE", output)
        self.assertIn("─", output)
        self.assertIn("require(condition, \"message\");", output)
        self.assertIn("CONTRACT USE", output)
        self.assertIn("contract RequireLab", output)
        self.assertIn("MENTAL MODEL", output)
        self.assertIn("STEP BY STEP", output)

        result, output = self.render("require", "1")
        self.assertEqual(result, 0)
        self.assertIn("LOWKEY // CONTRACT LAB", output)
        self.assertIn("contract RequireLab", output)

    def test_symbols_reference_covers_core_solidity_marks(self):
        result, output = self.render("symbols")
        self.assertEqual(result, 0)
        for token in (
            ";", ",", "()", "{}", "[]", ".", ":", "=>",
            "=", "+=", "-=", "*=", "/=", "%=",
            "+", "-", "*", "/", "%", "**", "++", "--",
            "==", "!=", "<", "<=", ">", ">=", "!", "&&", "||",
            "&", "|", "^", "~", "<<", ">>", "? :",
            "a[i]", "a[i:j]", "f{value: amount}()",
            "// comment", "/* block comment */", "/// NatSpec line",
        ):
            self.assertIn(token, output)

    def test_loop_topics_are_separate_and_contract_backed(self):
        for topic in ("for", "while", "do-while", "for-each", "loop-comparison"):
            result, output = self.render(topic)
            self.assertEqual(result, 0)
            self.assertIn("CONTRACT USE", output)
            self.assertIn("STEP BY STEP", output)
        result, output = self.render("loop-comparison")
        self.assertIn("for", output.lower())
        self.assertIn("while", output.lower())
        self.assertIn("do-while", output.lower())

    def test_globals_and_global_functions_are_separate(self):
        result, output = self.render("globals")
        self.assertEqual(result, 0)
        for token in ("msg.sender", "msg.value", "msg.data", "msg.sig",
                      "block.timestamp", "block.number", "tx.origin",
                      "gasleft()", "address(this).balance"):
            self.assertIn(token, output)

        result, output = self.render("global-functions")
        self.assertEqual(result, 0)
        for token in ("keccak256", "abi.encode", "abi.decode",
                      "type(T)", "gasleft()"):
            self.assertIn(token, output)

    def test_type_reference_tables_explain_key_and_value(self):
        result, output = self.render("mapping-types")
        self.assertEqual(result, 0)
        for token in ("KEY TYPE", "VALID?", "WHAT GOES INSIDE []",
                      "ValueType", "balances[msg.sender]"):
            self.assertIn(token, output)

        result, output = self.render("struct-types")
        self.assertEqual(result, 0)
        for token in ("FIELD TYPE", "WHAT IS THE VALUE?",
                      "FIELD NAME", "actual data", "amount: amount"):
            self.assertIn(token, output)

    def test_calldata_reference_connects_to_receive_and_fallback(self):
        result, output = self.render("calldata-deep")
        self.assertEqual(result, 0)
        for token in ("raw byte payload", "first four bytes",
                      "msg.data", "string calldata"):
            self.assertIn(token, output)

        result, output = self.render("receive-vs-fallback")
        self.assertEqual(result, 0)
        for token in ("Empty calldata", "fallback", "msg.data", "msg.value"):
            self.assertIn(token, output)

    def test_complex_term_alias_is_explained(self):
        result, output = self.render("terniary")
        self.assertEqual(result, 0)
        self.assertIn("TERNARY", output)
        self.assertIn("condition", output.lower())
        self.assertIn("value", output.lower())

    def test_unknown_topic_is_helpful(self):
        result, output = self.render("recieve")
        self.assertEqual(result, 2)
        self.assertIn("Did you mean:", output)
        self.assertIn("receive", output)


    def test_new_learning_tools_exist(self):
        result, output = self.render("keywords")
        self.assertEqual(result, 0)
        for token in ("contract KeywordsLab", "memory", "calldata", "storage"):
            self.assertIn(token, output)

        result, output = self.render("contract-anatomy")
        self.assertEqual(result, 0)
        for token in ("state", "modifier", "constructor", "receive", "fallback"):
            self.assertIn(token.lower(), output.lower())

        result, output = self.render("call-anatomy")
        self.assertEqual(result, 0)
        for token in ("call", "staticcall", "delegatecall"):
            self.assertIn(token, output)

        result, output = self.render("types-defaults")
        self.assertEqual(result, 0)
        self.assertIn("address(0)", output)
        self.assertIn("false", output)
        self.assertIn("delete user", output)

    def test_new_learning_commands(self):
        cases = [
            (("compare", "for", "while", "do-while"), "LOWKEY // COMPARE"),
            (("expression", "balances[msg.sender] += msg.value"), "LOWKEY // EXPRESSION READER"),
            (("practice", "mapping"), "LOWKEY // PRACTICE"),
            (("confused", "calldata"), "LOWKEY // COMMONLY CONFUSED"),
            (("patterns",), "LOWKEY // CHEAT • PATTERNS"),
        ]
        for args, marker in cases:
            result, output = self.render(*args)
            self.assertEqual(result, 0)
            self.assertIn(marker, output)

    def test_symbols_keywords_and_version_reference(self):
        result, output = self.render("symbols")
        self.assertEqual(result, 0)
        for token in ("|=", "^=", "&=", "<<=", ">>="):
            self.assertIn(token, output)

        result, output = self.render("keywords")
        self.assertEqual(result, 0)
        self.assertIn("unchecked", output)
        self.assertIn("delegatecall", output.lower())

        result, output = self.render("versioning")
        self.assertEqual(result, 0)
        self.assertIn("pragma solidity ^0.8.20", output)
        self.assertIn("Cancun-era", output)

    def test_global_reference_is_broad_and_calldata_lab_is_safe(self):
        result, output = self.render("globals-map")
        self.assertEqual(result, 0)
        for token in ("block.coinbase", "block.gaslimit", "block.basefee",
                      "block.prevrandao", "tx.gasprice",
                      "address(this).balance"):
            self.assertIn(token, output)

        for topic in ("globals", "calldata", "calldata-deep", "call-data-layout"):
            result, output = self.render(topic, "1")
            self.assertEqual(result, 0)
            self.assertNotIn("returns (bytes calldata)", output)

    def test_mapping_and_struct_outputs_keep_syntax_labels(self):
        result, output = self.render("mapping")
        self.assertEqual(result, 0)
        self.assertIn("SYNTAX", output)

        result, output = self.render("struct-types")
        self.assertEqual(result, 0)
        self.assertIn("FIELD NAME", output)



if __name__ == "__main__":
    unittest.main()
