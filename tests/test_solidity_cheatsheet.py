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

    def test_unknown_topic_is_helpful(self):
        result, output = self.render("recieve")
        self.assertEqual(result, 2)
        self.assertIn("Did you mean:", output)
        self.assertIn("receive", output)


if __name__ == "__main__":
    unittest.main()
