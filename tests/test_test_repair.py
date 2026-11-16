import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import test_repair


class TestRepairTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
        (self.root / "test" / ".lowkey").mkdir(parents=True)
        self.test_file = self.root / "test" / ".lowkey" / "Lowkey_Break_Fallback.t.sol"
        self.original = (
            "pragma solidity ^0.8.20;\n"
            "contract LowkeyBreakTest {\n"
            "    function testProbe() public {\n"
            "        uint256 first = 1;\n"
            "        uint256 second = first + 1;\n"
            "        assertEq(second, 2);\n"
            "    }\n"
            "}\n"
        )
        self.test_file.write_text(self.original, encoding="utf-8")

    def report(self):
        return {
            "summary": "The test keeps several temporary values alive at once.",
            "hint_one": "Look at the local values near the line named in the error.",
            "hint_two": "Could one small calculation move into a helper?",
            "concept": "A function can run out of room for temporary values.",
            "patch_old": "        uint256 first = 1;\n        uint256 second = first + 1;",
            "patch_new": "        uint256 second = _nextValue();\n",
            "patch_reason": "Move the temporary calculation into a helper.",
        }

    def test_guide_mode_gives_a_clue_without_changing_the_file(self):
        output = "Compiler error:\n  --> test/.lowkey/Lowkey_Break_Fallback.t.sol:5:9\n"
        stream = io.StringIO()
        with patch.dict(os.environ, {"LOWKEY_REPAIR_MODE_OVERRIDE": "guide"}), \
             patch.object(test_repair, "_ai_module") as ai_module, \
             contextlib.redirect_stdout(stream):
            ai = ai_module.return_value
            ai.status.return_value = {"enabled": True, "usable": True}
            ai.request_structured.return_value = self.report()
            code, handled = test_repair.handle_failure("walkthrough", ["--auto"], output, 1, self.root)
        self.assertEqual((code, handled), (1, True))
        self.assertEqual(self.test_file.read_text(encoding="utf-8"), self.original)
        self.assertIn("LOWKEY AI — GUIDE", stream.getvalue())
        self.assertIn("FIRST HINT", stream.getvalue())
        hint_output = io.StringIO()
        with contextlib.redirect_stdout(hint_output):
            self.assertEqual(test_repair.show_next_hint(self.root), 0)
        self.assertIn("Could one small calculation", hint_output.getvalue())

    def test_lazy_mode_requires_both_build_and_targeted_test_to_pass(self):
        output = "Compiler error:\n  --> test/.lowkey/Lowkey_Break_Fallback.t.sol:5:9\n"
        good = type("Result", (), {"returncode": 0, "stdout": "ok", "stderr": ""})()
        stream = io.StringIO()
        with patch.dict(os.environ, {"LOWKEY_REPAIR_MODE_OVERRIDE": "lazy"}), \
             patch.object(test_repair, "_ai_module") as ai_module, \
             patch.object(test_repair.subprocess, "run", return_value=good) as forge, \
             contextlib.redirect_stdout(stream):
            ai_module.return_value.status.return_value = {"enabled": True, "usable": True}
            ai_module.return_value.request_structured.return_value = self.report()
            code, handled = test_repair.handle_failure("build", [], output, 1, self.root)
        self.assertEqual((code, handled), (0, True))
        self.assertNotEqual(self.test_file.read_text(encoding="utf-8"), self.original)
        self.assertEqual(forge.call_count, 2)
        self.assertEqual(forge.call_args_list[0].args[0], ["forge", "build"])
        self.assertEqual(forge.call_args_list[1].args[0][:3], ["forge", "test", "--match-path"])
        history = json.loads((self.root / ".audit" / "ai-repair" / "history.json").read_text())
        self.assertEqual(len(history["repairs"]), 1)
        self.assertIn("LOWKEY AI — FIXED", stream.getvalue())

    def test_lazy_mode_restores_original_test_when_forge_check_fails(self):
        output = "Compiler error:\n  --> test/.lowkey/Lowkey_Break_Fallback.t.sol:5:9\n"
        failed = type("Result", (), {"returncode": 1, "stdout": "", "stderr": "still failing"})()
        with patch.dict(os.environ, {"LOWKEY_REPAIR_MODE_OVERRIDE": "lazy"}), \
             patch.object(test_repair, "_ai_module") as ai_module, \
             patch.object(test_repair.subprocess, "run", return_value=failed), \
             contextlib.redirect_stdout(io.StringIO()):
            ai_module.return_value.status.return_value = {"enabled": True, "usable": True}
            ai_module.return_value.request_structured.return_value = self.report()
            code, handled = test_repair.handle_failure("build", [], output, 1, self.root)
        self.assertEqual((code, handled), (1, True))
        self.assertEqual(self.test_file.read_text(encoding="utf-8"), self.original)

    def test_lazy_mode_never_changes_contract_source(self):
        source = self.root / "src"
        source.mkdir()
        contract = source / "Fallback.sol"
        original = "pragma solidity ^0.8.20; contract Fallback { }\n"
        contract.write_text(original, encoding="utf-8")
        output = "Compiler error:\n  --> src/Fallback.sol:1:20\n"
        stream = io.StringIO()
        report = dict(self.report())
        report.update({"patch_old": "contract Fallback { }", "patch_new": "contract Fallback { uint x; }"})
        with patch.dict(os.environ, {"LOWKEY_REPAIR_MODE_OVERRIDE": "lazy"}), \
             patch.object(test_repair, "_ai_module") as ai_module, \
             contextlib.redirect_stdout(stream):
            ai_module.return_value.status.return_value = {"enabled": True, "usable": True}
            ai_module.return_value.request_structured.return_value = report
            code, handled = test_repair.handle_failure("build", [], output, 1, self.root)
        self.assertEqual((code, handled), (1, True))
        self.assertEqual(contract.read_text(encoding="utf-8"), original)
        self.assertIn("never edit your contracts", stream.getvalue().lower())
        self.assertIn("foundry settings", stream.getvalue().lower())

    def test_lazy_mode_refuses_to_remove_a_security_assertion(self):
        patch_old = "        uint256 second = first + 1;\n        assertEq(second, 2);"
        patch_new = "        uint256 second = first + 1;"
        self.assertIsNone(test_repair._safe_patch(self.original, patch_old, patch_new))


if __name__ == "__main__":
    unittest.main()
