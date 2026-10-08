import importlib.util
import pathlib
from unittest.mock import patch
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "lk.py"

spec = importlib.util.spec_from_file_location("lowkeycast_state_diff", MODULE)
lk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lk)


class StateDiffGeneratorTests(unittest.TestCase):
    def test_repeat_count_log_uses_explicit_uint256_type(self):
        captured = {}

        def capture_generated_test(_prefix, body, announce=False):
            captured["body"] = body
            return "test/Lowkey_state_diff_regression.t.sol"

        config = {
            "target": "0x" + "1" * 40,
            "actor": "Alice",
            "wallets": {},
            "rpc": "http://127.0.0.1:0",
        }

        with patch.object(
            lk,
            "encode_target_call",
            return_value=("ping()", "deadbeef"),
        ), patch.object(
            lk,
            "resolve_lab_value",
            return_value="0",
        ), patch.object(
            lk,
            "validate_solidity_value",
            return_value="0",
        ), patch.object(
            lk,
            "actor_address",
            return_value="0x" + "2" * 40,
        ), patch.object(
            lk,
            "write_generated_test",
            side_effect=capture_generated_test,
        ), patch.object(
            lk,
            "run_foundry",
            return_value=lk.CommandResult("compile failed", 1),
        ), patch.object(
            lk,
            "discard_generated_test",
        ):
            result = lk.run_state_diff(config, ["ping", "--repeat", "2"])

        self.assertEqual(result, 1)
        self.assertIn(
            'console2.log("REPEAT_COUNT", uint256(2));',
            captured["body"],
        )
        self.assertNotIn(
            'console2.log("REPEAT_COUNT", 2);',
            captured["body"],
        )


if __name__ == "__main__":
    unittest.main()
