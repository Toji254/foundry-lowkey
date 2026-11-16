import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "tests" / "fixtures" / "acceptance" / "p0-break-e2e" / "run_campaigns.py"

spec = importlib.util.spec_from_file_location("p0_break_campaign_runner", MODULE)
runner = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = runner
spec.loader.exec_module(runner)


class P0BreakCampaignRunnerTests(unittest.TestCase):
    def test_shared_anvil_state_is_reverted_after_success(self):
        calls = []

        def fake_rpc(method, params):
            calls.append((method, params))
            return "0xabc" if method == "evm_snapshot" else True

        with patch.object(runner, "rpc", side_effect=fake_rpc):
            result = runner.run_with_snapshot(lambda: "campaigns passed")

        self.assertEqual(result, "campaigns passed")
        self.assertEqual(
            calls,
            [("evm_snapshot", []), ("evm_revert", ["0xabc"])],
        )

    def test_shared_anvil_state_is_reverted_when_campaign_raises(self):
        calls = []

        def fake_rpc(method, params):
            calls.append((method, params))
            return "0xdef" if method == "evm_snapshot" else True

        def fail_campaign():
            raise ValueError("fixture campaign failed")

        with patch.object(runner, "rpc", side_effect=fake_rpc):
            with self.assertRaisesRegex(ValueError, "fixture campaign failed"):
                runner.run_with_snapshot(fail_campaign)

        self.assertEqual(
            calls,
            [("evm_snapshot", []), ("evm_revert", ["0xdef"])],
        )

    def test_snapshot_revert_failure_fails_the_acceptance_runner(self):
        def fake_rpc(method, params):
            return "0x123" if method == "evm_snapshot" else False

        with patch.object(runner, "rpc", side_effect=fake_rpc):
            with self.assertRaisesRegex(RuntimeError, "failed to restore shared Anvil state"):
                runner.run_with_snapshot(lambda: None)


if __name__ == "__main__":
    unittest.main()
