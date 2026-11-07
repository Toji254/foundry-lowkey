import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "godmode.py"
SPEC = importlib.util.spec_from_file_location("lowkey_storage_metric_tested", MODULE)
godmode = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = godmode
SPEC.loader.exec_module(godmode)
_forge_storage_metric = godmode._forge_storage_metric


class ForgeStorageMetricTests(unittest.TestCase):
    def setUp(self):
        self.address = "0x" + "2" * 40
        self.slot = "0x" + "0" * 63 + "2"
        self.zero = "0x" + "0" * 64
        self.one = "0x" + "0" * 63 + "1"
        self.metric_spec = {
            "address": self.address,
            "slot": "0x2",
            "kind": "uint256_delta",
        }

    def normalized(self, accesses):
        return {
            "prestate": [{
                "address": self.address,
                "storage": [{"slot": self.slot, "value": self.zero}],
            }],
            "storage_accesses": accesses,
            # Deliberately empty: Forge does not guarantee a native-balance
            # record for every contract that participates in a callback.
            "balance_deltas": [],
        }

    def test_storage_metric_uses_trace_even_when_actor_balance_delta_is_missing(self):
        normalized = self.normalized([
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.zero,
                "is_write": False, "reverted": False,
            },
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.one,
                "is_write": True, "reverted": False,
            },
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.one, "new_value": self.one,
                "is_write": False, "reverted": False,
            },
        ])

        result = _forge_storage_metric(normalized, self.metric_spec)

        self.assertEqual(result["before"], 0)
        self.assertEqual(result["after"], 1)
        self.assertEqual(result["delta"], 1)
        self.assertEqual(result["writes"], 1)
        self.assertEqual(result["observations"], 3)

    def test_zero_delta_is_a_valid_successful_write_not_missing_fidelity(self):
        normalized = self.normalized([
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.zero,
                "is_write": True, "reverted": False,
            },
            {
                # A trailing read must not override the final successful write.
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.one,
                "is_write": False, "reverted": False,
            },
        ])

        result = _forge_storage_metric(normalized, self.metric_spec)

        self.assertEqual(result["delta"], 0)
        self.assertEqual(result["after"], 0)
        self.assertEqual(result["writes"], 1)

    def test_reverted_write_does_not_change_the_observed_metric(self):
        normalized = self.normalized([
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.zero,
                "is_write": True, "reverted": False,
            },
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.one,
                "is_write": True, "reverted": True,
            },
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.zero,
                "is_write": False, "reverted": False,
            },
        ])

        result = _forge_storage_metric(normalized, self.metric_spec)

        self.assertEqual(result["delta"], 0)
        self.assertEqual(result["writes"], 1)

    def test_metric_refuses_to_guess_when_the_slot_was_not_recorded(self):
        normalized = self.normalized([])
        normalized["prestate"][0]["storage"] = []

        with self.assertRaisesRegex(ValueError, "did not capture"):
            _forge_storage_metric(normalized, self.metric_spec)

    def test_metric_refuses_an_unobserved_slot_even_when_prestate_exists(self):
        normalized = self.normalized([])
        with self.assertRaisesRegex(ValueError, "did not observe"):
            _forge_storage_metric(normalized, self.metric_spec)

    def test_metric_rejects_a_trace_that_disagrees_with_transaction_prestate(self):
        normalized = self.normalized([
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.one, "new_value": self.one,
                "is_write": False, "reverted": False,
            },
        ])
        with self.assertRaisesRegex(ValueError, "differs from the normalized transaction prestate"):
            _forge_storage_metric(normalized, self.metric_spec)

    def test_metric_rejects_observations_without_a_successful_write(self):
        normalized = self.normalized([
            {
                "account": self.address, "slot": self.slot,
                "previous_value": self.zero, "new_value": self.zero,
                "is_write": False, "reverted": False,
            },
        ])
        with self.assertRaisesRegex(ValueError, "no successful write"):
            _forge_storage_metric(normalized, self.metric_spec)

    def test_metric_rejects_unsupported_metric_kinds(self):
        normalized = self.normalized([])
        metric_spec = {**self.metric_spec, "kind": "native_profit"}
        with self.assertRaisesRegex(ValueError, "supports only uint256_delta"):
            _forge_storage_metric(normalized, metric_spec)


if __name__ == "__main__":
    unittest.main()
