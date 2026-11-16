import random
import unittest

from lowkey import abi_support


class RecursiveABISupportTests(unittest.TestCase):
    def test_canonical_signature_expands_nested_tuple_types(self):
        item = {
            "type": "tuple[][2]",
            "components": [
                {"name": "owner", "type": "address"},
                {
                    "name": "limits",
                    "type": "tuple",
                    "components": [
                        {"name": "min", "type": "uint128"},
                        {"name": "enabled", "type": "bool"},
                    ],
                },
            ],
        }
        self.assertEqual(
            abi_support.canonical_abi_type(item),
            "(address,(uint128,bool))[][2]",
        )

    def test_canonicalizes_legacy_integer_and_byte_aliases(self):
        self.assertEqual(abi_support.canonical_abi_type({"type": "uint"}), "uint256")
        self.assertEqual(abi_support.canonical_abi_type({"type": "int[]"}), "int256[]")
        self.assertEqual(abi_support.canonical_abi_type({"type": "byte[4]"}), "bytes1[4]")

    def test_recursive_tuple_and_nested_array_samples_are_deterministic(self):
        item = {
            "type": "tuple[]",
            "components": [
                {"name": "recipient", "type": "address"},
                {"name": "amounts", "type": "uint256[][]"},
                {"name": "metadata", "type": "bytes"},
            ],
        }
        first = abi_support.sample_abi_value(
            item, "one", rng=random.Random(7), fallback_address="0x" + "22" * 20
        )
        second = abi_support.sample_abi_value(
            item, "one", rng=random.Random(7), fallback_address="0x" + "22" * 20
        )
        self.assertEqual(first, second)
        self.assertEqual(first, "[(0x" + "22" * 20 + ",[[1]],0x01)]")

    def test_zero_mode_preserves_fixed_array_lengths(self):
        values = abi_support.sample_abi_inputs(
            [
                {"type": "uint256[3]"},
                {"type": "address[]"},
                {"type": "bool[2][]"},
            ],
            "zero",
        )
        self.assertEqual(values, ["[0,0,0]", "[]", "[]"])

    def test_integer_width_boundaries_are_respected(self):
        item = {"type": "uint8"}
        self.assertEqual(abi_support.sample_abi_value(item, "max"), "255")
        self.assertEqual(abi_support.sample_abi_value({"type": "int8"}, "max"), "127")
        self.assertEqual(abi_support.sample_abi_value({"type": "int8"}, "normal", rng=random.Random(3)), "-1")

    def test_dynamic_string_bytes_and_function_inputs_are_supported(self):
        values = abi_support.sample_abi_inputs(
            [
                {"type": "string"},
                {"type": "bytes"},
                {"type": "bytes24"},
                {"type": "function"},
            ],
            "one",
        )
        self.assertEqual(values[0], "lowkey")
        self.assertEqual(values[1], "0x01")
        self.assertEqual(values[2], "0x" + "01" * 24)
        self.assertEqual(values[3], "0x" + "00" * 24)

    def test_missing_tuple_components_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "component"):
            abi_support.sample_abi_value({"type": "tuple"})

    def test_excessive_array_dimensions_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "64-element"):
            abi_support.sample_abi_value({"type": "uint256[65]"})

    def test_total_recursive_element_budget_prevents_large_fixed_expansions(self):
        with self.assertRaisesRegex(ValueError, "4096-element"):
            abi_support.sample_abi_value({"type": "uint256[64][64][2]"}, "one")

    def test_excessive_tuple_nesting_fails_closed(self):
        item = {"type": "uint256"}
        for _ in range(12):
            item = {"type": "tuple", "components": [item]}
        with self.assertRaisesRegex(ValueError, "depth limit"):
            abi_support.canonical_abi_type(item)


if __name__ == "__main__":
    unittest.main()
