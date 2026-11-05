from __future__ import annotations

import random
import re
import unittest

from lowkey import break_engine


class _Host:
    def anvil_rpc_info(self, _config):
        return {"accounts": [
            "0x1111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222",
        ]}

    @staticmethod
    def is_address(value):
        return bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", str(value)))


class P0SetupCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.host = _Host()
        self.target = break_engine.Target(
            contract="CompatibilityTarget",
            address="0x3333333333333333333333333333333333333333",
        )

    def test_dynamic_address_array_gets_a_nonempty_attacker_probe(self):
        values = break_engine._make_value(
            self.host,
            {"inputs": [{"name": "recipients", "type": "address[]"}]},
            random.Random(7),
            "one",
        )
        self.assertEqual(values, ["[0x2222222222222222222222222222222222222222]"])

    def test_fixed_address_array_preserves_abi_length(self):
        values = break_engine._make_value(
            self.host,
            {"inputs": [{"name": "recipients", "type": "address[3]"}]},
            random.Random(7),
            "one",
        )
        self.assertEqual(len(values[0][1:-1].split(",")), 3)

    def test_integer_array_is_not_misparsed_as_a_scalar_uint(self):
        values = break_engine._make_value(
            self.host,
            {"inputs": [{"name": "amounts", "type": "uint256[]"}]},
            random.Random(7),
            "one",
        )
        self.assertEqual(values, ["[1]"])

    def test_nested_and_tuple_abi_types_refuse_with_type_name(self):
        for abi_type in ("address[][]", "tuple"):
            with self.subTest(abi_type=abi_type):
                with self.assertRaisesRegex(ValueError, re.escape(abi_type)):
                    break_engine._make_value(
                        self.host,
                        {"inputs": [{"name": "value", "type": abi_type}]},
                        random.Random(7),
                        "one",
                    )

    def test_renderer_materializes_memory_array_and_uses_actor(self):
        declarations, expressions = break_engine._render_abi_arguments(
            [{"name": "recipients", "type": "address[]"}],
            ["[0x2222222222222222222222222222222222222222]"],
            actor_expr="address(ATTACKER)",
            prefix="testArg",
        )
        self.assertIn("new address[](1)", declarations)
        self.assertIn("testArg_0[0] = address(ATTACKER);", declarations)
        self.assertEqual(expressions, ["testArg_0"])

    def test_setup_discovery_supports_address_array_abi(self):
        setup = break_engine._find_setup_abi([
            {
                "type": "function",
                "name": "deposit",
                "stateMutability": "nonpayable",
                "inputs": [{"name": "recipients", "type": "address[]"}],
                "outputs": [],
            }
        ])
        self.assertIsNotNone(setup)
        self.assertEqual(setup["name"], "deposit")

    def test_unsupported_setup_type_is_not_guessed(self):
        setup = break_engine._find_setup_abi([
            {
                "type": "function",
                "name": "deposit",
                "stateMutability": "nonpayable",
                "inputs": [{"name": "details", "type": "tuple"}],
                "outputs": [],
            }
        ])
        self.assertIsNone(setup)

    def test_repeat_harness_uses_token_decimals_and_optional_return_approval(self):
        body = break_engine._render_repeat_test(
            self.target,
            {"inputs": [{"name": "amount", "type": "uint256"}]},
            "withdraw(uint256)",
            ["1"],
            "0",
            "accounting",
            None,
            entitlement_signature="credit(address)",
            asset_signature="asset()",
            setup_abi={
                "name": "deposit",
                "stateMutability": "nonpayable",
                "inputs": [{"name": "amount", "type": "uint256"}],
                "outputs": [],
            },
        )
        self.assertIn('abi.encodeWithSignature("decimals()")', body)
        self.assertIn("reportedDecimals <= 77", body)
        self.assertIn('TOKEN_DECIMALS_SOURCE', body)
        self.assertIn('fallback-18', body)
        self.assertIn("deal(assetToken, ATTACKER, tokenSeedAmount)", body)
        self.assertIn("returndata.length == 0", body)
        self.assertIn("LOWKEY_APPROVE_RESET_FAILED", body)
        self.assertIn('abi.encodeWithSignature("deposit(uint256)", 1)', body)
        self.assertNotIn("IERC20Lowkey(assetToken).approve", body)

    def test_reentrancy_actor_has_standard_receiver_hooks(self):
        body = break_engine._render_reentrancy_test(
            self.target,
            {"inputs": [{"name": "recipients", "type": "address[]"}]},
            "withdraw(address[])",
            ["[0x2222222222222222222222222222222222222222]"],
            2,
            setup_abi={
                "name": "deposit",
                "stateMutability": "payable",
                "inputs": [{"name": "recipients", "type": "address[]"}],
                "outputs": [],
            },
        )
        for marker in (
            "tokensReceived(",
            "onERC1155Received(",
            "onERC1155BatchReceived(",
            "onERC721Received(",
            "supportsInterface(",
            "setInterfaceImplementer(",
            "ERC777TokensRecipient",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, body)
        self.assertIn("abi.encodeWithSignature(\"deposit(address[])\", lowkeySetupArg_0)", body)
        self.assertIn("new address[](1)", body)


if __name__ == "__main__":
    unittest.main()
