import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "walkthrough.py"


spec = importlib.util.spec_from_file_location("lowkey_walkthrough", MODULE)
walk = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(walk)


class WalkthroughTests(unittest.TestCase):
    def test_address_classifier_does_not_confuse_actor_names(self):
        self.assertTrue(walk._is_address("0x" + "1" * 40))
        self.assertFalse(walk._is_address("Alice"))
        self.assertFalse(walk._is_address("0x" + "1" * 39))

    def test_split_params_handles_arrays_and_tuples(self):
        items = walk._split_params(
            "address agreement, tuple(address,uint256) data, address[] accounts"
        )
        self.assertEqual(len(items), 3)
        self.assertEqual(items[0], "address agreement")
        self.assertIn("tuple(address,uint256)", items[1])
        self.assertEqual(items[2], "address[] accounts")

    def test_source_parser_sees_typed_external_call(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "Factory.sol").write_text(
                """
                pragma solidity ^0.8.20;
                interface IAgreement { function owner() external view returns(address); }
                contract Factory {
                    address agreement;
                    function create(address a) external {
                        IAgreement(a).owner();
                    }
                }
                """,
                encoding="utf-8",
            )
            contracts = walk._parse_solidity_sources(root)
            factory = contracts["Factory"]
            create = next(x for x in factory.functions if x.name == "create")
            self.assertTrue(
                any(
                    c.get("kind") == "typed-call"
                    and c.get("interface") == "IAgreement"
                    and c.get("function") == "owner"
                    for c in create.calls
                )
            )

    def test_factory_does_not_synthesize_actors_as_create_pool_contract_roles(self):
        node = walk.LiveNode(
            address="0x" + "1" * 40,
            name="ConfidencePoolFactory",
            code_size=100,
            artifact_contract="ConfidencePoolFactory",
        )
        fn = walk.FunctionInfo(
            contract="ConfidencePoolFactory",
            name="createPool",
            inputs=[
                {"type": "address", "name": "agreement"},
                {"type": "address", "name": "stakeToken"},
                {"type": "uint256", "name": "expiry"},
                {"type": "uint256", "name": "minStake"},
                {"type": "address", "name": "recoveryAddress"},
                {"type": "address[]", "name": "accounts"},
            ],
            outputs=[],
            mutability="nonpayable",
            signature="createPool(address,address,uint256,uint256,address,address[])",
        )
        args, reason = walk._semantic_args(
            node,
            fn,
            {"ConfidencePoolFactory": [fn]},
            [node],
            {"Alice": "0x" + "a" * 40, "Bob": "0x" + "b" * 40},
            {},
            1_800_000_000,
            pathlib.Path(tmp := "."),
            "http://127.0.0.1:8545",
        )
        self.assertIsNone(args)
        self.assertIn("Agreement", reason)

    def test_error_decoder_reports_static_custom_error(self):
        err = {"name": "StakingClosed", "inputs": []}
        selector = walk._keccak_selector("StakingClosed()")
        decoded = walk._decode_error(selector, [err])
        self.assertEqual(decoded, "StakingClosed()")

    def test_mutations_include_zero_and_actor_swaps(self):
        actors = {
            "Alice": "0x" + "a" * 40,
            "Bob": "0x" + "b" * 40,
            "Attacker": "0x" + "c" * 40,
        }
        mutations = walk._mutations(1, "uint256", actors, __import__("random").Random(1337))
        self.assertIn(0, mutations)
        self.assertIn(2, mutations)

        addr_mutations = walk._mutations(
            actors["Alice"], "address", actors, __import__("random").Random(1337)
        )
        self.assertIn(actors["Bob"], addr_mutations)
        self.assertIn(walk.ZERO, addr_mutations)


if __name__ == "__main__":
    unittest.main()
