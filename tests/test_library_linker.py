import copy
import unittest

from lowkey.library_linker import (
    ArtifactIdentity,
    LinkError,
    extract_link_references,
    link_creation_bytecode,
    recursive_library_order,
)


def placeholder():
    return "__$" + "a" * 34 + "$__"


def library(source="contracts/core/PositionUtils.sol", name="PositionUtils", bytecode="0x6000"):
    return {
        "sourceName": source,
        "contractName": name,
        "abi": [],
        "bytecode": bytecode,
        "deployedBytecode": "0x6000",
        "linkReferences": {},
    }


class LibraryLinkerTests(unittest.TestCase):
    def setUp(self):
        self.lib = library()
        self.position_manager = {
            "sourceName": "contracts/core/PositionManager.sol",
            "contractName": "PositionManager",
            "abi": [],
            "bytecode": "0x6000" + placeholder() + "60" + placeholder() + "00",
            "linkReferences": {
                "contracts/core/PositionUtils.sol": {
                    "PositionUtils": [
                        {"start": 2, "length": 20},
                        {"start": 23, "length": 20},
                    ]
                }
            },
        }
        self.artifacts = {"contracts/core/PositionUtils.sol:PositionUtils": self.lib}
        self.address = "0x5fbdb2315678afecb367f032d93f642f64180aa3"

    def test_extracts_two_hardhat_link_references(self):
        refs = extract_link_references(self.position_manager)
        self.assertEqual([(r.start, r.length) for r in refs], [(2, 20), (23, 20)])
        self.assertEqual(refs[0].identity, ArtifactIdentity("contracts/core/PositionUtils.sol", "PositionUtils"))

    def test_links_both_references_to_same_library_without_mutating_artifact(self):
        original = copy.deepcopy(self.position_manager)
        result = link_creation_bytecode(
            self.position_manager,
            self.artifacts,
            {"contracts/core/PositionUtils.sol:PositionUtils": self.address},
            network_identity={"session_id": "test-session", "chain_id": 31337},
        )
        body = result.linked_bytecode[2:]
        self.assertEqual(body[4:44], self.address[2:])
        self.assertEqual(body[46:86], self.address[2:])
        self.assertEqual(len(result.links), 2)
        self.assertEqual(self.position_manager, original)
        self.assertEqual(result.evidence()["network_identity"]["session_id"], "test-session")

    def test_gmx_position_manager_offsets_link_to_same_library_address(self):
        total_bytes = 17000
        body = "00" * total_bytes
        for start in (15857, 16472):
            offset = start * 2
            body = body[:offset] + placeholder() + body[offset + 40:]
        gmx_manager = {
            "sourceName": "contracts/core/PositionManager.sol",
            "contractName": "PositionManager",
            "abi": [],
            "bytecode": "0x" + body,
            "linkReferences": {
                "contracts/core/PositionUtils.sol": {
                    "PositionUtils": [
                        {"start": 15857, "length": 20},
                        {"start": 16472, "length": 20},
                    ]
                }
            },
        }
        result = link_creation_bytecode(
            gmx_manager,
            self.artifacts,
            {"contracts/core/PositionUtils.sol:PositionUtils": self.address},
            network_identity={"session_id": "gmx-test", "chain_id": 31337},
        )
        linked = result.linked_bytecode[2:]
        for start in (15857, 16472):
            self.assertEqual(linked[start * 2:start * 2 + 40], self.address[2:])
        self.assertEqual(len(result.links), 2)

    def test_missing_library_address_fails_closed(self):
        with self.assertRaises(LinkError) as caught:
            link_creation_bytecode(self.position_manager, self.artifacts, {})
        self.assertEqual(caught.exception.code, "UNRESOLVED_LIBRARY")

    def test_duplicate_same_name_artifacts_are_ambiguous(self):
        duplicate = library("vendor/PositionUtils.sol")
        artifacts = {"a": self.lib, "b": duplicate}
        with self.assertRaises(LinkError) as caught:
            link_creation_bytecode(
                self.position_manager,
                artifacts,
                {"contracts/core/PositionUtils.sol:PositionUtils": self.address},
            )
        self.assertEqual(caught.exception.code, "AMBIGUOUS_LIBRARY_ARTIFACT")

    def test_wrong_source_artifact_is_not_accepted(self):
        wrong = library("other/PositionUtils.sol")
        with self.assertRaises(LinkError) as caught:
            link_creation_bytecode(
                self.position_manager,
                {"other/PositionUtils.sol:PositionUtils": wrong},
                {"contracts/core/PositionUtils.sol:PositionUtils": self.address},
            )
        self.assertEqual(caught.exception.code, "LIBRARY_SOURCE_MISMATCH")

    def test_invalid_offset_is_rejected(self):
        bad = copy.deepcopy(self.position_manager)
        bad["linkReferences"]["contracts/core/PositionUtils.sol"]["PositionUtils"][0]["start"] = 999
        with self.assertRaises(LinkError) as caught:
            link_creation_bytecode(bad, self.artifacts, {"contracts/core/PositionUtils.sol:PositionUtils": self.address})
        self.assertEqual(caught.exception.code, "INVALID_LINK_REFERENCE")

    def test_non_integer_offsets_are_rejected_without_coercion(self):
        for invalid in (2.5, True, "2"):
            with self.subTest(value=invalid):
                bad = copy.deepcopy(self.position_manager)
                bad["linkReferences"]["contracts/core/PositionUtils.sol"]["PositionUtils"][0]["start"] = invalid
                with self.assertRaises(LinkError) as caught:
                    extract_link_references(bad)
                self.assertEqual(caught.exception.code, "INVALID_LINK_REFERENCE")

    def test_wrong_length_is_rejected(self):
        bad = copy.deepcopy(self.position_manager)
        bad["linkReferences"]["contracts/core/PositionUtils.sol"]["PositionUtils"][0]["length"] = 19
        with self.assertRaises(LinkError) as caught:
            link_creation_bytecode(bad, self.artifacts, {"contracts/core/PositionUtils.sol:PositionUtils": self.address})
        self.assertEqual(caught.exception.code, "INVALID_LINK_REFERENCE")

    def test_foundry_nested_link_references_are_supported(self):
        foundry = {
            "sourceName": "src/Target.sol",
            "contractName": "Target",
            "bytecode": {
                "object": "0x6000" + placeholder() + "00",
                "linkReferences": {"contracts/core/PositionUtils.sol": {"PositionUtils": [{"start": 2, "length": 20}]}},
            },
        }
        refs = extract_link_references(foundry)
        self.assertEqual(len(refs), 1)
        result = link_creation_bytecode(foundry, self.artifacts, {"contracts/core/PositionUtils.sol:PositionUtils": self.address})
        self.assertIn(self.address[2:], result.linked_bytecode)

    def test_recursive_library_order_is_dependency_first(self):
        leaf = library("src/Leaf.sol", "Leaf")
        parent = library("src/Parent.sol", "Parent", "0x6000" + placeholder() + "00")
        parent["bytecode"] = {
            "object": "0x6000" + placeholder() + "00",
            "linkReferences": {"src/Leaf.sol": {"Leaf": [{"start": 2, "length": 20}]}},
        }
        target = {
            "sourceName": "src/Target.sol", "contractName": "Target",
            "bytecode": {"object": "0x6000" + placeholder() + "00", "linkReferences": {"src/Parent.sol": {"Parent": [{"start": 2, "length": 20}]}}},
        }
        artifacts = {"src/Parent.sol:Parent": parent, "src/Leaf.sol:Leaf": leaf}
        order = recursive_library_order(target, artifacts)
        self.assertEqual([item.qualified_name for item in order], ["src/Leaf.sol:Leaf", "src/Parent.sol:Parent"])

    def test_unrelated_synthetic_project_alpha_links_a_renamed_library(self):
        alpha_library = library("src/math/MathLibrary.sol", "MathLibrary")
        alpha_target = {
            "sourceName": "src/TokenVault.sol",
            "contractName": "TokenVault",
            "bytecode": {
                "object": "0x6000" + placeholder() + "00",
                "linkReferences": {"src/math/MathLibrary.sol": {"MathLibrary": [{"start": 2, "length": 20}]}},
            },
        }
        result = link_creation_bytecode(
            alpha_target,
            {"src/math/MathLibrary.sol:MathLibrary": alpha_library},
            {"src/math/MathLibrary.sol:MathLibrary": self.address},
        )
        self.assertEqual(result.identity.qualified_name, "src/TokenVault.sol:TokenVault")
        self.assertIn(self.address[2:], result.linked_bytecode)

    def test_unrelated_synthetic_project_beta_links_multiple_library_names(self):
        interest = library("src/finance/InterestCalculator.sol", "InterestCalculator")
        prices = library("src/oracle/PriceFeed.sol", "PriceFeed")
        beta_target = {
            "sourceName": "src/LendingPool.sol",
            "contractName": "LendingPool",
            "bytecode": "0x6000" + placeholder() + "60" + placeholder() + "00",
            "linkReferences": {
                "src/finance/InterestCalculator.sol": {"InterestCalculator": [{"start": 2, "length": 20}]},
                "src/oracle/PriceFeed.sol": {"PriceFeed": [{"start": 23, "length": 20}]},
            },
        }
        second_address = "0x" + "ab" * 20
        result = link_creation_bytecode(
            beta_target,
            {
                "src/finance/InterestCalculator.sol:InterestCalculator": interest,
                "src/oracle/PriceFeed.sol:PriceFeed": prices,
            },
            {
                "src/finance/InterestCalculator.sol:InterestCalculator": self.address,
                "src/oracle/PriceFeed.sol:PriceFeed": second_address,
            },
        )
        linked = result.linked_bytecode[2:]
        self.assertEqual(linked[4:44], self.address[2:])
        self.assertEqual(linked[46:86], second_address[2:])
        self.assertEqual(len(result.links), 2)

    def test_recursive_cycle_fails_closed(self):
        a = library("src/A.sol", "A")
        b = library("src/B.sol", "B")
        a["bytecode"] = {"object": "0x6000" + placeholder(), "linkReferences": {"src/B.sol": {"B": [{"start": 2, "length": 20}]}}}
        b["bytecode"] = {"object": "0x6000" + placeholder(), "linkReferences": {"src/A.sol": {"A": [{"start": 2, "length": 20}]}}}
        with self.assertRaises(LinkError) as caught:
            recursive_library_order(a, {"src/A.sol:A": a, "src/B.sol:B": b})
        self.assertEqual(caught.exception.code, "DEPENDENCY_CYCLE")

    def test_prelinked_different_address_is_not_overwritten(self):
        prelinked = copy.deepcopy(self.position_manager)
        old = "0x" + "11" * 20
        body = prelinked["bytecode"][2:]
        prelinked["bytecode"] = "0x" + body[:4] + old[2:] + body[44:]
        with self.assertRaises(LinkError) as caught:
            link_creation_bytecode(prelinked, self.artifacts, {"contracts/core/PositionUtils.sol:PositionUtils": self.address})
        self.assertEqual(caught.exception.code, "LIBRARY_ALREADY_LINKED_DIFFERENT_ADDRESS")


if __name__ == "__main__":
    unittest.main()
