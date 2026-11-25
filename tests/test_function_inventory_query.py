import contextlib
import io
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))
import lk


def _abi_function(name):
    return {
        "type": "function",
        "name": name,
        "stateMutability": "nonpayable",
        "inputs": [{"name": "value", "type": "uint256"}],
        "outputs": [],
    }


class FunctionInventoryQueryTests(unittest.TestCase):
    def test_exact_contract_selector_lists_all_compiled_abi_functions_without_live_target(self):
        abi = [_abi_function(f"method{index:02d}") for index in range(39)]
        artifact = {
            "contractName": "OrderBook",
            "sourceName": "contracts/core/OrderBook.sol",
            "abi": abi,
        }
        candidate = {
            "contract": "OrderBook",
            "path": "/tmp/project/out/OrderBook.sol/OrderBook.json",
            "artifact": artifact,
            "signatures": tuple(lk.format_signature(item) for item in abi),
            "source_name": "contracts/core/OrderBook.sol",
        }
        with patch.object(lk.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/project")), \
             patch.object(lk, "active_project_target", return_value=None), \
             patch.object(lk, "project_artifact_contract_artifacts", return_value=[candidate]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = lk.run_functions({}, ["OrderBook"])

        self.assertEqual(result, 0)
        rendered = output.getvalue()
        self.assertIn("Functions: 39", rendered)
        self.assertIn("method00(uint256)", rendered)
        self.assertIn("method38(uint256)", rendered)
        self.assertIn("Live     : none", rendered)

    def test_exact_selected_contract_name_clears_function_search_query(self):
        self.assertEqual(
            lk._function_query_for_selected_contract(
                "OrderBook", "OrderBook", {"target_contract": "OrderBook"}
            ),
            "",
        )
        self.assertEqual(
            lk._function_query_for_selected_contract(
                "executeSwapOrder", "OrderBook", {"target_contract": "OrderBook"}
            ),
            "executeSwapOrder",
        )

    def test_exact_contract_artifact_lookup_is_case_insensitive_and_deduplicates_identical_outputs(self):
        artifact = {
            "contractName": "OrderBook",
            "sourceName": "contracts/core/OrderBook.sol",
            "abi": [_abi_function("executeSwapOrder")],
        }
        with patch.object(lk, "local_artifact_paths", return_value=[
            "/project/out/OrderBook.sol/OrderBook.json",
            "/project/artifacts/OrderBook.json",
        ]), patch.object(lk, "read_artifact", side_effect=[artifact, artifact]):
            matches = lk.project_artifact_contract_artifacts("/project", "orderbook")

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["contract"], "OrderBook")
        self.assertEqual(matches[0]["source_name"], "contracts/core/OrderBook.sol")

    def test_same_name_different_sources_remain_ambiguous(self):
        first = {
            "contractName": "OrderBook",
            "sourceName": "contracts/core/OrderBook.sol",
            "abi": [_abi_function("executeSwapOrder")],
        }
        second = {
            "contractName": "OrderBook",
            "sourceName": "contracts/test/OrderBook.sol",
            "abi": [_abi_function("executeTestOrder")],
        }
        with patch.object(lk, "local_artifact_paths", return_value=[
            "/project/out/core/OrderBook.json",
            "/project/out/test/OrderBook.json",
        ]), patch.object(lk, "read_artifact", side_effect=[first, second]):
            matches = lk.project_artifact_contract_artifacts("/project", "OrderBook")

        self.assertEqual(len(matches), 2)
        self.assertNotEqual(matches[0]["source_name"], matches[1]["source_name"])


if __name__ == "__main__":
    unittest.main()
