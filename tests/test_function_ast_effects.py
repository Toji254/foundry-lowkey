import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
import sys
sys.path.insert(0, str(LOWKEY))

import lk


class FunctionAstEffectInventoryTests(unittest.TestCase):
    def _fixture(self, *, parser="SOLC_AST+LEXICAL", include_ast=True):
        root = pathlib.Path(tempfile.mkdtemp())
        source_path = root / "contracts" / "core" / "OrderBook.sol"
        source_path.parent.mkdir(parents=True)
        source_path.write_text("// fixture source\n", encoding="utf-8")

        nodes = [
            {"id": "fn", "kind": "function", "name": "executeSwapOrder",
             "signature": "executeSwapOrder()", "contract": "OrderBook",
             "file": "contracts/core/OrderBook.sol",
             "qualified_name": "OrderBook.executeSwapOrder()"},
            {"id": "helper", "kind": "function", "name": "_createSwapOrder",
             "signature": "_createSwapOrder()", "contract": "OrderBook",
             "file": "contracts/core/OrderBook.sol",
             "qualified_name": "OrderBook._createSwapOrder()"},
            {"id": "guard", "kind": "modifier", "name": "onlyGov",
             "signature": "onlyGov()", "contract": "OrderBook",
             "file": "contracts/core/OrderBook.sol",
             "qualified_name": "OrderBook.onlyGov"},
            {"id": "orders", "kind": "state_variable", "name": "swapOrders",
             "contract": "OrderBook", "file": "contracts/core/OrderBook.sol",
             "qualified_name": "OrderBook.swapOrders"},
            {"id": "index", "kind": "state_variable", "name": "swapOrdersIndex",
             "contract": "OrderBook", "file": "contracts/core/OrderBook.sol",
             "qualified_name": "OrderBook.swapOrdersIndex"},
            {"id": "event", "kind": "event", "name": "SwapOrderCreated",
             "contract": "OrderBook", "file": "contracts/core/OrderBook.sol",
             "qualified_name": "OrderBook.SwapOrderCreated"},
        ]
        ast_evidence = "SOLC_AST_DECLARATION_REFERENCE" if include_ast else "LEXICAL_SOURCE"
        storage_evidence = (
            "SOLC_AST_STORAGE_DECLARATION_REFERENCE" if include_ast else "LEXICAL_SOURCE"
        )
        edges = [
            {"id": "call", "kind": "CALLS", "from": "fn", "to": "helper",
             "resolution": "DIRECT", "evidence": ast_evidence},
            {"id": "modifier", "kind": "APPLIES_MODIFIER", "from": "fn", "to": "guard",
             "resolution": "DIRECT", "evidence": ast_evidence},
            {"id": "read", "kind": "READS", "from": "fn", "to": "orders",
             "resolution": "DIRECT", "evidence": storage_evidence,
             "access_path": "swapOrders[account][index]"},
            {"id": "write", "kind": "WRITES", "from": "fn", "to": "index",
             "resolution": "INFERRED", "evidence": "CALL_GRAPH_PROPAGATION",
             "access_path": "swapOrdersIndex",
             "via": ["fn", "helper"]},
            {"id": "emit", "kind": "EMITS", "from": "fn", "to": "event",
             "resolution": "DIRECT", "evidence": "LEXICAL_SOURCE"},
        ]
        index_data = {
            "root": str(root),
            "parser": parser,
            "ast": {
                "functions": 2 if include_ast else 0,
                "matched_units": 1,
                "stale_units": 0,
                "warnings": [],
            },
            "effect_propagation": {"depth_complete": True, "truncated_frontiers": 0},
            "inventory": {"complete": True, "uninspected": []},
            "nodes": nodes,
            "edges": edges,
        }
        record = {
            "name": "executeSwapOrder",
            "signature": "executeSwapOrder()",
            "reads": ["lexicalRead"],
            "writes": ["lexicalWrite"],
            "events": [],
            "modifiers": [],
            "risk_flags": [],
            "classes": [],
        }
        return root, source_path, index_data, record

    def test_ast_effects_include_helper_writes_modifiers_and_resolved_calls(self):
        root, source_path, index, record = self._fixture()
        try:
            report = lk._function_source_graph_effects(
                root, source_path, "OrderBook", [record], index=index
            )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(report["matched_functions"], 1)
        self.assertIn("swapOrders[account][index]", record["reads"])
        self.assertIn("swapOrdersIndex", record["writes"])
        self.assertEqual(record["modifiers"], ["onlyGov"])
        self.assertEqual(record["events"], ["OrderBook.SwapOrderCreated"])
        self.assertIn("OrderBook._createSwapOrder() [CALLS]", record["resolved_calls"])
        self.assertEqual(record["helper_effect_paths"], ["OrderBook._createSwapOrder()"])
        self.assertEqual(record["effect_basis"], "SOLC_AST + STATIC_CALL_GRAPH")

    def test_lexical_only_graph_is_not_mislabeled_as_compiler_ast(self):
        root, source_path, index, record = self._fixture(
            parser="LEXICAL", include_ast=False
        )
        try:
            report = lk._function_source_graph_effects(
                root, source_path, "OrderBook", [record], index=index
            )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(report["matched_functions"], 1)
        self.assertEqual(record["effect_basis"], "SOURCE_GRAPH_LEXICAL")
        self.assertNotEqual(record["effect_basis"], "SOLC_AST + STATIC_CALL_GRAPH")

    def test_ambiguous_or_missing_declaration_keeps_lexical_fallback(self):
        root, source_path, index, record = self._fixture()
        index["nodes"].append(dict(index["nodes"][0], id="duplicate"))
        try:
            report = lk._function_source_graph_effects(
                root, source_path, "OrderBook", [record], index=index
            )
        finally:
            import shutil
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(report["matched_functions"], 0)
        self.assertEqual(record["reads"], ["lexicalRead"])
        self.assertEqual(record["writes"], ["lexicalWrite"])
        self.assertEqual(record["effect_basis"], "LEXICAL_FALLBACK")
        self.assertIn("ambiguous", record["effect_basis_note"])


if __name__ == "__main__":
    unittest.main()
