import json
import tempfile
import unittest
from pathlib import Path

from lowkey.protocol_graph import compiler_ast_graph, runtime_trace_graph, build_full_protocol_graph


class ProtocolGraphTests(unittest.TestCase):
    def _build_info(self, root: Path, *, current_source: str | None = None):
        source = current_source if current_source is not None else "contract Vault { uint256 total; }"
        source_path = root / "src" / "Vault.sol"
        source_path.parent.mkdir(parents=True, exist_ok=True)
        source_path.write_text(source, encoding="utf-8")
        ast = {
            "nodeType": "SourceUnit",
            "id": 0,
            "nodes": [{
                "nodeType": "ContractDefinition",
                "id": 1,
                "name": "Vault",
                "contractKind": "contract",
                "abstract": False,
                "linearizedBaseContracts": [1],
                "baseContracts": [],
                "nodes": [
                    {
                        "nodeType": "VariableDeclaration", "id": 2,
                        "name": "total", "src": "20:5:0", "stateVariable": True,
                        "visibility": "internal",
                        "typeDescriptions": {"typeString": "uint256"},
                    },
                    {
                        "nodeType": "VariableDeclaration", "id": 7,
                        "name": "paused", "src": "25:6:0", "stateVariable": True,
                        "visibility": "public",
                        "typeDescriptions": {"typeString": "bool"},
                    },
                    {
                        "nodeType": "StructDefinition", "id": 8,
                        "name": "Position", "src": "2:15:0",
                        "members": [{
                            "nodeType": "VariableDeclaration", "id": 9,
                            "name": "shares",
                            "typeDescriptions": {"typeString": "uint256"},
                        }],
                    },
                    {
                        "nodeType": "EnumDefinition", "id": 10,
                        "name": "Status", "src": "18:20:0",
                        "members": [{"name": "Open"}, {"name": "Closed"}],
                    },
                    {
                        "nodeType": "EventDefinition", "id": 11,
                        "name": "Deposited", "src": "40:20:0",
                        "parameters": {"parameters": [{
                            "name": "account", "indexed": True,
                            "typeDescriptions": {"typeString": "address"},
                        }]},
                    },
                    {
                        "nodeType": "ErrorDefinition", "id": 12,
                        "name": "Paused", "src": "61:10:0",
                        "parameters": {"parameters": []},
                    },
                    {
                        "nodeType": "UserDefinedValueTypeDefinition", "id": 13,
                        "name": "Shares", "src": "72:12:0",
                        "underlyingType": {"typeDescriptions": {"typeString": "uint96"}},
                    },
                    {
                        "nodeType": "ModifierDefinition", "id": 6,
                        "name": "onlyOwner", "src": "5:10:0",
                        "body": {
                            "nodeType": "Block",
                            "statements": [{
                                "nodeType": "ExpressionStatement",
                                "expression": {
                                    "nodeType": "Identifier",
                                    "name": "paused",
                                    "referencedDeclaration": 7,
                                },
                            }],
                        },
                    },
                    {
                        "nodeType": "FunctionDefinition", "id": 3,
                        "name": "deposit", "src": "30:90:0", "kind": "function",
                        "visibility": "external", "stateMutability": "nonpayable",
                        "implemented": True,
                        "modifiers": [{"src": "35:9:0", "modifierName": {"referencedDeclaration": 6}}],
                        "parameters": {"parameters": []},
                        "body": {
                            "nodeType": "Block",
                            "statements": [{
                                "nodeType": "ExpressionStatement",
                                "expression": {
                                    "nodeType": "Assignment",
                                    "operator": "=",
                                    "leftHandSide": {
                                        "nodeType": "Identifier",
                                        "name": "total",
                                        "referencedDeclaration": 2,
                                    },
                                    "rightHandSide": {
                                        "nodeType": "FunctionCall", "src": "50:12:0",
                                        "expression": {
                                            "nodeType": "Identifier",
                                            "name": "helper",
                                            "referencedDeclaration": 5,
                                        },
                                        "arguments": [],
                                    },
                                },
                            }],
                        },
                    },
                    {
                        "nodeType": "FunctionDefinition", "id": 4,
                        "name": "balance", "src": "130:30:0", "kind": "function",
                        "visibility": "external", "stateMutability": "view",
                        "implemented": True,
                        "parameters": {"parameters": []},
                        "body": {
                            "nodeType": "Block",
                            "statements": [{
                                "nodeType": "ExpressionStatement",
                                "expression": {
                                    "nodeType": "Identifier",
                                    "name": "total",
                                    "referencedDeclaration": 2,
                                },
                            }],
                        },
                    },
                    {
                        "nodeType": "FunctionDefinition", "id": 5,
                        "name": "helper", "src": "170:20:0", "kind": "function",
                        "visibility": "internal", "stateMutability": "pure",
                        "implemented": True,
                        "parameters": {"parameters": []},
                        "body": {"nodeType": "Block", "statements": []},
                    },
                ],
            }],
        }
        info_dir = root / "out" / "build-info"
        info_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "solcVersion": "0.8.30",
            "input": {"sources": {"src/Vault.sol": {"content": source}}},
            "output": {"sources": {"src/Vault.sol": {"ast": ast}}},
        }
        (info_dir / "fixture.json").write_text(json.dumps(payload), encoding="utf-8")

    def test_compiler_ast_graph_extracts_contract_functions_and_state_dependencies(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self._build_info(root)
            graph = compiler_ast_graph(root)
        self.assertEqual(graph["status"], "AST_OBSERVED")
        self.assertEqual(graph["compiler_versions"], ["0.8.30"])
        functions = {node["name"]: node for node in graph["nodes"] if node["kind"] == "function"}
        self.assertEqual(functions["deposit"]["writes"], ["src/Vault.sol:Vault::state::total"])
        self.assertEqual(functions["balance"]["reads"], ["src/Vault.sol:Vault::state::total"])
        call_edge = next(edge for edge in graph["edges"] if edge["kind"] == "compiler_call_candidate")
        self.assertEqual(call_edge["source_span"], "50:12:0")
        self.assertTrue(any(edge["kind"] == "uses_modifier" for edge in graph["edges"]))
        modifier = next(node for node in graph["nodes"] if node["kind"] == "modifier")
        self.assertEqual(modifier["reads"], ["src/Vault.sol:Vault::state::paused"])
        declaration_kinds = {node["kind"] for node in graph["nodes"]}
        self.assertTrue({"struct", "enum", "event", "error", "user_defined_value_type"}.issubset(declaration_kinds))
        self.assertTrue(any(edge["kind"] == "state_dependency_candidate" for edge in graph["edges"]))

    def test_compiler_ast_rejects_stale_source_build_info(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self._build_info(root)
            (root / "src" / "Vault.sol").write_text("contract Vault { uint256 newer; }", encoding="utf-8")
            graph = compiler_ast_graph(root)
        self.assertEqual(graph["status"], "AST_UNAVAILABLE")
        self.assertEqual(graph["nodes"], [])
        self.assertTrue(any("changed since" in item["reason"] for item in graph["rejected_sources"]))

    def test_missing_build_info_returns_consistent_unavailable_shape(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ast = compiler_ast_graph(root)
            graph = build_full_protocol_graph(root)
        self.assertEqual(ast["status"], "AST_UNAVAILABLE")
        self.assertTrue(ast["limitations"])
        self.assertEqual(graph["state_dependency_graph"]["status"], "UNAVAILABLE")
        self.assertTrue(graph["state_dependency_graph"]["limitations"])
        self.assertEqual(graph["runtime_call_graph"]["status"], "RUNTIME_TRACE_UNAVAILABLE")

    def test_runtime_graph_uses_only_validated_canonical_trace_streams(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            audit = root / ".audit"
            audit.mkdir()
            report = {
                "run_id": "unit-fixture",
                "canonical_trace_events": [{
                    "seq": 0,
                    "backend": "anvil-calltracer",
                    "kind": "CALL",
                    "accessor": "0x" + "1" * 40,
                    "account": "0x" + "2" * 40,
                    "depth": 0,
                    "value": "0x0",
                    "selector": "0x12345678",
                    "calldata": "0x12345678",
                    "reverted": False,
                    "storage": None,
                    "storage_support": "declared_only",
                }],
            }
            (audit / "trace.json").write_text(json.dumps(report), encoding="utf-8")
            graph = runtime_trace_graph(root)
        self.assertEqual(graph["status"], "RUNTIME_TRACE_OBSERVED")
        self.assertEqual(len(graph["edges"]), 1)
        self.assertEqual(graph["edges"][0]["source"], "0x" + "1" * 40)
        self.assertEqual(graph["edges"][0]["target"], "0x" + "2" * 40)
        self.assertEqual(graph["edges"][0]["run_id"], "unit-fixture")

    def test_runtime_graph_rejects_malformed_trace_without_guessing(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            audit = root / ".audit"
            audit.mkdir()
            (audit / "trace.json").write_text(json.dumps({
                "canonical_trace_events": [{
                    "seq": 1, "backend": "anvil-calltracer", "kind": "CALL",
                    "accessor": None, "account": None, "depth": 0, "value": "0x0",
                    "selector": None, "calldata": None, "reverted": False,
                    "storage": None, "storage_support": "declared_only",
                }]
            }), encoding="utf-8")
            graph = runtime_trace_graph(root)
        self.assertEqual(graph["status"], "RUNTIME_TRACE_UNAVAILABLE")
        self.assertEqual(graph["edges"], [])
        self.assertTrue(graph["rejected"])

    def test_combined_graph_keeps_ast_and_runtime_evidence_separate(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self._build_info(root)
            (root / ".audit").mkdir()
            graph = build_full_protocol_graph(root)
        self.assertEqual(graph["compiler_ast"]["status"], "AST_OBSERVED")
        self.assertEqual(graph["runtime_call_graph"]["status"], "RUNTIME_TRACE_UNAVAILABLE")
        self.assertEqual(graph["state_dependency_graph"]["status"], "AST_CANDIDATES")


if __name__ == "__main__":
    unittest.main()
