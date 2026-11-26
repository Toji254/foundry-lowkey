"""Compiler-backed dependency evidence must remain generic and conservative."""
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

import project_tools
import source_ast


class CompilerDependencyEvidenceTests(unittest.TestCase):
    def _write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def _build_info(self, root, contents):
        definitions = {
            "src/Math.sol": [
                {"nodeType": "ContractDefinition", "id": 1, "name": "VectorMath", "contractKind": "library", "nodes": [], "baseContracts": []}
            ],
            "src/Interfaces.sol": [
                {"nodeType": "ContractDefinition", "id": 3, "name": "IPriceSource", "contractKind": "interface", "nodes": [], "baseContracts": []}
            ],
            "src/Helper.sol": [
                {"nodeType": "ContractDefinition", "id": 4, "name": "CacheFactory", "contractKind": "contract", "nodes": [], "baseContracts": []}
            ],
            "src/Other.sol": [
                {"nodeType": "ContractDefinition", "id": 5, "name": "SafeMath", "contractKind": "library", "nodes": [], "baseContracts": []}
            ],
            "src/Widget.sol": [
                {
                    "nodeType": "ContractDefinition", "id": 2, "name": "Widget", "contractKind": "contract", "baseContracts": [],
                    "nodes": [
                        {
                            "nodeType": "VariableDeclaration", "id": 20, "name": "priceSource", "stateVariable": True,
                            "src": "0:1:0",
                            "typeName": {"nodeType": "UserDefinedTypeName", "referencedDeclaration": 3},
                            "typeDescriptions": {"typeString": "contract IPriceSource"},
                        },
                        {
                            "nodeType": "FunctionDefinition", "id": 21, "name": "", "kind": "constructor",
                            "src": "0:1:0",
                            "parameters": {"parameters": [
                                {
                                    "nodeType": "VariableDeclaration", "id": 22, "name": "source", "src": "0:1:0",
                                    "typeName": {"nodeType": "UserDefinedTypeName", "referencedDeclaration": 3},
                                    "typeDescriptions": {"typeString": "contract IPriceSource"},
                                }
                            ]},
                            "body": {"nodeType": "Block", "statements": []},
                        },
                        {
                            "nodeType": "FunctionDefinition", "id": 23, "name": "createCache", "kind": "function",
                            "src": "0:1:0",
                            "body": {"nodeType": "Block", "statements": [
                                {"nodeType": "ExpressionStatement", "expression": {
                                    "nodeType": "NewExpression", "src": "0:1:0",
                                    "typeName": {"nodeType": "UserDefinedTypeName", "referencedDeclaration": 4},
                                }}
                            ]},
                        },
                    ],
                }
            ],
        }
        sources = {}
        output_sources = {}
        contracts = {}
        for index, (path, content) in enumerate(contents.items()):
            sources[path] = {"content": content}
            output_sources[path] = {"id": index, "ast": {"nodeType": "SourceUnit", "nodes": definitions[path]}}
            compiled_contracts = {}
            for declaration in definitions[path]:
                name = declaration["name"]
                evm = {"bytecode": {"linkReferences": {}}}
                if name == "Widget":
                    evm["bytecode"]["linkReferences"] = {
                        "src/Math.sol": {"VectorMath": [
                            {"start": 158, "length": 20},
                            {"start": 178, "length": 20},
                        ]}
                    }
                compiled_contracts[name] = {"evm": evm}
            contracts[path] = compiled_contracts
        build_info = {
            "input": {"sources": sources},
            "output": {"sources": output_sources, "contracts": contracts},
        }
        info_path = root / "out" / "build-info" / "generic.json"
        info_path.parent.mkdir(parents=True, exist_ok=True)
        info_path.write_text(json.dumps(build_info), encoding="utf-8")

    def test_compiler_evidence_distinguishes_link_creation_and_typed_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write(root, "foundry.toml", '[profile.default]\nsrc="src"\n')
            contents = {
                "src/Math.sol": "pragma solidity ^0.8.20; library VectorMath {}\n",
                "src/Interfaces.sol": "pragma solidity ^0.8.20; interface IPriceSource {}\n",
                "src/Helper.sol": "pragma solidity ^0.8.20; contract CacheFactory {}\n",
                "src/Widget.sol": "pragma solidity ^0.8.20; contract Widget {}\n",
            }
            for path, content in contents.items():
                self._write(root, path, content)
            self._build_info(root, contents)

            graph = project_tools.build_dependency_graph(root)
            edges = graph["typed_edges"]
            widget_edges = [edge for edge in edges if edge["from"] == "src/Widget.sol:Widget"]

            links = [edge for edge in widget_edges if edge["kind"] == "solidity-library-link"]
            self.assertEqual(len(links), 1)
            self.assertEqual(links[0]["to"], "src/Math.sol:VectorMath")
            self.assertEqual(links[0]["confidence"], "CONFIRMED")
            self.assertEqual(links[0]["link_references"], [(158, 20), (178, 20)])
            self.assertTrue(links[0]["auto_deploy"])
            compiler_report = graph["compiler_dependencies"]
            self.assertTrue(compiler_report["library_order_complete"])
            self.assertEqual(
                compiler_report["library_deployment_order"],
                ["src/Math.sol:VectorMath", "src/Widget.sol:Widget"],
            )
            self.assertEqual(compiler_report["library_cycles"], [])

            creations = [edge for edge in widget_edges if edge["kind"] == "creation-expression"]
            self.assertEqual(len(creations), 1)
            self.assertEqual(creations[0]["to"], "src/Helper.sol:CacheFactory")
            self.assertFalse(creations[0]["auto_deploy"])

            typed = [edge for edge in widget_edges if edge["kind"] == "state-contract-reference"]
            self.assertEqual(len(typed), 1)
            self.assertEqual(typed[0]["to"], "src/Interfaces.sol:IPriceSource")
            self.assertEqual(typed[0]["confidence"], "INFERRED")
            self.assertFalse(typed[0]["auto_deploy"])

            constructor_edges = [edge for edge in widget_edges if edge.get("function") == "constructor"]
            self.assertTrue(constructor_edges)
            self.assertTrue(all(edge["requires_resolution"] for edge in constructor_edges))
            # An import is not itself an instruction to deploy its imported symbol.
            self.assertFalse(any(edge.get("kind") == "import" and edge.get("auto_deploy") for edge in edges))

    def test_confirmed_library_cycle_blocks_linear_deployment_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write(root, "foundry.toml", '[profile.default]\nsrc="src"\n')
            contents = {
                "src/Math.sol": "pragma solidity ^0.8.20; library VectorMath {}\n",
                "src/Other.sol": "pragma solidity ^0.8.20; library SafeMath {}\n",
            }
            for path, content in contents.items():
                self._write(root, path, content)
            definitions = {
                path: [{
                    "nodeType": "ContractDefinition", "id": index, "name": name,
                    "contractKind": "library", "nodes": [], "baseContracts": [],
                }]
                for index, (path, name) in enumerate([
                    ("src/Math.sol", "VectorMath"),
                    ("src/Other.sol", "SafeMath"),
                ], 1)
            }
            source_inputs = {path: {"content": content} for path, content in contents.items()}
            output_sources = {
                path: {"id": index, "ast": {"nodeType": "SourceUnit", "nodes": definitions[path]}}
                for index, path in enumerate(contents)
            }
            output_contracts = {
                "src/Math.sol": {"VectorMath": {"evm": {"bytecode": {"linkReferences": {
                    "src/Other.sol": {"SafeMath": [{"start": 10, "length": 20}]}
                }}}}},
                "src/Other.sol": {"SafeMath": {"evm": {"bytecode": {"linkReferences": {
                    "src/Math.sol": {"VectorMath": [{"start": 12, "length": 20}]}
                }}}}},
            }
            info = root / "out" / "build-info" / "cycle.json"
            info.parent.mkdir(parents=True)
            info.write_text(json.dumps({
                "input": {"sources": source_inputs},
                "output": {"sources": output_sources, "contracts": output_contracts},
            }), encoding="utf-8")

            report = source_ast.compiler_dependency_evidence(root, contents)
            self.assertFalse(report["library_order_complete"])
            self.assertEqual(report["library_deployment_order"], [])
            self.assertEqual(report["library_cycles"], [[
                "src/Math.sol:VectorMath", "src/Other.sol:SafeMath",
            ]])
            self.assertEqual(len(report["library_order_blocked"]), 2)

    def test_stale_compiler_source_does_not_create_confirmed_edges(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._write(root, "foundry.toml", '[profile.default]\n')
            current = "pragma solidity ^0.8.20; contract Renamed {}\n"
            self._write(root, "src/Renamed.sol", current)
            old = "pragma solidity ^0.8.20; contract OldName {}\n"
            self._build_info(root, {
                "src/Math.sol": "pragma solidity ^0.8.20; library OldMath {}\n",
                "src/Interfaces.sol": "pragma solidity ^0.8.20; interface IOld {}\n",
                "src/Helper.sol": "pragma solidity ^0.8.20; contract OldHelper {}\n",
                "src/Widget.sol": old,
            })
            evidence = source_ast.compiler_dependency_evidence(root, {"src/Renamed.sol": current})
            self.assertEqual(evidence["edges"], [])
            self.assertGreater(evidence["stale_units"], 0)


if __name__ == "__main__":
    unittest.main()
