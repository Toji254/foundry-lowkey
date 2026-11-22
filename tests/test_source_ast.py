import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

import source_ast
from source_index import build_source_index, find_symbols


class SourceAstTests(unittest.TestCase):
    def _write(self, root: pathlib.Path, relative: str, content: str) -> pathlib.Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _src(self, source: str, text: str, start_after: int = 0) -> str:
        start = source.index(text, start_after)
        return f"{len(source[:start].encode('utf-8'))}:{len(text.encode('utf-8'))}:0"

    def _fixture(self, *, stale: bool = False):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        self._write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
        source = """
        pragma solidity ^0.8.20;

        contract Vault {
            modifier onlyAdmin() { _; }

            function withdraw() external onlyAdmin {
                _debit();
            }

            function _debit() internal {}
        }

        contract Other {
            function _debit() internal {}
        }
        """
        self._write(root, "src/Vault.sol", source)
        embedded_source = source + "// stale build-info source\n" if stale else source

        call_start = source.index("_debit();")
        modifier_start = source.index("onlyAdmin")
        vault_start = source.index("contract Vault")
        other_start = source.index("contract Other")
        withdraw_start = source.index("function withdraw")
        debit_start = source.index("function _debit", withdraw_start)
        modifier_def_start = source.index("modifier onlyAdmin")
        other_debit_start = source.index("function _debit", debit_start + 1)

        def node(node_id, node_type, name, start_text, *, kind=None, children=None, **extra):
            start = source.index(start_text)
            end = start + len(start_text)
            result = {
                "id": node_id,
                "nodeType": node_type,
                "name": name,
                "src": f"{len(source[:start].encode('utf-8'))}:{len(source[start:end].encode('utf-8'))}:0",
            }
            if kind is not None:
                result["kind"] = kind
            if children is not None:
                result["nodes"] = children
            result.update(extra)
            return result

        modifier_invocation = {
            "id": 20,
            "nodeType": "ModifierInvocation",
            "modifierName": {
                "id": 21,
                "nodeType": "Identifier",
                "name": "onlyAdmin",
                "referencedDeclaration": 5,
                "src": self._src(source, "onlyAdmin", source.index("function withdraw")),
            },
            "arguments": [],
            "src": self._src(source, "onlyAdmin"),
        }
        function_call = {
            "id": 30,
            "nodeType": "FunctionCall",
            "expression": {
                "id": 31,
                "nodeType": "Identifier",
                "name": "_debit",
                "referencedDeclaration": 4,
                "src": self._src(source, "_debit"),
            },
            "arguments": [],
            "src": self._src(source, "_debit();"),
        }

        vault_contract = {
            "id": 1,
            "nodeType": "ContractDefinition",
            "name": "Vault",
            "contractKind": "contract",
            "src": self._src(source, "contract Vault"),
            "nodes": [
                {
                    "id": 5,
                    "nodeType": "ModifierDefinition",
                    "name": "onlyAdmin",
                    "src": self._src(source, "modifier onlyAdmin"),
                    "virtual": False,
                    "body": {"id": 50, "nodeType": "Block", "statements": [], "src": self._src(source, "modifier onlyAdmin() { _; }")},
                },
                {
                    "id": 2,
                    "nodeType": "FunctionDefinition",
                    "kind": "function",
                    "name": "withdraw",
                    "visibility": "external",
                    "virtual": False,
                    "src": self._src(source, "function withdraw() external onlyAdmin {\n                _debit();\n            }"),
                    "modifiers": [modifier_invocation],
                    "body": {
                        "id": 32,
                        "nodeType": "Block",
                        "statements": [{
                            "id": 33,
                            "nodeType": "ExpressionStatement",
                            "expression": function_call,
                            "src": self._src(source, "_debit();"),
                        }],
                        "src": self._src(source, "{\n                _debit();\n            }"),
                    },
                },
                {
                    "id": 4,
                    "nodeType": "FunctionDefinition",
                    "kind": "function",
                    "name": "_debit",
                    "visibility": "internal",
                    "virtual": False,
                    "src": self._src(source, "function _debit() internal {}", debit_start),
                    "body": {"id": 40, "nodeType": "Block", "statements": [], "src": self._src(source, "{}")},
                },
            ],
        }
        other_contract = {
            "id": 10,
            "nodeType": "ContractDefinition",
            "name": "Other",
            "contractKind": "contract",
            "src": self._src(source, "contract Other"),
            "nodes": [{
                "id": 11,
                "nodeType": "FunctionDefinition",
                "kind": "function",
                "name": "_debit",
                "visibility": "internal",
                "virtual": False,
                "src": self._src(source, "function _debit() internal {}",),
                "body": {"id": 41, "nodeType": "Block", "statements": [], "src": self._src(source, "{}")},
            }],
        }
        ast = {
            "id": 0,
            "nodeType": "SourceUnit",
            "src": self._src(source, "pragma solidity"),
            "nodes": [vault_contract, other_contract],
        }
        build_info = {
            "id": "test-build",
            "solcVersion": "0.8.28",
            "input": {"sources": {"src/Vault.sol": {"content": embedded_source}}},
            "output": {"sources": {"src/Vault.sol": {"id": 0, "ast": ast}}},
        }
        self._write(root, "out/build-info/test.json", json.dumps(build_info))
        return temporary, root, source

    def test_ast_declaration_references_replace_lexical_same_name_resolution(self):
        temporary, root, _source = self._fixture()
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        withdraw = find_symbols(index, "Vault.withdraw()")[0]
        vault_debit = find_symbols(index, "Vault._debit()")[0]
        other_debit = find_symbols(index, "Other._debit()")[0]
        ast_calls = [
            edge for edge in index["edges"]
            if edge.get("from") == withdraw["id"]
            and edge.get("kind") == "CALLS"
            and edge.get("evidence") == "SOLC_AST_DECLARATION_REFERENCE"
        ]
        self.assertEqual(
            len(ast_calls), 1,
            msg=f"AST match diagnostics: {json.dumps(index.get('ast'), sort_keys=True)}; inventory={json.dumps(index.get('inventory'), sort_keys=True)}",
        )
        self.assertEqual(ast_calls[0]["to"], vault_debit["id"])
        self.assertNotEqual(ast_calls[0]["to"], other_debit["id"])
        self.assertEqual(ast_calls[0]["resolution"], "DIRECT")
        ast_modifiers = [
            edge for edge in index["edges"]
            if edge.get("from") == withdraw["id"]
            and edge.get("kind") == "APPLIES_MODIFIER"
            and edge.get("evidence") == "SOLC_AST_DECLARATION_REFERENCE"
        ]
        self.assertEqual(len(ast_modifiers), 1)
        self.assertEqual(index["parser"], "SOLC_AST+LEXICAL")
        self.assertGreaterEqual(index["ast"]["functions"], 3)

    def test_ast_storage_mapping_write_and_compound_write_are_declaration_resolved(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        self._write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
        source = """
        pragma solidity ^0.8.20;
        contract StorageVault {
            mapping(address => uint256) public balances;
            function set(address user, uint256 amount) external {
                balances[user] = amount;
            }
            function increase(address user, uint256 amount) external {
                balances[user] += amount;
            }
        }
        """
        self._write(root, "src/StorageVault.sol", source)

        state_src = self._src(source, "mapping(address => uint256) public balances")
        set_src = self._src(source, "function set(address user, uint256 amount) external {\n                balances[user] = amount;\n            }")
        increase_src = self._src(source, "function increase(address user, uint256 amount) external {\n                balances[user] += amount;\n            }")

        def ident(name, referenced, snippet):
            return {
                "id": referenced + 100,
                "nodeType": "Identifier",
                "name": name,
                "referencedDeclaration": referenced,
                "src": self._src(source, snippet),
            }

        def access_and_assignment(operator, expression):
            index_access = {
                "id": 30 if operator == "=" else 40,
                "nodeType": "IndexAccess",
                "baseExpression": ident("balances", 10, "balances"),
                "indexExpression": {
                    "id": 31 if operator == "=" else 41,
                    "nodeType": "Identifier",
                    "name": "user",
                    "referencedDeclaration": 21 if operator == "=" else 22,
                    "src": self._src(source, "user", source.index("function set") if operator == "=" else source.index("function increase")),
                },
                "src": self._src(source, expression),
            }
            assignment_start = source.index(expression)
            assignment = {
                "id": 32 if operator == "=" else 42,
                "nodeType": "Assignment",
                "operator": operator,
                "leftHandSide": index_access,
                "rightHandSide": {
                    "id": 33 if operator == "=" else 43,
                    "nodeType": "Identifier",
                    "name": "amount" if operator == "=" else "amount",
                    "referencedDeclaration": 23 if operator == "=" else 24,
                    "src": self._src(source, "amount", assignment_start),
                },
                "src": self._src(source, expression + (";" if operator == "=" else ";")),
            }
            return {
                "id": 34 if operator == "=" else 44,
                "nodeType": "ExpressionStatement",
                "expression": assignment,
                "src": self._src(source, expression + ";"),
            }

        set_expression = "balances[user] = amount"
        increase_expression = "balances[user] += amount"
        set_statement = access_and_assignment("=", set_expression)
        increase_statement = access_and_assignment("+=", increase_expression)

        contract_ast = {
            "id": 1,
            "nodeType": "ContractDefinition",
            "name": "StorageVault",
            "contractKind": "contract",
            "src": self._src(source, "contract StorageVault"),
            "nodes": [
                {
                    "id": 10,
                    "nodeType": "VariableDeclaration",
                    "name": "balances",
                    "stateVariable": True,
                    "visibility": "public",
                    "src": state_src,
                },
                {
                    "id": 2,
                    "nodeType": "FunctionDefinition",
                    "kind": "function",
                    "name": "set",
                    "visibility": "external",
                    "src": set_src,
                    "body": {
                        "id": 35,
                        "nodeType": "Block",
                        "statements": [set_statement],
                        "src": self._src(source, "{\n                balances[user] = amount;\n            }"),
                    },
                },
                {
                    "id": 3,
                    "nodeType": "FunctionDefinition",
                    "kind": "function",
                    "name": "increase",
                    "visibility": "external",
                    "src": increase_src,
                    "body": {
                        "id": 45,
                        "nodeType": "Block",
                        "statements": [increase_statement],
                        "src": self._src(source, "{\n                balances[user] += amount;\n            }"),
                    },
                },
            ],
        }
        build_info = {
            "id": "storage-test",
            "solcVersion": "0.8.28",
            "input": {"sources": {"src/StorageVault.sol": {"content": source}}},
            "output": {"sources": {"src/StorageVault.sol": {"id": 0, "ast": {
                "id": 0, "nodeType": "SourceUnit", "src": self._src(source, "pragma solidity"),
                "nodes": [contract_ast],
            }}}},
        }
        self._write(root, "out/build-info/storage.json", json.dumps(build_info))

        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        balances = find_symbols(index, "StorageVault.balances")[0]
        expected_balances_offset = source.index("mapping(address => uint256) public balances")
        self.assertEqual(balances.get("source_offset"), expected_balances_offset)
        self.assertEqual(
            balances.get("line"),
            source.count("\\n", 0, expected_balances_offset) + 1,
        )
        setter = find_symbols(index, "StorageVault.set(address,uint256)")[0]
        increase = find_symbols(index, "StorageVault.increase(address,uint256)")[0]
        ast_edges = [
            edge for edge in index["edges"]
            if edge.get("evidence") == "SOLC_AST_STORAGE_DECLARATION_REFERENCE"
            and edge.get("to") == balances["id"]
        ]
        self.assertTrue(any(
            edge.get("from") == setter["id"] and edge["kind"] == "WRITES"
            and edge.get("access_path") == "balances[user]"
            and edge.get("operation") == "="
            for edge in ast_edges
        ), msg=f"AST match diagnostics: {json.dumps(index.get('ast'), sort_keys=True)}; storage edges={json.dumps(ast_edges, sort_keys=True)}")
        self.assertTrue(any(
            edge.get("from") == increase["id"] and edge["kind"] == "WRITES"
            and edge.get("access_path") == "balances[user]"
            and edge.get("operation") == "+="
            for edge in ast_edges
        ))
        self.assertTrue(any(
            edge.get("from") == increase["id"] and edge["kind"] == "READS"
            and edge.get("access_path") == "balances[user]"
            and edge.get("operation") == "read-for-update"
            for edge in ast_edges
        ))
        self.assertGreaterEqual(index["ast"]["storage_edges"], 3)

    def test_ast_storage_parameter_tracks_library_mutation_back_to_mapping(self):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        self._write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
        source = """
        pragma solidity ^0.8.20;

        contract StorageVault {
            struct Position { uint256 debt; }
            mapping(address => Position) public positions;

            function increase(address user, uint256 amount) external {
                PositionLib.increaseDebt(positions[user], amount);
            }
        }

        library PositionLib {
            function increaseDebt(StorageVault.Position storage position, uint256 amount) internal {
                position.debt += amount;
            }
        }
        """
        self._write(root, "src/StorageVault.sol", source)

        def span(snippet, start_after=0):
            return self._src(source, snippet, start_after)

        positions_id = 13
        field_id = 12
        parameter_id = 32
        library_function_id = 31
        caller_start = source.index("function increase(")
        library_start = source.index("function increaseDebt(")
        call_start = source.index("PositionLib.increaseDebt(")
        caller_body_start = source.index("{", caller_start)
        library_body_start = source.index("{", library_start)

        call_argument = {
            "id": 41,
            "nodeType": "IndexAccess",
            "baseExpression": {
                "id": 42,
                "nodeType": "Identifier",
                "name": "positions",
                "referencedDeclaration": positions_id,
                "src": span("positions", call_start),
            },
            "indexExpression": {
                "id": 43,
                "nodeType": "Identifier",
                "name": "user",
                "referencedDeclaration": 21,
                "src": span("user", call_start),
            },
            "src": span("positions[user]", call_start),
        }
        library_call = {
            "id": 44,
            "nodeType": "FunctionCall",
            "expression": {
                "id": 45,
                "nodeType": "MemberAccess",
                "expression": {
                    "id": 46,
                    "nodeType": "Identifier",
                    "name": "PositionLib",
                    "referencedDeclaration": 30,
                    "src": span("PositionLib", call_start),
                },
                "memberName": "increaseDebt",
                "referencedDeclaration": library_function_id,
                "src": span("PositionLib.increaseDebt", call_start),
            },
            "arguments": [
                call_argument,
                {
                    "id": 47,
                    "nodeType": "Identifier",
                    "name": "amount",
                    "referencedDeclaration": 22,
                    "src": span("amount", call_start),
                },
            ],
            "src": span("PositionLib.increaseDebt(positions[user], amount)", call_start),
        }
        library_assignment = {
            "id": 55,
            "nodeType": "Assignment",
            "operator": "+=",
            "leftHandSide": {
                "id": 56,
                "nodeType": "MemberAccess",
                "expression": {
                    "id": 57,
                    "nodeType": "Identifier",
                    "name": "position",
                    "referencedDeclaration": parameter_id,
                    "src": span("position", library_start),
                },
                "memberName": "debt",
                "referencedDeclaration": field_id,
                "src": span("position.debt", library_start),
            },
            "rightHandSide": {
                "id": 58,
                "nodeType": "Identifier",
                "name": "amount",
                "referencedDeclaration": 33,
                "src": span("amount", library_start),
            },
            "src": span("position.debt += amount", library_start),
        }

        vault_ast = {
            "id": 10,
            "nodeType": "ContractDefinition",
            "name": "StorageVault",
            "contractKind": "contract",
            "src": span("contract StorageVault"),
            "nodes": [
                {
                    "id": 11,
                    "nodeType": "StructDefinition",
                    "name": "Position",
                    "src": span("struct Position"),
                    "members": [{
                        "id": field_id,
                        "nodeType": "VariableDeclaration",
                        "name": "debt",
                        "src": span("uint256 debt;"),
                    }],
                },
                {
                    "id": positions_id,
                    "nodeType": "VariableDeclaration",
                    "name": "positions",
                    "stateVariable": True,
                    "src": span("mapping(address => Position) public positions"),
                },
                {
                    "id": 20,
                    "nodeType": "FunctionDefinition",
                    "kind": "function",
                    "name": "increase",
                    "visibility": "external",
                    "src": span("function increase(address user, uint256 amount) external {\n                PositionLib.increaseDebt(positions[user], amount);\n            }"),
                    "body": {
                        "id": 48,
                        "nodeType": "Block",
                        "statements": [{
                            "id": 49,
                            "nodeType": "ExpressionStatement",
                            "expression": library_call,
                            "src": span("PositionLib.increaseDebt(positions[user], amount);", call_start),
                        }],
                        "src": span("{\n                PositionLib.increaseDebt(positions[user], amount);\n            }", caller_body_start),
                    },
                },
            ],
        }
        library_ast = {
            "id": 30,
            "nodeType": "ContractDefinition",
            "name": "PositionLib",
            "contractKind": "library",
            "src": span("library PositionLib"),
            "nodes": [{
                "id": library_function_id,
                "nodeType": "FunctionDefinition",
                "kind": "function",
                "name": "increaseDebt",
                "visibility": "internal",
                "src": span("function increaseDebt(StorageVault.Position storage position, uint256 amount) internal {\n                position.debt += amount;\n            }"),
                "parameters": {
                    "id": 50,
                    "nodeType": "ParameterList",
                    "parameters": [
                        {
                            "id": parameter_id,
                            "nodeType": "VariableDeclaration",
                            "name": "position",
                            "storageLocation": "storage",
                            "src": span("StorageVault.Position storage position", library_start),
                        },
                        {
                            "id": 33,
                            "nodeType": "VariableDeclaration",
                            "name": "amount",
                            "storageLocation": "default",
                            "src": span("uint256 amount", library_start),
                        },
                    ],
                },
                "body": {
                    "id": 51,
                    "nodeType": "Block",
                    "statements": [{
                        "id": 52,
                        "nodeType": "ExpressionStatement",
                        "expression": library_assignment,
                        "src": span("position.debt += amount;", library_body_start),
                    }],
                    "src": span("{\n                position.debt += amount;\n            }", library_body_start),
                },
            }],
        }
        build_info = {
            "id": "library-storage-build",
            "solcVersion": "0.8.28",
            "input": {"sources": {"src/StorageVault.sol": {"content": source}}},
            "output": {"sources": {"src/StorageVault.sol": {"id": 0, "ast": {
                "id": 0,
                "nodeType": "SourceUnit",
                "src": span("pragma solidity"),
                "nodes": [vault_ast, library_ast],
            }}}},
        }
        self._write(root, "out/build-info/library-storage.json", json.dumps(build_info))

        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        positions = find_symbols(index, "StorageVault.positions")[0]
        expected_positions_offset = source.index("mapping(address => Position) public positions")
        self.assertEqual(positions.get("source_offset"), expected_positions_offset)
        position_field = find_symbols(index, "StorageVault.Position.debt")[0]
        expected_field_offset = source.index("uint256 debt;")
        self.assertEqual(position_field.get("source_offset"), expected_field_offset)
        caller = find_symbols(index, "StorageVault.increase")[0]
        library_function = find_symbols(index, "PositionLib.increaseDebt")[0]
        library_writes = [
            edge for edge in index["edges"]
            if edge.get("from") == library_function["id"]
            and edge.get("to") == positions["id"]
            and edge.get("kind") == "WRITES"
            and edge.get("evidence") == "SOLC_AST_STORAGE_DECLARATION_REFERENCE"
        ]
        self.assertEqual(
            len(library_writes), 1,
            msg=f"AST match diagnostics: {json.dumps(index.get('ast'), sort_keys=True)}; storage edges={json.dumps([edge for edge in index['edges'] if edge.get('kind') in {'WRITES','ALIASES_STORAGE'}], sort_keys=True)}",
        )
        self.assertEqual(library_writes[0].get("access_path"), "positions[user].debt")
        self.assertEqual(library_writes[0].get("index_kinds"), ["mapping"])
        self.assertEqual(library_writes[0].get("index_types"), ["address"])
        self.assertEqual(library_writes[0].get("mapping_key_types"), ["address"])
        self.assertEqual(library_writes[0].get("mapping_depth"), 1)
        self.assertEqual(library_writes[0].get("terminal_type"), "uint256")
        self.assertEqual(library_writes[0].get("operation"), "+=")
        self.assertEqual(library_writes[0].get("resolution"), "INFERRED")
        self.assertIn(caller["id"], library_writes[0].get("via", []))
        self.assertTrue(any(
            edge.get("from") == caller["id"]
            and edge.get("kind") == "ALIASES_STORAGE"
            and edge.get("evidence") == "SOLC_AST_STORAGE_REFERENCE_ARGUMENT"
            and edge.get("access_path") == "positions[user]"
            for edge in index["edges"]
        ))

    def test_ast_constants_and_immutables_are_not_storage_reads_or_writes(self):
        source = "SCALE + deployedAt;\ndeployedAt = block.timestamp;"
        unit = {"path": "src/Values.sol", "source": source, "build_info": "test-build"}
        constant = {
            "id": "state:SCALE", "kind": "state_variable",
            "name": "SCALE", "storage_class": "constant",
        }
        immutable = {
            "id": "state:deployedAt", "kind": "state_variable",
            "name": "deployedAt", "storage_class": "immutable",
        }
        declarations = {
            ("test-build", 1): constant,
            ("test-build", 2): immutable,
        }

        def identifier(name: str, declaration: int, start_after: int = 0) -> dict:
            start = source.index(name, start_after)
            return {
                "nodeType": "Identifier",
                "name": name,
                "referencedDeclaration": declaration,
                "src": f"{start}:{len(name)}:0",
            }

        reader = {
            "nodeType": "FunctionDefinition",
            "body": {
                "nodeType": "Block",
                "statements": [{
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "BinaryOperation",
                        "operator": "+",
                        "leftExpression": identifier("SCALE", 1),
                        "rightExpression": identifier("deployedAt", 2, source.index("SCALE")),
                    },
                }],
            },
        }
        constructor_start = source.index("deployedAt =")
        constructor = {
            "nodeType": "FunctionDefinition",
            "body": {
                "nodeType": "Block",
                "statements": [{
                    "nodeType": "ExpressionStatement",
                    "expression": {
                        "nodeType": "Assignment",
                        "operator": "=",
                        "leftHandSide": identifier("deployedAt", 2, constructor_start),
                        "rightHandSide": {
                            "nodeType": "Literal",
                            "value": "1",
                            "src": f"{source.index('block.timestamp', constructor_start)}:15:0",
                        },
                    },
                }],
            },
        }
        edges = []
        source_ast._emit_ast_storage_effects(
            reader, {"id": "function:readMeta", "name": "readMeta"},
            unit=unit, declarations=declarations, edges=edges,
        )
        source_ast._emit_ast_storage_effects(
            constructor, {"id": "function:constructor", "name": "constructor"},
            unit=unit, declarations=declarations, edges=edges,
        )

        self.assertTrue(any(
            edge.get("kind") == "READS_CONSTANT"
            and edge.get("from") == "function:readMeta"
            and edge.get("to") == constant["id"]
            for edge in edges
        ))
        self.assertTrue(any(
            edge.get("kind") == "READS_IMMUTABLE"
            and edge.get("from") == "function:readMeta"
            and edge.get("to") == immutable["id"]
            for edge in edges
        ))
        self.assertTrue(any(
            edge.get("kind") == "INITIALIZES"
            and edge.get("from") == "function:constructor"
            and edge.get("to") == immutable["id"]
            and edge.get("persistence") == "immutable"
            for edge in edges
        ))
        self.assertFalse(any(
            edge.get("kind") in {"READS", "WRITES"}
            and edge.get("to") in {constant["id"], immutable["id"]}
            for edge in edges
        ))

    def test_ast_storage_index_kinds_follow_nested_mapping_and_array_types(self):
        source = "positions[user][token].samples[0]"
        build_id = "fixture"
        positions = {
            "id": "state:positions",
            "kind": "mapping",
            "name": "positions",
            "type": "mapping(address => mapping(address => Position))",
        }
        samples = {
            "id": "field:Position.samples",
            "kind": "struct_field",
            "name": "samples",
            "type": "uint256[]",
        }
        declarations = {
            (build_id, 1): positions,
            (build_id, 2): samples,
        }

        def node_span(text: str, start_after: int = 0) -> str:
            start = source.index(text, start_after)
            return f"{start}:{len(text)}:0"

        positions_ref = {
            "nodeType": "Identifier",
            "name": "positions",
            "referencedDeclaration": 1,
            "src": node_span("positions"),
        }
        first_index_start = source.index("[user]")
        first_index = {
            "nodeType": "IndexAccess",
            "baseExpression": positions_ref,
            "indexExpression": {
                "nodeType": "Identifier",
                "name": "user",
                "src": node_span("user"),
            },
            "src": f"{source.index('positions')}:{first_index_start + len('[user]') - source.index('positions')}:0",
        }
        second_index_start = source.index("[token]")
        second_index = {
            "nodeType": "IndexAccess",
            "baseExpression": first_index,
            "indexExpression": {
                "nodeType": "Identifier",
                "name": "token",
                "src": node_span("token"),
            },
            "src": f"{source.index('positions')}:{second_index_start + len('[token]') - source.index('positions')}:0",
        }
        member_start = source.index(".samples")
        member = {
            "nodeType": "MemberAccess",
            "expression": second_index,
            "memberName": "samples",
            "referencedDeclaration": 2,
            "src": f"{source.index('positions')}:{member_start + len('.samples') - source.index('positions')}:0",
        }
        array_index = {
            "nodeType": "IndexAccess",
            "baseExpression": member,
            "indexExpression": {
                "nodeType": "Literal",
                "value": "0",
                "src": node_span("0"),
            },
            "src": f"{source.index('positions')}:{len(source) - source.index('positions')}:0",
        }

        resolved = source_ast._storage_expression(
            array_index,
            build_info=build_id,
            declarations=declarations,
            aliases={},
            source=source,
        )
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved["path"], "positions[user][token].samples[0]")
        self.assertEqual(resolved["keys"], ["user", "token", "0"])
        self.assertEqual(resolved["index_kinds"], ["mapping", "mapping", "array"])
        self.assertEqual(resolved["index_types"], ["address", "address", "uint256"])
        self.assertEqual(resolved["terminal_type"], "uint256")

    def test_stale_build_info_is_rejected_and_lexical_fallback_remains(self):
        temporary, root, _source = self._fixture(stale=True)
        try:
            index = build_source_index(root, use_cache=False)
        finally:
            temporary.cleanup()

        self.assertEqual(index["parser"], "LEXICAL")
        self.assertEqual(index["ast"]["functions"], 0)
        self.assertGreaterEqual(index["ast"]["stale_units"], 1)
        withdraw = find_symbols(index, "Vault.withdraw()")[0]
        debit = find_symbols(index, "Vault._debit()")[0]
        self.assertTrue(any(
            edge.get("from") == withdraw["id"]
            and edge.get("to") == debit["id"]
            and edge.get("kind") == "CALLS"
            for edge in index["edges"]
        ))

    def test_build_info_manifest_changes_when_artifact_changes(self):
        temporary, root, _source = self._fixture()
        try:
            path = root / "out" / "build-info" / "test.json"
            first = source_ast.build_info_manifest(root)
            path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")
            second = source_ast.build_info_manifest(root)
        finally:
            temporary.cleanup()

        self.assertEqual(len(first["files"]), 1)
        self.assertNotEqual(first["files"][0]["sha256"], second["files"][0]["sha256"])


if __name__ == "__main__":
    unittest.main()
