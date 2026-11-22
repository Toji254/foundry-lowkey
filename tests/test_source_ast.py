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
                    "src": self._src(source, "function _debit() internal {}", debit_start + 1),
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
        self.assertEqual(len(ast_calls), 1)
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
